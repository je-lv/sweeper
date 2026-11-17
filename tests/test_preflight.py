# tests/test_preflight.py
import inspect
import sys
import time
from pathlib import Path
import pytest
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.scope import ScopeGuard
from sweeper.stages.base import FailureClass
from sweeper import preflight


class GoodStage:
    name = "good"
    requires = []
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def build_command(self, ctx):
        return ["/bin/echo", "hello"]

    def parse(self, raw_path):
        return iter(())


class BadArgStage(GoodStage):
    name = "badarg"

    def build_command(self, ctx):
        # A deterministic parse-time rejection, independent of host coreutils.
        return [sys.executable, "-c",
                "import sys; print('unknown flag: --nope', file=sys.stderr); sys.exit(2)"]


def ctx_for(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))


def test_valid_argument_list_reports_no_error(tmp_path):
    assert preflight.validate_arguments(GoodStage(), ctx_for(tmp_path)) == ""


def test_invalid_argument_list_is_detected(tmp_path):
    err = preflight.validate_arguments(BadArgStage(), ctx_for(tmp_path))
    assert err != ""


def test_preflight_reports_target_count(tmp_path):
    r = preflight.run_preflight(ctx_for(tmp_path), [GoodStage()])
    assert r.target_count == 1


def test_preflight_fails_on_empty_targets_file(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("# only comments\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    r = preflight.run_preflight(ctx, [GoodStage()])
    assert r.ok is False
    assert any("no targets" in e.lower() for e in r.errors)


def test_preflight_refuses_unreachable_proxy_for_web_stage(tmp_path, monkeypatch):
    ctx = ctx_for(tmp_path)
    ctx.config.proxy = "http://127.0.0.1:8080"
    stage = GoodStage()
    stage.name = "httpx"
    monkeypatch.setattr(preflight, "proxy_reachable", lambda proxy: False)
    r = preflight.run_preflight(ctx, [stage])
    assert r.ok is False
    assert any("proxy is unreachable" in e for e in r.errors)


def test_preflight_ignores_proxy_when_no_selected_stage_uses_it(tmp_path,
                                                               monkeypatch):
    ctx = ctx_for(tmp_path)
    ctx.config.proxy = "http://127.0.0.1:8080"
    monkeypatch.setattr(
        preflight, "proxy_reachable",
        lambda proxy: (_ for _ in ()).throw(AssertionError("must not probe")),
    )
    assert preflight.run_preflight(ctx, [GoodStage()]).ok is True


def test_arg_error_makes_preflight_fail(tmp_path):
    r = preflight.run_preflight(ctx_for(tmp_path), [BadArgStage()])
    assert r.ok is False
    assert "badarg" in " ".join(r.arg_errors)


def test_missing_binary_disables_stage_but_does_not_abort(tmp_path):
    class NeedsGhost(GoodStage):
        name = "needsghost"
        requires = ["ghost"]

    r = preflight.run_preflight(ctx_for(tmp_path), [NeedsGhost()])
    assert "needsghost" in r.disabled_stages
    assert r.ok is True   # degraded, not fatal


# --- C4: a disabled stage must come with a pre-populated skip result -------
# run_preflight's `disabled_stages` (names only) is not enough for the
# runner to skip correctly without re-deciding on its own. It must hand
# back a StageResult too, and the list of stages that are actually safe to
# run, so run_stages never needs to call binaries.resolve()/verify() itself.


def test_disabled_stage_gets_a_prepopulated_skip_result(tmp_path):
    class NeedsGhost(GoodStage):
        name = "needsghost"
        requires = ["ghost"]

    r = preflight.run_preflight(ctx_for(tmp_path), [NeedsGhost()])
    assert [res.stage for res in r.disabled_results] == ["needsghost"]
    [res] = r.disabled_results
    assert res.status == "skipped"
    assert res.failure is FailureClass.MISSING_BINARY
    assert "ghost" in res.reason
    assert r.runnable == []


def test_runnable_excludes_disabled_stages_but_keeps_the_rest(tmp_path):
    class NeedsGhost(GoodStage):
        name = "needsghost"
        requires = ["ghost"]

    r = preflight.run_preflight(ctx_for(tmp_path), [NeedsGhost(), GoodStage()])
    assert [s.name for s in r.runnable] == ["good"]


def test_impostor_binary_is_disabled_by_identity_not_just_existence(tmp_path, monkeypatch):
    """Reproduces C4 directly: a file exists at the candidate path (so a bare
    existence check would accept it) but fails the -version identity check.
    run_preflight must disable it — this is the exact scenario binaries.py
    exists to catch (/usr/bin/httpx being the Python HTTP client, not
    ProjectDiscovery's httpx)."""
    from sweeper import binaries

    impostor = tmp_path / "impostor-httpx"
    impostor.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-version" ]; then echo "impostor httpclient v1.0"; exit 0; fi\n'
        'echo EXECUTED\n'
    )
    impostor.chmod(0o755)
    monkeypatch.setitem(
        binaries.KNOWN_BINARIES, "impostor",
        binaries.BinarySpec("impostor", [impostor], "-version",
                            binaries.PD_IDENTITY, "n/a"),
    )
    assert binaries.resolve("impostor") is not None   # exists
    assert binaries.verify("impostor").ok is False     # but fails identity

    class ImpostorStage(GoodStage):
        name = "impostorstage"
        requires = ["impostor"]

    r = preflight.run_preflight(ctx_for(tmp_path), [ImpostorStage()])
    assert "impostorstage" in r.disabled_stages
    assert r.runnable == []
    [res] = r.disabled_results
    assert res.failure is FailureClass.MISSING_BINARY
    assert "identity check failed" in res.reason


# --- C2: an allowlist that refuses every target must fail preflight --------
# is_degraded() correctly exempts NO_INPUT ("naabu found no ports"), but
# that exemption is wrong for "the allowlist rejected every target" -- a
# fundamentally different situation that used to leave degraded:false and
# exit 0 with nothing scanned.


def test_preflight_fails_when_every_target_is_refused(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("evil.test\nalso-evil.test\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    # Simulate a scope narrower than the targets file -- any source of that
    # (a mismatch, a future --scope-file) must be caught here regardless of
    # cause.
    ctx.scope = ScopeGuard({"totally-different.example"})
    r = preflight.run_preflight(ctx, [GoodStage()])
    assert r.ok is False
    assert r.permitted_count == 0
    assert r.target_count == 2
    assert any("refused" in e.lower() and "2" in e for e in r.errors)


def test_preflight_permitted_count_matches_when_all_in_scope(tmp_path):
    r = preflight.run_preflight(ctx_for(tmp_path), [GoodStage()])
    assert r.permitted_count == r.target_count == 1
    assert r.ok is True


def test_preflight_partial_scope_refusal_does_not_fail_preflight(tmp_path):
    """Some, but not all, targets refused: preflight must still proceed --
    only a TOTAL refusal is fatal. Partial refusals are already visible via
    ctx.scope.refusals in the manifest."""
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\nevil.test\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.scope = ScopeGuard({"acc.example"})
    r = preflight.run_preflight(ctx, [GoodStage()])
    assert r.ok is True
    assert r.permitted_count == 1
    assert r.target_count == 2


def _fake_bin(tmp_path, name, body):
    p = tmp_path / name
    p.write_text("#!/bin/sh\n" + body)
    p.chmod(0o755)
    return p


def test_input_txt_path_is_swapped_for_a_probe_file_of_dead_endpoints(tmp_path):
    """The real targets file must never be read during preflight.

    build_command() points the tool at the run's REAL targets. Preflight
    redirects that to a throwaway file holding only the dead endpoint, so
    the flags still parse and the input still opens, but nothing real is
    contacted.
    """
    ctx = ctx_for(tmp_path)
    seen = tmp_path / "seen.out"        # not .txt: must not be substituted
    # copies whatever input file it is handed so the test can inspect it
    tool = _fake_bin(tmp_path, "reader", f'cat "$2" > "{seen}"\n')

    class ReaderStage(GoodStage):
        name = "reader"

        def build_command(self, c):
            return [str(tool), "-l", str(c.config.targets_file)]

    assert preflight.validate_arguments(ReaderStage(), ctx) == ""

    got = seen.read_text()
    # the tool read the probe file, not the engagement's real targets
    assert got.strip() == preflight.DEAD_ENDPOINT
    assert "acc.example" not in got

    probe_input = ctx.run_dir / "raw" / ".preflight-targets.txt"
    assert probe_input.read_text().strip() == preflight.DEAD_ENDPOINT


def test_generic_usage_block_is_not_an_arg_error(tmp_path):
    """A cobra-style usage dump on an ordinary runtime failure is NOT ARG_ERROR.

    ARG_ERROR aborts the entire run, so misreading a connection failure that
    happens to print usage text would kill a scan with a confident wrong
    diagnosis.
    """
    tool = _fake_bin(tmp_path, "cobraish",
                     'echo "usage: thing [opts]" >&2\n'
                     'echo "error: connection refused" >&2\nexit 1\n')

    class UsageStage(GoodStage):
        name = "usagey"

        def build_command(self, c):
            return [str(tool)]

    assert preflight.validate_arguments(UsageStage(), ctx_for(tmp_path)) == ""


def test_old_broad_marker_list_would_have_false_positived(tmp_path, monkeypatch):
    """Guard the guard: prove the narrowed list is what prevents the misfire.

    Without this the previous test could pass for an unrelated reason and
    silently stop protecting anything.
    """
    tool = _fake_bin(tmp_path, "cobraish2",
                     'echo "usage: thing [opts]" >&2\n'
                     'echo "error: connection refused" >&2\nexit 1\n')

    class UsageStage(GoodStage):
        name = "usagey2"

        def build_command(self, c):
            return [str(tool)]

    monkeypatch.setattr(
        preflight, "ARG_ERROR_MARKERS",
        ("error:", "usage:", "unknown flag", "unrecognized option",
         "invalid option", "flag provided but not defined"),
    )
    assert preflight.validate_arguments(UsageStage(), ctx_for(tmp_path)) != ""


def test_genuine_flag_error_is_still_caught(tmp_path):
    tool = _fake_bin(tmp_path, "picky",
                     'echo "unknown flag: --nope" >&2\nexit 1\n')

    class PickyStage(GoodStage):
        name = "picky"

        def build_command(self, c):
            return [str(tool), "--nope"]

    err = preflight.validate_arguments(PickyStage(), ctx_for(tmp_path))
    assert "unknown flag" in err.lower()


# Go's flag package has THREE distinct error classes, and the first
# narrowing of ARG_ERROR_MARKERS used clap wording that caught only the
# first. A mistyped rate/timeout value — the likeliest real typo — then
# passed preflight and reached the target, the exact false negative this
# module exists to prevent. These strings are copied verbatim from
# ~/.pdtm/go/bin/{dnsx,naabu,httpx} on this machine (all exit rc=2).
GO_FLAG_ERRORS = [
    pytest.param("flag provided but not defined: -definitely-not-a-flag",
                 id="unknown-flag-name"),
    pytest.param("flag needs an argument: -retry",
                 id="flag-missing-its-value"),
    pytest.param('invalid value "abc" for flag -retry: parse error',
                 id="unparseable-flag-value"),
]


@pytest.mark.parametrize("message", GO_FLAG_ERRORS)
def test_all_go_flag_error_classes_are_caught(tmp_path, message):
    tool = _fake_bin(tmp_path, "goish", f'echo {message!r} >&2\nexit 2\n')

    class GoStage(GoodStage):
        name = "goish"

        def build_command(self, c):
            return [str(tool)]

    assert preflight.validate_arguments(GoStage(), ctx_for(tmp_path)) != "", (
        f"Go flag error not classified as an argument error: {message!r}"
    )


def test_timeout_is_configurable_and_honoured(tmp_path):
    """A binary still running when the clock runs out counts as accepting.

    It got past argument parsing, so there is nothing left to catch.
    """
    tool = _fake_bin(tmp_path, "sleeper", 'sleep 30\n')

    class SleepyStage(GoodStage):
        name = "sleepy"

        def build_command(self, c):
            return [str(tool)]

    started = time.monotonic()
    assert preflight.validate_arguments(SleepyStage(), ctx_for(tmp_path),
                                        timeout=0.5) == ""
    assert time.monotonic() - started < 10, "the timeout argument was ignored"


def test_run_preflight_honours_the_configured_preflight_timeout(tmp_path):
    """RunConfig.preflight_timeout must actually reach validate_arguments."""
    tool = _fake_bin(tmp_path, "sleeper2", 'sleep 30\n')

    class SleepyStage(GoodStage):
        name = "sleepy2"

        def build_command(self, c):
            return [str(tool)]

    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      preflight_timeout=0.5))
    started = time.monotonic()
    report = preflight.run_preflight(ctx, [SleepyStage()])
    assert time.monotonic() - started < 10, "preflight_timeout was not plumbed"
    assert report.arg_errors == []


def test_default_timeout_is_short_enough_to_matter():
    """Pin the default: the whole point is that preflight is not slow.

    25s per stage was over two minutes of dead time before a six-stage
    scan started. This is a production-latency budget, not a test-speed one.
    """
    sig = inspect.signature(preflight.validate_arguments)
    assert sig.parameters["timeout"].default <= 5.0
    assert RunConfig(targets_file=Path("x")).preflight_timeout <= 5.0


def test_an_argument_error_is_caught_well_inside_the_default_timeout(tmp_path):
    """The shortened timeout is only safe because rejections are instant.

    validate_arguments treats a timeout as success, so if a binary took
    longer to reject a bad flag than the timeout allows, preflight would
    silently stop catching the entire ARG_ERROR class — the exact defect
    Task 8 existed to prevent, reintroduced invisibly. Measured against the
    real binaries, all three reject in under 0.3s against a 3s budget; this
    pins that a rejection slower than an instant is still caught.
    """
    tool = _fake_bin(tmp_path, "slowreject",
                     'sleep 0.2\necho "flag needs an argument: -rate" >&2\n'
                     'exit 2\n')

    class SlowRejectStage(GoodStage):
        name = "slowreject"

        def build_command(self, c):
            return [str(tool)]

    err = preflight.validate_arguments(SlowRejectStage(), ctx_for(tmp_path))
    assert "flag needs an argument" in err.lower()


def test_pd_style_fatal_runtime_error_is_not_an_arg_error(tmp_path):
    """A [FTL] runtime failure from a PD tool must not read as ARG_ERROR.

    "invalid value" is the loosest marker in the list; this pins that it
    does not fire on the real fatal-error format these tools use when
    something goes wrong at runtime rather than at argument parsing.
    """
    tool = _fake_bin(tmp_path, "ftl",
                     'echo "[FTL] Could not run enumeration: '
                     'open /nope.txt: no such file or directory" >&2\n'
                     'exit 1\n')

    class FtlStage(GoodStage):
        name = "ftl"

        def build_command(self, c):
            return [str(tool)]

    assert preflight.validate_arguments(FtlStage(), ctx_for(tmp_path)) == ""


# --- Bounding the marker search to the start of the output -----------------
# ARG_ERROR is the most disruptive outcome in the taxonomy: it aborts the
# whole run. The marker match is a case-insensitive substring test, and it
# must search STDOUT (see _looks_like_arg_error), so scan CONTENT can collide
# with a marker phrase. Bounding the search to the first few lines keeps
# detection while preventing a crawled page body from killing a run.


def _scan_output_with_marker_buried(marker_line_no=20, total=40):
    """40 lines of plausible scan output, one containing a marker phrase."""
    lines = []
    for i in range(1, total + 1):
        if i == marker_line_no:
            lines.append(
                '{"url":"http://acc.example/settings",'
                '"body":"<p>Error: invalid value supplied for field</p>"}'
            )
        else:
            lines.append(f'{{"url":"http://acc.example/page{i}","status":200}}')
    return "\n".join(lines) + "\n"


def test_marker_buried_in_scan_content_is_not_an_arg_error():
    """A crawled page containing "invalid value" must not abort the run."""
    assert preflight._looks_like_arg_error(
        _scan_output_with_marker_buried(), ""
    ) is False


def test_arg_error_on_the_first_line_is_still_caught():
    """A genuine error, followed by other output, must still be detected."""
    stdout = ("flag provided but not defined: -definitely-not-a-flag\n"
              + _scan_output_with_marker_buried())
    assert preflight._looks_like_arg_error(stdout, "") is True


def test_marker_search_covers_stdout_not_just_stderr():
    """Pins a fact that looks like a bug and must not be "corrected".

    dnsx/naabu/httpx write argument errors to STDOUT and leave stderr
    completely empty. Verified 2026-07-29 by capturing the two streams to
    separate files: stdout 54 bytes containing the message, stderr 0 bytes.
    Go's flag package normally uses stderr, but goflags redirects. Matching
    stderr only would miss EVERY argument error on every one of these tools.
    """
    assert preflight._looks_like_arg_error(
        "flag provided but not defined: -nope\n", ""
    ) is True


def test_marker_search_still_covers_stderr():
    """Non-PD tools (nmap, ffuf, arjun) do use stderr; both must be searched."""
    assert preflight._looks_like_arg_error(
        "", "ls: unrecognized option '--nope'\n"
    ) is True


def test_scan_line_bound_is_at_least_two_lines():
    """A banner line before the error must not push it out of the window."""
    assert preflight.ARG_ERROR_SCAN_LINES >= 2
    stdout = "some banner\n" * (preflight.ARG_ERROR_SCAN_LINES - 1)
    stdout += "flag needs an argument: -retry\n"
    assert preflight._looks_like_arg_error(stdout, "") is True


def test_real_binaries_write_arg_errors_to_stdout(tmp_path):
    """The stdout fact, re-verified against the real binaries themselves.

    If a future goflags release moves these messages to stderr, this fails
    loudly rather than preflight silently ceasing to detect anything.
    """
    import subprocess
    from sweeper import binaries
    for name in ("dnsx", "naabu", "httpx"):
        path = binaries.resolve(name)
        if path is None:
            pytest.skip(f"{name} not installed")
        proc = subprocess.run([str(path), "-definitely-not-a-flag"],
                              capture_output=True, text=True, timeout=15)
        assert proc.returncode != 0
        assert preflight._looks_like_arg_error(proc.stdout, proc.stderr), (
            f"{name}: argument error no longer detected "
            f"(stdout={proc.stdout[:80]!r} stderr={proc.stderr[:80]!r})"
        )
        assert "flag provided but not defined" in proc.stdout.lower(), (
            f"{name} no longer writes argument errors to stdout — "
            "the marker search must continue to cover stdout"
        )


test_real_binaries_write_arg_errors_to_stdout = pytest.mark.slow(
    test_real_binaries_write_arg_errors_to_stdout
)


# --- first_meaningful_line: diagnostics must search both streams -----------


def test_first_meaningful_line_prefers_stdout():
    """stdout is searched first because that is where these tools write."""
    assert preflight.first_meaningful_line(
        "flag provided but not defined: -nope\n", "", "fallback"
    ) == "flag provided but not defined: -nope"


def test_first_meaningful_line_falls_back_to_stderr():
    """Non-PD tools do use stderr; both streams must be covered."""
    assert preflight.first_meaningful_line(
        "", "ls: unrecognized option\n", "fallback"
    ) == "ls: unrecognized option"


def test_first_meaningful_line_skips_blank_leading_lines():
    assert preflight.first_meaningful_line(
        "\n\n   \n", "  real message  \n", "fallback"
    ) == "real message"


def test_first_meaningful_line_returns_default_when_there_is_no_output():
    """No output on either stream must give the placeholder, not '' or a crash."""
    assert preflight.first_meaningful_line("", "", "fallback") == "fallback"
    assert preflight.first_meaningful_line("\n  \n", "\n", "fallback") == "fallback"


def test_first_meaningful_line_returns_only_one_line():
    assert preflight.first_meaningful_line(
        "one\ntwo\nthree\n", "", "fallback"
    ) == "one"


# --- argparse (arjun) prints its usage block FIRST, error LAST -------------
# A head-only scan window covers Go/cobra (error first) but misses argparse:
# arjun prints a multi-line usage block, then the error, measured at line 7
# of 7 for a real invocation. The window has to cover both ends of the
# output, while still excluding JSON scan content (the katana case below).


def _arjun_style_usage_block(error_line):
    """A 6-line argparse usage block followed by the error, as arjun emits."""
    return (
        "usage: arjun [-h] [-u URL] [-o JSON_FILE] [-oT TEXT_FILE] [-oB [BURP_PROXY]]\n"
        "             [-d DELAY] [-t THREADS] [-w WORDLIST] [-m METHOD]\n"
        "             [-i [IMPORT_FILE]] [-T TIMEOUT] [-c CHUNKS] [-q]\n"
        "             [--rate-limit RATE_LIMIT] [--headers [HEADERS]]\n"
        "             [--passive [PASSIVE]] [--stable] [--include INCLUDE]\n"
        "             [--disable-redirects] [--casing CASING]\n"
        f"{error_line}\n"
    )


def test_argparse_error_after_a_six_line_usage_block_is_caught():
    """The error sits at line 7 of 7 -- outside a head-only window."""
    stderr = _arjun_style_usage_block(
        "arjun: error: unrecognized arguments: --nope"
    )
    assert preflight._looks_like_arg_error("", stderr) is True


def test_head_only_window_would_have_missed_the_argparse_error():
    """Guard the guard: prove the old head-only scan really did miss this.

    Without this, the previous test could pass for an unrelated reason and
    silently stop protecting arjun.
    """
    stderr = _arjun_style_usage_block(
        "arjun: error: unrecognized arguments: --nope"
    )
    lines = [l for l in stderr.splitlines() if l.strip()]
    head_only = "\n".join(lines[:preflight.ARG_ERROR_SCAN_LINES]).lower()
    assert not any(m in head_only for m in preflight.ARG_ERROR_MARKERS)


def test_marker_buried_near_the_tail_of_scan_content_is_not_an_arg_error():
    """Scanning the tail too must not resurrect the katana false-positive.

    Same shape as test_marker_buried_in_scan_content_is_not_an_arg_error but
    with the buried marker near the END of the output, where the new tail
    window looks.
    """
    assert preflight._looks_like_arg_error(
        _scan_output_with_marker_buried(marker_line_no=39, total=40), ""
    ) is False


@pytest.mark.slow
def test_real_arjun_argument_error_is_caught(tmp_path):
    import subprocess
    from sweeper import binaries

    path = binaries.resolve("arjun")
    if path is None:
        pytest.skip("arjun not installed")
    proc = subprocess.run([str(path), "--definitely-not-a-flag"],
                          capture_output=True, text=True, timeout=15)
    assert proc.returncode != 0
    assert preflight._looks_like_arg_error(proc.stdout, proc.stderr), (
        f"arjun argument error no longer detected "
        f"(stdout={proc.stdout[:200]!r} stderr={proc.stderr[:200]!r})"
    )


# --- TargetLeakInProbe: fail-closed backstop over substitution shapes -------
#
# validate_arguments substitutes a dead endpoint into two argument SHAPES it
# recognises (a URL, a *.txt input path). That is an allowlist, and an
# allowlist of shapes fails open: any argument that is neither a URL nor a
# *.txt path passes through untouched. A new nmap stage did exactly that —
# passed the real target as bare positional argv — and preflight's own
# "nothing but 127.0.0.1:1 is ever contacted" probe scanned production with
# it. The fix here is not another recognised shape (that is the enumeration
# trap this codebase has hit four times before); it is a property check on
# the built probe's CONTENT: after substitution, no real target value may
# survive anywhere in the argv, checked by containment, not by shape.


def test_bare_positional_target_is_refused_and_subprocess_never_runs(
    tmp_path, monkeypatch
):
    """The regression case: a stage whose build_command writes a real
    target straight into argv, with no http:// prefix and no .txt suffix
    to trip the existing substitution.

    subprocess.run is monkeypatched so non-execution can be asserted
    directly — asserting only that TargetLeakInProbe was raised would also
    pass if the guard fired AFTER the packet had already gone out.
    """
    calls = []
    monkeypatch.setattr(
        preflight.subprocess, "run",
        lambda *a, **k: calls.append((a, k)),
    )

    class BareArgvStage(GoodStage):
        name = "bareargv"

        def build_command(self, c):
            return ["/bin/echo", "acc.example"]

    with pytest.raises(preflight.TargetLeakInProbe) as exc_info:
        preflight.validate_arguments(BareArgvStage(), ctx_for(tmp_path))

    assert calls == []
    msg = str(exc_info.value)
    assert "bareargv" in msg
    assert "acc.example" in msg


@pytest.mark.parametrize(
    "make_value",
    [
        # Embedded in a combined flag=value token, NOT as the whole
        # argument — an argument that IS exactly "https://acc.example/path"
        # is already neutralised by validate_arguments' existing startswith
        # substitution before the new guard ever runs. These four all start
        # with "--target=", so none of them trip that shape-based branch;
        # only the new content-based guard can catch them.
        pytest.param(lambda t: f"https://{t}/path", id="url-embedded"),
        pytest.param(lambda t: f"{t}:443", id="host-port"),
        pytest.param(lambda t: f"www.{t}", id="subdomain"),
        pytest.param(lambda t: f"other.example,{t},third.example",
                     id="comma-joined-list"),
    ],
)
def test_target_embedded_in_a_larger_argument_is_caught(tmp_path, make_value):
    class EmbeddedStage(GoodStage):
        name = "embedded"

        def build_command(self, c):
            return ["/bin/echo", f"--target={make_value('acc.example')}"]

    with pytest.raises(preflight.TargetLeakInProbe) as exc_info:
        preflight.validate_arguments(EmbeddedStage(), ctx_for(tmp_path))
    assert "acc.example" in str(exc_info.value)


@pytest.mark.parametrize(
    "target_line, probe_arg",
    [
        pytest.param("a", "/bin/echo -a --rate 800",
                     id="single-char-target"),
        pytest.param("/", "/bin/echo /tmp/sweeper-test/out/raw/x.txt",
                     id="slash-target"),
    ],
)
def test_degenerate_target_does_not_false_positive_or_crash(
    tmp_path, target_line, probe_arg
):
    """A single character or a bare "/" cannot be told apart from an
    incidental substring of nearly any argument. The guard must treat these
    as unmatchable rather than either crashing on them or flagging ordinary
    flags/paths as a leak.
    """
    t = tmp_path / "targets.txt"
    t.write_text(f"acc.example\n{target_line}\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))

    class DegenerateStage(GoodStage):
        name = "degenerate"

        def build_command(self, c):
            return probe_arg.split()

    # Must not raise, and must not crash — a real (non-degenerate) target is
    # also present in the file, proving the guard is still active, just not
    # tripped by the degenerate one or by the unrelated probe argv above.
    assert preflight.validate_arguments(DegenerateStage(), ctx) == ""


def test_empty_string_target_is_tolerated_without_crashing(tmp_path):
    """An empty target value cannot reach _real_targets via the targets
    file — _parse_targets strips blank lines before load_targets() ever
    sees them — so this exercises ctx.store directly, the other source
    _real_targets reads from, to prove the empty string is filtered out
    (by MIN_TARGET_LEN) rather than crashing re.compile or matching
    everything as an empty-string substring would.
    """
    ctx = ctx_for(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HOST, "", meta={}))

    class DegenerateStage(GoodStage):
        name = "degenerate"

        def build_command(self, c):
            return ["/bin/echo", "hello", "world"]

    assert preflight.validate_arguments(DegenerateStage(), ctx) == ""


def test_real_targets_are_length_filtered_and_deduped(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\nhttps://acc.example/\na\n\n#comment\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    assert preflight._real_targets(ctx) == ["acc.example"]


def test_dead_endpoint_and_probe_input_path_never_trip_the_guard(tmp_path):
    """Explicit requirement: the two values validate_arguments constructs
    itself — the dead-endpoint URL and the probe-input file path — must
    never be treated as a leak, even when a real in-scope target happens to
    normalize to "127.0.0.1" (the same host DEAD_ENDPOINT uses).
    """
    t = tmp_path / "targets.txt"
    t.write_text("127.0.0.1\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))

    class UrlStage(GoodStage):
        name = "urlstage"

        def build_command(self, c):
            return ["/bin/echo", "https://127.0.0.1/", "-l",
                    str(c.config.targets_file).replace(
                        c.config.targets_file.name, "input.txt")]

    assert preflight.validate_arguments(UrlStage(), ctx) == ""


# --- regression: the real stages must still pass the guard -----------------
# This is the test that matters most. A guard tight enough to catch a bare
# hostname positional argument but loose enough to still accept every real
# stage's actual command is the whole point — a guard that blocks real
# stages is a guard the next person disables. All five ship targets through
# a -l/-list/-i/-iL *.txt file, per each stage's own build_command, so none
# of them should ever reach TargetLeakInProbe; this proves it against the
# real binaries, not just against the shape of the code.


def _real_stage_cases():
    from sweeper.stages.cdncheck import CdncheckStage
    from sweeper.stages.dnsx import DnsxStage
    from sweeper.stages.httpx import HttpxStage
    from sweeper.stages.naabu import NaabuStage
    from sweeper.stages.nmap import NmapStage
    return [
        pytest.param(DnsxStage, "dnsx", id="dnsx"),
        pytest.param(NaabuStage, "naabu", id="naabu"),
        pytest.param(HttpxStage, "httpx", id="httpx"),
        pytest.param(CdncheckStage, "cdncheck", id="cdncheck"),
        pytest.param(NmapStage, "nmap", id="nmap"),
    ]


@pytest.mark.slow
@pytest.mark.parametrize("stage_cls, binary_name", _real_stage_cases())
def test_real_stages_pass_the_target_leak_guard(tmp_path, stage_cls, binary_name):
    from sweeper import binaries

    if binaries.resolve(binary_name) is None:
        pytest.skip(f"{binary_name} not installed; cannot probe the real binary")

    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    # Same seeding app.prepare() would do, so the store-derived side of
    # _real_targets is exercised too, not just the targets-file side.
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example",
                           meta={"src": "targets-file"}))

    err = preflight.validate_arguments(stage_cls(), ctx)
    assert err == "", (
        f"{binary_name} rejected its own real command during preflight: {err}"
    )


# --- A preflight probe must never write where the real run writes ----------
# runner.py's contract is that raw tool output "is written before parsing and
# never rewritten: it is the evidence trail". A probe is a DRY RUN against a
# dead endpoint, so if it can write to a real evidence path the first content
# in that file is preflight's dummy output rather than the tool's -- silently
# corrupting the trail. This is expressed generically, via the single
# ctx.raw_path() factory every writes_own_raw stage must already derive its
# output path from, rather than by enumerating output flags (-o, -oJ, -oX,
# ...), which would be a per-tool allowlist that omits the next tool.


class WritesOwnRawStage(GoodStage):
    """Shaped like vhost/arjun: the tool writes its own result file, at the
    path the runner will later hand to parse()."""
    name = "writesown"
    raw_suffix = "json"
    writes_own_raw = True

    def build_command(self, ctx):
        outfile = ctx.raw_path(self.name, self.raw_suffix)
        outfile.parent.mkdir(parents=True, exist_ok=True)
        # A real tool writes this file as it runs; /bin/echo stands in for
        # the subprocess actually doing so during the probe.
        return ["/usr/bin/tee", str(outfile)]


def _ctx(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))


def test_probe_does_not_create_the_real_evidence_file(tmp_path):
    ctx = _ctx(tmp_path)
    real = ctx.raw_path("writesown", "json")
    preflight.validate_arguments(WritesOwnRawStage(), ctx, timeout=1.0)
    assert not real.exists(), (
        "preflight's probe wrote the real run's raw evidence file; the first "
        "content there must be the tool's real output, not a dry-run dummy"
    )


def test_probe_output_goes_to_a_throwaway_path_instead(tmp_path):
    ctx = _ctx(tmp_path)
    stage = WritesOwnRawStage()
    with preflight.probe_output_redirected(ctx) as scratch:
        cmd = stage.build_command(ctx)
    outfile = Path(cmd[-1])
    assert outfile.parent == scratch
    assert outfile != ctx.raw_path("writesown", "json")


def test_raw_path_is_restored_after_the_probe(tmp_path):
    """The redirect must not leak past build_command(): the runner calls
    ctx.raw_path() itself to decide what to hand parse(), so a ctx left
    pointing at the scratch directory would send every stage's real output
    there.
    """
    ctx = _ctx(tmp_path)
    before = ctx.raw_path("writesown", "json")
    preflight.validate_arguments(WritesOwnRawStage(), ctx, timeout=1.0)
    assert ctx.raw_path("writesown", "json") == before
    assert "raw_path" not in vars(ctx), "probe left an instance attribute behind"


def test_raw_path_is_restored_even_when_build_command_raises(tmp_path):
    class Exploding(WritesOwnRawStage):
        def build_command(self, ctx):
            raise RuntimeError("boom")

    ctx = _ctx(tmp_path)
    before = ctx.raw_path("writesown", "json")
    with pytest.raises(RuntimeError):
        preflight.validate_arguments(Exploding(), ctx, timeout=1.0)
    assert ctx.raw_path("writesown", "json") == before


def test_normal_stage_output_path_is_unaffected(tmp_path):
    """Stages that let the runner capture stdout never call ctx.raw_path in
    build_command at all; nothing about them may change.
    """
    ctx = _ctx(tmp_path)
    err = preflight.validate_arguments(GoodStage(), ctx, timeout=1.0)
    assert err == ""
    assert "raw_path" not in vars(ctx)


def test_a_stage_hardcoding_its_evidence_path_is_refused(tmp_path):
    """Fail-closed backstop for the one way the redirect can be bypassed:
    a stage that hardcodes the evidence path instead of deriving it from
    ctx.raw_path(), so the swap never reaches it.
    """
    ctx = _ctx(tmp_path)
    hardcoded = str(ctx.raw_path("hardcoded", "json"))

    class Hardcodes(GoodStage):
        name = "hardcoded"
        raw_suffix = "json"
        writes_own_raw = True

        def build_command(self, ctx):
            return ["/bin/echo", "-o", hardcoded]

    with pytest.raises(preflight.EvidenceWriteInProbe) as exc:
        preflight.validate_arguments(Hardcodes(), ctx, timeout=1.0)
    assert "hardcoded" in str(exc.value)


def test_real_vhost_stage_probe_leaves_the_evidence_path_untouched(tmp_path):
    """The concrete case the review caught, against the real stage."""
    from sweeper.stages.vhost import VhostStage

    ctx = _ctx(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                           meta={"host": "acc.example"}))
    real = ctx.raw_path("vhost", "json")
    preflight.validate_arguments(VhostStage(), ctx, timeout=1.0)
    assert not real.exists()


# --- B3: a multi-host targets line must refuse the run --------------------
# "127.0.0.0/30" normalizes to "127.0.0.0", so the allowlist held one host
# while the raw "/30" was seeded as a target and handed to naabu, which
# scans all four. The three that were never allowlisted were scanned, then
# refused by admission control and filed under discoveries_refused -- the
# one bucket that by design never marks a run degraded. The run reported
# "1 requested, 1 in scope. No findings." and degraded:false.


def _preflight_for(tmp_path, targets_text):
    t = tmp_path / "targets.txt"
    t.write_text(targets_text)
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    return ctx, preflight.run_preflight(ctx, [GoodStage()])


@pytest.mark.parametrize("line", [
    "127.0.0.0/30",
    "10.0.0.0/16",
    "2001:db8::/126",
    "2001:db8::/64",      # not enumerable: an expanding fix cannot cover it
    "10.0.0.1-5",
    "10.0.0.*",
])
def test_multi_host_targets_line_refuses_the_run(tmp_path, line):
    ctx, report = _preflight_for(tmp_path, line + "\n")
    assert report.ok is False
    assert any(line in e for e in report.errors), report.errors


def test_the_refusal_names_the_line_and_says_what_to_do(tmp_path):
    """An operator-facing error, not a generic scope message: the run dies
    here, so this text is the only thing telling them why and how to fix it.
    """
    ctx, report = _preflight_for(tmp_path, "10.0.0.0/24\n")
    [err] = [e for e in report.errors if "10.0.0.0/24" in e]
    assert "more than one host" in err
    assert "own line" in err          # the remedy, spelled out


def test_a_multi_host_line_refuses_the_run_even_when_other_targets_are_fine(
        tmp_path):
    """The mixed file is the dangerous one: the run has permitted targets, so
    the generic no-permitted-targets check stays quiet and the run would
    otherwise start and sweep the range.
    """
    ctx, report = _preflight_for(tmp_path, "acc.example\n10.0.0.0/24\n")
    assert report.permitted_count == 1      # acc.example is genuinely fine
    assert report.ok is False
    assert any("10.0.0.0/24" in e for e in report.errors), report.errors


def test_no_host_inside_the_range_is_ever_seeded_as_a_target(tmp_path):
    """The store is what stages build their command from; naabu reads
    ArtifactKind.HOST. Nothing derived from the range may be in there --
    neither the raw "/24" line (which naabu would expand) nor the single
    address normalize() salvaged from it.
    """
    from sweeper import app

    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n10.0.0.0/24\n")
    ctx = app.prepare(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    hosts = list(ctx.store.values(ArtifactKind.HOST))
    assert hosts == ["acc.example"]
    assert not any("10.0.0" in h for h in hosts)


def test_a_range_whose_own_address_is_also_listed_still_refuses_the_run(
        tmp_path):
    """The defect reconstructed end to end from a plausible targets file.

    Listing 127.0.0.0 puts that host in the allowlist, so the "/30" line
    matches its own entry: the run started, naabu swept four addresses, and
    three of them were never in scope.
    """
    from sweeper import app

    t = tmp_path / "targets.txt"
    t.write_text("127.0.0.0\n127.0.0.0/30\n")
    cfg = RunConfig(targets_file=t, outdir=tmp_path / "out")
    ctx = app.prepare(cfg)
    assert list(ctx.store.values(ArtifactKind.HOST)) == ["127.0.0.0"]
    report = preflight.run_preflight(ctx, [GoodStage()])
    assert report.ok is False
    assert any("127.0.0.0/30" in e for e in report.errors), report.errors


def test_ordinary_targets_file_still_passes_preflight(tmp_path):
    """A check that fires on ordinary input is a check that gets disabled."""
    ctx, report = _preflight_for(
        tmp_path, "acc.example\nacc.example:8443\nhttp://127.0.0.1/app\n")
    assert report.ok is True
    assert report.errors == []


def test_wildcard_dns_scope_line_still_passes_preflight(tmp_path):
    """"*.acc.example" denotes many hosts too, but its allowlist entry covers
    every one of them. It is the sanctioned form and must keep working.
    """
    ctx, report = _preflight_for(tmp_path, "*.acc.example\nacc.example\n")
    assert report.ok is True
    assert report.errors == []


# --- B5: the leak guard must not fire on preflight's own scratch paths, must
# --- not print credentials, and must not crash the run ----------------------
#
# _find_leak checks probe argv by CONTENT, which is the right property and the
# reason it caught the nmap regression. But three things followed from doing
# it naively.
#
# (a) The only argv values that are not targets are paths, and every one of
#     them is derived from ctx.run_dir -- which is outdir/<timestamp>, and
#     outdir is whatever the operator typed. "--outdir recon/acc.example" is a
#     standard engagement layout, and under it the guard fired on the scratch
#     output path PREFLIGHT ITSELF injected via probe_output_redirected()
#     (arjun -oJ, vhost -o), on nuclei's -secret-file, and on katana's header
#     file. A guard that refuses the ordinary layout is a guard the next
#     person disables.
# (b) The offending argument was interpolated into the exception message. A
#     stage's argv can hold live credentials -- arjun passes ctx.auth as ONE
#     literal --headers string -- and any Burp-imported cookie whose value
#     carries a "returnUrl=https://<target>/..." matches by content, so the
#     live session cookie was rendered verbatim into a message that is
#     printed, logged to sweep.log and recorded in run.json.
# (c) It escaped run_preflight, which app.execute() used to call outside every
#     try:. The run directory was left with no run.json and no report -- a
#     directory that reads afterwards as a clean, empty scan -- and the menu
#     REPL died with a traceback, discarding the operator's settings and
#     credentials.


class _ScratchWriter(GoodStage):
    """Shaped like arjun/vhost: derives its output path from ctx.raw_path(),
    which preflight redirects into its own scratch directory."""
    name = "scratchwriter"
    raw_suffix = "json"
    writes_own_raw = True

    def build_command(self, ctx):
        return ["/bin/echo", "-o", str(ctx.raw_path(self.name, self.raw_suffix))]


def _ctx_with_target_named_outdir(tmp_path):
    """The reported layout: an --outdir whose path contains the target host."""
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t,
                                      outdir=tmp_path / "recon" / "acc.example"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example",
                           meta={"src": "targets-file"}))
    return ctx


def test_scratch_output_path_under_a_target_named_outdir_is_not_a_leak(tmp_path):
    ctx = _ctx_with_target_named_outdir(tmp_path)
    assert "acc.example" in str(ctx.run_dir), "fixture no longer reproduces (a)"
    assert preflight.validate_arguments(_ScratchWriter(), ctx, timeout=1.0) == ""


@pytest.mark.parametrize(
    "sidecar",
    [
        # nuclei -secret-file, the fourth site of the same defect.
        pytest.param(("auth", "secrets.yaml"), id="nuclei-secret-file"),
        # A sidecar no stage has written yet. Whitelisting the run's own
        # directory tree rather than enumerating today's four flags is what
        # keeps the fifth one from re-opening this.
        pytest.param(("raw", "some-future-sidecar.dat"), id="future-sidecar"),
    ],
)
def test_any_run_dir_path_under_a_target_named_outdir_is_not_a_leak(
    tmp_path, sidecar
):
    ctx = _ctx_with_target_named_outdir(tmp_path)

    class Sidecar(GoodStage):
        name = "sidecar"

        def build_command(self, c):
            return ["/bin/echo", "-f", str(c.run_dir.joinpath(*sidecar))]

    assert preflight.validate_arguments(Sidecar(), ctx, timeout=1.0) == ""


def test_guard_still_fires_on_a_bare_target_under_a_target_named_outdir(tmp_path):
    """The other half of (a): whitelisting the run directory must not become
    a blanket amnesty. A genuine bare-positional leak in the SAME argv as a
    whitelisted scratch path must still be refused.
    """
    ctx = _ctx_with_target_named_outdir(tmp_path)

    class LeakyWriter(_ScratchWriter):
        name = "leakywriter"

        def build_command(self, c):
            return ["/bin/echo", "-o",
                    str(c.raw_path(self.name, self.raw_suffix)),
                    "acc.example"]

    with pytest.raises(preflight.TargetLeakInProbe):
        preflight.validate_arguments(LeakyWriter(), ctx, timeout=1.0)


def test_a_target_appended_to_a_whitelisted_path_is_still_a_leak(tmp_path):
    """Eliding a safe value leaves the rest of the argument to be checked --
    it does not clear the whole argument. Otherwise a stage could hide a
    target behind a run-dir prefix.
    """
    ctx = _ctx_with_target_named_outdir(tmp_path)

    class Smuggler(GoodStage):
        name = "smuggler"

        def build_command(self, c):
            return ["/bin/echo", f"{c.run_dir}/raw/out.json,acc.example"]

    with pytest.raises(preflight.TargetLeakInProbe):
        preflight.validate_arguments(Smuggler(), ctx, timeout=1.0)


def test_elide_never_splices_two_fragments_into_a_match():
    """_elide blanks with a space, not with "". Removing the safe value
    outright could join what is on either side of it into a hostname that
    matches something neither fragment did -- a false POSITIVE, which is the
    fail-closed direction, but the space also keeps the label boundaries
    intact for the negative case below.
    """
    assert preflight._elide("acc.SAFEexample", {"SAFE"}) == "acc. example"
    assert preflight._find_leak(
        ["acc.SAFEexample"], safe_values={"SAFE"}, targets=["acc.example"],
    ) is None


def test_empty_safe_value_cannot_disable_the_guard():
    """str.replace("", " ") interleaves a space between every character, which
    would stop every target pattern from matching -- the guard silently off.
    """
    assert preflight._find_leak(
        ["acc.example"], safe_values={""}, targets=["acc.example"],
    ) == (0, "acc.example")


SESSION_COOKIE = "Sup3rSecretSessionValue"


class _ArjunShaped(GoodStage):
    """arjun's real shape: credentials as ONE literal --headers string. The
    returnUrl cookie carries the target host, which is what trips the guard.
    """
    name = "arjunshaped"

    def build_command(self, ctx):
        return ["/bin/echo", "--headers",
                "User-Agent: x\n"
                f"Cookie: session={SESSION_COOKIE}; "
                "returnUrl=https://acc.example/cart"]


def test_credential_bearing_argument_is_never_rendered_into_the_message(tmp_path):
    """(b). The guard still fires -- a target hostname inside a credential is
    indistinguishable by content from one in a positional argument, and
    eliding operator-supplied secret values would erase a genuine leak
    whenever a cookie value happened to equal the target. What must NOT
    happen is the live cookie landing in a message that is printed, logged
    and persisted.
    """
    ctx = ctx_for(tmp_path)
    with pytest.raises(preflight.TargetLeakInProbe) as exc_info:
        preflight.validate_arguments(_ArjunShaped(), ctx, timeout=1.0)
    msg = str(exc_info.value)
    assert SESSION_COOKIE not in msg, "live session cookie leaked into the message"
    assert "Cookie:" not in msg and "returnUrl" not in msg
    # Still says which stage, which argument and which target, so it stays
    # diagnosable without the value.
    assert "arjunshaped" in msg
    assert "#2" in msg
    assert "acc.example" in msg


def test_find_leak_cannot_return_the_offending_argument():
    """The no-credentials-in-the-message property is structural, not a
    convention the caller has to remember: _find_leak hands back an index.
    """
    assert preflight._find_leak(
        ["/bin/echo", f"secret={SESSION_COOKIE}@acc.example"],
        safe_values=set(), targets=["acc.example"],
    ) == (1, "acc.example")


def test_leaking_stage_is_recorded_as_a_preflight_error_not_raised(tmp_path):
    """(c). run_preflight must RETURN a refused report -- the precedent
    validate_custom_templates set -- so execute() writes run.json and the
    report and exits 2, instead of the exception escaping the one phase that
    used to sit outside every try:.
    """
    ctx = ctx_for(tmp_path)

    class BareArgvStage(GoodStage):
        name = "bareargv"

        def build_command(self, c):
            return ["/bin/echo", "acc.example"]

    report = preflight.run_preflight(ctx, [BareArgvStage()])
    assert report.ok is False, "a target leak must still refuse the run"
    assert any("bareargv" in e and "acc.example" in e for e in report.errors), \
        report.errors


def test_a_leaking_stage_does_not_suppress_the_checks_on_the_others(tmp_path):
    """`continue`, not `break`: the offending probe never ran, so there is no
    reason to stop, and the operator gets every problem in one pass.
    """
    ctx = ctx_for(tmp_path)

    class BareArgvStage(GoodStage):
        name = "bareargv"

        def build_command(self, c):
            return ["/bin/echo", "acc.example"]

    report = preflight.run_preflight(ctx, [BareArgvStage(), BadArgStage()])
    assert report.ok is False
    assert any("bareargv" in e for e in report.errors), report.errors
    assert "badarg" in " ".join(report.arg_errors)


def test_leak_refusal_never_executes_the_probe(tmp_path, monkeypatch):
    """Recording the failure instead of raising must not move the guard to
    AFTER the subprocess. Asserting only on report.ok would pass either way.
    """
    calls = []
    monkeypatch.setattr(preflight.subprocess, "run",
                        lambda *a, **k: calls.append((a, k)))

    class BareArgvStage(GoodStage):
        name = "bareargv"

        def build_command(self, c):
            return ["/bin/echo", "acc.example"]

    report = preflight.run_preflight(ctx_for(tmp_path), [BareArgvStage()])
    assert report.ok is False
    assert calls == [], "the probe ran despite a detected target leak"


@pytest.mark.slow
@pytest.mark.parametrize("stage_name", ["arjun", "vhost", "nuclei"])
def test_real_writes_own_raw_stages_pass_under_a_target_named_outdir(
    tmp_path, stage_name
):
    """The reported case against the real stages and the real binaries, not
    just against a stand-in with the same shape.
    """
    from sweeper import binaries
    from sweeper.stages.arjun import ArjunStage
    from sweeper.stages.nuclei import NucleiStage
    from sweeper.stages.vhost import VhostStage

    stage_cls, binary_name = {
        "arjun": (ArjunStage, "arjun"),
        "vhost": (VhostStage, "ffuf"),
        "nuclei": (NucleiStage, "nuclei"),
    }[stage_name]
    if binaries.resolve(binary_name) is None:
        pytest.skip(f"{binary_name} not installed; cannot probe the real binary")

    ctx = _ctx_with_target_named_outdir(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                           meta={"host": "acc.example"}))
    # nuclei's -secret-file path is run-dir derived too, and is only present
    # on an authenticated run -- set it directly rather than through
    # app.execute() so this stays a preflight-level test.
    ctx.secret_file = ctx.run_dir / "auth" / "secrets.yaml"

    err = preflight.validate_arguments(stage_cls(), ctx, timeout=3.0)
    assert err == "", f"{binary_name} rejected its own real command: {err}"
