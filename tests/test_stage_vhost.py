from pathlib import Path

import pytest

from sweeper import binaries, preflight
from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.vhost import VhostStage
from sweeper.useragents import USER_AGENTS

FIX = Path(__file__).parent / "fixtures" / "vhost.json"
FIX_THREE = Path(__file__).parent / "fixtures" / "vhost-three-distinct.json"


def test_contract():
    assert registry.validate(VhostStage()) == []


def test_only_runs_at_high_and_full():
    s = VhostStage()
    assert s.levels["low"] == [] and s.levels["mid"] == []
    assert s.levels["high"] and s.levels["full"]


def test_distinct_response_is_reported_as_a_vhost():
    f = [x for x in VhostStage().parse(FIX) if isinstance(x, Finding)]
    assert len(f) == 1
    assert "internal" in f[0].evidence


def test_identical_baseline_responses_are_suppressed():
    f = [x for x in VhostStage().parse(FIX) if isinstance(x, Finding)]
    assert not any("admin" in x.evidence for x in f)
    assert not any("staging" in x.evidence for x in f)


def test_discovered_vhost_is_yielded_as_an_http_service_artifact():
    """The CRITICAL defect this guards: `produces` declared HTTP_SERVICE but
    parse() only ever yielded Findings, so a discovered vhost never entered
    ctx.store and every downstream HTTP_SERVICE consumer (nuclei, katana,
    jsrecon, arjun) silently never scanned it. Finding a hidden vhost and
    then not probing it is the weaker half of the feature.
    """
    out = list(VhostStage().parse(FIX))
    arts = [a for a in out if isinstance(a, Artifact)]
    assert len(arts) == 1, "no HTTP_SERVICE artifact produced for the vhost"
    assert arts[0].kind is ArtifactKind.HTTP_SERVICE
    # meta["host"] must be the DISCOVERED VHOST NAME -- that is what the
    # runner's admission choke point scope-checks.
    assert arts[0].meta["host"] == "internal"
    assert arts[0].value == "https://internal"


def test_baseline_rows_produce_no_artifact_either():
    """Suppression applies to artifacts, not just findings: the wildcard
    baseline is not a discovery and must not enter the store.
    """
    arts = [a for a in VhostStage().parse(FIX) if isinstance(a, Artifact)]
    names = {a.meta["host"] for a in arts}
    assert "admin" not in names and "staging" not in names


# --- finding-id collision: every discovered vhost must survive -------------
# Before the matcher fix, parse() emitted target=<origin url> (constant
# across every row) and template_id="vhost-discovered" (a constant) with no
# matcher, so every vhost discovered under one origin hashed to the SAME
# finding_id. ArtifactStore.add_finding() kept only the first and silently
# discarded the rest -- the whole point of this stage is finding hidden
# vhosts, and it reported one of them.


def test_three_distinct_vhosts_under_one_origin_produce_three_findings():
    findings = [f for f in VhostStage().parse(FIX_THREE) if isinstance(f, Finding)]
    assert len(findings) == 3
    assert {f.evidence.split()[1] for f in findings} == {"admin", "staging", "internal"}


def test_three_distinct_vhosts_have_three_distinct_ids():
    findings = [f for f in VhostStage().parse(FIX_THREE) if isinstance(f, Finding)]
    assert len({f.id for f in findings}) == 3


def test_vhost_finding_matcher_is_the_discovered_vhost_name():
    findings = [f for f in VhostStage().parse(FIX) if isinstance(f, Finding)]
    assert findings[0].matcher == "internal"


def test_vhost_finding_ids_are_identical_across_two_parses_of_the_same_scan():
    """Plan 3's run-to-run diffing depends on finding_id being stable for an
    identical rerun -- matcher must be derived from something intrinsic and
    repeatable (the vhost name), never a timestamp or ordering index.
    """
    first = {f.id for f in VhostStage().parse(FIX_THREE) if isinstance(f, Finding)}
    second = {f.id for f in VhostStage().parse(FIX_THREE) if isinstance(f, Finding)}
    assert first == second
    assert len(first) == 3


def test_three_distinct_vhosts_all_reach_the_store_with_no_collisions(tmp_path):
    """End-to-end through the real runner: three genuinely different vhosts
    discovered under one origin must all survive store.add_finding(), and
    none of them should be recorded as a finding-id collision (that would
    mean the matcher fix did not actually distinguish them).
    """
    from sweeper.runner import run_stages

    def _three_results() -> str:
        import json as _json
        rows = [
            {"input": {"FUZZ": "aaa"}, "status": 200, "length": 100, "words": 10,
             "url": "https://acc.example/", "host": "aaa"},
            {"input": {"FUZZ": "bbb"}, "status": 200, "length": 100, "words": 10,
             "url": "https://acc.example/", "host": "bbb"},
            {"input": {"FUZZ": "ccc"}, "status": 200, "length": 100, "words": 10,
             "url": "https://acc.example/", "host": "ccc"},
            {"input": {"FUZZ": "admin"}, "status": 200, "length": 900, "words": 90,
             "url": "https://acc.example/", "host": "admin"},
            {"input": {"FUZZ": "staging"}, "status": 200, "length": 800, "words": 80,
             "url": "https://acc.example/", "host": "staging"},
            {"input": {"FUZZ": "internal"}, "status": 200, "length": 700, "words": 70,
             "url": "https://acc.example/", "host": "internal"},
        ]
        return _json.dumps({"results": rows, "config": {}})

    t = tmp_path / "targets.txt"
    t.write_text("*.acc.example\nacc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                           meta={"host": "acc.example"}))
    [result] = run_stages(ctx, [_StubbedVhost(_three_results())])

    assert result.findings == 3
    assert ctx.store.finding_collisions == []
    stored_names = {f.matcher for f in ctx.store.findings}
    assert stored_names == {"admin", "staging", "internal"}


def test_produces_declaration_matches_what_parse_actually_yields():
    """A stage that declares a kind it never emits is a silent coverage gap
    -- nothing in the manifest says the downstream consumers got nothing.
    Tie the declaration to observed behaviour rather than asserting the
    literal set, so this keeps meaning something if the stage grows a kind.
    """
    stage = VhostStage()
    emitted = {a.kind for a in stage.parse(FIX) if isinstance(a, Artifact)}
    emitted |= {ArtifactKind.FINDING
                for a in stage.parse(FIX) if isinstance(a, Finding)}
    assert emitted == stage.produces


def test_raw_suffix_and_writes_own_raw_are_declared():
    """ffuf's -s suppresses stdout entirely, so the runner must not clobber
    the file ffuf itself wrote with an (empty) captured-stdout write -- see
    runner.py's raw_suffix/writes_own_raw contract (Task 3.5) and the vhost
    defect it exists to fix: parse() reading an empty file on every run.
    """
    s = VhostStage()
    assert s.raw_suffix == "json"
    assert s.writes_own_raw is True


def ctx_for(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)
    )
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                            meta={"host": "acc.example"}))
    return ctx


def test_output_file_is_the_same_path_the_runner_will_hand_to_parse(tmp_path):
    """End-to-end check for the "ad-hoc path parse() never read" defect:
    the file build_command tells ffuf to write (-o) must be byte-identical
    to ctx.raw_path(stage.name, stage.raw_suffix), the path runner.py
    computes from the stage's own declared raw_suffix.
    """
    ctx = ctx_for(tmp_path)
    stage = VhostStage()
    cmd = stage.build_command(ctx)
    outfile = Path(cmd[cmd.index("-o") + 1])
    expected = ctx.raw_path(stage.name, stage.raw_suffix)
    assert outfile == expected
    assert outfile.suffix == ".json"


def test_of_json_flag_present(tmp_path):
    cmd = VhostStage().build_command(ctx_for(tmp_path))
    assert "-of" in cmd
    assert cmd[cmd.index("-of") + 1] == "json"


def test_silent_flag_present_so_stdout_carries_nothing(tmp_path):
    """ffuf -s writes zero bytes to stdout -- this is exactly why
    writes_own_raw exists. Pin the flag that causes it.
    """
    cmd = VhostStage().build_command(ctx_for(tmp_path))
    assert "-s" in cmd


def test_target_goes_through_u_not_bare_argv(tmp_path):
    cmd = VhostStage().build_command(ctx_for(tmp_path))
    assert "-u" in cmd
    assert cmd[cmd.index("-u") + 1] == "https://acc.example"


def test_host_header_fuzzes_the_host(tmp_path):
    """The header must be FULLY QUALIFIED, not the bare wordlist label.

    `Host: FUZZ` sends "Host: admin", which matches no virtual host on any
    server, so every guess falls through to the wildcard default and the
    stage can never find anything. See tests/test_stage_vhost_hostpattern.py.
    """
    cmd = VhostStage().build_command(ctx_for(tmp_path))
    assert "Host: FUZZ.acc.example" in cmd
    assert "Host: FUZZ" not in cmd


def test_build_command_sends_a_browser_user_agent(tmp_path):
    cmd = VhostStage().build_command(ctx_for(tmp_path))
    headers = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-H"]
    ua_headers = [h for h in headers if h.startswith("User-Agent: ")]
    assert ua_headers, "no User-Agent header sent"
    assert ua_headers[0][len("User-Agent: "):] in USER_AGENTS


def test_no_mutation_flags_at_any_level():
    """Only `full` may mutate request parameters; vhost only fuzzes the
    Host header (GET requests), never -X/-d, at any level.
    """
    for level in LEVELS:
        args = " ".join(VhostStage().levels[level])
        assert "-X" not in args and "-d" not in args


def test_every_running_level_caps_the_request_rate():
    """ffuf's default is `-rate 0` -- UNBOUNDED. `-t` bounds concurrency,
    not requests per second, so threads alone are not a rate cap: 25 threads
    with no cap is 25 threads going as fast as the origin answers. The
    client rules of engagement bar DoS and the sibling stage (naabu) treats
    an explicit per-level rate as required, so every level that actually
    runs must carry one.
    """
    stage = VhostStage()
    for level in LEVELS:
        args = stage.levels[level]
        if not args:
            continue                     # level does not run this stage
        assert "-rate" in args, f"{level}: no -rate cap on a fuzzing stage"
        rate = int(args[args.index("-rate") + 1])
        assert 0 < rate <= 50, f"{level}: -rate {rate} is not a bounded rate"


def test_rate_escalates_with_level_and_never_exceeds_concurrency():
    """Escalating like naabu's 150/500/800/1000, but an order of magnitude
    lower: naabu's rate is SYN packets across a whole host list, while every
    request here is a full HTTP request/response against ONE host.
    """
    stage = VhostStage()
    high, full = stage.levels["high"], stage.levels["full"]
    high_rate = int(high[high.index("-rate") + 1])
    full_rate = int(full[full.index("-rate") + 1])
    assert high_rate < full_rate, "rate must escalate from high to full"
    # One request per second per thread: the pacing rule the values encode.
    assert high_rate == int(high[high.index("-t") + 1])
    assert full_rate == int(full[full.index("-t") + 1])


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("ffuf") is None,
                    reason="ffuf not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    ctx = ctx_for(tmp_path, level=level)
    err = preflight.validate_arguments(VhostStage(), ctx)
    assert err == "", f"ffuf rejected the {level!r} flag set: {err}"


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("ffuf") is None,
                    reason="ffuf not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_with_no_http_service_yet(tmp_path, level):
    """Matches preflight's real calling shape: it validates every stage's
    build_command() before httpx has produced any HTTP_SERVICE artifacts,
    so `-u ""` is exactly what a real preflight run probes here.
    """
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      level=level))
    err = preflight.validate_arguments(VhostStage(), ctx)
    assert err == "", f"ffuf rejected the {level!r} flag set with no target: {err}"


def test_no_real_target_survives_preflight_substitution(tmp_path):
    """Re-check of the preflight target-leak guard against vhost's REAL
    build_command (Task 3.5 only verified this against a synthetic
    ffuf-shaped stage). The -u URL is substituted by shape; this confirms
    the substituted probe argv is actually clean of "acc.example" by
    CONTENT, not just by assumption.
    """
    ctx = ctx_for(tmp_path)
    cmd = VhostStage().build_command(ctx)
    # preflight.probe_argv, NOT a copy of it inlined here. This test used to
    # reimplement the substitution, and the copy went stale the moment a new
    # argument shape (the Host header) was added to the real one: the test
    # kept passing against a substitution preflight no longer performed,
    # while the real guard refused the run.
    probe = preflight.probe_argv(cmd, "SUBSTITUTED.txt")
    leak = preflight._find_leak(
        probe,
        safe_values={"http://" + preflight.DEAD_ENDPOINT, "SUBSTITUTED.txt"},
        targets=preflight._real_targets(ctx),
    )
    assert leak is None, f"real target leaked into probe argv: {leak}"


# --- discovered vhosts and the admission choke point ------------------------
# These drive the REAL runner rather than re-implementing its admission
# logic in the test: mirroring runner.py's per-kind host extraction here is
# exactly how a test keeps passing after the thing it checks has drifted.


class _StubbedVhost(VhostStage):
    """VhostStage with the ffuf invocation replaced by a canned result file.

    Everything downstream of the subprocess -- writes_own_raw handling,
    parse(), admission control, discovery-refusal accounting -- is the real
    code path.
    """

    def __init__(self, results_json: str):
        self._results_json = results_json

    def build_command(self, ctx):
        outfile = ctx.raw_path(self.name, self.raw_suffix)
        outfile.parent.mkdir(parents=True, exist_ok=True)
        outfile.write_text(self._results_json, encoding="utf-8")
        return ["/bin/true"]


def _results(fuzz: str) -> str:
    """One distinct vhost against a two-row wildcard baseline."""
    import json as _json
    rows = [
        {"input": {"FUZZ": "aaa"}, "status": 200, "length": 100, "words": 10,
         "url": "https://acc.example/", "host": "aaa"},
        {"input": {"FUZZ": "bbb"}, "status": 200, "length": 100, "words": 10,
         "url": "https://acc.example/", "host": "bbb"},
        {"input": {"FUZZ": fuzz}, "status": 200, "length": 999, "words": 99,
         "url": "https://acc.example/", "host": fuzz},
    ]
    return _json.dumps({"results": rows, "config": {}})


def _run_with(tmp_path, allow: str, fuzz: str):
    from sweeper.runner import run_stages
    t = tmp_path / "targets.txt"
    t.write_text(allow + "\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                           meta={"host": "acc.example"}))
    [result] = run_stages(ctx, [_StubbedVhost(_results(fuzz))])
    return ctx, result


def test_out_of_scope_vhost_is_refused_by_the_choke_point(tmp_path):
    """A hidden vhost on an in-scope IP may belong to a different tenant
    entirely: the TCP connection being to an authorized address does not
    make the VIRTUAL HOST authorized. So an out-of-allowlist vhost name is
    surfaced and counted but never enters the store, exactly like one of
    subfinder's discovered subdomains.
    """
    ctx, result = _run_with(tmp_path, allow="acc.example", fuzz="other-tenant")

    # Not scanned: never admitted to the pool downstream stages read.
    assert "https://other-tenant" not in ctx.store.values(ArtifactKind.HTTP_SERVICE)
    # But surfaced: recorded in the discovery-refusal accounting...
    assert any(d["host"] == "other-tenant" and d["stage"] == "vhost"
               for d in ctx.scope.discoveries_refused)
    # ...and NOT in the operator-target refusal list, which means something
    # different (see scope.py's accounting split).
    assert ctx.scope.refusals == []
    # The finding still reports it -- refusing to SCAN is not refusing to TELL.
    assert result.findings == 1


def test_in_scope_vhost_is_admitted_to_the_store(tmp_path):
    """The other half: once the vhost name is inside the allowlist (an
    operator having widened scope, or a wordlist of in-scope FQDNs), the
    artifact must actually reach the pool nuclei/katana/jsrecon/arjun read.
    """
    ctx, result = _run_with(tmp_path, allow="*.acc.example",
                            fuzz="internal.acc.example")

    assert "https://internal.acc.example" in ctx.store.values(
        ArtifactKind.HTTP_SERVICE
    )
    assert result.artifacts == 1
    assert ctx.scope.discoveries_refused == []


def test_admitted_vhost_carries_its_hostname_in_meta(tmp_path):
    ctx, _ = _run_with(tmp_path, allow="*.acc.example",
                       fuzz="internal.acc.example")
    art = next(a for a in ctx.store.get(ArtifactKind.HTTP_SERVICE)
               if a.value == "https://internal.acc.example")
    assert art.meta["host"] == "internal.acc.example"
    assert art.meta["src"] == "vhost"
