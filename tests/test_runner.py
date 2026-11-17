import json
import sys
from enum import Enum, auto
from pathlib import Path

import pytest
from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.auth import SecretBundle
from sweeper.context import RunConfig, RunContext
from sweeper.runner import AbortRun, _timeout, run_stages
from sweeper.stages.base import FailureClass


class Base:
    requires = []
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def parse(self, raw_path):
        return iter(())


class Emits(Base):
    name = "emits"

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        yield Artifact(ArtifactKind.PORT, "acc.example:443")


class NeedsMissingBinary(Base):
    name = "needsbin"
    requires = ["ghost"]

    def build_command(self, ctx):
        return ["/bin/true"]


class ConsumesPorts(Base):
    name = "consumesports"
    consumes = ArtifactKind.PORT
    produces = {ArtifactKind.HTTP_SERVICE}

    def build_command(self, ctx):
        return ["/bin/true"]


class ArgErrorStage(Base):
    name = "argerror"

    def build_command(self, ctx):
        return [sys.executable, "-c",
                "import sys; print('unknown flag: --nope', file=sys.stderr); sys.exit(2)"]


class EmptyDependencyFailure(Base):
    name = "emptydependency"

    def build_command(self, ctx):
        return ["/bin/true"]

    def empty_result_error(self, ctx):
        return "configured dependency became unreachable"


class EmptyProxyStage(Base):
    name = "content"

    def build_command(self, ctx):
        return ["/bin/true"]


class ConsumesAny(Base):
    name = "consumesany"
    consumes = ArtifactKind.HTTP_SERVICE
    consumes_any = {ArtifactKind.HTTP_SERVICE, ArtifactKind.UDP_PORT}

    def build_command(self, ctx):
        return ["/bin/true"]


def ctx_for(tmp_path, seed_host=True):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    if seed_host:
        ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    return ctx


def test_successful_stage_records_artifacts(tmp_path):
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [Emits()])
    assert r.status == "complete"
    assert r.artifacts == 1
    assert ctx.store.values(ArtifactKind.PORT) == ["acc.example:443"]


def test_stage_artifact_count_matches_deduplicated_store(tmp_path):
    class EmitsDuplicate(Emits):
        name = "emitsduplicate"

        def parse(self, raw_path):
            yield Artifact(ArtifactKind.PORT, "acc.example:443")
            yield Artifact(ArtifactKind.PORT, "acc.example:443",
                           meta={"ips": ["192.0.2.1"]})

    ctx = ctx_for(tmp_path)
    [result] = run_stages(ctx, [EmitsDuplicate()])
    assert result.artifacts == 1
    assert len(ctx.store.get(ArtifactKind.PORT)) == 1


def test_raw_output_written_before_parsing(tmp_path):
    ctx = ctx_for(tmp_path)
    run_stages(ctx, [Emits()])
    assert ctx.raw_path("emits").exists()


def test_empty_result_health_check_can_degrade_a_zero_exit_stage(tmp_path):
    [result] = run_stages(ctx_for(tmp_path), [EmptyDependencyFailure()])
    assert result.status == "failed"
    assert result.failure is FailureClass.TRANSPORT
    assert result.reason == "configured dependency became unreachable"


def test_proxy_stage_empty_result_degrades_if_proxy_died(tmp_path, monkeypatch):
    from sweeper import preflight

    ctx = ctx_for(tmp_path)
    ctx.config.proxy = "http://127.0.0.1:8080"
    monkeypatch.setattr(preflight, "proxy_reachable", lambda proxy: False)

    [result] = run_stages(ctx, [EmptyProxyStage()])

    assert result.status == "failed"
    assert result.failure is FailureClass.TRANSPORT
    assert "proxy became unreachable" in result.reason


def test_consumes_any_runs_when_one_input_kind_exists(tmp_path):
    ctx = ctx_for(tmp_path, seed_host=False)
    ctx.store.add(Artifact(ArtifactKind.UDP_PORT, "acc.example:53"))
    [result] = run_stages(ctx, [ConsumesAny()])
    assert result.status == "complete"


def test_consumes_any_skips_only_when_every_input_kind_is_empty(tmp_path):
    [result] = run_stages(ctx_for(tmp_path, seed_host=False), [ConsumesAny()])
    assert result.status == "skipped"
    assert result.failure is FailureClass.NO_INPUT


# Binary identity is decided exactly once, by preflight.run_preflight(),
# which hands run_stages only the stages it verified. run_stages trusts that
# list completely: it does not, and must not, independently check whether a
# stage's `requires` binaries can be found (that used to be a SECOND, weaker
# check here -- existence via binaries.resolve() only, no identity
# verification -- and disagreeing with preflight's verify() is exactly how
# an impostor at a candidate path got executed after preflight had already
# disabled it). See tests/test_preflight.py for the missing-binary/impostor
# coverage; this file only proves run_stages runs what it is handed.
def test_run_stages_executes_whatever_it_is_handed_without_checking_binaries(tmp_path):
    """Documents the contract change directly: a stage naming a binary that
    does not exist is NOT skipped by run_stages itself -- it is executed
    (or fails on its own terms) exactly like any other stage, because the
    caller (execute()) is responsible for only ever passing report.runnable."""
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [NeedsMissingBinary()])
    assert r.status == "complete"


def test_empty_input_skips_with_no_input_class(tmp_path):
    ctx = ctx_for(tmp_path, seed_host=False)
    ctx.store._by_kind[ArtifactKind.PORT] = {}
    [r] = run_stages(ctx, [ConsumesPorts()])
    assert r.status == "skipped"
    assert r.failure is FailureClass.NO_INPUT


def test_arg_error_aborts_the_whole_run(tmp_path):
    ctx = ctx_for(tmp_path)
    with pytest.raises(AbortRun):
        run_stages(ctx, [ArgErrorStage(), Emits()])


def test_stage_failure_does_not_prevent_later_stages(tmp_path):
    # ConsumesPorts consumes PORT artifacts; ctx_for() never seeds any, so it
    # skips with NO_INPUT. Emits consumes HOST, which IS seeded, so it still
    # runs to completion -- one stage skipping must not block another.
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [ConsumesPorts(), Emits()])
    assert [r.status for r in results] == ["skipped", "complete"]


def test_progress_callback_invoked_per_stage(tmp_path):
    seen = []
    run_stages(ctx_for(tmp_path), [Emits()],
               on_progress=lambda name, state: seen.append((name, state)))
    assert ("emits", "running") in seen
    assert ("emits", "complete") in seen


# --- PARTIAL must never be reported as a clean completion -------------------
# A stage that exits non-zero having produced only part of its output is
# degraded coverage. If it lands in the manifest as status="complete",
# degraded=false, the report claims ground it never actually covered.


class PartialStage(Base):
    """Emits a record, then exits non-zero — the classic truncated scan."""
    name = "partial"

    def build_command(self, ctx):
        return ["/bin/sh", "-c", "echo partial-row; exit 3"]

    def parse(self, raw_path):
        yield Artifact(ArtifactKind.PORT, "acc.example:8443")


class TransportFailStage(Base):
    """Exits non-zero having produced nothing at all."""
    name = "transportfail"

    def build_command(self, ctx):
        return ["/bin/sh", "-c", "exit 4"]


def test_partial_output_marks_stage_partial_not_complete(tmp_path):
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [PartialStage()])
    assert r.status == "partial"
    assert r.failure is FailureClass.PARTIAL
    assert r.reason == "exit 3 with partial output"


def test_partial_stage_still_parses_what_it_produced(tmp_path):
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [PartialStage()])
    assert r.artifacts == 1
    assert ctx.store.values(ArtifactKind.PORT) == ["acc.example:8443"]


def test_partial_stage_marks_the_run_degraded(tmp_path):
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [PartialStage()])
    ctx.write_manifest(results)
    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["degraded"] is True
    assert manifest["stages"]["partial"]["status"] == "partial"
    assert manifest["stages"]["partial"]["failure"] == "PARTIAL"


def test_nonzero_exit_with_no_output_is_still_transport_failure(tmp_path):
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [TransportFailStage()])
    assert r.status == "failed"
    assert r.failure is FailureClass.TRANSPORT


def test_transport_failure_marks_the_run_degraded(tmp_path):
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [TransportFailStage()])
    ctx.write_manifest(results)
    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["degraded"] is True


def test_partial_stage_does_not_prevent_later_stages(tmp_path):
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [PartialStage(), Emits()])
    assert [r.status for r in results] == ["partial", "complete"]


# --- _timeout must never raise ---------------------------------------------
# It is evaluated as an argument to subprocess.run inside a try that only
# catches TimeoutExpired and OSError, so any exception here escapes
# run_stages and kills every remaining stage over a one-character typo.


def _ctx_with_limit(tmp_path, limit):
    ctx = ctx_for(tmp_path)
    ctx.config.time_limit = limit
    return ctx


@pytest.mark.parametrize("spec,expected", [
    ("45s", 45),
    ("45m", 2700),
    ("2h", 7200),
    (" 45M ", 2700),      # whitespace and case are tolerated
    ("45 m", 2700),
])
def test_timeout_parses_well_formed_values(tmp_path, spec, expected):
    assert _timeout(_ctx_with_limit(tmp_path, spec)) == expected


def test_timeout_returns_none_when_unset(tmp_path):
    # Not a malformed value — the default "no per-stage limit" case.
    assert _timeout(_ctx_with_limit(tmp_path, "")) is None


@pytest.mark.parametrize("spec", ["abc", "m", "45", "5", "45x", "-3m"])
def test_malformed_timeout_returns_none_instead_of_raising(tmp_path, spec):
    ctx = _ctx_with_limit(tmp_path, spec)
    assert _timeout(ctx) is None


@pytest.mark.parametrize("spec", ["abc", "m", "45"])
def test_malformed_timeout_is_logged_with_the_offending_value(tmp_path, spec):
    ctx = _ctx_with_limit(tmp_path, spec)
    _timeout(ctx)
    log = (ctx.run_dir / "sweep.log").read_text(encoding="utf-8")
    assert repr(spec) in log
    assert "45s / 45m / 2h" in log


def test_malformed_time_limit_does_not_abort_the_run(tmp_path):
    """End to end: a typo in one config field must not kill every stage."""
    ctx = _ctx_with_limit(tmp_path, "abc")
    results = run_stages(ctx, [Emits()])
    assert [r.status for r in results] == ["complete"]
    assert ctx.store.values(ArtifactKind.PORT) == ["acc.example:443"]


# --- Scan content must never be mistaken for an argument error -------------
# ARG_ERROR raises AbortRun, killing the whole run. The marker match must
# search stdout (these tools write argument errors there), so a crawled page
# body containing a marker phrase plus an unrelated non-zero exit would
# otherwise abort everything with a confident wrong diagnosis.


def _scan_output_stage(tmp_path, name, first_line=""):
    """A stage whose tool emits 40 lines of scan output, then exits non-zero."""
    lines = []
    if first_line:
        lines.append(first_line)
    for i in range(1, 41):
        if i == 20:
            lines.append('{"url":"http://acc.example/settings",'
                         '"body":"<p>Error: invalid value supplied</p>"}')
        else:
            lines.append(f'{{"url":"http://acc.example/page{i}","status":200}}')
    payload = tmp_path / f"{name}-payload.txt"
    payload.write_text("\n".join(lines) + "\n", encoding="utf-8")

    class ScanStage(Base):
        pass

    ScanStage.name = name
    ScanStage.build_command = lambda self, ctx: [
        "/bin/sh", "-c", f'cat "{payload}"; exit 1'
    ]
    return ScanStage()


def test_marker_in_scan_content_does_not_abort_the_run(tmp_path):
    """The regression guard: a page body containing a marker phrase."""
    ctx = ctx_for(tmp_path)
    stage = _scan_output_stage(tmp_path, "scancontent")
    results = run_stages(ctx, [stage])          # must not raise AbortRun
    [r] = results
    assert r.failure is not FailureClass.ARG_ERROR
    assert r.status == "partial"
    assert r.failure is FailureClass.PARTIAL


def test_marker_in_scan_content_does_not_prevent_later_stages(tmp_path):
    ctx = ctx_for(tmp_path)
    stage = _scan_output_stage(tmp_path, "scancontent2")
    results = run_stages(ctx, [stage, Emits()])
    assert [r.status for r in results] == ["partial", "complete"]


def test_genuine_arg_error_on_first_line_still_aborts(tmp_path):
    """Bounding the search must not weaken real detection."""
    ctx = ctx_for(tmp_path)
    stage = _scan_output_stage(
        tmp_path, "realargerror",
        first_line="flag provided but not defined: -definitely-not-a-flag",
    )
    with pytest.raises(AbortRun):
        run_stages(ctx, [stage])


def test_arg_error_written_to_stdout_only_is_still_caught(tmp_path):
    """These tools write argument errors to stdout, not stderr.

    Verified against the real binaries: stdout carries the message, stderr is
    empty. A stdout-blind match would miss every argument error, so this pins
    that stdout is searched.
    """
    ctx = ctx_for(tmp_path)

    class StdoutArgError(Base):
        name = "stdoutargerror"

        def build_command(self, c):
            return ["/bin/sh", "-c",
                    'echo "flag provided but not defined: -nope"; exit 2']

    with pytest.raises(AbortRun):
        run_stages(ctx, [StdoutArgError()])


# --- Failure reasons must carry the tool's actual message ------------------
# These tools write diagnostics to stdout and leave stderr empty, so reading
# stderr alone made every reason degrade to its placeholder. ARG_ERROR is the
# one class that kills the whole run, so that is exactly when the operator
# most needs the real message rather than a tautology.

REAL_ARG_ERROR = "flag provided but not defined: -definitely-not-a-flag"


class StdoutArgErrorStage(Base):
    """Mirrors the real binaries: message on stdout, stderr empty, rc=2."""
    name = "stdoutargerror"

    def build_command(self, ctx):
        return ["/bin/sh", "-c", f'echo "{REAL_ARG_ERROR}"; exit 2']


def test_arg_error_reason_is_the_tools_actual_message(tmp_path):
    ctx = ctx_for(tmp_path)
    with pytest.raises(AbortRun) as exc:
        run_stages(ctx, [StdoutArgErrorStage()])
    # run_stages no longer writes the manifest itself (see
    # test_run_stages_does_not_write_a_manifest_before_raising below); the
    # caller writes it, exactly as execute() does on the real abort path.
    ctx.write_manifest(exc.value.results)
    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    reason = manifest["stages"]["stdoutargerror"]["reason"]
    assert reason == REAL_ARG_ERROR
    assert reason != "argument rejected"


# --- a manifest run_stages wrote itself must not read as a clean run -------
# ctx.aborted_reason is set by the CALLER, only after AbortRun is caught. A
# manifest written by run_stages itself, before that, necessarily records
# aborted:false for a run that is -- at that very moment -- aborting. Any
# future direct caller of run_stages (bypassing execute()) would read that
# manifest and see a clean run.
#
# This used to be enforced by run_stages writing NO manifest at all. It now
# checkpoints after every stage, because a process killed by the kernel
# never reaches its caller's handlers and a whole run was lost that way on
# 2026-08-05. The invariant is unchanged and enforced differently: a
# checkpoint is marked `run_status: in-progress`, so the aborted:false it
# necessarily carries cannot be read as a finished, clean run. The marker is
# the load-bearing part -- if it ever stops being written, this reverts to
# exactly the defect the original test was guarding.


def test_a_manifest_written_before_the_caller_aborts_is_marked_in_progress(
        tmp_path):
    ctx = ctx_for(tmp_path)
    with pytest.raises(AbortRun):
        run_stages(ctx, [StdoutArgErrorStage()])

    path = ctx.run_dir / "run.json"
    if not path.exists():
        return   # writing none at all satisfies the invariant too
    manifest = json.loads(path.read_text(encoding="utf-8"))
    assert manifest["run_status"] == "in-progress", (
        "run_stages wrote a manifest before its caller could set "
        "ctx.aborted_reason, and did not mark it -- it records aborted:false "
        "and would be read as a clean run"
    )


def test_abort_run_message_carries_the_real_diagnostic(tmp_path):
    """This is the text the operator sees on the terminal."""
    ctx = ctx_for(tmp_path)
    with pytest.raises(AbortRun) as exc:
        run_stages(ctx, [StdoutArgErrorStage()])
    assert REAL_ARG_ERROR in str(exc.value)
    assert "argument rejected" not in str(exc.value)


def test_arg_error_is_logged_with_the_real_diagnostic(tmp_path):
    """Scoped to the ARG_ERROR line specifically.

    A bare `REAL_ARG_ERROR in log` check passes vacuously: the RUN line
    echoes the whole command, which here carries the error text as an
    argument to /bin/echo. Caught by noticing this test passed before the
    fix, when the reason was still the placeholder.
    """
    ctx = ctx_for(tmp_path)
    with pytest.raises(AbortRun):
        run_stages(ctx, [StdoutArgErrorStage()])
    log = (ctx.run_dir / "sweep.log").read_text(encoding="utf-8")
    arg_error_lines = [l for l in log.splitlines() if "ARG_ERROR" in l]
    assert arg_error_lines, "no ARG_ERROR line was logged"
    assert REAL_ARG_ERROR in arg_error_lines[0]
    assert "argument rejected" not in arg_error_lines[0]


def test_abort_run_carries_the_results_gathered_so_far(tmp_path):
    """Without them the caller has nothing to record.

    A caller that discards them and writes an empty manifest overwrites the
    one run_stages already wrote, destroying the only account of why the run
    died -- at exactly the moment an operator needs it.
    """
    ctx = ctx_for(tmp_path)
    with pytest.raises(AbortRun) as exc:
        run_stages(ctx, [NeedsMissingBinary(), StdoutArgErrorStage(), Emits()])
    results = exc.value.results
    assert [r.stage for r in results] == ["needsbin", "stdoutargerror"]
    failed = results[-1]
    assert failed.failure is FailureClass.ARG_ERROR
    assert failed.reason == REAL_ARG_ERROR


def test_transport_reason_is_the_real_message_not_the_exit_code(tmp_path):
    """TRANSPORT is only reached with blank stdout, so the message is on stderr.

    Kept as a regression guard: the shared helper must not lose the stderr
    diagnostic that this path has always reported correctly.
    """
    ctx = ctx_for(tmp_path)

    class TransportStage(Base):
        name = "transportmsg"

        def build_command(self, c):
            return ["/bin/sh", "-c",
                    'echo "dial tcp 10.0.0.1:443: connect: connection refused" >&2;'
                    ' exit 1']

    [r] = run_stages(ctx, [TransportStage()])
    assert r.failure is FailureClass.TRANSPORT
    assert r.reason == "dial tcp 10.0.0.1:443: connect: connection refused"
    assert r.reason != "exit 1"


def test_transport_reason_falls_back_to_exit_code_with_no_output(tmp_path):
    """No output on either stream: placeholder, not '' and not a crash."""
    ctx = ctx_for(tmp_path)

    class SilentFailStage(Base):
        name = "silentfail"

        def build_command(self, c):
            return ["/bin/sh", "-c", "exit 7"]

    [r] = run_stages(ctx, [SilentFailStage()])
    assert r.failure is FailureClass.TRANSPORT
    assert r.reason == "exit 7"


def test_transport_reason_is_capped_at_200_chars(tmp_path):
    ctx = ctx_for(tmp_path)

    class ChattyStage(Base):
        name = "chatty"

        def build_command(self, c):
            return ["/bin/sh", "-c", f'echo "{"x" * 500}" >&2; exit 1']

    [r] = run_stages(ctx, [ChattyStage()])
    assert len(r.reason) == 200


class ParseCrashStage(Base):
    """A stage whose parse() hits unreadable tool output partway through.

    ET.ParseError is what a truncated nmap XML document actually raises, and
    it is a SyntaxError subclass, so this exercises the real containment path
    rather than a stand-in.
    """
    name = "parsecrash"

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        import xml.etree.ElementTree as ET
        yield Artifact(ArtifactKind.PORT, "acc.example:443")
        raise ET.ParseError("unclosed token: line 23, column 35")


def test_parse_crash_does_not_kill_the_run(tmp_path):
    """"One stage failing must not kill a run" has to cover parse(), too.

    Subprocess failures were contained but parser exceptions propagated
    straight out of the stage loop, so a single nmap timeout producing a
    truncated XML document aborted every stage after it -- defeating the
    PARTIAL class the runner sets one line earlier.
    """
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [ParseCrashStage(), Emits()])
    assert [r.stage for r in results] == ["parsecrash", "emits"]
    assert results[1].status == "complete"


def test_parse_crash_is_recorded_as_failed_and_degrades_the_run(tmp_path):
    """A swallowed parse error reporting clean would be worse than the crash."""
    from sweeper.stages.base import Coverage, is_degraded
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [ParseCrashStage()])
    assert r.status == "failed"
    assert r.failure is FailureClass.PARSE_ERROR
    assert is_degraded([r], Coverage()) is True


def test_parse_crash_keeps_what_was_yielded_before_the_exception(tmp_path):
    """A parser that dies halfway keeps the half it got."""
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [ParseCrashStage()])
    assert r.artifacts == 1
    assert "acc.example:443" in ctx.store.values(ArtifactKind.PORT)


def test_parse_crash_reason_names_the_exception_and_the_salvage_count(tmp_path):
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [ParseCrashStage()])
    assert "ParseError" in r.reason
    assert "unclosed token" in r.reason
    assert "1 artifacts" in r.reason


def test_parse_crash_reason_is_capped_at_200_chars(tmp_path):
    ctx = ctx_for(tmp_path)

    class ChattyParseCrash(Base):
        name = "chattyparsecrash"

        def build_command(self, c):
            return ["/bin/echo", "x"]

        def parse(self, raw_path):
            raise ValueError("y" * 500)
            yield  # pragma: no cover - generator marker

    [r] = run_stages(ctx, [ChattyParseCrash()])
    assert len(r.reason) == 200


class BuggyParser(Base):
    """A parse() that raises a plain programming error, not a data error."""
    name = "buggyparser"

    def build_command(self, ctx):
        return ["/bin/echo", "x"]

    def parse(self, raw_path):
        raise KeyError("boom")
        yield  # pragma: no cover - generator marker


def test_a_parser_bug_is_contained_too_not_only_malformed_output(tmp_path):
    """Containment is deliberately broad -- it covers parser BUGS as well.

    Weighing the field outcomes decides it: containing costs the operator one
    stage and gives them a loud PARSE_ERROR on a degraded run, while
    propagating loses every other stage's results inside a scan window that
    may not come back. "Fail loudly" is satisfied by a degraded run naming
    the stage; it does not require aborting.
    """
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [BuggyParser(), Emits()])
    assert [r.stage for r in results] == ["buggyparser", "emits"]
    assert results[0].status == "failed"
    assert results[0].failure is FailureClass.PARSE_ERROR
    assert results[1].status == "complete", "a parser bug killed a later stage"


@pytest.mark.parametrize("stage_cls", [ParseCrashStage, BuggyParser])
def test_contained_parse_failure_writes_a_traceback_to_the_log(tmp_path, stage_cls):
    """A contained programming error with no traceback is how a bug survives
    for months. The report gets the one-liner; the log gets the stack.
    """
    ctx = ctx_for(tmp_path)
    run_stages(ctx, [stage_cls()])
    log = (ctx.run_dir / "sweep.log").read_text(encoding="utf-8")
    assert "PARSE_ERROR traceback" in log
    assert "Traceback (most recent call last)" in log
    # The frame that actually raised, so the stack is usable.
    assert "in parse" in log
    assert "tests/test_runner.py" in log


@pytest.mark.parametrize("exc_type", [KeyboardInterrupt, SystemExit])
def test_keyboard_interrupt_and_system_exit_are_not_contained(tmp_path, exc_type):
    """`except Exception` must not swallow BaseException.

    Ctrl-C has to interrupt a wedged parser, and Plan 3's SIGINT handling
    depends on this staying true.
    """
    ctx = ctx_for(tmp_path)

    class Interrupted(Base):
        name = "interrupted"

        def build_command(self, c):
            return ["/bin/echo", "x"]

        def parse(self, raw_path):
            raise exc_type()
            yield  # pragma: no cover - generator marker

    with pytest.raises(exc_type):
        run_stages(ctx, [Interrupted()])


# --- Admission control: the choke point -------------------------------------
# Nothing a stage's parse() yields may reach ctx.store unless the scope guard
# permits the host it refers to. This is the inversion from "every consumer
# stage filters its own input" to "the store only ever holds what scope
# allowed in" -- see runner.py's module-level comment.


class EmitsHosts(Base):
    """A fake discovery stage: yields whatever HOST values the test wants,
    the same shape subfinder's parse() produces (unconfirmed hosts, some
    never in the targets file)."""
    name = "discovers"
    consumes = None
    produces = {ArtifactKind.HOST}

    def __init__(self, values):
        self._values = values

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        for v in self._values:
            yield Artifact(ArtifactKind.HOST, v, meta={"src": "discovers"})


def test_out_of_scope_artifact_is_not_added_to_the_store(tmp_path):
    ctx = ctx_for(tmp_path, seed_host=False)
    [r] = run_stages(ctx, [EmitsHosts(["evil.test"])])
    assert r.status == "complete"
    assert ctx.store.values(ArtifactKind.HOST) == []


def test_out_of_scope_artifact_is_recorded_as_a_discovery_refusal(tmp_path):
    ctx = ctx_for(tmp_path, seed_host=False)
    run_stages(ctx, [EmitsHosts(["evil.test"])])
    assert ctx.scope.discoveries_refused == [
        {"stage": "discovers", "kind": "HOST", "value": "evil.test",
         "host": "evil.test"}
    ]
    # And NOT in the operator-target-refusal list -- see the accounting
    # split in scope.py / the task's "this matters" requirement.
    assert ctx.scope.refusals == []


def test_out_of_scope_discovery_is_logged_not_silently_dropped(tmp_path):
    ctx = ctx_for(tmp_path, seed_host=False)
    run_stages(ctx, [EmitsHosts(["evil.test"])])
    log = (ctx.run_dir / "sweep.log").read_text(encoding="utf-8")
    assert "discovery refused" in log
    assert "evil.test" in log


def test_in_scope_artifact_is_admitted_unchanged(tmp_path):
    """Regression guard: existing in-scope behaviour must not move at all."""
    ctx = ctx_for(tmp_path, seed_host=False)
    [r] = run_stages(ctx, [EmitsHosts(["acc.example"])])
    assert r.status == "complete"
    assert r.artifacts == 1
    assert ctx.store.values(ArtifactKind.HOST) == ["acc.example"]
    assert ctx.scope.discoveries_refused == []


def test_mixed_batch_admits_in_scope_and_refuses_out_of_scope(tmp_path):
    ctx = ctx_for(tmp_path, seed_host=False)
    [r] = run_stages(ctx, [EmitsHosts(["acc.example", "evil.test", "also-evil.test"])])
    assert ctx.store.values(ArtifactKind.HOST) == ["acc.example"]
    assert {d["host"] for d in ctx.scope.discoveries_refused} == {
        "evil.test", "also-evil.test"
    }
    assert r.status == "complete"


class UnknownKind(Enum):
    """Stands in for a future ArtifactKind (tlsx/vhost/katana/... are
    coming) that admission control has never seen. Constructed separately
    from sweeper.artifacts.ArtifactKind on purpose -- the whole point is to
    exercise the code path for a kind that has NO entry in runner.py's
    extractor table, which is exactly what a forgotten update to that table
    would look like."""
    MYSTERY = auto()


class EmitsUnknownKind(Base):
    name = "futurestage"
    consumes = None
    produces = set()

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        yield Artifact(UnknownKind.MYSTERY, "acc.example", meta={"host": "acc.example"})


def test_unrecognised_artifact_kind_is_refused_not_admitted(tmp_path):
    """THE load-bearing test: fail CLOSED on an unrecognised ArtifactKind.

    Even though the artifact's host ("acc.example") is plainly in scope and
    carried in meta["host"] too, admission control must refuse it anyway --
    the whole point is that an unrecognised kind gets no benefit of the
    doubt. A new ArtifactKind added later and never wired into runner.py's
    extractor table must not silently bypass scope.
    """
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [EmitsUnknownKind()])
    assert r.status == "complete"
    assert ctx.store._by_kind.get(UnknownKind.MYSTERY, {}) == {}
    assert any(d["kind"] == "MYSTERY" for d in ctx.scope.discoveries_refused)


def test_unrecognised_artifact_kind_refusal_does_not_use_refusals_list(tmp_path):
    ctx = ctx_for(tmp_path)
    run_stages(ctx, [EmitsUnknownKind()])
    assert ctx.scope.refusals == []


# --- Host extraction per ArtifactKind ---------------------------------------
# PORT ("host:port") and HTTP_SERVICE (a URL) must resolve to the correct
# host, including forms that look like a plain host:port but are actually a
# userinfo-section masquerade -- scope.normalize() already defends against
# "acc.example:80@evil.test" addressing evil.test, and extraction must not
# undo that by parsing the authority itself instead of delegating to it.


class EmitsPorts(Base):
    name = "emitsports"
    consumes = None
    produces = {ArtifactKind.PORT}

    def __init__(self, artifacts):
        self._artifacts = artifacts

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        yield from self._artifacts


def test_port_kind_extracts_host_from_meta(tmp_path):
    ctx = ctx_for(tmp_path)
    stage = EmitsPorts([Artifact(ArtifactKind.PORT, "acc.example:8443",
                                 meta={"host": "acc.example"})])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.PORT) == ["acc.example:8443"]


def test_port_kind_falls_back_to_value_when_meta_has_no_host(tmp_path):
    ctx = ctx_for(tmp_path)
    stage = EmitsPorts([Artifact(ArtifactKind.PORT, "acc.example:8443")])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.PORT) == ["acc.example:8443"]


def test_port_userinfo_masquerade_is_refused_not_admitted(tmp_path):
    """"acc.example:80@evil.test" as a bare PORT value: naive extraction
    (split on the first colon) reads "acc.example" and admits it while the
    string that would actually be handed to a scanner addresses evil.test."""
    ctx = ctx_for(tmp_path)
    stage = EmitsPorts([Artifact(ArtifactKind.PORT, "acc.example:80@evil.test")])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.PORT) == []
    assert any(d["host"] == "evil.test" for d in ctx.scope.discoveries_refused)


class EmitsHttpServices(Base):
    name = "emitshttp"
    consumes = None
    produces = {ArtifactKind.HTTP_SERVICE}

    def __init__(self, artifacts):
        self._artifacts = artifacts

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        yield from self._artifacts


def test_http_service_kind_extracts_host_from_url(tmp_path):
    ctx = ctx_for(tmp_path)
    stage = EmitsHttpServices([
        Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example:8443/path")
    ])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.HTTP_SERVICE) == [
        "https://acc.example:8443/path"
    ]


def test_http_service_userinfo_masquerade_is_refused(tmp_path):
    """"https://acc.example@evil.test/" addresses evil.test -- acc.example
    is userinfo before the "@", not the host."""
    ctx = ctx_for(tmp_path)
    stage = EmitsHttpServices([
        Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example@evil.test/")
    ])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.HTTP_SERVICE) == []
    assert any(d["host"] == "evil.test" for d in ctx.scope.discoveries_refused)


def test_http_service_ipv6_literal_is_extracted_and_checked(tmp_path):
    ctx = ctx_for(tmp_path)
    # Bracket notation, matching how normalize() itself expects a bare IPv6
    # literal to be spelled (see scope.py: unbracketed "::1" prefixed with
    # "//" is not a valid URL authority and normalizes to "").
    ctx.scope.extend(["[::1]"], reason="test: IPv6 host in scope")
    stage = EmitsHttpServices([
        Artifact(ArtifactKind.HTTP_SERVICE, "https://[::1]:8443/path")
    ])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.HTTP_SERVICE) == [
        "https://[::1]:8443/path"
    ]


def test_http_service_ipv6_literal_out_of_scope_is_refused(tmp_path):
    ctx = ctx_for(tmp_path, seed_host=False)
    stage = EmitsHttpServices([
        Artifact(ArtifactKind.HTTP_SERVICE, "https://[::2]:8443/path")
    ])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.HTTP_SERVICE) == []
    assert any(d["host"] == "::2" for d in ctx.scope.discoveries_refused)


class EmitsDnsRecords(Base):
    name = "emitsdns"
    consumes = None
    produces = {ArtifactKind.DNS_RECORD}

    def __init__(self, artifacts):
        self._artifacts = artifacts

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        yield from self._artifacts


def test_dns_record_kind_extracts_host_from_meta(tmp_path):
    ctx = ctx_for(tmp_path)
    stage = EmitsDnsRecords([
        Artifact(ArtifactKind.DNS_RECORD, "acc.example A 10.0.0.5",
                 meta={"host": "acc.example", "type": "A", "value": "10.0.0.5"})
    ])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.DNS_RECORD) == ["acc.example A 10.0.0.5"]


def test_dns_record_out_of_scope_host_is_refused(tmp_path):
    ctx = ctx_for(tmp_path)
    stage = EmitsDnsRecords([
        Artifact(ArtifactKind.DNS_RECORD, "evil.test A 10.0.0.5",
                 meta={"host": "evil.test", "type": "A", "value": "10.0.0.5"})
    ])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.DNS_RECORD) == []
    assert any(d["host"] == "evil.test" for d in ctx.scope.discoveries_refused)


def test_dns_record_with_no_meta_host_fails_closed(tmp_path):
    """No safe fallback exists (the value is space-separated, not a URL or
    host:port) -- an empty meta["host"] must refuse, not guess."""
    ctx = ctx_for(tmp_path)
    stage = EmitsDnsRecords([Artifact(ArtifactKind.DNS_RECORD, "acc.example A 10.0.0.5")])
    run_stages(ctx, [stage])
    assert ctx.store.values(ArtifactKind.DNS_RECORD) == []


# --- A discovery-heavy run must not read as degraded ------------------------
# is_degraded()/Coverage must never see discovery refusals: Coverage's
# targets_permitted/targets_requested are captured once, before run_stages
# runs at all (see app.execute()), and a StageResult's status is untouched
# by per-artifact admission control -- a stage that discovers 200
# out-of-scope hosts and otherwise behaves normally still completes cleanly.


def test_many_out_of_scope_discoveries_do_not_degrade_the_run(tmp_path):
    from sweeper.stages.base import Coverage, is_degraded
    ctx = ctx_for(tmp_path, seed_host=False)
    many_evil = [f"evil{i}.test" for i in range(200)]
    results = run_stages(ctx, [EmitsHosts(many_evil)])
    assert len(ctx.scope.discoveries_refused) == 200
    assert [r.status for r in results] == ["complete"]
    assert is_degraded(results, ctx.coverage) is False


def test_many_out_of_scope_discoveries_do_not_pollute_scope_refusals(tmp_path):
    ctx = ctx_for(tmp_path, seed_host=False)
    many_evil = [f"evil{i}.test" for i in range(200)]
    run_stages(ctx, [EmitsHosts(many_evil)])
    assert ctx.scope.refusals == []


# --- The five per-stage scope.filter() calls stay in place as defence in
# depth; admission control does not remove the need for them, and this repo
# already exercises them directly in tests/test_stage_*.py. Nothing here
# duplicates that coverage.


# --- confirm_discovered() must keep working ---------------------------------
# The subfinder flow: discoveries held OUTSIDE the store in pending_hosts,
# operator approves a subset, ScopeGuard.extend() widens scope, only THEN are
# the approved hosts added as HOST artifacts. Admission control must not
# interfere with that direct ctx.store.add() call, and a host refused earlier
# in the run must become admissible immediately after extend().


def test_confirm_discovered_flow_survives_admission_control(tmp_path):
    from sweeper.stages.subfinder import confirm_discovered

    ctx = ctx_for(tmp_path, seed_host=False)
    # Simulates what run_stages would do with a routed-in discovery stage:
    # the undiscovered host is refused, exactly like subfinder's own
    # docstring says it must be if it were ever run through the ordinary
    # loop (it is not, by design -- but this proves refusal-then-extension
    # composes correctly through the new admission gate regardless).
    run_stages(ctx, [EmitsHosts(["new.acc.example"])])
    assert ctx.store.values(ArtifactKind.HOST) == []
    assert any(d["host"] == "new.acc.example" for d in ctx.scope.discoveries_refused)

    n = confirm_discovered(ctx, discovered=["new.acc.example"],
                           approved=["new.acc.example"])
    assert n == 1
    assert "new.acc.example" in ctx.store.values(ArtifactKind.HOST)

    # And the same host, discovered again by a later stage post-extension,
    # is now admitted through the ordinary gate too.
    run_stages(ctx, [EmitsHosts(["new.acc.example"])])
    assert ctx.store.values(ArtifactKind.HOST) == ["new.acc.example"]


# --- writes_own_raw / raw_suffix --------------------------------------------
# A stage whose tool writes its own result file (ffuf's -o, arjun's -oJ)
# must not have that file clobbered by the runner's stdout capture -- the
# exact bug that left vhost and arjun parsing an empty file on every run.


def test_writes_own_raw_stage_survives_stdout_capture(tmp_path):
    # A stage that declares writes_own_raw=True (vhost, arjun after Tasks 4
    # and 7) writes its own result file via -o/-oJ; the runner must not
    # then clobber it with captured stdout, which is exactly the bug that
    # left vhost and arjun parsing an empty file on every run.
    ctx = ctx_for(tmp_path)
    seen_paths = []

    class WritesOwnRaw(Base):
        name = "writesown"
        raw_suffix = "json"
        writes_own_raw = True

        def build_command(self, ctx):
            outfile = ctx.raw_path(self.name, self.raw_suffix)
            outfile.parent.mkdir(parents=True, exist_ok=True)
            outfile.write_text('{"tool-wrote":"this"}', encoding="utf-8")
            # Deliberately emits stdout too, to prove the runner does not
            # let it win.
            return ["/bin/echo", "stdout-noise-the-runner-must-not-keep"]

        def parse(self, raw_path):
            seen_paths.append(Path(raw_path))
            return iter(())

    run_stages(ctx, [WritesOwnRaw()])
    raw = ctx.raw_path("writesown", "json")
    assert raw.read_text(encoding="utf-8") == '{"tool-wrote":"this"}'
    # parse() must have been handed the SAME path the stage wrote to.
    assert seen_paths == [raw]


def test_normal_stage_still_captures_stdout_as_before(tmp_path):
    # writes_own_raw defaults to False and raw_suffix defaults to "jsonl",
    # so every stage that predates this task (dnsx, naabu, httpx, cdncheck,
    # nmap, subfinder) must behave exactly as it did before.
    ctx = ctx_for(tmp_path)
    run_stages(ctx, [Emits()])
    assert ctx.raw_path("emits").read_text(encoding="utf-8").strip() == '{"ok":1}'


def test_secret_value_redacted_from_log_and_manifest(tmp_path):
    ctx = ctx_for(tmp_path)
    # ctx.auth carries credentials only on an auth-mode run -- see
    # context.AuthModeViolation.
    ctx.config.auth_mode = "auth"
    ctx.auth = SecretBundle(headers={"Authorization": "Bearer topsecrettoken123"})

    class LeaksAuthInArgv(Base):
        name = "leaksauth"

        def build_command(self, ctx):
            return ["/bin/echo", "-H", "Authorization: Bearer topsecrettoken123"]

    results = run_stages(ctx, [LeaksAuthInArgv()])
    ctx.write_manifest(results)
    log = (ctx.run_dir / "sweep.log").read_text(encoding="utf-8")
    manifest_text = (ctx.run_dir / "run.json").read_text(encoding="utf-8")
    # Assert on the VALUE, not on log format or a placeholder string.
    assert "topsecrettoken123" not in log
    assert "topsecrettoken123" not in manifest_text
    assert "[REDACTED]" in log


def test_no_auth_configured_command_is_unchanged(tmp_path):
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [Emits()])
    assert r.command == ["/bin/echo", '{"ok":1}']


# --- result.findings counts what was actually STORED -----------------------
# Previously: `result.findings += 1` for every Finding a stage yielded, so a
# stage whose matcher failed to distinguish two genuinely different findings
# reported findings=2 while ctx.store held 1 -- an internal contradiction in
# a document (run.json / the report) that is client-facing evidence.


class EmitsFindings(Base):
    """A stage that yields exactly the Findings handed to it."""
    name = "emitsfindings"
    produces = {ArtifactKind.FINDING}

    def __init__(self, findings):
        self._findings = findings

    def build_command(self, ctx):
        return ["/bin/true"]

    def parse(self, raw_path):
        yield from self._findings


def _colliding_pair():
    """Two DIFFERENT findings sharing (stage, target, template_id, matcher)
    -- the exact defect class this fix closes: no matcher distinguishes
    them, so they hash to the same id.
    """
    return [
        Finding(stage="emitsfindings", severity="medium", title="First",
                target="acc.example", template_id="t-1", evidence="one"),
        Finding(stage="emitsfindings", severity="medium", title="Second",
                target="acc.example", template_id="t-1", evidence="two"),
    ]


def test_findings_count_reflects_what_the_store_actually_kept(tmp_path):
    """A collision must not inflate result.findings: the store kept 1, so
    the report may not claim 2."""
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [EmitsFindings(_colliding_pair())])
    assert len(ctx.store.findings) == 1
    assert r.findings == 1, "result.findings overcounted a collision"
    assert len(ctx.store.finding_collisions) == 1


def test_findings_count_for_a_clean_run_with_no_collisions(tmp_path):
    ctx = ctx_for(tmp_path)
    findings = [
        Finding(stage="x", severity="medium", title="A",
                target="acc.example", template_id="t-a"),
        Finding(stage="x", severity="low", title="B",
                target="acc.example", template_id="t-b"),
    ]
    [r] = run_stages(ctx, [EmitsFindings(findings)])
    assert r.findings == 2
    assert len(ctx.store.findings) == 2
    assert ctx.store.finding_collisions == []


def test_same_finding_submitted_twice_still_produces_one(tmp_path):
    """Dedupe of a genuine resubmission (same id, SAME content -- e.g. a
    fact re-emitted from two lines of tool output) must keep working: this
    is not a collision, and must not be double-counted as stored either.
    """
    ctx = ctx_for(tmp_path)
    f = Finding(stage="x", severity="medium", title="A",
                target="acc.example", template_id="t-a", evidence="same")
    resubmit = Finding(stage="x", severity="medium", title="A",
                        target="acc.example", template_id="t-a", evidence="same")
    assert f.id == resubmit.id
    [r] = run_stages(ctx, [EmitsFindings([f, resubmit])])
    assert len(ctx.store.findings) == 1
    assert r.findings == 1
    assert ctx.store.finding_collisions == []


def test_findings_count_stable_across_two_identical_runs(tmp_path):
    """Plan 3's run-to-run diffing depends on finding_id being identical for
    the same scan run twice; this pins that the *count* the manifest would
    report is identical too, run over run.
    """
    ctx1 = ctx_for(tmp_path)
    ctx2 = ctx_for(tmp_path)
    findings = _colliding_pair()
    [r1] = run_stages(ctx1, [EmitsFindings(list(findings))])
    [r2] = run_stages(ctx2, [EmitsFindings(list(findings))])
    assert r1.findings == r2.findings
    assert {f.id for f in ctx1.store.findings} == {f.id for f in ctx2.store.findings}


def test_parse_error_reason_reports_findings_actually_stored(tmp_path):
    """The PARSE_ERROR reason string must stay coherent with the new
    stored-not-yielded semantics: it should never claim more findings than
    ctx.store actually holds at the point of failure.
    """
    class CrashesAfterCollision(Base):
        name = "crashesaftercollision"
        produces = {ArtifactKind.FINDING}

        def build_command(self, ctx):
            return ["/bin/true"]

        def parse(self, raw_path):
            yield from _colliding_pair()
            raise RuntimeError("boom")

    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [CrashesAfterCollision()])
    assert r.status == "failed"
    assert r.failure is FailureClass.PARSE_ERROR
    assert "1 findings" in r.reason
    assert len(ctx.store.findings) == 1


def test_manifest_finding_count_matches_the_store_end_to_end(tmp_path):
    """run_stages() + write_manifest() together, both with and without a
    collision: run.json must never claim more findings than ctx.store
    actually holds.
    """
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [EmitsFindings(_colliding_pair())])
    ctx.write_manifest(results)
    manifest = json.loads((ctx.run_dir / "run.json").read_text())

    assert len(ctx.store.findings) == 1
    assert manifest["findings_stored"] == 1
    assert manifest["stages"]["emitsfindings"]["findings"] == 1
    assert manifest["stages"]["emitsfindings"]["collisions"] == 1
    assert len(manifest["finding_collisions"]) == 1

    ctx2 = ctx_for(tmp_path)
    clean = [
        Finding(stage="x", severity="medium", title="A",
                target="acc.example", template_id="t-a"),
        Finding(stage="x", severity="low", title="B",
                target="acc.example", template_id="t-b"),
    ]
    results2 = run_stages(ctx2, [EmitsFindings(clean)])
    ctx2.write_manifest(results2)
    manifest2 = json.loads((ctx2.run_dir / "run.json").read_text())
    assert manifest2["findings_stored"] == 2
    assert manifest2["stages"]["emitsfindings"]["findings"] == 2
    assert manifest2["stages"]["emitsfindings"]["collisions"] == 0
    assert manifest2["finding_collisions"] == []


def test_per_stage_finding_counts_sum_to_the_store_across_stages(tmp_path):
    """The reconciliation invariant itself: summing every stage's reported
    finding count must reproduce exactly what the store holds -- no stage
    may claim a finding another stage already stored.
    """
    class SecondStage(EmitsFindings):
        name = "second"

    first = EmitsFindings([
        Finding(stage="x", severity="medium", title="Shared",
                target="acc.example", template_id="t-shared"),
        Finding(stage="x", severity="low", title="OnlyFirst",
                target="acc.example", template_id="t-first"),
    ])
    second = SecondStage([
        # A resubmission of a finding stage one already stored: correct to
        # dedupe silently, and it must NOT be counted as stored by `second`.
        Finding(stage="x", severity="medium", title="Shared",
                target="acc.example", template_id="t-shared"),
        Finding(stage="x", severity="high", title="OnlySecond",
                target="acc.example", template_id="t-second"),
    ])

    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [first, second])
    ctx.write_manifest(results)
    manifest = json.loads((ctx.run_dir / "run.json").read_text())

    assert manifest["stages"]["emitsfindings"]["findings"] == 2
    assert manifest["stages"]["second"]["findings"] == 1, \
        "a resubmission of an already-stored finding was double-counted"
    assert sum(s["findings"] for s in manifest["stages"].values()) == 3
    assert manifest["findings_stored"] == len(ctx.store.findings) == 3
    assert manifest["finding_collisions"] == []


# --- a stage the SYSTEM killed is not a stage that failed --------------------
# Measured on a live run 2026-08-05: katana went `partial` after 124s under a
# 90-MINUTE limit, and the manifest said `exit -9 with partial output`. The
# kernel log said what that actually was:
#
#   oom-kill: task=katana, pid=67402
#   Out of memory: Killed process 67402 (katana) anon-rss:9737344kB
#
# 9.3 GB on a 15 GB box, in two minutes. "exit -9" is accurate and useless:
# an operator reads it as "the tool broke" and looks at the tool, when the
# answer is that the box is too small for this scope at this level. Same
# reasoning as the time-limit reason directly above it -- the status cannot
# distinguish these, so the reason must.


class SignalKilledStage(Base):
    """Emits a row, then dies to SIGKILL — what the OOM killer leaves behind."""
    name = "signalkilled"

    def build_command(self, ctx):
        return ["/bin/sh", "-c", "echo partial-row; kill -9 $$"]

    def parse(self, raw_path):
        yield Artifact(ArtifactKind.PORT, "acc.example:8443")


def test_a_signal_killed_stage_says_it_was_killed(tmp_path):
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [SignalKilledStage()])

    assert r.status == "partial"
    assert "SIGKILL" in r.reason, r.reason
    assert "exit -9 with partial output" != r.reason, (
        "the bare signal number tells the operator nothing to act on")


def test_the_kill_reason_points_at_how_to_confirm_it(tmp_path):
    """sweeper cannot prove it was the OOM killer -- a signal can also come
    from an operator or a supervisor -- so it must not claim so. It names
    the likeliest cause and the command that settles it, which is the
    difference between an actionable reason and a guess in a deliverable."""
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [SignalKilledStage()])

    assert "journalctl" in r.reason, r.reason
    assert "out of memory" in r.reason.lower()


def test_an_ordinary_non_zero_exit_is_not_called_a_signal(tmp_path):
    """The regression guard. Widening this must not relabel every partial."""
    ctx = ctx_for(tmp_path)
    [r] = run_stages(ctx, [PartialStage()])

    assert r.reason == "exit 3 with partial output"


def test_the_reason_reaches_sweep_log_not_only_the_manifest(tmp_path):
    """An operator watching a live run saw `partial — 2824 artifacts, 0
    findings` and nothing else; the reason existed only in run.json, read
    after the fact. A stage that stopped early has to say why where the
    person watching it will see it."""
    ctx = ctx_for(tmp_path)
    run_stages(ctx, [SignalKilledStage()])

    log = (ctx.run_dir / "sweep.log").read_text(encoding="utf-8")
    line = [ln for ln in log.splitlines() if "signalkilled: partial" in ln]
    assert line, log
    assert "SIGKILL" in line[0], line[0]


def test_only_sigkill_suggests_the_out_of_memory_killer():
    """The OOM killer sends SIGKILL, never SIGTERM. A SIGTERM is an
    operator, a supervisor or a container stopping the stage -- the lab runs
    in RESUME.md were SIGTERMed by hand -- and telling that operator the
    likely cause is memory pressure is a confident wrong answer in a run
    record, which is the failure this whole taxonomy exists to prevent."""
    from sweeper.runner import _partial_exit_reason
    assert "memory" in _partial_exit_reason(-9)
    term = _partial_exit_reason(-15)
    assert "SIGTERM" in term
    assert "memory" not in term.lower(), term
