import json
from pathlib import Path

import pytest
from sweeper import app
from sweeper.artifacts import ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.scope import ScopeGuard


# --- The one property that generalizes most of this branch review's finds --
# Enumerated defects (C3's dropped stage, a scope mismatch, a missing
# binary...) only catch the specific cases someone thought of. The product
# now computes this itself: RunContext.coverage (see sweeper/stages/base.py's
# Coverage + is_degraded) is the denominator, populated by app.execute()
# before run_stages and recorded in the manifest under "coverage". This
# helper is reduced from an independent reimplementation (which itself
# false-positived on duplicate target lines and was never aimed at a partial
# refusal) to a self-consistency check: the manifest's own `degraded` flag
# must agree with its own recorded `coverage` numbers and stage entries. It
# is not a substitute for testing Coverage/is_degraded directly -- see
# tests/test_stage_base.py for that -- only a guard that every end-to-end
# path that writes a real run.json does not compute one and print the other.
# `targets_file` and `requested_stage_count` are unused now but kept so
# every call site below did not need editing.


def assert_coverage_property(run_dir: Path, targets_file: Path,
                             requested_stage_count: int) -> None:
    manifest = json.loads((Path(run_dir) / "run.json").read_text(encoding="utf-8"))
    cov = manifest.get("coverage") or {}
    stage_entries = set(manifest["stages"])
    stages_requested = cov.get("stages_requested", [])
    gap = (
        cov.get("targets_permitted", 0) < cov.get("targets_requested", 0)
        or any(name not in stage_entries for name in stages_requested)
    )
    if gap:
        assert manifest["degraded"] is True, (
            f"coverage gap recorded in {run_dir}'s own manifest "
            f"(coverage={cov}, stages={sorted(stage_entries)}) but "
            "manifest['degraded'] is False"
        )


def test_build_stages_orders_dnsx_naabu_httpx(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    names = [s.name for s in app.build_stages(RunConfig(targets_file=t))]
    assert names.index("naabu") < names.index("httpx")
    assert "dnsx" in names


def test_build_stages_honours_explicit_selection(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    cfg = RunConfig(targets_file=t, stages=["dnsx"])
    assert [s.name for s in app.build_stages(cfg)] == ["dnsx"]


# --- C3: an unknown --stages name must fail loudly, never silently drop ----
# "--stages dnsx,naabu,htpx" ran two stages and the report printed "All
# selected stages completed." -- a typo silently deleted a stage from the
# scan with no error at all.


def test_build_stages_rejects_an_unknown_stage_name(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    cfg = RunConfig(targets_file=t, stages=["dnsx", "naabu", "htpx"])
    with pytest.raises(ValueError) as exc:
        app.build_stages(cfg)
    msg = str(exc.value)
    assert "htpx" in msg                                          # the typo, named
    assert "dnsx" in msg and "naabu" in msg and "httpx" in msg     # valid names listed


# --- A broken stage MODULE must surface as itself, not as a config typo ----
# main()'s bare `except ValueError` used to catch both the unknown-name
# ValueError from build_stages AND the registry contract-violation ValueError
# from the very same function, presenting a programming error (a stage
# module violating its own declared contract) as a friendly "fix your typo"
# message. They are now different exception types.


class ContractBreakingStage:
    """produces is a set per the Stage contract; this one is not."""
    name = "contractbreaker"
    requires = []
    consumes = ArtifactKind.HOST
    produces = "not-a-set"     # violates registry.validate's contract
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def build_command(self, ctx):
        return ["/bin/true"]

    def parse(self, raw_path):
        return iter(())


def test_stage_contract_violation_is_not_a_valueerror(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    cfg = RunConfig(targets_file=t, stages=["contractbreaker"])
    import sweeper.app as app_module
    orig = app_module.ALL_STAGES
    try:
        app_module.ALL_STAGES = (ContractBreakingStage,)
        with pytest.raises(app.StageContractViolation) as exc:
            app.build_stages(cfg)
        assert not isinstance(exc.value, ValueError), (
            "a contract violation must not be catchable by the same "
            "except ValueError that handles an unknown --stages typo"
        )
        assert "contractbreaker" in str(exc.value)
    finally:
        app_module.ALL_STAGES = orig


def test_stage_contract_violation_escapes_main_uncaught(tmp_path, monkeypatch):
    """main()'s `except ValueError` must not swallow this and print a
    friendly config-mistake message; it must propagate."""
    monkeypatch.setattr(app, "ALL_STAGES", (ContractBreakingStage,))
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    with pytest.raises(app.StageContractViolation):
        app.main(["--targets", str(t), "--outdir", str(tmp_path / "out"),
                 "--no-menu", "--stages", "contractbreaker"])


def test_unknown_stage_name_on_the_cli_exits_nonzero_not_a_traceback(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "ALL_STAGES", (CleanStage,))
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    rc = app.main(["--targets", str(t), "--outdir", str(tmp_path / "out"),
                   "--no-menu", "--stages", "cleanstage,typo"])
    assert rc != 0
    assert _run_dirs(tmp_path) == [], "a run started (and an empty dir was left) despite the typo"


def test_unknown_stage_name_via_the_menu_path_does_not_kill_the_repl(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "ALL_STAGES", (CleanStage,))
    seen = {}

    def fake_run_menu(state, prompt_fn, runner_fn):
        state.config.stages = ["typo"]
        runner_fn(state)          # must not raise
        seen["reached"] = True

    monkeypatch.setattr("sweeper.ui.menu.run_menu", fake_run_menu)
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    rc = app.main(["--targets", str(t), "--outdir", str(tmp_path / "out")])
    assert rc == 0
    assert seen["reached"], "the ValueError escaped the REPL"
    assert _run_dirs(tmp_path) == []


def test_seed_hosts_populates_store_from_targets(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\nb.example\n")
    ctx = app.prepare(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    assert sorted(ctx.store.values(ArtifactKind.HOST)) == ["acc.example", "b.example"]


def test_out_of_scope_target_never_seeded(tmp_path, monkeypatch):
    """The refused entry must come from the TARGETS FILE.

    Adding it via scope.filter() after prepare() tests nothing: prepare()
    never saw it, so the assertion holds even if prepare() seeded blindly.

    It cannot be a second bare hostname either. RunContext.create builds the
    ScopeGuard from the same targets file it seeds from, so every bare host in
    that file is in scope BY CONSTRUCTION -- "evil.test" on its own line is
    seeded, correctly.

    It also cannot be the C1 userinfo-bypass shape any more:
    "acc.example:80@evil.test" now normalizes to "evil.test" on BOTH the
    allowlist-storage side (__init__) and the comparison side (allows()),
    so a targets file that lists it now legitimately permits exactly the
    host it addresses -- that self-consistency is what the C1 fix restores.
    To exercise prepare()'s refusal-respecting behaviour here, the
    allowlist is narrowed directly to simulate any source of a scope
    narrower than the targets file (a future --scope-file, a scope that was
    never extend()-ed to cover a line, etc). The property under test is
    prepare() honouring ctx.scope.filter(), not how the scope came to be
    narrow.
    """
    t = tmp_path / "t.txt"
    t.write_text("acc.example\nevil.test\n")

    from sweeper.scope import ScopeGuard
    original_create = RunContext.create.__func__

    def narrowed_create(cls, config):
        ctx = original_create(cls, config)
        ctx.scope = ScopeGuard({"acc.example"})   # evil.test deliberately excluded
        return ctx

    monkeypatch.setattr(RunContext, "create", classmethod(narrowed_create))

    ctx = app.prepare(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    seeded = ctx.store.values(ArtifactKind.HOST)
    assert "acc.example" in seeded
    assert "evil.test" not in seeded, (
        "prepare() seeded a host the scope guard refuses"
    )
    assert any(r["normalized"] == "evil.test" for r in ctx.scope.refusals)


# --- The live proof: a PARTIAL scope refusal must degrade the run ----------
# The branch re-review's diagnosis: a refused target produces a refusals
# entry and NO StageResult, so the old any()-over-results is_degraded could
# never see it. Two targets, one refused, every selected stage completing
# cleanly used to produce degraded:false, no banner, and "All selected
# stages completed." -- exit 0. Driven through the real app.execute() entry
# point, not the lower-level units, and pinning the banner and the refused
# target's name in the report, not merely the boolean.


def test_partial_scope_refusal_degrades_the_run(tmp_path, monkeypatch):
    t = tmp_path / "t.txt"
    t.write_text("acc.example\nevil.test\n")

    original_create = RunContext.create.__func__

    def narrowed_create(cls, config):
        ctx = original_create(cls, config)
        ctx.scope = ScopeGuard({"acc.example"})   # evil.test refused
        return ctx

    monkeypatch.setattr(RunContext, "create", classmethod(narrowed_create))
    monkeypatch.setattr(app, "ALL_STAGES", (CleanStage,))

    ctx, results = app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))

    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["stages"]["cleanstage"]["status"] == "complete", (
        "the stage itself must have completed cleanly -- the point is that "
        "coverage, not stage execution, is what is incomplete here"
    )
    assert manifest["degraded"] is True, (
        "a refused target is a coverage gap even when every selected stage "
        "completes"
    )
    assert manifest["coverage"]["targets_requested"] == 2
    assert manifest["coverage"]["targets_permitted"] == 1

    report = (ctx.run_dir / "report.md").read_text(encoding="utf-8")
    assert "DEGRADED RUN" in report
    assert "evil.test" in report
    # The stage itself really did complete -- "All selected stages
    # completed" is an honest statement about STAGE coverage. It is TARGET
    # coverage that is incomplete, and that is what the denominator line and
    # the DEGRADED banner communicate; the point of this test is that they
    # do so even though the per-stage table alone would read as clean.
    coverage_section = report[report.index("## Coverage"):]
    assert "2 requested" in coverage_section
    assert "1 in scope" in coverage_section
    assert "1 refused" in coverage_section


def test_execute_writes_manifest_and_report(tmp_path, monkeypatch):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    # Force every stage to be unavailable so no network traffic occurs.
    monkeypatch.setattr("sweeper.binaries.resolve", lambda name: None)
    ctx, results = app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    assert (ctx.run_dir / "run.json").exists()
    assert (ctx.run_dir / "report.md").exists()
    manifest = json.loads((ctx.run_dir / "run.json").read_text())
    assert manifest["degraded"] is True
    assert_coverage_property(ctx.run_dir, t, len(app.ALL_STAGES))


# --- --triage-file plumbing --------------------------------------------
# RunConfig gained a triage_file field, but a field absent from main()'s
# explicit RunConfig(...) call keeps its default no matter what argparse
# parsed -- the same shape as the write_markdown/write_html call-site gap
# this task also fixes. Assert on the resolved path TriageState actually
# received, not merely that the flag parses without error: parsing was
# never the broken half.


def test_cli_triage_file_reaches_triage_state(tmp_path, monkeypatch):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    triage_path = tmp_path / "custom-triage.json"
    seen = {}

    class _RecordingTriageState:
        def __init__(self, path):
            seen["path"] = path
            self.load_error = None

        def apply(self, findings):
            return findings

    monkeypatch.setattr("sweeper.app.TriageState", _RecordingTriageState)
    monkeypatch.setattr("sweeper.binaries.resolve", lambda name: None)
    rc = app.main([
        "--targets", str(t), "--outdir", str(tmp_path / "out"),
        "--no-menu", "--triage-file", str(triage_path),
    ])
    assert rc == 0
    assert seen["path"] == triage_path


def test_cli_without_triage_file_uses_the_default_path(tmp_path, monkeypatch):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    seen = {}

    class _RecordingTriageState:
        def __init__(self, path):
            seen["path"] = path
            self.load_error = None

        def apply(self, findings):
            return findings

    monkeypatch.setattr("sweeper.app.TriageState", _RecordingTriageState)
    monkeypatch.setattr("sweeper.binaries.resolve", lambda name: None)
    rc = app.main([
        "--targets", str(t), "--outdir", str(tmp_path / "out"), "--no-menu",
    ])
    assert rc == 0
    assert seen["path"] == app.default_triage_path()


def test_main_returns_nonzero_when_preflight_fails(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("# no targets\n")
    rc = app.main(["--targets", str(t), "--outdir", str(tmp_path / "out"), "--no-menu"])
    assert rc != 0


# --- C4: an impostor binary must be skipped, never executed -----------------
# preflight.run_preflight computed binaries.verify() (identity check) and
# recorded the failure in disabled_stages, but run_stages re-decided using
# binaries.resolve() alone (existence only) and executed the impostor
# anyway, recording status=complete. This is the exact /usr/bin/httpx-is-
# the-Python-client scenario binaries.py exists to prevent, driven through
# the real app.execute() entry point rather than the lower-level units.


def test_impostor_binary_is_skipped_not_executed(tmp_path, monkeypatch):
    from sweeper import binaries

    marker = tmp_path / "EXECUTED"
    impostor = tmp_path / "impostor-httpx"
    impostor.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-version" ]; then echo "impostor httpclient v1.0"; exit 0; fi\n'
        f'echo EXECUTED > "{marker}"\n'
        'echo \'{"real":"scan"}\'\n'
    )
    impostor.chmod(0o755)
    monkeypatch.setitem(
        binaries.KNOWN_BINARIES, "impostor",
        binaries.BinarySpec("impostor", [impostor], "-version",
                            binaries.PD_IDENTITY, "n/a"),
    )
    assert binaries.resolve("impostor") is not None    # a bare existence
    assert binaries.verify("impostor").ok is False      # check would accept it

    class ImpostorHttpxStage:
        name = "httpx"
        requires = ["impostor"]
        consumes = ArtifactKind.HOST
        produces = {ArtifactKind.HTTP_SERVICE}
        levels = {"low": [], "mid": [], "high": [], "full": []}
        optional = False

        def build_command(self, ctx):
            return [str(impostor), "-scan"]

        def parse(self, raw_path):
            return iter(())

    monkeypatch.setattr(app, "ALL_STAGES", (ImpostorHttpxStage,))
    t = tmp_path / "t.txt"; t.write_text("127.0.0.1\n")
    ctx, results = app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))

    assert not marker.exists(), "the impostor binary was executed for real"
    [r] = results
    assert r.status == "skipped"
    assert r.failure.name == "MISSING_BINARY"
    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["stages"]["httpx"]["status"] == "skipped"
    assert manifest["degraded"] is True
    assert_coverage_property(ctx.run_dir, t, 1)


# --- An aborted run must not destroy its own record ------------------------
# run_stages writes a manifest naming the failed stage and its diagnostic,
# then raises AbortRun. A caller that discards the results and writes an
# empty manifest OVERWRITES that record: the report then reads "No stages
# ran. Nothing was scanned." -- indistinguishable from an operator selecting
# no stages, with no mention of an abort and degraded=false. An abort is
# precisely when the operator needs the record, so these pin its content,
# not merely the existence of the files.

REAL_ARG_ERROR = "flag provided but not defined: -definitely-not-a-flag"


class LateArgErrorStage:
    """Accepts its arguments at preflight, rejects them at run time.

    preflight.validate_arguments substitutes its own probe file for any .txt
    argument, so the stage can tell the two invocations apart. That is how a
    tool which parses some flags only once it starts real work behaves, and
    it is the only way to reach run_stages' ARG_ERROR path through execute().
    """
    name = "lateargerror"
    requires = []
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def build_command(self, ctx):
        infile = ctx.run_dir / "raw" / "lateargerror-input.txt"
        infile.parent.mkdir(parents=True, exist_ok=True)
        infile.write_text("acc.example\n", encoding="utf-8")
        return ["/bin/sh", "-c",
                f'case "$1" in *preflight*) exit 0;; esac; '
                f'echo "{REAL_ARG_ERROR}"; exit 2',
                "sh", str(infile)]

    def parse(self, raw_path):
        return iter(())


class CleanStage:
    """Completes normally at both preflight and run time."""
    name = "cleanstage"
    requires = []
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        return iter(())


def _run_with(monkeypatch, tmp_path, stage_cls):
    monkeypatch.setattr(app, "ALL_STAGES", (stage_cls,))
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx, results = app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    # Applied here rather than in each caller: every test that goes through
    # this helper gets the property checked, not just the ones someone
    # thought to add it to.
    assert_coverage_property(ctx.run_dir, t, requested_stage_count=1)
    return ctx, results


def _manifest(ctx):
    return json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))


def test_aborted_run_manifest_records_the_abort_and_its_reason(tmp_path, monkeypatch):
    ctx, results = _run_with(monkeypatch, tmp_path, LateArgErrorStage)
    manifest = _manifest(ctx)
    assert manifest["aborted"] is True
    assert manifest["degraded"] is True
    assert REAL_ARG_ERROR in manifest["aborted_reason"]
    assert manifest["aborted_reason"] != "argument rejected"


def test_aborted_run_manifest_keeps_the_failed_stage(tmp_path, monkeypatch):
    """The results gathered before the abort must survive into the manifest."""
    ctx, results = _run_with(monkeypatch, tmp_path, LateArgErrorStage)
    stages = _manifest(ctx)["stages"]
    assert "lateargerror" in stages
    assert stages["lateargerror"]["status"] == "failed"
    assert stages["lateargerror"]["failure"] == "ARG_ERROR"
    assert stages["lateargerror"]["reason"] == REAL_ARG_ERROR


def test_aborted_run_report_leads_with_the_abort_and_names_the_reason(tmp_path, monkeypatch):
    ctx, results = _run_with(monkeypatch, tmp_path, LateArgErrorStage)
    report = (ctx.run_dir / "report.md").read_text(encoding="utf-8")
    assert "RUN ABORTED" in report
    assert REAL_ARG_ERROR in report
    assert "No stages ran" not in report


def test_aborted_run_report_lists_the_failed_stage_in_coverage(tmp_path, monkeypatch):
    ctx, results = _run_with(monkeypatch, tmp_path, LateArgErrorStage)
    report = (ctx.run_dir / "report.md").read_text(encoding="utf-8")
    coverage = report[report.index("## Coverage"):]
    assert "lateargerror" in coverage
    assert "ARG_ERROR" in coverage


def test_aborted_run_is_recorded_in_the_sweep_log(tmp_path, monkeypatch):
    ctx, results = _run_with(monkeypatch, tmp_path, LateArgErrorStage)
    log = (ctx.run_dir / "sweep.log").read_text(encoding="utf-8")
    abort_lines = [l for l in log.splitlines() if "ABORTED" in l]
    assert abort_lines, "no ABORTED line was logged"
    assert REAL_ARG_ERROR in abort_lines[0]


def test_clean_run_is_not_marked_aborted(tmp_path, monkeypatch):
    ctx, results = _run_with(monkeypatch, tmp_path, CleanStage)
    manifest = _manifest(ctx)
    assert manifest["aborted"] is False
    assert manifest["aborted_reason"] == ""
    assert manifest["degraded"] is False


def test_clean_run_banner_is_unchanged(tmp_path, monkeypatch):
    ctx, results = _run_with(monkeypatch, tmp_path, CleanStage)
    report = (ctx.run_dir / "report.md").read_text(encoding="utf-8")
    assert "RUN ABORTED" not in report
    assert "DEGRADED RUN" not in report


# --- I2: a parse() exception is CONTAINED, and still leaves a full record --
# These tests used to pin the opposite: that a stage's parse() blowing up
# propagated out of execute() and set aborted_reason. That intent was
# deliberately changed. Weighing the field outcomes decided it -- containing
# costs one stage and yields a loud PARSE_ERROR on a degraded run, whereas
# propagating loses every other stage's results inside a scan window that may
# not come back. "Fail loudly" is satisfied by a degraded run that names the
# stage; it does not require aborting the run.
#
# The original record-keeping requirement these tests were written for still
# holds and is still asserted: a failure of this class must leave a manifest
# and a report that say what happened. What changed is that the run now
# finishes and reports DEGRADED instead of ABORTED, so the record lives in
# stages{} rather than in aborted_reason -- and the traceback, which an
# aborting run got for free from the propagating exception, is now written
# explicitly to sweep.log so a contained bug stays debuggable.


class ExplodingStage:
    """A stage whose parse() raises a plain programming error."""
    name = "exploding"
    requires = []
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        raise KeyError("boom")
        yield   # pragma: no cover — makes this a generator, matching parse()'s contract


def test_parse_exception_is_contained_and_still_writes_manifest_and_report(
        tmp_path, monkeypatch):
    """The run completes; the offending stage carries PARSE_ERROR.

    Formerly asserted that KeyError propagated and set aborted_reason. The
    record-keeping half of that requirement is unchanged and still checked
    here -- only the mechanism moved, from an abort to a degraded run.
    """
    monkeypatch.setattr(app, "ALL_STAGES", (ExplodingStage,))
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")

    # No pytest.raises: the run finishes.
    ctx, results = app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))

    run_dir = next((tmp_path / "out").iterdir())
    assert (run_dir / "run.json").exists()
    assert (run_dir / "report.md").exists()
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))

    assert manifest["aborted"] is False
    assert manifest["aborted_reason"] == ""
    # Still degraded, and the reason is still recorded -- in stages{} now.
    assert manifest["degraded"] is True
    stage = manifest["stages"]["exploding"]
    assert stage["status"] == "failed"
    assert stage["failure"] == "PARSE_ERROR"
    assert "KeyError" in stage["reason"] and "boom" in stage["reason"]

    # The traceback an aborting run got for free is now written explicitly.
    log = (run_dir / "sweep.log").read_text(encoding="utf-8")
    assert "PARSE_ERROR traceback" in log
    assert "Traceback (most recent call last)" in log
    assert "KeyError" in log

    assert_coverage_property(run_dir, t, requested_stage_count=1)


def test_contained_parse_exception_is_named_in_the_report(tmp_path, monkeypatch):
    """A degraded run is only "loud" if the report actually says so."""
    monkeypatch.setattr(app, "ALL_STAGES", (ExplodingStage,))
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    run_dir = next((tmp_path / "out").iterdir())
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "DEGRADED RUN" in report
    assert "exploding" in report


# --- A stage that completed before a LATER stage exploded must survive -----
# execute()'s except Exception clause used to discard run_results entirely
# (always merging with []), so a stage that finished cleanly vanished from
# the manifest along with the one that actually broke. run_stages now
# mutates a list the caller already holds, so the caller keeps whatever
# completed regardless of how the exception unwound the stack.


class CleanFirstStage:
    """Completes normally and produces the PORT the next stage consumes."""
    name = "cleanfirst"
    requires = []
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        from sweeper.artifacts import Artifact
        yield Artifact(ArtifactKind.PORT, "acc.example:443")


class ExplodesSecondStage:
    """Depends on cleanfirst's output (forcing it to run second), then
    raises a plain programming error from parse()."""
    name = "explodessecond"
    requires = []
    consumes = ArtifactKind.PORT
    produces = {ArtifactKind.HTTP_SERVICE}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def build_command(self, ctx):
        return ["/bin/echo", '{"ok":1}']

    def parse(self, raw_path):
        raise KeyError("boom2")
        yield   # pragma: no cover — makes this a generator, matching parse()'s contract


def test_contained_parse_exception_preserves_stages_that_already_completed(
        tmp_path, monkeypatch):
    """A stage that completed before a later stage's parse() blew up survives.

    This held under the old propagating contract and must still hold now that
    the exception is contained -- the containment must not quietly drop
    earlier results on its way past.
    """
    monkeypatch.setattr(app, "ALL_STAGES", (CleanFirstStage, ExplodesSecondStage))
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")

    app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))

    run_dir = next((tmp_path / "out").iterdir())
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["stages"]["cleanfirst"]["status"] == "complete", (
        "the stage that finished before the crash vanished from the manifest"
    )
    assert manifest["stages"]["explodessecond"]["failure"] == "PARSE_ERROR"
    assert manifest["degraded"] is True
    assert manifest["aborted"] is False


# --- A run that dies at preflight must leave a record too -------------------
# Writing only a manifest, with the reason on the console, leaves a run
# directory that reads as a clean empty scan.


def _failed_preflight(tmp_path, monkeypatch):
    """No targets: preflight fails. CleanStage keeps it off the real binaries."""
    monkeypatch.setattr(app, "ALL_STAGES", (CleanStage,))
    t = tmp_path / "t.txt"; t.write_text("# no targets\n")
    with pytest.raises(SystemExit) as exc:
        app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    assert exc.value.code == 2
    run_dir = next((tmp_path / "out").iterdir())
    assert_coverage_property(run_dir, t, requested_stage_count=1)
    return run_dir


def test_preflight_failure_writes_both_manifest_and_report(tmp_path, monkeypatch):
    run_dir = _failed_preflight(tmp_path, monkeypatch)
    assert (run_dir / "run.json").exists()
    assert (run_dir / "report.md").exists()


def test_preflight_failure_manifest_carries_the_reason(tmp_path, monkeypatch):
    run_dir = _failed_preflight(tmp_path, monkeypatch)
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["aborted"] is True
    assert manifest["degraded"] is True
    assert "no targets" in manifest["aborted_reason"]


def test_preflight_failure_report_leads_with_the_abort(tmp_path, monkeypatch):
    run_dir = _failed_preflight(tmp_path, monkeypatch)
    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "RUN ABORTED" in report
    assert "no targets" in report


def test_preflight_failure_is_recorded_in_the_sweep_log(tmp_path, monkeypatch):
    run_dir = _failed_preflight(tmp_path, monkeypatch)
    log = (run_dir / "sweep.log").read_text(encoding="utf-8")
    assert [l for l in log.splitlines() if "ABORTED" in l and "no targets" in l]


# --- The typed acknowledgement is the operator's recorded authorisation -----
# Held only on MenuState it dies with the process, so the most invasive scan
# the tool performs would leave no evidence it was authorised.

ACK = [{"level": "full", "phrase": "I ACKNOWLEDGE", "at": "2026-07-29T00:00:00Z"}]


def test_acknowledgement_reaches_the_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "ALL_STAGES", (CleanStage,))
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    # level must match ACK's "full": the manifest filters acknowledgements to
    # the run's FINAL level (see test_context.py's stale-acknowledgement
    # tests), so a "full" ack on a "mid" run would be correctly dropped.
    ctx, _ = app.execute(
        RunConfig(targets_file=t, outdir=tmp_path / "out", level="full"),
        acknowledgements=ACK,
    )
    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["acknowledgements"] == ACK


def test_run_without_acknowledgement_records_none(tmp_path, monkeypatch):
    ctx, _ = _run_with(monkeypatch, tmp_path, CleanStage)
    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["acknowledgements"] == []


# --- A failed run must not kill the REPL ------------------------------------
# run_menu is stubbed because it is not what is under test: the _runner
# closure main() builds is, and it is exercised for real, against a real
# execute() that really raises SystemExit.


def _drive_menu(tmp_path, monkeypatch, targets, stage_cls=CleanStage):
    monkeypatch.setattr(app, "ALL_STAGES", (stage_cls,))
    seen = {}

    def fake_run_menu(state, prompt_fn, runner_fn):
        # "full" so it matches ACK's level -- the manifest filters
        # acknowledgements to the run's FINAL level (stale-acknowledgement
        # fix), so a mismatched level here would make ACK vanish from the
        # manifest and this helper's tests would not be testing what they
        # say they are.
        state.config.level = "full"          # a setting the operator entered
        state.acknowledgements = list(ACK)
        runner_fn(state)                     # must not raise
        seen["level"] = state.config.level
        seen["config"] = state.config

    monkeypatch.setattr("sweeper.ui.menu.run_menu", fake_run_menu)
    t = tmp_path / "t.txt"; t.write_text(targets)
    rc = app.main(["--targets", str(t), "--outdir", str(tmp_path / "out")])
    # Wired in here so every _drive_menu caller gets the property checked,
    # not just the ones someone thought to add it to -- the fix wave's
    # original property was never reached from this path at all.
    out = tmp_path / "out"
    run_dirs = list(out.iterdir()) if out.exists() else []
    if run_dirs:
        assert_coverage_property(run_dirs[-1], t, requested_stage_count=1)
    return rc, seen


def test_preflight_failure_in_the_menu_does_not_kill_the_repl(tmp_path, monkeypatch):
    rc, seen = _drive_menu(tmp_path, monkeypatch, "# no targets\n")
    assert rc == 0
    assert seen["level"] == "full", "operator settings were lost"


def test_menu_passes_the_acknowledgement_through_to_the_manifest(tmp_path, monkeypatch):
    rc, seen = _drive_menu(tmp_path, monkeypatch, "acc.example\n")
    assert rc == 0
    run_dir = next((tmp_path / "out").iterdir())
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["acknowledgements"] == ACK


# --- The level gates must hold on the CLI path too --------------------------
# The typed acknowledgement and the `high` confirmation lived only in the menu
# REPL, so `-l full --no-menu` ran dast parameter fuzzing -- which places
# orders and burns single-use coupons on a client's system -- with nothing
# asked and acknowledgements: [] in the manifest. A safety control reachable
# through only one of two entry points is not a control.

def _cli(tmp_path, monkeypatch, *extra, targets="acc.example\n"):
    monkeypatch.setattr(app, "ALL_STAGES", (CleanStage,))
    t = tmp_path / "t.txt"; t.write_text(targets)
    rc = app.main(["--targets", str(t), "--outdir", str(tmp_path / "out"),
                   "--no-menu", *extra])
    # Only reached when main() returned normally (the gate-refusal callers
    # all raise SystemExit, caught by the caller's pytest.raises before this
    # line). One run directory is created per successful call.
    out = tmp_path / "out"
    run_dirs = list(out.iterdir()) if out.exists() else []
    if run_dirs:
        assert_coverage_property(run_dirs[-1], t, requested_stage_count=1)
    return rc


def _run_dirs(tmp_path):
    out = tmp_path / "out"
    return list(out.iterdir()) if out.exists() else []


def test_full_level_without_acknowledgement_is_refused(tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as exc:
        _cli(tmp_path, monkeypatch, "-l", "full")
    assert exc.value.code != 0
    assert _run_dirs(tmp_path) == [], "a run started despite the missing gate"


def test_removed_acknowledge_option_is_refused(tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as exc:
        _cli(tmp_path, monkeypatch, "-l", "full", "--acknowledge", "wrong phrase")
    assert exc.value.code != 0
    assert _run_dirs(tmp_path) == [], "a run started despite the missing gate"


def test_full_level_with_ack_proceeds(tmp_path, monkeypatch):
    assert _cli(tmp_path, monkeypatch, "-l", "full", "--ack") == 0
    assert len(_run_dirs(tmp_path)) == 1


def test_full_level_acknowledgement_is_recorded_in_the_manifest(tmp_path, monkeypatch):
    _cli(tmp_path, monkeypatch, "-l", "full", "--ack")
    run_dir = _run_dirs(tmp_path)[0]
    acks = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))["acknowledgements"]
    assert len(acks) == 1
    assert acks[0]["level"] == "full"
    assert acks[0]["phrase"] == "--ack"
    assert acks[0]["via"] == "cli"
    assert acks[0]["at"]


def test_high_level_without_yes_is_refused(tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as exc:
        _cli(tmp_path, monkeypatch, "-l", "high")
    assert exc.value.code != 0
    assert _run_dirs(tmp_path) == [], "a run started despite the missing gate"


def test_high_level_with_yes_proceeds(tmp_path, monkeypatch):
    assert _cli(tmp_path, monkeypatch, "-l", "high", "--yes") == 0
    assert len(_run_dirs(tmp_path)) == 1


def test_high_level_run_records_the_acknowledgement(tmp_path, monkeypatch):
    """Spec 2.2/6.1/12.1(5): BOTH gates are recorded in the manifest with a
    timestamp, not only `full`'s typed acknowledgement. --yes is a weaker
    confirmation than a typed phrase, but it must still leave a record that
    the DoS-adjacent 65535-port sweep was actually confirmed."""
    _cli(tmp_path, monkeypatch, "-l", "high", "--yes")
    run_dir = _run_dirs(tmp_path)[0]
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    acks = manifest["acknowledgements"]
    assert len(acks) == 1
    assert acks[0]["level"] == "high"
    assert acks[0]["via"] == "cli"
    assert acks[0]["at"]
    assert manifest["level"] == "high"


@pytest.mark.parametrize("level", ["low", "mid"])
def test_ordinary_levels_need_no_gate_flags(tmp_path, monkeypatch, level):
    """The gates must not obstruct ordinary use."""
    assert _cli(tmp_path, monkeypatch, "-l", level) == 0
    assert len(_run_dirs(tmp_path)) == 1


# --- main() must map SystemExit codes faithfully ----------------------------
# `int(exc.code or 1)` turned SystemExit(0) into a failure and raised
# ValueError on a string code.

# (None, 1) pins a deliberate deviation from Python's convention, where a
# bare SystemExit() means success: for a scanning tool an ambiguous exit
# status is reported as failure.
@pytest.mark.parametrize("code,expected", [(0, 0), (2, 2), (7, 7), (None, 1)])
def test_main_returns_the_exit_code_unchanged(tmp_path, monkeypatch, code, expected):
    def boom(*a, **kw):
        raise SystemExit(code)
    monkeypatch.setattr(app, "execute", boom)
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    rc = app.main(["--targets", str(t), "--outdir", str(tmp_path / "out"), "--no-menu"])
    assert rc == expected


def test_main_maps_a_string_exit_code_to_one_without_raising(tmp_path, monkeypatch):
    def boom(*a, **kw):
        raise SystemExit("something went wrong")
    monkeypatch.setattr(app, "execute", boom)
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    rc = app.main(["--targets", str(t), "--outdir", str(tmp_path / "out"), "--no-menu"])
    assert rc == 1


# --- The gates must not depend on which door you came through ---------------
# Conditioning them on --no-menu left the other path open: `-l full` without
# --no-menu opens the menu ALREADY at full, and the REPL's gate fires only
# when the operator CHANGES the level, never for a preset one. Pressing R ran
# dast fuzzing with acknowledgements: [].

def _cli_menu(tmp_path, monkeypatch, *extra, targets="acc.example\n",
              run_it=False):
    """Drive main() WITHOUT --no-menu. run_menu is stubbed; the gates under
    test run before it is ever reached."""
    monkeypatch.setattr(app, "ALL_STAGES", (CleanStage,))
    seen = {}

    def fake_run_menu(state, prompt_fn, runner_fn):
        seen["state"] = state
        seen["acknowledgements"] = list(state.acknowledgements)
        seen["level"] = state.config.level
        if run_it:
            runner_fn(state)

    monkeypatch.setattr("sweeper.ui.menu.run_menu", fake_run_menu)
    t = tmp_path / "t.txt"; t.write_text(targets)
    rc = app.main(["--targets", str(t), "--outdir", str(tmp_path / "out"), *extra])
    if run_it:
        run_dirs = _run_dirs(tmp_path)
        if run_dirs:
            assert_coverage_property(run_dirs[0], t, requested_stage_count=1)
    return rc, seen


def test_full_level_via_menu_path_without_acknowledgement_is_refused(tmp_path, monkeypatch):
    """The case round 3 left open: no --no-menu, so the CLI gate was skipped."""
    with pytest.raises(SystemExit) as exc:
        _cli_menu(tmp_path, monkeypatch, "-l", "full")
    assert exc.value.code != 0
    assert _run_dirs(tmp_path) == [], "a run started despite the missing gate"


def test_full_level_via_menu_path_with_removed_option_is_refused(tmp_path, monkeypatch):
    with pytest.raises(SystemExit):
        _cli_menu(tmp_path, monkeypatch, "-l", "full", "--acknowledge", "nope")
    assert _run_dirs(tmp_path) == []


def test_high_level_via_menu_path_without_yes_is_refused(tmp_path, monkeypatch):
    with pytest.raises(SystemExit) as exc:
        _cli_menu(tmp_path, monkeypatch, "-l", "high")
    assert exc.value.code != 0
    assert _run_dirs(tmp_path) == []


def test_full_level_via_menu_path_seeds_the_acknowledgement_on_menu_state(tmp_path, monkeypatch):
    rc, seen = _cli_menu(tmp_path, monkeypatch, "-l", "full", "--ack")
    assert rc == 0
    assert seen["level"] == "full"
    assert len(seen["acknowledgements"]) == 1
    assert seen["acknowledgements"][0]["phrase"] == "--ack"
    assert seen["acknowledgements"][0]["via"] == "cli"


def test_acknowledgement_from_cli_survives_a_run_started_in_the_repl(tmp_path, monkeypatch):
    """The whole point: the authorisation must reach the manifest of the run."""
    rc, seen = _cli_menu(tmp_path, monkeypatch, "-l", "full", "--ack", run_it=True)
    assert rc == 0
    run_dir = _run_dirs(tmp_path)[0]
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["level"] == "full"
    assert len(manifest["acknowledgements"]) == 1
    assert manifest["acknowledgements"][0]["phrase"] == "--ack"
    assert manifest["acknowledgements"][0]["via"] == "cli"


def test_high_level_via_menu_path_with_yes_proceeds(tmp_path, monkeypatch):
    rc, seen = _cli_menu(tmp_path, monkeypatch, "-l", "high", "--yes")
    assert rc == 0
    assert seen["level"] == "high"
    assert len(seen["acknowledgements"]) == 1
    assert seen["acknowledgements"][0]["level"] == "high"
    assert seen["acknowledgements"][0]["via"] == "cli"


@pytest.mark.parametrize("level", ["low", "mid"])
def test_ordinary_levels_open_the_menu_with_no_gate_flags(tmp_path, monkeypatch, level):
    """The gates must not obstruct ordinary interactive use."""
    rc, seen = _cli_menu(tmp_path, monkeypatch, "-l", level)
    assert rc == 0
    assert seen["level"] == level
    assert seen["acknowledgements"] == []


def test_menu_opens_by_default_with_no_level_flag(tmp_path, monkeypatch):
    rc, seen = _cli_menu(tmp_path, monkeypatch)
    assert rc == 0
    assert seen["level"] == "mid"


# --- B5: a preflight target-leak must leave a record and spare the REPL -----
# preflight.run_preflight() was the one phase called OUTSIDE every try: in
# execute(), and TargetLeakInProbe is a RuntimeError that neither main() nor
# _runner catches. A stage whose build_command leaked a target therefore left
# a run directory with no run.json and no report -- indistinguishable
# afterwards from a clean, empty scan -- and killed the menu REPL with a
# traceback, discarding the operator's settings and credentials.


class LeakyStage(CleanStage):
    """Passes the real target as bare positional argv -- the nmap regression
    TargetLeakInProbe exists to catch."""
    name = "leakystage"

    def build_command(self, ctx):
        return ["/bin/echo", "acc.example"]


def _leaked_preflight(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "ALL_STAGES", (LeakyStage,))
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    with pytest.raises(SystemExit) as exc:
        app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    assert exc.value.code == 2, "a target leak must still refuse the run"
    run_dir = next((tmp_path / "out").iterdir())
    assert_coverage_property(run_dir, t, requested_stage_count=1)
    return run_dir


def test_target_leak_writes_both_manifest_and_report(tmp_path, monkeypatch):
    run_dir = _leaked_preflight(tmp_path, monkeypatch)
    assert (run_dir / "run.json").exists()
    assert (run_dir / "report.md").exists()


def test_target_leak_manifest_carries_the_reason(tmp_path, monkeypatch):
    run_dir = _leaked_preflight(tmp_path, monkeypatch)
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["aborted"] is True
    assert "leakystage" in manifest["aborted_reason"]
    assert "acc.example" in manifest["aborted_reason"]
    # No stage ran: the refusal is fail-closed, not a degraded run.
    assert manifest["stages"] == {}


def test_target_leak_in_the_menu_does_not_kill_the_repl(tmp_path, monkeypatch):
    rc, seen = _drive_menu(tmp_path, monkeypatch, "acc.example\n",
                           stage_cls=LeakyStage)
    assert rc == 0
    assert seen["level"] == "full", "operator settings were lost"


def test_an_exception_escaping_preflight_still_leaves_a_record(tmp_path, monkeypatch):
    """The general half of the same defect. TargetLeakInProbe is recorded by
    run_preflight now, but nothing about run_preflight guarantees it is the
    only thing that can raise -- EvidenceWriteInProbe still does. Whatever
    escapes, the run directory must not read afterwards as a clean empty scan.
    """
    monkeypatch.setattr(app, "ALL_STAGES", (CleanStage,))

    def boom(ctx, stages):
        raise RuntimeError("preflight exploded")

    monkeypatch.setattr(app.preflight, "run_preflight", boom)
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    # Re-raised, not swallowed: an exception here is a bug and must surface.
    with pytest.raises(RuntimeError, match="preflight exploded"):
        app.execute(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    run_dir = next((tmp_path / "out").iterdir())
    assert (run_dir / "run.json").exists(), "no run.json: the run left no record"
    assert (run_dir / "report.md").exists()
    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["aborted"] is True
    assert "preflight exploded" in manifest["aborted_reason"]
