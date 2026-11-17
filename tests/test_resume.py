import json
import os
import signal
import sys

import pytest
from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.resume import (ResumeError, incomplete_stages, load_manifest,
                            requested_stages, restore_store, resume_run,
                            stages_to_rerun)
from sweeper.runner import run_stages
from sweeper.stages.base import Coverage, FailureClass, StageResult, is_degraded


def finished_run(tmp_path, stage_states, config=None, coverage=None,
                 collisions=()):
    t = tmp_path / "t.txt"
    if not t.exists():
        t.write_text("acc.example\n")
    ctx = RunContext.create(
        config or RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    ctx.store.add(Artifact(ArtifactKind.PORT, "acc.example:443"))
    if coverage is not None:
        ctx.coverage = coverage
    for finding in collisions:
        ctx.store.add_finding(finding)
    ctx.store.flush()
    ctx.write_manifest([
        StageResult(stage=name, status=status,
                    failure=FailureClass.NONE if status == "complete"
                    else FailureClass.TRANSPORT)
        for name, status in stage_states
    ])
    return ctx.run_dir


def test_load_manifest_reads_run_json(tmp_path):
    run = finished_run(tmp_path, [("dnsx", "complete")])
    assert load_manifest(run)["stages"]["dnsx"]["status"] == "complete"


def test_incomplete_stages_excludes_completed(tmp_path):
    run = finished_run(tmp_path, [("dnsx", "complete"), ("naabu", "failed")])
    assert incomplete_stages(load_manifest(run)) == ["naabu"]


def test_no_input_skips_are_not_resumed(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.write_manifest([StageResult(stage="httpx", status="skipped",
                                    failure=FailureClass.NO_INPUT,
                                    reason="no ports")])
    assert incomplete_stages(load_manifest(ctx.run_dir)) == []


def test_missing_binary_skips_are_resumable(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.write_manifest([StageResult(stage="naabu", status="skipped",
                                    failure=FailureClass.MISSING_BINARY,
                                    reason="absent")])
    assert incomplete_stages(load_manifest(ctx.run_dir)) == ["naabu"]


def test_interrupted_skips_are_resumable(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.write_manifest([StageResult(stage="naabu", status="skipped",
                                    failure=FailureClass.INTERRUPTED,
                                    reason="run interrupted")])
    assert incomplete_stages(load_manifest(ctx.run_dir)) == ["naabu"]


def test_interrupted_stage_result_degrades_the_run():
    results = [StageResult(stage="naabu", status="skipped",
                           failure=FailureClass.INTERRUPTED,
                           reason="run interrupted")]
    assert is_degraded(results, Coverage(stages_requested=["naabu"])) is True


def test_restore_store_reloads_artifacts(tmp_path):
    run = finished_run(tmp_path, [("dnsx", "complete")])
    t = tmp_path / "t.txt"
    fresh = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out2"))
    n = restore_store(fresh, run)
    assert n == 2
    assert "acc.example:443" in fresh.store.values(ArtifactKind.PORT)


def test_restore_from_missing_run_returns_zero(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    assert restore_store(ctx, tmp_path / "nonexistent") == 0


def test_load_manifest_raises_on_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_manifest(tmp_path / "nope")


# --- SIGINT (Fix 1): a Ctrl-C'd run must not look clean and complete -----

class _SlowFirstStage:
    """An in-process stage that sends itself SIGINT while it "runs", so the
    handler installed by run_stages fires mid-loop, exactly as a real
    Ctrl-C would between two stages."""
    name = "first"
    requires: list = []
    consumes = None
    produces = set()
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False
    in_process = True

    def run_in_process(self, ctx):
        os.kill(os.getpid(), signal.SIGINT)
        return ctx.raw_path(self.name)

    def parse(self, raw_path):
        return iter(())


class _SecondStage:
    name = "second"
    requires: list = []
    consumes = None
    produces = set()
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False
    in_process = True

    def run_in_process(self, ctx):
        return ctx.raw_path(self.name)

    def parse(self, raw_path):
        return iter(())


def test_sigint_marks_remaining_stages_interrupted(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))

    results = run_stages(ctx, [_SlowFirstStage(), _SecondStage()])

    assert results[0].status == "complete"          # already in flight, finishes
    assert results[1].status == "skipped"
    assert results[1].failure == FailureClass.INTERRUPTED
    assert ctx.aborted_reason == "interrupted by operator (SIGINT)"


def test_sigint_interrupted_run_is_degraded_and_resumable(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["first", "second"])

    results = run_stages(ctx, [_SlowFirstStage(), _SecondStage()])
    ctx.write_manifest(results)

    manifest = load_manifest(ctx.run_dir)
    assert manifest["degraded"] is True
    assert manifest["aborted"] is True
    assert incomplete_stages(manifest) == ["second"]


# --- resume_run (Fix 2) ----------------------------------------------------

#: What a fake stage's build_command returns. A real, harmless executable:
#: resume_run now runs the whole preflight, which executes every stage's
#: argument list against a dead endpoint, so a stage with no build_command
#: at all is no longer a valid stage on this path -- exactly as it is not on
#: app.execute()'s. Contains no target and no run-directory path, so
#: preflight's leak and evidence-write backstops both pass.
PROBE_ARGV = [sys.executable, "-c", ""]


class _FakeResumableStage:
    """Stands in for a real Stage in resume_run tests: monkeypatching
    sweeper.app.ALL_STAGES to just this class means resume_run only ever
    has one candidate stage to re-run, so which stage actually ran is
    unambiguous."""
    name = "fake"
    requires: list = []
    consumes = None
    produces = set()
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False
    in_process = True

    def __init__(self):
        self.ran = False

    def build_command(self, ctx):
        return list(PROBE_ARGV)

    def run_in_process(self, ctx):
        self.ran = True
        raw = ctx.raw_path(self.name)
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text("{}\n", encoding="utf-8")
        return raw

    def parse(self, raw_path):
        return iter(())


def test_resume_reruns_only_incomplete_stages(tmp_path, monkeypatch):
    ran_names = []

    class _Fake(_FakeResumableStage):
        def run_in_process(self, ctx):
            ran_names.append(self.name)
            return super().run_in_process(ctx)

    run_dir = finished_run(tmp_path, [("dnsx", "complete")])
    # Record one more, incomplete, stage on top of the "dnsx complete" manifest.
    manifest_path = run_dir / "run.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["stages"]["fake"] = {"status": "failed", "failure": "TRANSPORT",
                                  "reason": "connection reset", "artifacts": 0,
                                  "findings": 0, "duration_s": 0.0, "command": []}
    manifest_path.write_text(json.dumps(manifest))

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_Fake,))
    resumed_ctx, results = resume_run(run_dir)

    assert ran_names == ["fake"]
    statuses = {r.stage: r.status for r in results}
    assert statuses["dnsx"] == "complete"
    assert statuses["fake"] == "complete"


def test_resume_reruns_interrupted_stage(tmp_path, monkeypatch):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.write_manifest([StageResult(stage="fake", status="skipped",
                                    failure=FailureClass.INTERRUPTED,
                                    reason="run interrupted")])

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    resumed_ctx, results = resume_run(ctx.run_dir)

    assert results[0].stage == "fake"
    assert results[0].status == "complete"


def test_resume_missing_run_dir_raises_resume_error(tmp_path):
    with pytest.raises(ResumeError):
        resume_run(tmp_path / "does-not-exist")


def test_resume_corrupt_manifest_raises_resume_error(tmp_path):
    run_dir = tmp_path / "run1"
    run_dir.mkdir()
    (run_dir / "run.json").write_text("{ not json", encoding="utf-8")
    with pytest.raises(ResumeError):
        resume_run(run_dir)


def test_cli_resume_of_missing_dir_exits_nonzero_without_raising(tmp_path):
    from sweeper.app import main
    code = main(["--resume", str(tmp_path / "nope")])
    assert code != 0


# --- B6: the resume path goes through preflight ----------------------------
#
# Every test below fails against the pre-fix resume.py, which called
# run_stages() directly and so bypassed preflight entirely.


def _one_incomplete_run(tmp_path, **kwargs):
    """A run directory whose only stage, "fake", did not finish."""
    return finished_run(tmp_path, [("fake", "failed")], **kwargs)


def test_resume_preflights_exactly_the_stages_it_is_about_to_run(
        tmp_path, monkeypatch):
    seen = []
    real = __import__("sweeper.preflight", fromlist=["run_preflight"]).run_preflight

    def spy(ctx, stages):
        seen.append([s.name for s in stages])
        return real(ctx, stages)

    monkeypatch.setattr("sweeper.preflight.run_preflight", spy)
    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    resume_run(_one_incomplete_run(tmp_path))

    assert seen == [["fake"]]


def test_resume_of_an_auth_manifest_without_credentials_is_refused(
        tmp_path, monkeypatch):
    """A resume can never be handed credentials, so an auth manifest must be
    refused outright -- not silently downgraded to an anonymous scan under a
    run.json that still says auth_mode: auth."""
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    run_dir = _one_incomplete_run(
        tmp_path,
        config=RunConfig(targets_file=t, outdir=tmp_path / "out",
                         auth_mode="auth"),
    )
    ran = []

    class _Fake(_FakeResumableStage):
        def run_in_process(self, ctx):
            ran.append(self.name)
            return super().run_in_process(ctx)

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_Fake,))
    with pytest.raises(SystemExit) as exc:
        resume_run(run_dir)

    assert exc.value.code == 2
    assert ran == []                      # not one packet sent
    manifest = load_manifest(run_dir)
    assert manifest["aborted"] is True
    assert "auth mode selected but no credentials" in manifest["aborted_reason"]
    # And the stage is still recorded as unfinished, so the refusal did not
    # launder it into a completed run.
    assert incomplete_stages(manifest) == ["fake"]


def test_resume_refusal_keeps_the_original_runs_stage_results(
        tmp_path, monkeypatch):
    """execute() writes an empty manifest when preflight refuses; resume must
    not, because the file it would overwrite is the only record of the stages
    that already succeeded."""
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    run_dir = finished_run(
        tmp_path, [("dnsx", "complete"), ("fake", "failed")],
        config=RunConfig(targets_file=t, outdir=tmp_path / "out",
                         auth_mode="auth"),
    )

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    with pytest.raises(SystemExit):
        resume_run(run_dir)

    stages = load_manifest(run_dir)["stages"]
    assert stages["dnsx"]["status"] == "complete"
    assert stages["fake"]["status"] == "failed"


class _UnknownBinaryStage(_FakeResumableStage):
    """A stage whose binary cannot pass binaries.verify()'s identity check."""
    name = "fake"
    requires = ["definitely-not-a-real-binary"]


def test_resume_verifies_binary_identity_in_this_execution(
        tmp_path, monkeypatch):
    ran = []

    class _Fake(_UnknownBinaryStage):
        def run_in_process(self, ctx):
            ran.append(self.name)
            return super().run_in_process(ctx)

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_Fake,))
    _ctx, results = resume_run(_one_incomplete_run(tmp_path))

    assert ran == []
    result = {r.stage: r for r in results}["fake"]
    assert result.status == "skipped"
    assert result.failure is FailureClass.MISSING_BINARY


def test_resume_does_not_inherit_tool_versions_it_did_not_verify(
        tmp_path, monkeypatch):
    """tool_versions is evidence: a resumed stage's findings must be
    attributed to a binary THIS execution checked."""
    run_dir = _one_incomplete_run(tmp_path)
    manifest_path = run_dir / "run.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["tool_versions"] = {"naabu": "9.9.9-from-the-old-run"}
    manifest_path.write_text(json.dumps(manifest))

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_UnknownBinaryStage,))
    ctx, _results = resume_run(run_dir)

    # The re-run stage's binary failed verification, so no version was
    # recorded for it -- and nothing invented one.
    assert "definitely-not-a-real-binary" not in ctx.tool_versions
    # The carried-over entry is still there (it is real evidence for the
    # stages that already completed) but it was not treated as a check.
    assert ctx.tool_versions["naabu"] == "9.9.9-from-the-old-run"


def test_resume_restores_the_full_operator_config(tmp_path, monkeypatch):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    triage = tmp_path / "triage.json"
    original = RunConfig(
        targets_file=t, outdir=tmp_path / "out", level="high",
        rate_override=50, time_limit="45m", subdomain_enum=True,
        proxy="http://127.0.0.1:8080", verify_secrets=True,
        stages=["fake"], triage_file=triage,
    )
    run_dir = _one_incomplete_run(tmp_path, config=original)

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    ctx, _results = resume_run(run_dir)

    restored = ctx.config
    # Every field except the two resume deliberately pins to the run dir.
    assert restored.rate_override == 50            # a client no-DoS choice
    assert restored.time_limit == "45m"
    assert restored.level == "high"
    assert restored.subdomain_enum is True
    assert restored.proxy == "http://127.0.0.1:8080"
    assert restored.verify_secrets is True
    assert restored.stages == ["fake"]
    assert restored.triage_file == triage
    assert restored.targets_file == run_dir / "targets.txt"


def test_resume_restores_custom_templates_and_revalidates_them(
        tmp_path, monkeypatch):
    """custom_templates is the setting nothing else on disk records, so a
    resume that drops it silently never runs the client's own templates.
    Restored, it goes back through preflight's validation -- which refuses a
    directory that is no longer there."""
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    templates = tmp_path / "client-templates"
    templates.mkdir()
    run_dir = _one_incomplete_run(
        tmp_path,
        config=RunConfig(targets_file=t, outdir=tmp_path / "out",
                         custom_templates=str(templates)),
    )
    assert load_manifest(run_dir)["config"]["custom_templates"] == str(templates)
    templates.rmdir()

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    with pytest.raises(SystemExit):
        resume_run(run_dir)

    assert "custom template directory not found" in \
        load_manifest(run_dir)["aborted_reason"]


def test_resume_of_a_manifest_without_a_config_block_says_so(
        tmp_path, monkeypatch):
    """A run directory written by an older sweeper cannot have its operator
    settings recovered -- proceeding silently is what this fix removes."""
    run_dir = _one_incomplete_run(tmp_path)
    manifest_path = run_dir / "run.json"
    manifest = json.loads(manifest_path.read_text())
    del manifest["config"]
    manifest_path.write_text(json.dumps(manifest))

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    ctx, _results = resume_run(run_dir)

    assert any("predates full run-config persistence" in w
               for w in ctx.warnings)
    assert any("predates full run-config persistence" in w
               for w in load_manifest(run_dir)["warnings"])


# --- B6.4: downstream pure consumers of a re-run enricher ------------------

class _Enricher(_FakeResumableStage):
    """Reads the HTTP_SERVICE pool and adds to it -- katana's shape."""
    name = "enricher"
    consumes = ArtifactKind.HTTP_SERVICE
    produces = {ArtifactKind.HTTP_SERVICE}

    def parse(self, raw_path):
        return iter((Artifact(ArtifactKind.HTTP_SERVICE,
                              "https://acc.example/new",
                              meta={"host": "acc.example"}),))


class _PureConsumer(_FakeResumableStage):
    """Reads the HTTP_SERVICE pool and emits only findings -- nuclei's shape."""
    name = "consumer"
    consumes = ArtifactKind.HTTP_SERVICE
    produces = set()


def _pipeline_run(tmp_path, states):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                           meta={"host": "acc.example"}))
    ctx.store.flush()
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["enricher", "consumer"])
    ctx.write_manifest([
        StageResult(stage=name, status=status,
                    failure=FailureClass.NONE if status == "complete"
                    else FailureClass.TRANSPORT)
        for name, status in states
    ])
    return ctx.run_dir


def test_resuming_an_enricher_reruns_its_downstream_pure_consumer(
        tmp_path, monkeypatch):
    """The consumer is recorded `complete`, but it scanned a pool the
    re-running enricher can still add to. Leaving it alone is how three new
    services reached the asset inventory with nothing scanning them, under
    "All selected stages completed"."""
    run_dir = _pipeline_run(
        tmp_path, [("enricher", "failed"), ("consumer", "complete")])
    ran = []

    class _E(_Enricher):
        def run_in_process(self, ctx):
            ran.append(self.name)
            return super().run_in_process(ctx)

    class _C(_PureConsumer):
        def run_in_process(self, ctx):
            ran.append(self.name)
            return super().run_in_process(ctx)

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_E, _C))
    _ctx, _results = resume_run(run_dir)

    assert ran == ["enricher", "consumer"]


def test_a_complete_consumer_is_left_alone_when_nothing_upstream_reruns(
        tmp_path, monkeypatch):
    """The converse: invalidation must be driven by the dependency graph, not
    applied to every complete stage."""
    run_dir = _pipeline_run(
        tmp_path, [("enricher", "complete"), ("consumer", "failed")])
    ran = []

    class _E(_Enricher):
        def run_in_process(self, ctx):
            ran.append(self.name)
            return super().run_in_process(ctx)

    class _C(_PureConsumer):
        def run_in_process(self, ctx):
            ran.append(self.name)
            return super().run_in_process(ctx)

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_E, _C))
    resume_run(run_dir)

    assert ran == ["consumer"]


def test_invalidated_downstream_stages_are_recorded_as_a_warning(
        tmp_path, monkeypatch):
    run_dir = _pipeline_run(
        tmp_path, [("enricher", "failed"), ("consumer", "complete")])
    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_Enricher, _PureConsumer))
    ctx, _results = resume_run(run_dir)
    assert any("consumer" in w and "recorded them complete" in w
               for w in ctx.warnings)


def test_stages_to_rerun_matches_what_resume_actually_runs(
        tmp_path, monkeypatch):
    """The CLI seeds its progress display from this before the resume starts;
    a list that omits the invalidated stages shows rows appearing that it
    said were not running."""
    run_dir = _pipeline_run(
        tmp_path, [("enricher", "failed"), ("consumer", "complete")])
    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_Enricher, _PureConsumer))

    planned = stages_to_rerun(load_manifest(run_dir))
    _ctx, results = resume_run(run_dir)

    assert planned == ["enricher", "consumer"]
    assert planned == [r.stage for r in results]


# --- B6.5: finding_collisions survive a resume -----------------------------

def _colliding_pair(stage):
    """Two DIFFERENT findings that hash to one id (same stage/target/
    template_id/matcher, different evidence) -- see store.add_finding."""
    common = dict(stage=stage, target="acc.example", template_id="tpl",
                  matcher="m", severity="high", title="t")
    return (Finding(evidence="first", **common),
            Finding(evidence="second", **common))


def test_resume_restores_finding_collisions(tmp_path, monkeypatch):
    """A collision says the reported finding count is an UNDERCOUNT, and
    diff.py keys its undercount guard off this exact field. Only the first of
    a colliding pair is ever written to findings.jsonl, so a resume that does
    not carry the record over erases the warning permanently."""
    run_dir = _one_incomplete_run(
        tmp_path, collisions=_colliding_pair("dnsx"))
    assert len(load_manifest(run_dir)["finding_collisions"]) == 1

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    ctx, _results = resume_run(run_dir)

    assert [c["stage"] for c in ctx.store.finding_collisions] == ["dnsx"]
    assert len(load_manifest(run_dir)["finding_collisions"]) == 1


def test_collisions_of_a_rerun_stage_are_not_carried_over_and_doubled(
        tmp_path, monkeypatch):
    """The re-run stage recomputes every other number it reports; its old
    collision rows would be counted twice the moment it re-detects them."""
    run_dir = _one_incomplete_run(
        tmp_path, collisions=_colliding_pair("fake"))
    assert len(load_manifest(run_dir)["finding_collisions"]) == 1

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    ctx, _results = resume_run(run_dir)

    assert ctx.store.finding_collisions == []


def test_a_refused_resume_leaves_the_collision_record_intact(
        tmp_path, monkeypatch):
    """Nothing ran, so nothing may be subtracted from the record -- including
    the collisions held back for the stage the resume was going to re-run."""
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    run_dir = _one_incomplete_run(
        tmp_path,
        config=RunConfig(targets_file=t, outdir=tmp_path / "out",
                         auth_mode="auth"),
        collisions=_colliding_pair("fake"),
    )
    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    with pytest.raises(SystemExit):
        resume_run(run_dir)

    assert [c["stage"] for c in
            load_manifest(run_dir)["finding_collisions"]] == ["fake"]


# --- the follow-on finding: stages with no recorded result at all ----------

def test_incomplete_stages_includes_requested_stages_with_no_result(tmp_path):
    """Everything after an AbortRun, and every stage of a preflight-refused
    run, has no entry in manifest["stages"] at all. Iterating that dict alone
    made repeated --resume a no-op on exactly those runs."""
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["dnsx", "naabu", "httpx"])
    ctx.write_manifest([StageResult(stage="dnsx", status="complete")])

    manifest = load_manifest(ctx.run_dir)
    assert incomplete_stages(manifest) == ["httpx", "naabu"]
    assert requested_stages(manifest) == ["dnsx", "naabu", "httpx"]


def test_a_preflight_refused_run_records_no_stages_and_resumes_all(tmp_path):
    """The extreme case: preflight refused, so run.json has stages: {} and
    coverage.stages_requested is the only record that anything was asked
    for."""
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["dnsx", "naabu"])
    ctx.aborted_reason = "preflight failed: no targets"
    ctx.write_manifest([])

    manifest = load_manifest(ctx.run_dir)
    assert manifest["stages"] == {}
    assert incomplete_stages(manifest) == ["dnsx", "naabu"]


def test_a_stage_no_longer_in_all_stages_keeps_its_recorded_result(
        tmp_path, monkeypatch):
    """It cannot be re-run, so its old row must survive rather than vanish
    from the manifest along with the run's account of it."""
    run_dir = finished_run(tmp_path, [("retired", "failed"), ("fake", "failed")])
    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    _ctx, results = resume_run(run_dir)

    statuses = {r.stage: r.status for r in results}
    assert statuses["retired"] == "failed"
    assert statuses["fake"] == "complete"


def test_cli_resume_of_an_auth_run_exits_two_without_raising(
        tmp_path, monkeypatch):
    from sweeper.app import main
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    run_dir = _one_incomplete_run(
        tmp_path,
        config=RunConfig(targets_file=t, outdir=tmp_path / "out",
                         auth_mode="auth"),
    )
    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    assert main(["--resume", str(run_dir)]) == 2


# --- O3.1: resume must not duplicate the journal it restored ---------------
#
# restore_store() reads every artifacts/*.jsonl row back into a FRESH
# ArtifactStore whose flushed high-water marks all start at 0, and resume_run
# points that store at the SAME run directory. So without the
# ctx.store.mark_all_flushed() call the next flush() re-appends every restored
# row to the file it was just read from -- once per resume, compounding. The
# store-side half of this control is pinned in tests/test_store.py; this is
# the call site, and deleting either one on its own reproduces the bug.


def _journal_rows(run_dir):
    d = run_dir / "artifacts"
    return {p.name: len([l for l in p.read_text(encoding="utf-8").splitlines()
                         if l.strip()])
            for p in sorted(d.iterdir())}


def _run_with_one_incomplete_stage(tmp_path):
    """A finished run carrying artifacts and a finding, plus one stage that
    did not complete so there is something for the resume to re-run."""
    run_dir = finished_run(
        tmp_path, [("dnsx", "complete"), ("fake", "failed")],
        collisions=[Finding(stage="dnsx", severity="low", title="t",
                            target="acc.example", template_id="tpl")])
    return run_dir


def test_resume_does_not_duplicate_the_restored_artifact_journal(
        tmp_path, monkeypatch):
    run_dir = _run_with_one_incomplete_stage(tmp_path)
    before = _journal_rows(run_dir)
    # Not vacuous: there is something on disk that COULD be duplicated.
    assert before == {"findings.jsonl": 1, "hosts.jsonl": 1, "ports.jsonl": 1}

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    resume_run(run_dir)

    assert _journal_rows(run_dir) == before


def test_repeated_resumes_do_not_compound_the_journal(tmp_path, monkeypatch):
    """One resume doubles it; the property is that N resumes change nothing."""
    run_dir = _run_with_one_incomplete_stage(tmp_path)
    before = _journal_rows(run_dir)

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    for _ in range(3):
        # Put the stage back in the incomplete state so there is always
        # something to re-run.
        manifest_path = run_dir / "run.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["stages"]["fake"] = {"status": "failed", "failure": "TRANSPORT",
                                      "reason": "connection reset"}
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        resume_run(run_dir)

    assert _journal_rows(run_dir) == before


def test_resume_keeps_findings_stored_reconciled_with_findings_jsonl(
        tmp_path, monkeypatch):
    """The number the manifest reports and the number a reader of
    findings.jsonl counts are the same number. A duplicated journal row makes
    the file say two where the manifest -- and diff.py, which loads the same
    file -- say one."""
    run_dir = _run_with_one_incomplete_stage(tmp_path)

    monkeypatch.setattr("sweeper.app.ALL_STAGES", (_FakeResumableStage,))
    resume_run(run_dir)

    manifest = load_manifest(run_dir)
    assert _journal_rows(run_dir)["findings.jsonl"] == manifest["findings_stored"]


# --- O3.2: the two halves of run_stages' SIGINT contract that had no test --
#
# The graceful half (first Ctrl-C finishes the running stage, marks the rest
# INTERRUPTED) is covered above. These two are the ones that were unguarded:
#
#   * the escape hatch -- a SECOND Ctrl-C must raise KeyboardInterrupt
#     immediately. An operator who has decided the run must stop NOW and finds
#     Ctrl-C doing nothing twice in a row will reach for `kill -9`, and a
#     SIGKILLed run leaves raw evidence half-written, which is what the
#     graceful path exists to avoid in the first place.
#
#   * handler restoration -- run_stages installs a closure over THIS run's
#     ctx and interrupted-flag. If it is not put back, that closure outlives
#     the run: a later Ctrl-C (at the menu prompt, or during a second
#     run_stages call) is swallowed into a finished run's state instead of
#     reaching the caller, and it takes two more to get out.

def _spin_until(predicate, timeout=5.0):
    """Busy-wait so pending signal handlers get bytecode boundaries to run on.

    A bare sleep would work too, but spinning on a predicate keeps the test
    fast when the handler fires (it always does, immediately) while still
    failing loudly rather than hanging if it never does.
    """
    import time
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        pass
    return predicate()


class _DoubleInterruptStage:
    """Sends itself two SIGINTs, waiting for the first to be observed in
    between so the two are never coalesced into one delivery."""
    name = "double"
    requires: list = []
    consumes = None
    produces = set()
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False
    in_process = True

    def run_in_process(self, ctx):
        os.kill(os.getpid(), signal.SIGINT)
        assert _spin_until(lambda: bool(ctx.aborted_reason)), (
            "the FIRST SIGINT never reached run_stages' handler -- this test "
            "is not exercising what it claims to")
        os.kill(os.getpid(), signal.SIGINT)
        _spin_until(lambda: False, timeout=2.0)
        raise AssertionError(
            "the second SIGINT was swallowed: run_stages kept going instead "
            "of raising KeyboardInterrupt")

    def parse(self, raw_path):
        return iter(())


def _ctx(tmp_path, name="out"):
    t = tmp_path / "t.txt"
    if not t.exists():
        t.write_text("acc.example\n")
    return RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / name))


def test_second_sigint_raises_immediately_rather_than_being_swallowed(tmp_path):
    ctx = _ctx(tmp_path)
    with pytest.raises(KeyboardInterrupt, match="second interrupt"):
        run_stages(ctx, [_DoubleInterruptStage()])


def test_the_escape_hatch_leaves_the_first_interrupt_s_record_intact(tmp_path):
    """Bailing out immediately must not cost the operator the reason the run
    is degraded -- write_manifest and the report banner both read this."""
    ctx = _ctx(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        run_stages(ctx, [_DoubleInterruptStage()])
    assert ctx.aborted_reason == "interrupted by operator (SIGINT)"


def test_sigint_handler_is_restored_when_the_run_ends_normally(tmp_path):
    ctx = _ctx(tmp_path)
    before = signal.getsignal(signal.SIGINT)
    run_stages(ctx, [_SecondStage()])
    assert signal.getsignal(signal.SIGINT) is before


def test_sigint_handler_is_restored_when_the_run_ends_by_raising(tmp_path):
    """It is installed in a try/finally for a reason: the escape hatch exits
    run_stages by exception, and that is exactly the path after which an
    operator is most likely to hit Ctrl-C again."""
    ctx = _ctx(tmp_path)
    before = signal.getsignal(signal.SIGINT)
    with pytest.raises(KeyboardInterrupt):
        run_stages(ctx, [_DoubleInterruptStage()])
    assert signal.getsignal(signal.SIGINT) is before


def test_ctrl_c_after_a_run_reaches_the_caller_not_the_finished_run(tmp_path):
    """The behaviour, not just handler identity: a Ctrl-C delivered after
    run_stages returns must run the CALLER's handler (the menu's, in the real
    app) and must not be absorbed into the finished run's state."""
    ctx = _ctx(tmp_path)
    fired = []
    previous = signal.signal(signal.SIGINT, lambda *a: fired.append(a[0]))
    try:
        run_stages(ctx, [_SecondStage()])
        os.kill(os.getpid(), signal.SIGINT)
        assert _spin_until(lambda: bool(fired)), (
            "SIGINT after the run reached neither the caller's handler nor "
            "anything else -- it was swallowed")
    finally:
        signal.signal(signal.SIGINT, previous)

    assert fired == [signal.SIGINT]
    assert ctx.aborted_reason == "", (
        "a finished run's SIGINT closure absorbed an interrupt aimed at the "
        "caller, and marked that run aborted after the fact")
