"""A run that dies must leave the work it already did.

The manifest was written ONCE, at the end of execute(). Every exception path
wrote one too, so an abort, a failed preflight and a stage crash were all
covered -- but a process that never gets to run its handlers is not, and on
2026-08-05 that happened for real: the box ran out of memory mid-scan and
rebooted. Seven stages had completed. The run directory held every artifact
they produced, and `--resume` refused it with `no run.json`, because the one
file that says WHAT COMPLETED had never been written. The whole run was lost
and had to be redone from the first stage.

Two properties, and the second is the one that makes the first safe:

1. The manifest is rewritten after every stage, so a hard kill costs at most
   the stage that was running.
2. A checkpoint is MARKED as one. A truncated run that reads as a finished
   one is worse than no manifest at all -- it is the silent-partial-coverage
   failure this project keeps closing, promoted to the file that describes
   the whole run.

Written atomically, because the crash that motivated this can land mid-write
just as easily as between stages, and a half-written run.json is not a
smaller problem than a missing one: resume refuses a corrupt manifest too.
"""

import json

from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.runner import run_stages


class Base:
    requires = []
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def parse(self, raw_path):
        return iter(())


def ctx_for(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n", encoding="utf-8")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    return ctx


def manifest_of(ctx):
    path = ctx.run_dir / "run.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


class First(Base):
    name = "first"

    def build_command(self, ctx):
        return ["/bin/echo", "{}"]

    def parse(self, raw_path):
        yield Artifact(ArtifactKind.PORT, "acc.example:443")


class SeesTheManifest(Base):
    """Reads run.json DURING the run, which is the only way to prove the
    checkpoint happened while there was still something to lose."""
    name = "sees"
    seen = None

    def build_command(self, ctx):
        SeesTheManifest.seen = manifest_of(ctx)
        return ["/bin/echo", "{}"]


class Explodes(Base):
    """Dies in a way no handler catches -- the closest a test gets to the
    kernel killing the process."""
    name = "explodes"

    def build_command(self, ctx):
        raise KeyboardInterrupt("the box went down")


def test_a_completed_stage_is_on_disk_before_the_next_one_starts(tmp_path):
    """The defect, directly. Seven stages had completed and none of them was
    recorded anywhere a resume could read."""
    SeesTheManifest.seen = None
    ctx = ctx_for(tmp_path)

    run_stages(ctx, [First(), SeesTheManifest()])

    seen = SeesTheManifest.seen
    assert seen is not None, "no manifest existed while the run was going"
    assert "first" in seen["stages"], seen["stages"].keys()
    assert seen["stages"]["first"]["status"] == "complete"


def test_a_checkpoint_never_reads_as_a_finished_run(tmp_path):
    """The property that makes checkpointing safe rather than dangerous."""
    SeesTheManifest.seen = None
    ctx = ctx_for(tmp_path)

    run_stages(ctx, [First(), SeesTheManifest()])

    assert SeesTheManifest.seen["run_status"] == "in-progress"


def test_the_stage_that_was_running_is_the_only_thing_lost(tmp_path):
    """A kill during stage two keeps stage one's record. That is the whole
    bargain: at most one stage of work, instead of all of it."""
    ctx = ctx_for(tmp_path)

    try:
        run_stages(ctx, [First(), Explodes()])
    except KeyboardInterrupt:
        pass

    m = manifest_of(ctx)
    assert m is not None, "the run died leaving no manifest at all"
    assert m["stages"]["first"]["status"] == "complete"
    assert m["run_status"] == "in-progress"


def test_a_finished_run_says_so(tmp_path):
    """The regression guard for the marker: if every manifest is
    'in-progress', the marker means nothing and a real completion cannot be
    told from a crash."""
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [First()])
    ctx.write_manifest(results)

    assert manifest_of(ctx)["run_status"] == "finished"


def test_a_failed_write_does_not_destroy_the_last_good_manifest(tmp_path):
    """Written to a temporary file and renamed. A crash mid-write would
    otherwise turn "no manifest" into "corrupt manifest", which resume
    refuses just as firmly -- a different way to lose the same run."""
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [First()])
    ctx.write_manifest(results)
    good = manifest_of(ctx)

    class Unserialisable:
        pass

    ctx.coverage = Unserialisable()      # blows up inside json.dumps
    try:
        ctx.write_manifest(results)
    except Exception:
        pass

    assert manifest_of(ctx) == good, "a failed write damaged the manifest"
    assert not list(ctx.run_dir.glob("run.json.*")), "temp file left behind"


def test_a_checkpointed_run_can_be_resumed(tmp_path):
    """The point of all of it: the run directory the crash left behind is
    one `--resume` accepts."""
    from sweeper.resume import load_manifest, stages_to_rerun
    ctx = ctx_for(tmp_path)

    try:
        run_stages(ctx, [First(), Explodes()])
    except KeyboardInterrupt:
        pass

    m = load_manifest(ctx.run_dir)
    assert "first" not in stages_to_rerun(m), (
        "a completed stage would be scanned again on resume")
