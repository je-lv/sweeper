"""One retry for a stage that died without producing anything.

Measured 2026-08-04 against the lab: naabu 2.6.1 hung and self-aborted at its
own 180-second deadline in 4 of 16 invocations, with no output and no pattern.
naabu produces the PORT artifacts every later stage consumes, so when it dies
the whole run comes back empty -- on a live engagement, a wasted window.

The retry is deliberately narrow, because every extra attempt is more traffic
to a client's estate:

  * ONLY when the tool exited non-zero having written NOTHING. Partial output
    means the tool did work; re-running it would duplicate that work and the
    findings parsed from it.
  * NEVER when --time-limit stopped it. The operator set that bound; a retry
    would quietly spend it twice.
  * NEVER on ARG_ERROR. A rejected argument list will be rejected again, and
    it aborts the whole run anyway.
  * Exactly one extra attempt, never a loop.

`attempts` is recorded on the result so the manifest states that the target
was scanned twice. A second sweep a client cannot see in the record is
exactly the kind of silent difference this project keeps finding.
"""
from pathlib import Path

import pytest
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.runner import AbortRun, run_stages
from sweeper.stages.base import FailureClass


class Base:
    requires = []
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def parse(self, raw_path):
        return iter(())


def ctx_for(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    return ctx


def counter(tmp_path, name):
    """A shell fragment that appends one line per execution."""
    return tmp_path / f"{name}.count"


def runs(path):
    return len(path.read_text().splitlines()) if path.exists() else 0


class FlakyOnce(Base):
    """Fails with no output the first time, succeeds the second.

    This is the naabu flake in miniature: same command, same target, a
    different outcome seconds apart.
    """
    name = "flaky"

    def __init__(self, tmp_path):
        self.count = counter(tmp_path, "flaky")

    def build_command(self, ctx):
        return ["/bin/sh", "-c",
                f'echo x >> {self.count}; '
                f'if [ $(wc -l < {self.count}) -lt 2 ]; then exit 1; fi; '
                f'echo \'{{"ok":1}}\'']

    def parse(self, raw_path):
        yield Artifact(ArtifactKind.PORT, "acc.example:443")


class AlwaysDies(Base):
    name = "alwaysdies"

    def __init__(self, tmp_path):
        self.count = counter(tmp_path, "alwaysdies")

    def build_command(self, ctx):
        return ["/bin/sh", "-c", f"echo x >> {self.count}; exit 1"]


class Clean(Base):
    name = "clean"

    def __init__(self, tmp_path):
        self.count = counter(tmp_path, "clean")

    def build_command(self, ctx):
        return ["/bin/sh", "-c", f'echo x >> {self.count}; echo \'{{"ok":1}}\'']


class PartialOutput(Base):
    name = "partial"

    def __init__(self, tmp_path):
        self.count = counter(tmp_path, "partial")

    def build_command(self, ctx):
        return ["/bin/sh", "-c",
                f'echo x >> {self.count}; echo \'{{"half":1}}\'; exit 1']


class Slow(Base):
    name = "slow"

    def __init__(self, tmp_path):
        self.count = counter(tmp_path, "slow")

    def build_command(self, ctx):
        return ["/bin/sh", "-c", f"echo x >> {self.count}; sleep 30"]


class ArgError(Base):
    name = "argerror"

    def __init__(self, tmp_path):
        self.count = counter(tmp_path, "argerror")

    def build_command(self, ctx):
        return ["/bin/sh", "-c",
                f"echo x >> {self.count}; "
                "echo 'error: unknown flag --nope' >&2; exit 2"]


def only(results, name):
    return next(r for r in results if r.stage == name)


def test_a_stage_that_died_with_no_output_is_retried_and_can_succeed(tmp_path):
    stage = FlakyOnce(tmp_path)
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [stage])
    r = only(results, "flaky")
    assert runs(stage.count) == 2, "the failed attempt was not retried"
    assert r.status == "complete", r.reason
    assert r.attempts == 2


def test_the_retry_is_a_single_attempt_not_a_loop(tmp_path):
    stage = AlwaysDies(tmp_path)
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [stage])
    r = only(results, "alwaysdies")
    assert runs(stage.count) == 2, "expected exactly one retry"
    assert r.status == "failed"
    assert r.failure is FailureClass.TRANSPORT
    assert r.attempts == 2


def test_a_stage_that_works_first_time_is_run_once(tmp_path):
    stage = Clean(tmp_path)
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [stage])
    assert runs(stage.count) == 1
    assert only(results, "clean").attempts == 1


def test_partial_output_is_never_retried(tmp_path):
    """The tool did work. Re-running duplicates the traffic that produced it,
    and the findings parsed from the first attempt are already real."""
    stage = PartialOutput(tmp_path)
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [stage])
    r = only(results, "partial")
    assert runs(stage.count) == 1, "a stage with output must not be re-run"
    assert r.status == "partial"
    assert r.attempts == 1


def test_a_time_limited_stage_is_never_retried(tmp_path):
    """--time-limit is the operator's bound, often a client's engagement
    term. Retrying would spend it twice."""
    stage = Slow(tmp_path)
    ctx = ctx_for(tmp_path, time_limit="1s")
    results = run_stages(ctx, [stage])
    r = only(results, "slow")
    assert runs(stage.count) == 1, "a time-limited stop must not be retried"
    assert r.attempts == 1
    assert "time limit" in r.reason


def test_an_argument_error_is_never_retried(tmp_path):
    """It will be rejected identically, and it aborts the run regardless."""
    stage = ArgError(tmp_path)
    ctx = ctx_for(tmp_path)
    with pytest.raises(AbortRun):
        run_stages(ctx, [stage])
    assert runs(stage.count) == 1


def test_the_manifest_records_that_the_target_was_scanned_twice(tmp_path):
    """A second sweep of a client's estate that the record does not show is
    the kind of silent difference this project exists to surface."""
    import json
    stage = FlakyOnce(tmp_path)
    ctx = ctx_for(tmp_path)
    results = run_stages(ctx, [stage])
    ctx.write_manifest(results)
    data = json.loads((ctx.run_dir / "run.json").read_text())
    assert data["stages"]["flaky"]["attempts"] == 2
