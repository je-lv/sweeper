"""A stage's tool must never inherit sweeper's stdin.

Found 2026-08-04, diagnosing what looked like a naabu flake: naabu hung and
self-aborted at its own 180-second deadline in roughly a quarter of runs, with
no output, while the identical command run by hand finished in 5 seconds.

The cause was not naabu. Every ProjectDiscovery tool reads its target list
from stdin when stdin looks like a pipe rather than a terminal -- that is how
`cat hosts.txt | httpx` works. runner.py passed no `stdin` to Popen, so the
tool inherited sweeper's. Whenever sweeper itself was launched with a pipe on
stdin -- cron, CI, a wrapper script, anything non-interactive, which is
exactly the --no-menu automation path -- the tool blocked reading a pipe that
would never deliver anything, until its internal deadline killed it.

The consequences are the ones this project cares about most: naabu produces
the PORT artifacts every later stage consumes, so the whole run comes back
empty, and it looks like a flaky tool rather than a configuration defect.

DEVNULL, not inheritance, on every child sweeper spawns. It is also the right
answer on the interactive path: a stage's tool must not be able to eat the
operator's keystrokes at the menu prompt.
"""
import os
import time

import pytest
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.runner import run_stages


@pytest.fixture
def stdin_is_an_open_pipe():
    """Replace fd 0 with a pipe nobody ever writes to.

    This is what a non-interactive launch looks like to a child process. The
    write end is deliberately held open for the whole test: close it and the
    reader gets EOF, which is the passing condition we are trying to test
    for, so the test would pass without the fix.
    """
    read_fd, write_fd = os.pipe()
    saved = os.dup(0)
    os.dup2(read_fd, 0)
    try:
        yield
    finally:
        os.dup2(saved, 0)
        for fd in (saved, read_fd, write_fd):
            try:
                os.close(fd)
            except OSError:
                pass


class ReadsStdin:
    """A stage whose tool drains stdin before doing its work.

    `cat` returns immediately on /dev/null and blocks forever on an open
    pipe -- the same behaviour that makes a ProjectDiscovery tool hang.
    """
    name = "readsstdin"
    requires = []
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def build_command(self, ctx):
        return ["/bin/sh", "-c", 'cat > /dev/null; echo \'{"ok":1}\'']

    def parse(self, raw_path):
        yield Artifact(ArtifactKind.PORT, "acc.example:443")


def test_a_stage_does_not_block_on_sweepers_stdin(tmp_path, stdin_is_an_open_pipe):
    """Without the fix this stage blocks until the time limit kills it, and
    the run records a failure that has nothing to do with the target.

    The 5s time limit is what stops a regression from hanging the suite: the
    real tools bound this with their own three-minute deadlines.
    """
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", time_limit="5s"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))

    started = time.time()
    results = run_stages(ctx, [ReadsStdin()])
    elapsed = time.time() - started

    r = next(x for x in results if x.stage == "readsstdin")
    assert r.status == "complete", (
        f"the stage inherited sweeper's stdin and blocked on it: "
        f"{r.status}/{r.failure.name} — {r.reason}"
    )
    assert elapsed < 5, f"stage blocked for {elapsed:.1f}s on inherited stdin"
    assert r.attempts == 1, "a stdin hang must not be spent on a retry too"


def test_preflight_probe_does_not_block_on_sweepers_stdin(tmp_path,
                                                          stdin_is_an_open_pipe):
    """preflight runs the real binary to check its argument list.

    It treats a timeout as "arguments accepted", so an inherited-stdin hang
    there is silent: every probe times out, every stage passes validation,
    and the run proceeds having validated nothing.
    """
    from sweeper import preflight

    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))

    started = time.time()
    preflight.validate_arguments(ReadsStdin(), ctx)
    elapsed = time.time() - started
    assert elapsed < 3, (
        f"preflight's probe blocked for {elapsed:.1f}s on inherited stdin"
    )
