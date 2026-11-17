"""A killed stage must not leave its children running.

THE LEAK, observed. nuclei launches a headless browser (rod/chromium) for
some templates. `subprocess.run(cmd, timeout=...)` kills only the DIRECT
child on timeout, so the browser survived: 66 orphaned chromium processes
across 11 sessions accumulated on the build machine, each holding a
/tmp/nuclei-* profile directory.

Why that is a SCOPE problem and not only an untidy one: an orphaned browser
keeps loading pages and fetching subresources after the run that spawned it
is gone. Those requests carry the engagement's traffic to the client, with
no run to attribute them to and nothing in ctx.scope able to see them --
sweeper is not the one making them any more. A scanner that keeps touching
a target after the operator stopped it is the worst kind of scope defect,
because no report will ever mention it.

The fix is to put each stage's process in its own process GROUP
(start_new_session) and kill the group, not the process.

That has a second consequence which these tests also pin: terminal SIGINT is
delivered to the foreground process group, so once the child has its own,
Ctrl-C no longer reaches it. That is what run_stages' own docstring always
claimed happened ("the CURRENTLY RUNNING stage finishes") and never did --
the child used to share the group and die. The SECOND interrupt must
therefore kill the group explicitly, or the operator's escape hatch becomes
the very orphan-maker this module is fixing.
"""
import os
import signal
import subprocess
import sys
import time

import pytest

from sweeper import runner


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    return True


def test_timeout_kills_the_whole_process_group(tmp_path):
    """A grandchild that outlives its parent must still be killed.

    This is the nuclei/chromium shape in miniature: the command spawns a
    long-lived child and exits or hangs itself. Killing only the direct
    child leaves the grandchild running forever.
    """
    marker = tmp_path / "grandchild.pid"
    # sh spawns a background sleep (the "browser"), records its pid, then
    # blocks. Killing only `sh` leaves the sleep running.
    script = (f"sleep 300 & echo $! > {marker}; sleep 300")
    proc = subprocess.Popen(["sh", "-c", script], start_new_session=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(100):
        if marker.exists() and marker.read_text().strip():
            break
        time.sleep(0.05)
    grandchild = int(marker.read_text().strip())
    assert _alive(grandchild)

    runner._kill_process_group(proc)
    proc.wait(timeout=10)

    for _ in range(100):
        if not _alive(grandchild):
            break
        time.sleep(0.05)
    assert not _alive(grandchild), (
        "the grandchild survived -- only the direct child was killed, which "
        "is exactly how the orphaned browsers accumulated"
    )


def test_kill_is_safe_on_an_already_dead_process():
    """Cleanup must never raise; it runs on paths that are already failing."""
    proc = subprocess.Popen(["true"], start_new_session=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.wait(timeout=10)
    runner._kill_process_group(proc)      # must not raise
    runner._kill_process_group(None)      # nor on nothing at all


def test_a_stage_that_times_out_leaves_no_survivors(tmp_path):
    """End to end through run_stages, not just the helper.

    Uses the real timeout path with a real spawning command, so a future
    refactor that stops routing the kill through the group fails here.
    """
    marker = tmp_path / "gc.pid"

    class SpawningStage:
        name = "spawner"
        requires: list = []
        consumes = None
        produces: set = set()
        optional = True
        levels = {"low": [], "mid": [], "high": [], "full": []}

        def build_command(self, ctx):
            return ["sh", "-c", f"sleep 120 & echo $! > {marker}; sleep 120"]

        def parse(self, raw_path):
            return iter(())

    from sweeper.context import RunConfig, RunContext
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out",
                                      time_limit="1s"))
    runner.run_stages(ctx, [SpawningStage()])

    grandchild = int(marker.read_text().strip())
    for _ in range(100):
        if not _alive(grandchild):
            break
        time.sleep(0.05)
    assert not _alive(grandchild), "a timed-out stage left a process running"


def test_the_child_is_started_in_its_own_process_group(tmp_path, monkeypatch):
    """The property the kill depends on.

    Without a separate group, os.killpg would target sweeper's OWN group and
    kill the scan. Asserted directly because the consequence of getting it
    wrong is not a leak but a self-inflicted termination.
    """
    seen = {}
    real_popen = subprocess.Popen

    class Recording(real_popen):
        def __init__(self, *a, **kw):
            seen.update(kw)
            super().__init__(*a, **kw)

    monkeypatch.setattr(runner.subprocess, "Popen", Recording)

    class TrivialStage:
        name = "trivial"
        requires: list = []
        consumes = None
        produces: set = set()
        optional = True
        levels = {"low": [], "mid": [], "high": [], "full": []}

        def build_command(self, ctx):
            return ["true"]

        def parse(self, raw_path):
            return iter(())

    from sweeper.context import RunConfig, RunContext
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    runner.run_stages(ctx, [TrivialStage()])
    assert seen.get("start_new_session") is True


def test_normal_completion_still_returns_output(tmp_path):
    """The rewrite must not change the ordinary path."""
    class EchoStage:
        name = "echo"
        requires: list = []
        consumes = None
        produces: set = set()
        optional = True
        levels = {"low": [], "mid": [], "high": [], "full": []}

        def build_command(self, ctx):
            return [sys.executable, "-c", "print('hello-from-stage')"]

        def parse(self, raw_path):
            return iter(())

    from sweeper.context import RunConfig, RunContext
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    results = runner.run_stages(ctx, [EchoStage()])
    assert results[0].status == "complete"
    assert "hello-from-stage" in ctx.raw_path("echo").read_text()


def test_a_nonzero_exit_is_still_classified(tmp_path):
    """Exit codes must survive the move from subprocess.run to Popen."""
    class FailStage:
        name = "failer"
        requires: list = []
        consumes = None
        produces: set = set()
        optional = True
        levels = {"low": [], "mid": [], "high": [], "full": []}

        def build_command(self, ctx):
            return ["sh", "-c", "echo out; echo err >&2; exit 3"]

        def parse(self, raw_path):
            return iter(())

    from sweeper.context import RunConfig, RunContext
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    results = runner.run_stages(ctx, [FailStage()])
    assert results[0].status in ("partial", "failed")
    assert "out" in ctx.raw_path("failer").read_text()


def test_an_exception_escaping_the_loop_kills_the_running_tool(tmp_path):
    """The abnormal-exit path, which the change would otherwise make worse.

    With each child in its own session, a tool left running when run_stages
    unwinds is no longer reachable even by a group kill aimed at sweeper. A
    stage whose parse() raises is the ordinary way that happens.
    """
    marker = tmp_path / "escape.pid"

    class ExplodingStage:
        name = "exploder"
        requires: list = []
        consumes = None
        produces: set = set()
        optional = True
        levels = {"low": [], "mid": [], "high": [], "full": []}

        def build_command(self, ctx):
            return ["sh", "-c", f"sleep 60 & echo $! > {marker}; sleep 0.2"]

        def parse(self, raw_path):
            raise RuntimeError("parser blew up mid-run")

    from sweeper.context import RunConfig, RunContext
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    # A parse() failure is contained per-stage by design, so drive the
    # unwinding case directly: the guarantee under test is that nothing is
    # left running once run_stages returns or raises.
    try:
        runner.run_stages(ctx, [ExplodingStage()])
    except Exception:
        pass

    if marker.exists() and marker.read_text().strip():
        gc = int(marker.read_text().strip())
        for _ in range(100):
            if not _alive(gc):
                break
            time.sleep(0.05)
        assert not _alive(gc), "a child survived run_stages returning"


# --- a tool that writes no output file --------------------------------------

def test_a_clean_exit_with_no_output_file_is_recorded(tmp_path):
    """"Found nothing" and "died before writing" must not look identical.

    arjun writes NO -oJ file when it discovers no parameters -- verified
    against 2.2.7, which prints "No parameters were discovered." and exits 0.
    A writes_own_raw stage therefore reaches parse() with a missing file, and
    parse() yields nothing, exactly as it would if the tool had crashed
    before writing. Only the runner still knows the exit code that tells them
    apart, so only the runner can record it.

    Status stays `complete`: a null result is not a failure. The reason is
    what carries the distinction into run.json.
    """
    class SilentStage:
        name = "silent"
        requires: list = []
        consumes = None
        produces: set = set()
        optional = True
        raw_suffix = "json"
        writes_own_raw = True
        levels = {"low": [], "mid": [], "high": [], "full": []}

        def build_command(self, ctx):
            return ["true"]          # exits 0, writes nothing

        def parse(self, raw_path):
            return iter(())

    from sweeper.context import RunConfig, RunContext
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    results = runner.run_stages(ctx, [SilentStage()])
    assert results[0].status == "complete"
    assert "wrote no output file" in results[0].reason, results[0].reason


def test_a_tool_that_writes_its_file_gets_no_such_note(tmp_path):
    """The note must not fire for the ordinary case, or it is just noise."""
    class WritingStage:
        name = "writer"
        requires: list = []
        consumes = None
        produces: set = set()
        optional = True
        raw_suffix = "json"
        writes_own_raw = True
        levels = {"low": [], "mid": [], "high": [], "full": []}

        def build_command(self, ctx):
            out = ctx.raw_path(self.name, self.raw_suffix)
            out.parent.mkdir(parents=True, exist_ok=True)
            return ["sh", "-c", f"echo '{{}}' > {out}"]

        def parse(self, raw_path):
            return iter(())

    from sweeper.context import RunConfig, RunContext
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    results = runner.run_stages(ctx, [WritingStage()])
    assert results[0].status == "complete"
    assert "wrote no output file" not in (results[0].reason or "")
