"""The progress display shows what a watching operator has to act on.

Everything here comes from something that was invisible during a live run
this week:

  - katana went `partial` and the table said only "partial". The reason --
    killed by the kernel, not by sweeper -- reached run.json and the report,
    both read after the run was over.
  - the machine filled up and nothing said so until the OOM killer fired.
  - a stage that had finished showed no counts, so "did that find anything"
    meant waiting for the report.
  - scope refusals accumulated silently; a run that is refusing hundreds of
    discoveries looks identical to one refusing none.

BINDING, not a wider callback. The (name, state) callback stays exactly as
it is, and the reporter is instead handed the ctx and the results list the
runner already mutates in place. That keeps every existing caller and test
working, and means a run driven WITHOUT binding renders exactly as before
rather than crashing on missing data.
"""

import io

import pytest
from rich.console import Console

from sweeper.stages.base import StageResult
from sweeper.ui.progress import ProgressReporter


def _console(width=100):
    return Console(file=io.StringIO(), force_terminal=True, width=width,
                   color_system=None)


def _text(reporter, console):
    console.print(reporter._render())
    return console.file.getvalue()


class _FakeScope:
    def __init__(self, n=0):
        self.refusals = [{"target": f"h{i}", "normalized": f"h{i}"}
                         for i in range(n)]


class _FakeCtx:
    def __init__(self, refusals=0, level="high", auth_mode="unauth"):
        self.scope = _FakeScope(refusals)

        class _C:
            pass
        self.config = _C()
        self.config.level = level
        self.config.auth_mode = auth_mode


def test_an_unbound_reporter_renders_exactly_as_before():
    """A caller that never binds -- every existing test, and any future
    direct user of ProgressReporter -- must not crash or show blanks where
    counts would be."""
    c = _console()
    r = ProgressReporter(["dnsx", "naabu"], console=c)

    out = _text(r, c)

    assert "dnsx" in out and "naabu" in out


def test_a_finished_stage_shows_what_it_produced():
    c = _console()
    r = ProgressReporter(["dnsx"], console=c)
    results = [StageResult(stage="dnsx", status="complete",
                           artifacts=2, findings=7)]
    r.bind(results=results)
    r("dnsx", "complete")

    out = _text(r, c)

    assert "2" in out and "7" in out


def test_the_reason_a_stage_stopped_early_is_on_screen():
    """The live-run defect: `partial` with no explanation until the report.
    An operator watching the run is the person who can still act on it."""
    c = _console()
    r = ProgressReporter(["katana"], console=c)
    results = [StageResult(stage="katana", status="partial", artifacts=2824,
                           reason="killed by SIGKILL with partial output — "
                                  "the system killed this stage")]
    r.bind(results=results)
    r("katana", "partial")

    out = _text(r, c)

    assert "SIGKILL" in out


def test_a_completed_stage_does_not_get_a_reason_line():
    """Only the stages that need explaining get the extra row; otherwise the
    table doubles in height for nothing."""
    c = _console()
    r = ProgressReporter(["dnsx"], console=c)
    r.bind(results=[StageResult(stage="dnsx", status="complete", artifacts=2)])
    r("dnsx", "complete")

    assert "└" not in _text(r, c)


def test_memory_headroom_is_shown():
    c = _console()
    r = ProgressReporter(["dnsx"], console=c)
    r.bind(reading=(2 * 1024**3, 16 * 1024**3))

    out = _text(r, c)

    assert "mem" in out.lower()
    assert "16" in out, "the total the operator is measuring against is missing"


def test_a_machine_that_cannot_report_memory_shows_no_gauge():
    """Non-Linux, or a container without /proc. A blank is honest; a zero
    would read as "no memory left" and a 100% would read as "plenty"."""
    c = _console()
    r = ProgressReporter(["dnsx"], console=c)
    r.bind(reading=None)

    assert "mem" not in _text(r, c).lower()


@pytest.mark.parametrize("used_fraction,expect_alarm", [(0.5, False), (0.93, True)])
def test_the_gauge_changes_appearance_under_pressure(used_fraction, expect_alarm):
    """A number alone is not a warning -- nobody watching a table does
    arithmetic. Near the ceiling it has to LOOK different."""
    total = 16 * 1024**3
    c = _console()
    r = ProgressReporter(["dnsx"], console=c)
    r.bind(reading=(int(total * (1 - used_fraction)), total))

    assert ("LOW" in _text(r, c)) is expect_alarm


def test_scope_refusals_are_visible_while_they_happen():
    """A run refusing hundreds of discoveries looks identical to one
    refusing none, and the difference is the whole scope-safety story."""
    c = _console()
    r = ProgressReporter(["katana"], console=c)
    r.bind(ctx=_FakeCtx(refusals=659))

    assert "659" in _text(r, c)


def test_the_header_names_the_run():
    c = _console()
    r = ProgressReporter(["dnsx"], console=c)
    r.bind(ctx=_FakeCtx(level="high", auth_mode="auth"))

    out = _text(r, c)

    assert "high" in out and "auth" in out


def test_binding_never_lets_a_display_error_kill_the_run():
    """A progress display that raises takes down the scan it is describing,
    which is a strictly worse outcome than a wrong-looking table."""
    class Hostile:
        @property
        def scope(self):
            raise RuntimeError("boom")

    c = _console()
    r = ProgressReporter(["dnsx"], console=c)
    r.bind(ctx=Hostile())

    _text(r, c)   # must not raise


def test_the_non_tty_path_still_prints_one_plain_line_per_transition():
    """cron and CI read this. It must stay one durable line, with no ANSI
    and no redraw -- the regression guard for the dense table leaking into
    the piped path."""
    c = Console(file=io.StringIO(), force_terminal=False, width=100)
    r = ProgressReporter(["dnsx"], console=c)
    r.bind(results=[StageResult(stage="dnsx", status="complete", artifacts=2,
                                findings=7)])
    r("dnsx", "complete")

    out = c.file.getvalue()
    assert out.count("\n") == 1, out
    assert "\x1b[" not in out


def test_a_long_reason_does_not_widen_the_whole_table():
    """The reason is a summary here; sweep.log and the report carry it in
    full. Left unbounded it becomes the longest cell in the grid, stretches
    the name column for every row, and wraps mid-sentence."""
    c = _console(width=86)
    r = ProgressReporter(["katana"], console=c)
    r.bind(results=[StageResult(
        stage="katana", status="partial", artifacts=2824,
        reason="killed by SIGKILL with partial output — the system killed "
               "this stage, sweeper did not. The usual cause is the kernel "
               "running out of memory; confirm with: journalctl -k")])
    r("katana", "partial")

    lines = [ln.rstrip() for ln in _text(r, c).splitlines() if ln.strip()]
    assert all(len(ln) <= 86 for ln in lines), lines
    reason_lines = [ln for ln in lines if "SIGKILL" in ln]
    assert len(reason_lines) == 1, f"reason wrapped across rows: {reason_lines}"


def test_the_counts_are_labelled_inline_per_row():
    """Two bare numbers per row is a puzzle. The redesign drops the header row
    (nothing to scroll back to on a long list) and labels each count where it
    sits: artifacts as `Na`, findings as `Nf`, so every row self-describes."""
    c = _console()
    r = ProgressReporter(["dnsx"], console=c)
    r.bind(results=[StageResult(stage="dnsx", status="complete", artifacts=2,
                                findings=7)])
    r("dnsx", "complete")

    out = _text(r, c)
    assert "2a" in out, "artifact count is not labelled"
    assert "7f" in out, "finding count is not labelled"
