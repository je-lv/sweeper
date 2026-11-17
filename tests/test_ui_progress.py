"""ProgressReporter: the CLI's live view of run_stages()'s on_progress hook.

Prefers asserting on the callback's rendered OUTPUT (plain text lines, ANSI
presence/absence, the state->style mapping) over rich internals (Table rows,
Live's private state), per the brief: the former survives a rich upgrade.
"""
from __future__ import annotations

import io
import json
import re

from rich.console import Console

from sweeper.ui import theme
from sweeper.ui.progress import _STATE_LABEL, _STATE_STYLE, ProgressReporter

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _console(tty: bool) -> Console:
    return Console(file=io.StringIO(), force_terminal=tty,
                   color_system="standard" if tty else None, width=100)


# --- The state table: every state runner.py actually emits, read directly
# off its _notify() call sites (runner.py:181, :184, :210, :292, :387, :396)
# rather than guessed. INTERRUPTED skips never reach _notify at all (see
# runner.py:169-172) so it is deliberately absent here.

KNOWN_RUNNER_STATES = ("running", "skipped", "failed", "complete", "partial")


def test_every_known_runner_state_has_a_style_and_a_label():
    for state in KNOWN_RUNNER_STATES:
        assert state in _STATE_STYLE, f"{state!r} has no style"
        assert state in _STATE_LABEL, f"{state!r} has no label"


def test_outcomes_use_the_theme_styles_and_skipped_recedes_from_partial():
    # Outcomes reuse theme.OK/BAD/WARN/ACCENT rather than inventing colours.
    assert _STATE_STYLE["complete"] == theme.OK
    assert _STATE_STYLE["failed"] == theme.BAD
    assert _STATE_STYLE["partial"] == theme.WARN
    assert _STATE_STYLE["running"] == theme.ACCENT
    # skipped is NOT WARN. A NO_INPUT skip is the expected downstream of an
    # upstream miss, not a fault of its own; rendered WARN-yellow, a column of
    # nine skips drowned the one red failure that needed acting on. It recedes
    # to a muted grey, still distinct from partial (a genuine WARN) and from
    # every other outcome.
    assert _STATE_STYLE["skipped"] != theme.WARN
    assert _STATE_STYLE["skipped"] != _STATE_STYLE["partial"]
    assert len({_STATE_STYLE[s] for s in
                ("complete", "failed", "partial", "skipped", "running")}) == 5


def test_a_completed_stage_is_visibly_distinct_from_skipped_failed_and_partial():
    complete_style = _STATE_STYLE["complete"]
    for degraded_state in ("skipped", "partial", "failed"):
        assert _STATE_STYLE[degraded_state] != complete_style, (
            f"{degraded_state!r} renders identically to 'complete'"
        )


# --- Every callback handles every state, and an unknown one is contained ---


def test_callback_accepts_every_known_state_without_raising():
    console = _console(tty=False)
    reporter = ProgressReporter(["dnsx", "naabu", "httpx"], console=console)
    with reporter:
        reporter("dnsx", "running")
        reporter("dnsx", "complete")
        reporter("naabu", "skipped")
        reporter("httpx", "running")
        reporter("httpx", "failed")
    # No exception -- that is the assertion. Sanity-check the rows landed.
    assert reporter._rows["dnsx"].status == "complete"
    assert reporter._rows["naabu"].status == "skipped"
    assert reporter._rows["httpx"].status == "failed"


def test_unknown_state_does_not_crash_and_freezes_the_row():
    console = _console(tty=False)
    reporter = ProgressReporter(["mystage"], console=console)
    with reporter:
        reporter("mystage", "running")
        reporter("mystage", "some-future-state")   # must not raise
    row = reporter._rows["mystage"]
    assert row.status == "some-future-state"
    # Frozen, not left ticking as if still "running".
    assert row.finished is not None


def test_unknown_state_is_still_rendered_not_silently_dropped():
    console = _console(tty=False)
    reporter = ProgressReporter(["mystage"], console=console)
    with reporter:
        reporter("mystage", "a-brand-new-state")
    out = console.file.getvalue()
    assert "mystage" in out
    assert "a-brand-new-state" in out


# --- Non-TTY: plain lines, no ANSI, no redraw -------------------------------


def test_non_tty_output_has_no_ansi_escapes():
    console = _console(tty=False)
    assert console.is_terminal is False
    reporter = ProgressReporter(["dnsx", "naabu", "httpx"], console=console)
    with reporter:
        reporter("dnsx", "running")
        reporter("dnsx", "complete")
        reporter("naabu", "skipped")
        reporter("httpx", "running")
        reporter("httpx", "failed")
    out = console.file.getvalue()
    assert not ANSI.search(out), f"escape codes leaked into piped output: {out!r}"


def test_non_tty_emits_exactly_one_line_per_state_transition():
    console = _console(tty=False)
    reporter = ProgressReporter(["dnsx"], console=console)
    with reporter:
        reporter("dnsx", "running")
        reporter("dnsx", "complete")
    lines = [l for l in console.file.getvalue().splitlines() if l.strip()]
    assert len(lines) == 2
    assert "dnsx" in lines[0] and "running" in lines[0]
    assert "dnsx" in lines[1] and "complete" in lines[1]


def test_non_tty_lines_name_the_state_distinctly_for_each_outcome():
    console = _console(tty=False)
    reporter = ProgressReporter(["a", "b", "c", "d"], console=console)
    with reporter:
        reporter("a", "complete")
        reporter("b", "skipped")
        reporter("c", "partial")
        reporter("d", "failed")
    out = console.file.getvalue()
    assert "a: complete" in out
    assert "b: skipped" in out
    assert "c: partial" in out
    assert "d: failed" in out


def test_non_tty_never_prints_a_command_or_credential():
    """Requirement 4: stage name and state only, never argv/headers."""
    console = _console(tty=False)
    reporter = ProgressReporter(["httpx"], console=console)
    with reporter:
        reporter("httpx", "running")
        reporter("httpx", "complete")
    out = console.file.getvalue()
    assert "-H" not in out
    assert "Authorization" not in out
    assert "Cookie" not in out


# --- TTY: a live redraw, and ANSI IS expected there -------------------------


def test_tty_mode_is_detected_from_the_console():
    console = _console(tty=True)
    assert console.is_terminal is True
    reporter = ProgressReporter(["dnsx"], console=console)
    assert reporter.tty is True


def test_tty_mode_does_not_use_the_plain_line_format():
    console = _console(tty=True)
    reporter = ProgressReporter(["dnsx"], console=console)
    with reporter:
        reporter("dnsx", "running")
        reporter("dnsx", "complete")
    out = console.file.getvalue()
    # The non-tty branch's format is "name: state (Xs)" -- confirms the TTY
    # branch took the Live/table path instead of also printing plain lines.
    assert "dnsx: running" not in out
    assert "dnsx: complete" not in out


def test_tty_mode_renders_with_colour():
    console = _console(tty=True)
    reporter = ProgressReporter(["dnsx"], console=console)
    with reporter:
        reporter("dnsx", "failed")
    out = console.file.getvalue()
    assert ANSI.search(out), "a real terminal should get styled output"


# --- Stage list known up front, plus graceful handling of a surprise -------


def test_planned_stages_all_start_pending():
    console = _console(tty=False)
    reporter = ProgressReporter(["dnsx", "naabu", "httpx"], console=console)
    assert [reporter._rows[n].status for n in ("dnsx", "naabu", "httpx")] == \
        ["pending"] * 3


def test_a_stage_outside_the_planned_list_is_still_shown_not_dropped():
    console = _console(tty=False)
    reporter = ProgressReporter([], console=console)
    with reporter:
        reporter("surprise", "running")
        reporter("surprise", "complete")
    assert "surprise" in reporter._order
    out = console.file.getvalue()
    assert "surprise: running" in out
    assert "surprise: complete" in out


def test_a_skip_with_no_prior_running_event_does_not_crash():
    """NO_INPUT skips (runner.py:181) go straight to 'skipped' with no
    'running' event first."""
    console = _console(tty=False)
    reporter = ProgressReporter(["naabu"], console=console)
    with reporter:
        reporter("naabu", "skipped")
    row = reporter._rows["naabu"]
    assert row.status == "skipped"
    assert row.elapsed(row.finished) is not None


# --- Refresh discipline: not per artifact -----------------------------------


def test_does_not_redraw_per_artifact_only_per_state_transition():
    """Requirement 5: refresh on state transitions, not on every artifact
    the stage happened to find. run_stages() never calls on_progress for
    individual artifacts (only for the five states above) -- this pins that
    __call__ triggers exactly one redraw per invocation, no more, with no
    hidden per-artifact hook. A real rich.live.Live also auto-refreshes on
    its own background timer, which is irrelevant to and would make a count
    against the REAL Live flaky -- so this drives the redraw call directly
    against a stand-in, not a live background thread."""
    class _FakeLive:
        def __init__(self):
            self.calls = 0

        def refresh(self):
            self.calls += 1

    console = _console(tty=True)
    reporter = ProgressReporter(["dnsx"], console=console)
    reporter._live = _FakeLive()
    reporter("dnsx", "running")
    reporter("dnsx", "complete")
    assert reporter._live.calls == 2


# --- End to end through the real CLI entry point ----------------------------


def test_cli_run_prints_progress_and_still_ends_with_done(tmp_path, monkeypatch, capsys):
    """The display must not swallow or alter the final `done -> <path>` line."""
    from sweeper import app

    class CleanStage:
        name = "cleanstage"
        requires: list = []
        consumes = app.ArtifactKind.HOST
        produces = {app.ArtifactKind.PORT}
        levels = {"low": [], "mid": [], "high": [], "full": []}
        optional = False

        def build_command(self, ctx):
            return ["/bin/echo", '{"ok":1}']

        def parse(self, raw_path):
            return iter(())

    monkeypatch.setattr(app, "ALL_STAGES", (CleanStage,))
    # rich colourises on a FORCE_COLOR/CLICOLOR_FORCE override regardless of
    # whether the stream is a terminal, and honouring those is correct
    # behaviour -- but this test asserts the PLAIN-LINE branch, so it has to
    # control what selects that branch instead of inheriting whatever the
    # developer's shell exports. Found the hard way: the suite passed all day
    # and then failed on a machine whose shell set FORCE_COLOR=3, with a
    # diff that looked like a product regression and was not.
    for var in ("FORCE_COLOR", "CLICOLOR_FORCE"):
        monkeypatch.delenv(var, raising=False)
    # theme.console is built at IMPORT time, so it has already read those
    # variables by the time this test runs -- deleting them is necessary for
    # anything constructed later but cannot un-colour the existing console.
    # no_color is what actually selects the plain branch on the instance the
    # run will use.
    # theme.console is built at IMPORT time and has already read those
    # variables, so deleting them cannot un-colour it. Replacing it is
    # cleaner than patching no_color/_force_terminal/_color_system
    # individually: no_color strips COLOUR but leaves bold, and this test is
    # about the plain branch as a whole.
    from rich.console import Console
    from sweeper.ui import theme
    monkeypatch.setattr(theme, "console",
                        Console(force_terminal=False, no_color=True,
                                color_system=None))
    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")

    rc = app.main(["--targets", str(t), "--outdir", str(tmp_path / "out"),
                   "--no-menu"])
    assert rc == 0

    out = capsys.readouterr().out
    # pytest's capsys is not a real terminal -- the plain-line branch, so no
    # ANSI leaks into captured test output either.
    assert not ANSI.search(out)
    assert "cleanstage: running" in out
    assert "cleanstage: complete" in out
    # theme.console wraps long paths across lines at its configured width,
    # so pin ordering/content rather than "the literal last line" -- "done"
    # must appear, after every progress line, and nothing progress-shaped
    # follows it.
    assert "done" in out and "→" in out
    last_progress_at = out.rindex("cleanstage: complete")
    done_at = out.rindex("done")
    assert done_at > last_progress_at, "the done output was not last"
    assert "cleanstage:" not in out[done_at:], (
        "progress output appeared after the done line"
    )

    run_dir = next((tmp_path / "out").iterdir())
    manifest = json.loads((run_dir / "run.json").read_text())
    assert manifest["stages"]["cleanstage"]["status"] == "complete"


def test_cli_run_with_a_degraded_run_shows_each_outcome_distinctly(tmp_path, monkeypatch):
    from sweeper import app

    class SkippedStage:
        name = "skipme"
        requires: list = []
        consumes = app.ArtifactKind.PORT   # never seeded -> NO_INPUT skip
        produces = {app.ArtifactKind.HTTP_SERVICE}
        levels = {"low": [], "mid": [], "high": [], "full": []}
        optional = False

        def build_command(self, ctx):
            return ["/bin/true"]

        def parse(self, raw_path):
            return iter(())

    class FailedStage:
        name = "failme"
        requires: list = []
        consumes = app.ArtifactKind.HOST
        produces = {app.ArtifactKind.PORT}
        levels = {"low": [], "mid": [], "high": [], "full": []}
        optional = False

        def build_command(self, ctx):
            return ["/bin/sh", "-c", "exit 1"]

        def parse(self, raw_path):
            return iter(())

    monkeypatch.setattr(app, "ALL_STAGES", (SkippedStage, FailedStage))
    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")

    ctx, results = app.execute(app.RunConfig(targets_file=t, outdir=tmp_path / "out"))
    statuses = {r.stage: r.status for r in results}
    assert statuses["skipme"] == "skipped"
    assert statuses["failme"] == "failed"

    # Confirm the reporter itself renders these two differently from a
    # 'complete' stage, driving it exactly the way run_stages() would.
    console = _console(tty=False)
    reporter = ProgressReporter(["skipme", "failme", "okstage"], console=console)
    with reporter:
        reporter("skipme", "skipped")
        reporter("failme", "running")
        reporter("failme", "failed")
        reporter("okstage", "running")
        reporter("okstage", "complete")
    out = console.file.getvalue()
    assert "skipme: skipped" in out
    assert "failme: failed" in out
    assert "okstage: complete" in out
