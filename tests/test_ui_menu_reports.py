"""Menu options 8 (triage), 9 (diff) and O (open last report).

Everything here goes through `apply_choice`/`run_menu` — the operator's
actual path — rather than calling the underlying modules directly. A menu
option can be perfectly wired to a working module and still be dead (see
`test_option_8_records_a_verdict_through_main`, which is exactly that defect:
`MenuState.triage` defaults to None, so an option-8 branch that guards on it
prompts for a verdict and records nothing).
"""
import io
import json
from pathlib import Path

import pytest
from rich.console import Console

from sweeper import app
from sweeper.context import RunConfig
from sweeper.triage import STATUSES, TriageState, default_triage_path
from sweeper.ui import theme
from sweeper.ui.menu import MenuState, _latest_run_dir, apply_choice, run_menu


def state(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    s = MenuState(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    s.triage = TriageState(tmp_path / "triage.json")
    return s


@pytest.fixture
def captured(monkeypatch):
    """theme.console, redirected and made wide.

    Wide because the assertions below look for whole tokens ("[critical]",
    a run directory path) and rich wraps at 80 columns by default, which
    would split them across lines and make a passing test impossible to
    distinguish from a broken one.
    """
    sink = io.StringIO()
    monkeypatch.setattr(theme, "console", Console(file=sink, width=300,
                                                  force_terminal=False))
    return sink


# ---------------------------------------------------------------------------
# 8) Triage a finding
# ---------------------------------------------------------------------------

def test_triage_option_sets_status(tmp_path):
    s = state(tmp_path)
    answers = iter(["abc123", "false-positive", "publishable key"])
    apply_choice(s, "8", prompt_fn=lambda *a, **k: next(answers))
    assert s.triage.get("abc123") == "false-positive"
    assert s.triage.note("abc123") == "publishable key"


def test_invalid_triage_status_is_rejected_without_crashing(tmp_path):
    s = state(tmp_path)
    answers = iter(["abc123", "probably-fine", ""])
    apply_choice(s, "8", prompt_fn=lambda *a, **k: next(answers))
    assert s.triage.get("abc123") == "new"


def test_invalid_triage_status_says_so(tmp_path, captured):
    s = state(tmp_path)
    answers = iter(["abc123", "probably-fine", ""])
    apply_choice(s, "8", prompt_fn=lambda *a, **k: next(answers))
    assert "probably-fine" in captured.getvalue()


def test_triage_status_prompt_offers_exactly_what_set_accepts(tmp_path):
    """The prompt is derived from STATUSES, not retyped beside it.

    A hand-written list drifts: a status added to triage.STATUSES that the
    menu never offers is unreachable for the operator, and one offered that
    `set()` rejects is a guaranteed error message.
    """
    s = state(tmp_path)
    prompts = []

    def prompt_fn(msg=""):
        prompts.append(msg)
        return {0: "abc123"}.get(len(prompts) - 1, "")

    apply_choice(s, "8", prompt_fn=prompt_fn)
    status_prompt = next(p for p in prompts if p.lower().startswith("status"))
    for status in STATUSES:
        assert status in status_prompt


def test_triage_without_state_says_so_instead_of_silently_doing_nothing(
        tmp_path, captured):
    """The failure an operator cannot see is the one that matters.

    With no TriageState attached, option 8 can only decline. Declining
    silently — prompting for a verdict, accepting it and returning — tells
    the operator their decision was recorded when nothing was written.
    """
    s = state(tmp_path)
    s.triage = None
    assert apply_choice(s, "8", prompt_fn=lambda *a, **k: "abc123") == "continue"
    assert "triage" in captured.getvalue().lower()
    assert "unavailable" in captured.getvalue().lower()


def test_triage_save_failure_is_reported_and_keeps_the_repl(tmp_path, captured):
    """A verdict that could not be written must not look like one that was."""
    s = state(tmp_path)

    def boom(*a, **k):
        raise OSError("read-only file system")

    s.triage.save = boom
    answers = iter(["abc123", "confirmed", ""])
    assert apply_choice(s, "8", prompt_fn=lambda *a, **k: next(answers)) == "continue"
    assert "read-only file system" in captured.getvalue()
    assert "NOT" in captured.getvalue()


def test_option_8_records_a_verdict_through_main(tmp_path, monkeypatch, captured):
    """The whole feature, driven the way an operator drives it.

    `MenuState.triage` defaults to None and nothing in the plan's Task 7 sets
    it, so every unit test above can pass while option 8 does nothing at all
    for a real operator. This is the test that fails in that case.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")

    answers = iter(["8", "abc123", "accepted-risk", "signed off by client",
                    "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))

    assert app.main(["-t", str(targets), "-o", str(tmp_path / "out")]) == 0

    persisted = TriageState(home / ".sweeper" / "triage.json")
    assert persisted.get("abc123") == "accepted-risk"
    assert persisted.note("abc123") == "signed off by client"


def test_default_triage_path_is_outside_any_run_directory(tmp_path, monkeypatch):
    """Inheriting verdicts across re-scans is the point; a per-run file cannot."""
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    assert default_triage_path() == home / ".sweeper" / "triage.json"


def test_corrupt_triage_file_is_announced_at_startup(tmp_path, monkeypatch,
                                                     captured):
    """Unreadable triage state makes every finding read as untriaged.

    triage.py fails closed and says so via `load_error`; it is only useful if
    a caller surfaces it. Silently starting over means an operator re-reads
    findings they already dismissed as new ones.
    """
    home = tmp_path / "home"
    (home / ".sweeper").mkdir(parents=True)
    (home / ".sweeper" / "triage.json").write_text("{not json")
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    monkeypatch.setattr("builtins.input", lambda *a, **k: "q")

    app.main(["-t", str(targets), "-o", str(tmp_path / "out")])
    assert "triage" in captured.getvalue().lower()
    assert "untriaged" in captured.getvalue()


# ---------------------------------------------------------------------------
# 9) Diff two runs
# ---------------------------------------------------------------------------

def _run(dir_path, findings, *, complete=("nuclei",)):
    """A run directory in the shape diff.load_run reads."""
    from sweeper.artifacts import Finding
    import dataclasses

    art = Path(dir_path) / "artifacts"
    art.mkdir(parents=True)
    rows = [dataclasses.asdict(f) for f in findings]
    with (art / "findings.jsonl").open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    (Path(dir_path) / "run.json").write_text(json.dumps({
        "degraded": False, "aborted": False, "aborted_reason": "",
        "coverage": {"targets_requested": 1, "targets_permitted": 1,
                     "stages_requested": list(complete)},
        "stages": {n: {"status": "complete", "failure": "NONE", "reason": ""}
                   for n in complete},
        "findings_stored": len(rows),
        "finding_collisions": [],
    }) + "\n")
    return Path(dir_path)


def _finding(template_id, severity="critical", title=None):
    from sweeper.artifacts import Finding
    return Finding(stage="nuclei", severity=severity,
                   title=title or template_id, target="acc.example",
                   template_id=template_id)


def test_diff_option_returns_continue(tmp_path):
    s = state(tmp_path)
    answers = iter([str(tmp_path / "a"), str(tmp_path / "b")])
    assert apply_choice(s, "9", prompt_fn=lambda *a, **k: next(answers)) == "continue"


def test_diff_of_two_real_runs_reports_the_new_finding(tmp_path, captured):
    _run(tmp_path / "a", [_finding("old-issue")])
    _run(tmp_path / "b", [_finding("old-issue"), _finding("new-issue")])
    s = state(tmp_path)
    answers = iter([str(tmp_path / "a"), str(tmp_path / "b")])
    apply_choice(s, "9", prompt_fn=lambda *a, **k: next(answers))
    out = captured.getvalue()
    assert "NEW (1)" in out
    assert "new-issue" in out


def test_diff_output_keeps_its_severity_labels(tmp_path, captured):
    """render_diff emits Markdown; rich would eat it.

    `console.print("[critical] ...")` reads `[critical]` as a style tag and
    DELETES it from the output — every severity label silently vanishing
    from a comparison the operator is about to act on. Printed with markup
    disabled, the label survives.
    """
    _run(tmp_path / "a", [])
    _run(tmp_path / "b", [_finding("cve-2026-0001", severity="critical")])
    s = state(tmp_path)
    answers = iter([str(tmp_path / "a"), str(tmp_path / "b")])
    apply_choice(s, "9", prompt_fn=lambda *a, **k: next(answers))
    assert "[critical]" in captured.getvalue()


def test_diff_does_not_interpret_a_finding_title_as_console_markup(
        tmp_path, captured):
    """Finding titles are scanner output, i.e. attacker-influenced text."""
    _run(tmp_path / "a", [])
    _run(tmp_path / "b", [_finding("t1", title="banner [bold red]spoof[/]")])
    s = state(tmp_path)
    answers = iter([str(tmp_path / "a"), str(tmp_path / "b")])
    apply_choice(s, "9", prompt_fn=lambda *a, **k: next(answers))
    assert "[bold red]spoof[/]" in captured.getvalue()


def test_diff_with_an_unreadable_directory_says_so(tmp_path, captured):
    """Printing nothing is indistinguishable from "no differences"."""
    _run(tmp_path / "a", [_finding("x")])
    s = state(tmp_path)
    answers = iter([str(tmp_path / "a"), str(tmp_path / "nope")])
    assert apply_choice(s, "9", prompt_fn=lambda *a, **k: next(answers)) == "continue"
    out = captured.getvalue()
    assert "nope" in out
    assert "not run" in out.lower() or "not a run directory" in out.lower()


# ---------------------------------------------------------------------------
# _latest_run_dir
# ---------------------------------------------------------------------------

def test_latest_run_dir_picks_the_most_recent(tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir()
    (outdir / "20260101-000000").mkdir()
    (outdir / "20260102-000000").mkdir()
    assert _latest_run_dir(outdir).name == "20260102-000000"


def test_latest_run_dir_none_when_outdir_missing(tmp_path):
    assert _latest_run_dir(tmp_path / "out") is None


def test_latest_run_dir_none_when_outdir_is_empty(tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir()
    assert _latest_run_dir(outdir) is None


def test_latest_run_dir_orders_same_second_collisions_numerically(tmp_path):
    """context.new_run_dir suffixes same-second collisions -2, -3, ... -10.

    Lexicographically "...-10" sorts before "...-2", so a raw name sort hands
    the operator the second run of that second and calls it the latest.
    """
    outdir = tmp_path / "out"
    outdir.mkdir()
    for name in ("20260101-000000", "20260101-000000-2", "20260101-000000-10"):
        (outdir / name).mkdir()
    assert _latest_run_dir(outdir).name == "20260101-000000-10"


def test_latest_run_dir_ignores_directories_that_are_not_runs(tmp_path):
    """Anything else under outdir sorts against real runs by name."""
    outdir = tmp_path / "out"
    outdir.mkdir()
    (outdir / "20260101-000000").mkdir()
    (outdir / "notes-for-the-client").mkdir()
    assert _latest_run_dir(outdir).name == "20260101-000000"


def test_latest_run_dir_ignores_files(tmp_path):
    outdir = tmp_path / "out"
    outdir.mkdir()
    (outdir / "20260101-000000").mkdir()
    (outdir / "20260102-000000").write_text("not a directory")
    assert _latest_run_dir(outdir).name == "20260101-000000"


# ---------------------------------------------------------------------------
# O) Open last report
# ---------------------------------------------------------------------------

def _with_report(s, name="20260101-000000", body="<html></html>"):
    outdir = Path(s.config.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    run = outdir / name
    run.mkdir()
    (run / "report.html").write_text(body)
    return run


def test_open_report_with_no_runs_does_not_crash(tmp_path):
    s = state(tmp_path)
    assert apply_choice(s, "o", prompt_fn=lambda *a, **k: "n") == "continue"


def test_open_report_with_no_runs_says_so(tmp_path, captured):
    s = state(tmp_path)
    apply_choice(s, "o", prompt_fn=lambda *a, **k: "n")
    assert "no runs" in captured.getvalue().lower()


def test_open_report_with_no_report_html_does_not_crash(tmp_path):
    s = state(tmp_path)
    outdir = Path(s.config.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "20260101-000000").mkdir()   # a run dir, but no report.html
    assert apply_choice(s, "o", prompt_fn=lambda *a, **k: "n") == "continue"


def test_open_report_prints_the_absolute_path(tmp_path, captured):
    s = state(tmp_path)
    run = _with_report(s)
    apply_choice(s, "o", prompt_fn=lambda *a, **k: "n")
    printed = captured.getvalue()
    assert str((run / "report.html").resolve()) in printed


def test_open_report_declines_to_launch_without_confirmation(tmp_path, monkeypatch):
    s = state(tmp_path)
    _with_report(s)

    calls = []
    monkeypatch.setattr("sweeper.ui.menu.shutil.which",
                        lambda name: "/usr/bin/xdg-open")
    monkeypatch.setattr("sweeper.ui.menu.subprocess.Popen",
                        lambda *a, **k: calls.append(a))
    result = apply_choice(s, "o", prompt_fn=lambda *a, **k: "n")   # declines
    assert result == "continue"
    assert calls == []


@pytest.mark.parametrize("answer", ["", "no", "N", "later", "yes please"])
def test_open_report_launches_nothing_unless_the_answer_is_yes(
        tmp_path, monkeypatch, answer):
    """Confirmation is opt-in. Anything that is not y/yes launches nothing."""
    s = state(tmp_path)
    _with_report(s)

    calls = []
    monkeypatch.setattr("sweeper.ui.menu.shutil.which",
                        lambda name: "/usr/bin/xdg-open")
    monkeypatch.setattr("sweeper.ui.menu.subprocess.Popen",
                        lambda *a, **k: calls.append(a))
    apply_choice(s, "o", prompt_fn=lambda *a, **k: answer)
    assert calls == []


def test_open_report_launches_xdg_open_on_confirmation(tmp_path, monkeypatch):
    s = state(tmp_path)
    run = _with_report(s)

    calls = []
    monkeypatch.setattr("sweeper.ui.menu.shutil.which",
                        lambda name: "/usr/bin/xdg-open")
    monkeypatch.setattr("sweeper.ui.menu.subprocess.Popen",
                        lambda *a, **k: calls.append(a))
    apply_choice(s, "o", prompt_fn=lambda *a, **k: "y")
    assert len(calls) == 1
    assert str((run / "report.html").resolve()) in calls[0][0]


def test_open_report_without_xdg_open_does_not_crash(tmp_path, monkeypatch):
    s = state(tmp_path)
    _with_report(s)
    monkeypatch.setattr("sweeper.ui.menu.shutil.which", lambda name: None)
    result = apply_choice(s, "o", prompt_fn=lambda *a, **k: "y")
    assert result == "continue"


def test_open_report_without_xdg_open_still_prints_the_path(tmp_path, monkeypatch,
                                                            captured):
    s = state(tmp_path)
    run = _with_report(s)
    monkeypatch.setattr("sweeper.ui.menu.shutil.which", lambda name: None)
    apply_choice(s, "o", prompt_fn=lambda *a, **k: "y")
    assert str((run / "report.html").resolve()) in captured.getvalue()


def test_open_report_without_xdg_open_never_asks_to_open(tmp_path, monkeypatch):
    """No point offering a confirmation for something that cannot happen."""
    s = state(tmp_path)
    _with_report(s)
    prompts = []
    monkeypatch.setattr("sweeper.ui.menu.shutil.which", lambda name: None)
    apply_choice(s, "o", prompt_fn=lambda msg="": prompts.append(msg) or "y")
    assert not any("xdg-open" in p for p in prompts)


def test_open_report_picks_the_newest_run(tmp_path, monkeypatch):
    s = state(tmp_path)
    _with_report(s, name="20260101-000000", body="<html>old</html>")
    newest = _with_report(s, name="20260103-000000", body="<html>new</html>")

    calls = []
    monkeypatch.setattr("sweeper.ui.menu.shutil.which",
                        lambda name: "/usr/bin/xdg-open")
    monkeypatch.setattr("sweeper.ui.menu.subprocess.Popen",
                        lambda *a, **k: calls.append(a))
    apply_choice(s, "o", prompt_fn=lambda *a, **k: "y")
    assert str((newest / "report.html").resolve()) in calls[0][0]


# ---------------------------------------------------------------------------
# The menu itself
# ---------------------------------------------------------------------------

def test_menu_lists_the_new_options(tmp_path, captured):
    """Rendered through run_menu, so a stray brace in MENU fails here."""
    s = state(tmp_path)
    run_menu(s, prompt_fn=lambda *a, **k: "q", runner_fn=lambda st: None)
    out = captured.getvalue()
    assert "8) Triage a finding" in out
    assert "9) Diff two runs" in out
    assert "O) Open last report" in out


def test_run_and_quit_still_work_with_the_new_branches(tmp_path):
    s = state(tmp_path)
    assert apply_choice(s, "r", prompt_fn=lambda *a, **k: "") == "run"
    assert apply_choice(s, "q", prompt_fn=lambda *a, **k: "") == "quit"


def test_uppercase_o_reaches_the_open_report_branch(tmp_path, captured):
    """The menu prints `O)`; apply_choice lowercases before dispatch."""
    s = state(tmp_path)
    apply_choice(s, "O", prompt_fn=lambda *a, **k: "n")
    assert "no runs" in captured.getvalue().lower()
