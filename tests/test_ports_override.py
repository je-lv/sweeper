"""--ports: operator control over which ports naabu actually scans.

The precondition for a live `high` run is to confirm IP ownership or restrict
the port range before scanning. Until this flag existed, the second option was
impossible because naabu's selection was hardcoded
per level, so the only way to narrow `high` was to stop running `high`.

It matters because scope is enforced per HOST while services are host:PORT.
An all-ports scan of an authorised name reaches every service bound to that
name's IP; on shared hosting that can include services the client does not
own, and since no off-scope HOSTNAME is ever resolved, the scope guard has
nothing to refuse. See tests/test_scope.py for the half that guard does cover.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from sweeper import app
from sweeper.context import RunConfig, RunContext
from sweeper.profile import load_profile, save_profile
from sweeper.report.markdown import render_markdown


def base_args(tmp_path, *extra):
    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")
    return ["--targets", str(t), "--outdir", str(tmp_path / "out"),
            "--no-menu", "--stages", "dnsx", *extra]


def config_from(monkeypatch, argv):
    """Run main() far enough to capture the RunConfig it builds."""
    captured = {}

    def fake_execute(config, *a, **kw):
        captured["config"] = config
        return SimpleNamespace(run_dir=Path("/dev/null")), []

    monkeypatch.setattr(app, "execute", fake_execute)
    app.main(argv)
    return captured["config"]


# --- The flag reaches the config ------------------------------------------

def test_a_top_n_selection_reaches_the_config(tmp_path, monkeypatch):
    cfg = config_from(monkeypatch, base_args(tmp_path, "--ports", "top-100"))
    assert cfg.ports == "top-100"


def test_an_explicit_port_list_reaches_the_config(tmp_path, monkeypatch):
    cfg = config_from(monkeypatch, base_args(tmp_path, "--ports", "80,443,8443"))
    assert cfg.ports == "80,443,8443"


def test_the_default_is_empty_meaning_the_levels_own_selection(tmp_path, monkeypatch):
    cfg = config_from(monkeypatch, base_args(tmp_path))
    assert cfg.ports == ""
    assert cfg.udp_ports == ""


def test_a_udp_selection_reaches_the_config(tmp_path, monkeypatch):
    cfg = config_from(monkeypatch, base_args(tmp_path, "--udp-ports", "53,161"))
    assert cfg.udp_ports == "53,161"


# --- Validation happens at argument time, before anything is sent ----------

@pytest.mark.parametrize("value", [
    "abc",            # not a port specification at all
    "top100",         # the shorthand without its separator
    "top-0",          # there is no port 0
    "top-70000",      # more ports than exist
    "top-",           # no count
    "80;443",         # wrong separator -- naabu would read one odd port
    "0",              # ports start at 1
    "65536",          # ports end at 65535
    "9000-80",        # descending range
    "80-",            # half a range
    "-443",           # half a range
    "80,,443",        # empty element
    "",               # explicitly asking for nothing
])
def test_a_port_specification_that_is_not_one_is_refused(tmp_path, value):
    """Refused at parse time, not discovered once naabu is already running.

    Two distinct failures are being prevented. A value naabu REJECTS becomes
    a stage-level ARG_ERROR partway into a run that has already started
    writing evidence. A value naabu ACCEPTS under a meaning the operator did
    not intend -- `80;443` is one -- scans something other than what was
    authorised, and nothing anywhere reports that it did.
    """
    with pytest.raises(SystemExit):
        app.main(base_args(tmp_path, "--ports", value))


@pytest.mark.parametrize("value", [
    "top-1", "top-100", "top-1000", "top-65535",
    "80", "1-65535", "80,443", "80,443,8443", "1-1024",
    "80,443,8000-9000", "8000-9000,80",
])
def test_well_formed_port_specifications_are_accepted(tmp_path, monkeypatch, value):
    cfg = config_from(monkeypatch, base_args(tmp_path, "--ports", value))
    assert cfg.ports == value


def test_malformed_udp_port_specification_is_refused(tmp_path):
    with pytest.raises(SystemExit):
        app.main(base_args(tmp_path, "--udp-ports", "top100"))


# --- It must survive a resume ---------------------------------------------

def test_a_profile_round_trip_preserves_the_restriction(tmp_path):
    """A reloaded profile that quietly reverted to 65535 ports would be
    exactly the failure this flag exists to prevent."""
    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")
    cfg = RunConfig(targets_file=t, outdir=tmp_path / "out", level="high",
                    ports="top-100")
    p = save_profile(cfg, tmp_path / "x.profile")
    assert load_profile(p).ports == "top-100"


def test_a_profile_round_trip_preserves_udp_restriction(tmp_path):
    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")
    cfg = RunConfig(targets_file=t, outdir=tmp_path / "out",
                    udp_ports="top-100")
    assert load_profile(save_profile(cfg, tmp_path / "u.profile")).udp_ports == "top-100"


def test_a_manifest_round_trip_preserves_the_restriction(tmp_path):
    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")
    cfg = RunConfig(targets_file=t, outdir=tmp_path / "out", level="high",
                    ports="80,443")
    restored = RunConfig.from_manifest(cfg.to_manifest(),
                                       targets_file=t, outdir=tmp_path / "out")
    assert restored.ports == "80,443"


# --- A restricted scan must not read as an exhaustive one -----------------

def report_ctx(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw))


def test_the_report_names_the_restriction_in_its_coverage_section(tmp_path):
    """Same principle as `stopped at the 20m time limit`: a bounded scan
    states its bound, so the findings list cannot be read as everything
    there was to find."""
    md = render_markdown(report_ctx(tmp_path, level="high", ports="top-100"), [])
    coverage = md[md.index("## Coverage"):]
    assert "top-100" in coverage
    assert "port" in coverage.lower()


def test_an_unrestricted_run_claims_no_port_restriction(tmp_path):
    md = render_markdown(report_ctx(tmp_path, level="high"), [])
    coverage = md[md.index("## Coverage"):]
    assert "restricted" not in coverage.lower()


def test_the_html_report_names_the_restriction_too(tmp_path):
    """The HTML report is the one the design spec designates for handing to
    the client, and the one the menu's `o` key opens. A caveat present only
    in report.md is absent from the document the engagement is discussed
    over."""
    from sweeper.report.html import render_html
    html = render_html(report_ctx(tmp_path, level="high", ports="top-100"), [])
    assert "top-100" in html


def test_reports_name_udp_restriction(tmp_path):
    ctx = report_ctx(tmp_path, udp_ports="53,161")
    md = render_markdown(ctx, [])
    assert "UDP ports:** restricted" in md
    from sweeper.report.html import render_html
    assert "UDP ports:" in render_html(ctx, [])


# --- Menu parity ----------------------------------------------------------
# A control reachable through only one of two entry points is not a control:
# this repo has already fixed that defect for --rate/--time-limit (060f3aa)
# and for authenticated scanning (8f81eef).

def test_the_menu_can_set_a_port_restriction(tmp_path):
    from sweeper.ui.menu import MenuState, apply_choice
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    s = MenuState(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    answers = iter(["", "", "top-100", "", "", ""])
    apply_choice(s, "6", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.ports == "top-100"


def test_the_menu_refuses_a_malformed_port_restriction(tmp_path):
    """Left unvalidated, a typo here reaches naabu as an ARG_ERROR and
    aborts the run -- from the one entry point where the operator is sitting
    right there and could have been told."""
    from sweeper.ui.menu import MenuState, apply_choice
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    s = MenuState(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    answers = iter(["", "", "top100", "", "", ""])
    apply_choice(s, "6", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.ports == ""


# --- The confirmation must describe the scan actually about to run --------

def test_the_high_gate_stops_claiming_65535_ports_when_narrowed(tmp_path):
    """`high` asks "runs a full 65535-port sweep. Proceed?" -- which is
    false once --ports narrows it, and false in the direction that makes the
    operator refuse a scan they authorised, or distrust the prompt."""
    from sweeper.ui.menu import MenuState, gate_level
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    s = MenuState(RunConfig(targets_file=t, outdir=tmp_path / "out",
                            ports="top-100"))
    seen = []

    def prompt(text):
        seen.append(text)
        return "y"

    assert gate_level(s, "high", prompt) is True
    assert "top-100" in seen[0]
    assert "65535" not in seen[0]


def test_the_cli_high_gate_describes_the_narrowed_scan(tmp_path, capsys):
    """The CLI's refusal message is the menu prompt's counterpart, and was
    overstating the same scan."""
    with pytest.raises(SystemExit):
        app.main(base_args(tmp_path, "--level", "high", "--ports", "top-100"))
    err = capsys.readouterr().err
    assert "top-100" in err
    assert "65535" not in err


def test_the_high_gate_still_says_65535_when_not_narrowed(tmp_path):
    from sweeper.ui.menu import MenuState, gate_level
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    s = MenuState(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    seen = []
    gate_level(s, "high", lambda text: (seen.append(text), "y")[1])
    assert "65535" in seen[0]
