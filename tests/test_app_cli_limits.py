"""--time-limit and --rate on the CLI, not only on the menu.

Both fields existed on RunConfig, were persisted to run.json, were restored
by --resume, and could be set from exactly one place: the interactive menu.
An operator running --no-menu -- the automation path, and the one used by
anything scripted -- could set neither.

app.py already states the rule this broke, about the level gates: a control
reachable through only one of two entry points is not a control. --rate is
the client's no-DoS rules-of-engagement term (see stages/naabu.py), and
--time-limit is the ONLY bound on a stage's runtime, which otherwise has no
default at all.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from sweeper import app


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
        # execute() returns (ctx, results); main unpacks it and prints
        # ctx.run_dir. A bare 0 makes main die on the unpack, which would
        # fail these tests for a reason that has nothing to do with flags.
        return SimpleNamespace(run_dir=Path("/dev/null")), []

    monkeypatch.setattr(app, "execute", fake_execute)
    app.main(argv)
    return captured["config"]


def test_time_limit_reaches_the_config(tmp_path, monkeypatch):
    cfg = config_from(monkeypatch, base_args(tmp_path, "--time-limit", "45m"))
    assert cfg.time_limit == "45m"


def test_rate_reaches_the_config(tmp_path, monkeypatch):
    cfg = config_from(monkeypatch, base_args(tmp_path, "--rate", "25"))
    assert cfg.rate_override == 25


def test_defaults_are_unchanged_when_neither_is_given(tmp_path, monkeypatch):
    cfg = config_from(monkeypatch, base_args(tmp_path))
    assert cfg.time_limit == ""
    assert cfg.rate_override == 0


@pytest.mark.parametrize("value", ["45", "abc", "m", "45 minutes", "-5m"])
def test_a_time_limit_with_no_usable_unit_is_refused(tmp_path, value):
    """runner._timeout IGNORES a malformed value and applies no limit.

    That is right for a value arriving from an old profile mid-run, and
    wrong for one just typed: `--time-limit 45` would run completely
    unbounded while the operator believed they had capped it. Refuse at
    argument time instead.
    """
    with pytest.raises(SystemExit):
        app.main(base_args(tmp_path, "--time-limit", value))


@pytest.mark.parametrize("value", ["45s", "45m", "2h", "90S"])
def test_well_formed_time_limits_are_accepted(tmp_path, monkeypatch, value):
    cfg = config_from(monkeypatch, base_args(tmp_path, "--time-limit", value))
    assert cfg.time_limit == value


def test_a_negative_rate_is_refused(tmp_path):
    with pytest.raises(SystemExit):
        app.main(base_args(tmp_path, "--rate", "-1"))


def test_the_cli_value_actually_bounds_a_stage(tmp_path, monkeypatch):
    """The config field is only useful if runner._timeout reads it.

    Without this the test above passes for a flag that is stored and never
    consulted -- a setting that reports itself as applied while changing
    nothing, which is the defect class this project keeps finding.
    """
    from sweeper import runner
    cfg = config_from(monkeypatch, base_args(tmp_path, "--time-limit", "45m"))
    ctx = type("Ctx", (), {"config": cfg, "log": lambda self, m: None})()
    assert runner._timeout(ctx) == 45 * 60
