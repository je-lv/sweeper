from sweeper.ui import theme


def test_every_severity_has_a_style():
    for sev in ("critical", "high", "medium", "low", "info"):
        assert sev in theme.SEVERITY_STYLE


def test_severity_styles_are_distinct():
    styles = [theme.SEVERITY_STYLE[s]
              for s in ("critical", "high", "medium", "low", "info")]
    assert len(set(styles)) == 5


def test_banner_mentions_level_and_auth_mode(tmp_path):
    from sweeper.context import RunConfig
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    cfg = RunConfig(targets_file=t, level="high", auth_mode="auth")
    rendered = theme.render_to_text(theme.banner(cfg, tmp_path / "run"))
    assert "high" in rendered
    assert "auth" in rendered
