import dataclasses

import pytest
import yaml
from pathlib import Path
from sweeper.context import RunConfig
from sweeper.profile import ProfileError, save_profile, load_profile, list_profiles


def make_cfg(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunConfig(targets_file=t, outdir=tmp_path / "out", level="high",
                     auth_mode="auth", stages=["dnsx", "naabu"], proxy="http://127.0.0.1:8080")


def test_roundtrip_preserves_fields(tmp_path):
    cfg = make_cfg(tmp_path)
    p = save_profile(cfg, tmp_path / "acc.profile")
    back = load_profile(p)
    assert back.level == "high"
    assert back.auth_mode == "auth"
    assert back.stages == ["dnsx", "naabu"]
    assert back.proxy == "http://127.0.0.1:8080"
    assert back.targets_file == cfg.targets_file


def test_profile_is_yaml_text(tmp_path):
    p = save_profile(make_cfg(tmp_path), tmp_path / "acc.profile")
    assert "level: high" in p.read_text()


def test_list_profiles_finds_saved(tmp_path):
    save_profile(make_cfg(tmp_path), tmp_path / "a.profile")
    save_profile(make_cfg(tmp_path), tmp_path / "b.profile")
    assert {p.name for p in list_profiles(tmp_path)} == {"a.profile", "b.profile"}


def test_load_rejects_unknown_level(tmp_path):
    p = tmp_path / "bad.profile"
    p.write_text("targets_file: /tmp/t.txt\nlevel: apocalyptic\n")
    with pytest.raises(ProfileError, match="level"):
        load_profile(p)


def test_load_rejects_unknown_auth_mode(tmp_path):
    p = tmp_path / "bad.profile"
    p.write_text("targets_file: /tmp/t.txt\nauth_mode: telepathy\n")
    with pytest.raises(ProfileError, match="auth_mode"):
        load_profile(p)


# --- Any failure to load a profile is ONE kind of thing --------------------
# A YAML syntax error, a scalar or list-valued document, a missing required
# key -- each used to raise a different exception type, and a caller that
# enumerated the types it expected always missed one. All five must raise
# exactly ProfileError.


def test_broken_yaml_syntax_raises_profile_error(tmp_path):
    p = tmp_path / "bad.profile"
    p.write_text("targets_file: [unterminated\n  level: mid\n")
    with pytest.raises(ProfileError):
        load_profile(p)


def test_scalar_profile_raises_profile_error(tmp_path):
    p = tmp_path / "bad.profile"
    p.write_text("just a plain scalar string\n")
    with pytest.raises(ProfileError):
        load_profile(p)


def test_list_valued_targets_file_raises_profile_error(tmp_path):
    p = tmp_path / "bad.profile"
    p.write_text("targets_file: [a, b]\n")
    with pytest.raises(ProfileError):
        load_profile(p)


def test_missing_targets_file_key_raises_profile_error(tmp_path):
    p = tmp_path / "bad.profile"
    p.write_text("level: mid\n")
    with pytest.raises(ProfileError):
        load_profile(p)


def test_profile_error_names_the_path_and_keeps_the_cause(tmp_path):
    """A reader following the traceback must be able to see both what path
    failed to load AND the real underlying problem, not just "ProfileError"
    with no further information."""
    p = tmp_path / "bad.profile"
    p.write_text("targets_file: [unterminated\n")
    with pytest.raises(ProfileError) as exc_info:
        load_profile(p)
    assert str(p) in str(exc_info.value)
    assert exc_info.value.__cause__ is not None


# --- Relative paths must not silently reload against a different CWD -------
# save_profile wrote paths as given: a relative targets_file/outdir would
# reload relative to the CWD at LOAD time, not the CWD it was SAVED from.
# outdir defaults to the relative Path("recon/sweeper"), so a profile saved
# in one directory and loaded from another silently writes scan output
# somewhere else entirely -- a scan-output integrity problem, not a
# portability nicety.


def test_relative_paths_are_resolved_to_absolute_on_save(tmp_path, monkeypatch):
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    t = workdir / "targets.txt"
    t.write_text("acc.example\n")
    monkeypatch.chdir(workdir)

    cfg = RunConfig(targets_file=Path("targets.txt"), outdir=Path("recon/sweeper"))
    p = save_profile(cfg, tmp_path / "rel.profile")
    data = yaml.safe_load(p.read_text())

    assert Path(data["targets_file"]).is_absolute()
    assert Path(data["outdir"]).is_absolute()
    assert Path(data["targets_file"]) == (workdir / "targets.txt").resolve()
    assert Path(data["outdir"]) == (workdir / "recon" / "sweeper").resolve()


def test_relative_profile_reloads_correctly_from_a_different_cwd(tmp_path, monkeypatch):
    """The end-to-end case the bug produced: save here, load from elsewhere."""
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    t = workdir / "targets.txt"
    t.write_text("acc.example\n")
    monkeypatch.chdir(workdir)
    cfg = RunConfig(targets_file=Path("targets.txt"), outdir=Path("out"))
    p = save_profile(cfg, tmp_path / "rel2.profile")

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    back = load_profile(p)

    assert back.targets_file == (workdir / "targets.txt").resolve()
    assert back.outdir == (workdir / "out").resolve()


def test_save_profile_refuses_to_silently_drop_an_unpersisted_field(tmp_path):
    """The runtime half of the round-trip guard, with a test that can fail.

    test_every_runconfig_field_survives_a_round_trip catches an unpersisted
    field in CI. This pins the guard inside save_profile itself, so removing
    that guard is a test failure rather than a silent return to the
    behaviour that dropped preflight_timeout and then resolver. Without a
    test here the guard is unfalsifiable -- it would still "pass" if the
    check were deleted, because every real field IS currently persisted.
    """
    @dataclasses.dataclass
    class ExtendedConfig(RunConfig):
        a_field_nobody_persisted: str = "x"

    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    dest = tmp_path / "unwritten.profile"
    with pytest.raises(ProfileError, match="a_field_nobody_persisted"):
        save_profile(ExtendedConfig(targets_file=t), dest)
    assert not dest.exists(), (
        "the guard must fire BEFORE the file is written, or a half-correct "
        "profile is left on disk for the next load to pick up"
    )


def test_every_runconfig_field_survives_a_round_trip(tmp_path):
    """Driven by dataclasses.fields, so a new RunConfig field fails here
    rather than being silently dropped on reload."""
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    cfg = RunConfig(
        targets_file=t, outdir=tmp_path / "out", level="high", auth_mode="auth",
        stages=["dnsx", "naabu"], proxy="http://127.0.0.1:8080",
        user_agent="Mozilla/5.0 fixed-profile-agent",
        rate_override=999, ports="top-100", udp_ports="53,161",
        resolver_fallback=False,
        time_limit="45m", subdomain_enum=True,
        preflight_timeout=7.5, verify_secrets=True,
        custom_templates="/opt/custom-templates",
        triage_file=tmp_path / "custom-triage.json",
        resolver="10.0.0.53:5353",
        content_wordlists="/opt/words-a.txt,/opt/words-b.txt",
        content_wordlists_only=True,
    )
    back = load_profile(save_profile(cfg, tmp_path / "a.profile"))

    names = [f.name for f in dataclasses.fields(RunConfig)]
    lost = [n for n in names if getattr(cfg, n) != getattr(back, n)]
    assert not lost, f"fields dropped by the profile round trip: {lost}"

    # Every value above must differ from the field default, or a dropped
    # field would still compare equal and the test would pass vacuously.
    defaults = RunConfig(targets_file=t)
    same_as_default = [
        n for n in names
        if n != "targets_file" and getattr(cfg, n) == getattr(defaults, n)
    ]
    assert not same_as_default, (
        "these fields are set to their default, so the round-trip assertion "
        f"cannot detect them being dropped: {same_as_default}"
    )


def test_old_profile_without_custom_templates_key_still_loads(tmp_path):
    """A profile saved before custom_templates existed must still load,
    defaulting to "no custom templates" rather than raising ProfileError
    over a key that simply predates the field."""
    p = tmp_path / "old.profile"
    t = tmp_path / "targets.txt"; t.write_text("acc.example\n")
    p.write_text(yaml.safe_dump({
        "targets_file": str(t), "outdir": str(tmp_path / "out"),
        "level": "mid", "auth_mode": "unauth", "stages": [], "proxy": "",
        "rate_override": 0, "time_limit": "", "subdomain_enum": False,
        "preflight_timeout": 3.0, "verify_secrets": False,
        # no "custom_templates" key at all
    }))
    back = load_profile(p)
    assert back.custom_templates == ""
