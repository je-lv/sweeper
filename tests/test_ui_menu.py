import pytest
from sweeper.context import RunConfig
from sweeper.ui.menu import MenuState, apply_choice, run_menu


def state(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\nshop.acc.example\n")
    return MenuState(RunConfig(targets_file=t, outdir=tmp_path / "out"))


def test_level_choice_updates_config(tmp_path):
    # "low" is deliberate: it is the one level with no confirmation gate, so
    # this test exercises the plain level-change path. Using "high" here
    # would contradict test_high_level_requires_only_yn_confirmation — an
    # always-"high" prompt_fn answers the y/N confirmation with "high",
    # which is not "y", so the level correctly does NOT change.
    s = state(tmp_path)
    apply_choice(s, "1", prompt_fn=lambda *a, **k: "low")
    assert s.config.level == "mid"          # option 1 is targets, not level
    apply_choice(s, "2", prompt_fn=lambda *a, **k: "low")
    assert s.config.level == "low"


def test_invalid_level_is_rejected_and_config_unchanged(tmp_path):
    s = state(tmp_path)
    apply_choice(s, "2", prompt_fn=lambda *a, **k: "apocalyptic")
    assert s.config.level == "mid"


def test_auth_mode_toggle(tmp_path):
    s = state(tmp_path)
    apply_choice(s, "3", prompt_fn=lambda *a, **k: "auth")
    assert s.config.auth_mode == "auth"


def test_full_level_requires_typed_acknowledgement(tmp_path):
    s = state(tmp_path)
    apply_choice(s, "2", prompt_fn=lambda *a, **k: "full")
    assert s.config.level == "mid", "full must not be set without acknowledgement"
    # An always-"full" prompt_fn answers the phrase prompt with "full", which
    # is a WRONG phrase — so this is the abandoned-acknowledgement path.
    assert s.acknowledgements == []


def test_full_level_set_after_typed_acknowledgement(tmp_path):
    s = state(tmp_path)
    answers = iter(["full", "I ACKNOWLEDGE", "yes"])
    apply_choice(s, "2", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.level == "full"
    assert any(a["level"] == "full" for a in s.acknowledgements)


def test_high_level_requires_only_yn_confirmation(tmp_path):
    s = state(tmp_path)
    answers = iter(["high", "y"])
    apply_choice(s, "2", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.level == "high"


def test_high_level_confirmation_is_recorded_in_the_manifest_record(tmp_path):
    """Spec 2.2/6.1/12.1(5): BOTH gates are recorded, not only `full`'s."""
    s = state(tmp_path)
    answers = iter(["high", "y"])
    apply_choice(s, "2", prompt_fn=lambda *a, **k: next(answers))
    assert len(s.acknowledgements) == 1
    assert s.acknowledgements[0]["level"] == "high"
    assert s.acknowledgements[0]["via"] == "menu"
    assert s.acknowledgements[0]["at"]


def test_high_level_declined_confirmation_leaves_level_unchanged(tmp_path):
    s = state(tmp_path)
    answers = iter(["high", "n"])
    apply_choice(s, "2", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.level == "mid"
    assert s.acknowledgements == []


def test_wrong_phrase_records_no_acknowledgement(tmp_path):
    s = state(tmp_path)
    answers = iter(["full", "i acknowledge"])
    apply_choice(s, "2", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.level == "mid"
    assert s.acknowledgements == []


def test_declined_second_confirmation_records_no_acknowledgement(tmp_path):
    s = state(tmp_path)
    answers = iter(["full", "I ACKNOWLEDGE", "n"])
    apply_choice(s, "2", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.level == "mid"
    assert s.acknowledgements == []


def test_successful_acknowledgement_is_recorded_once(tmp_path):
    s = state(tmp_path)
    answers = iter(["full", "I ACKNOWLEDGE", "yes"])
    apply_choice(s, "2", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.level == "full"
    assert len(s.acknowledgements) == 1


def test_targets_count_reflects_file(tmp_path):
    assert state(tmp_path).target_count == 2


def test_quit_returns_quit_signal(tmp_path):
    assert apply_choice(state(tmp_path), "q", prompt_fn=lambda *a, **k: "") == "quit"


def test_run_returns_run_signal(tmp_path):
    assert apply_choice(state(tmp_path), "r", prompt_fn=lambda *a, **k: "") == "run"


def test_unknown_key_is_ignored(tmp_path):
    s = state(tmp_path)
    assert apply_choice(s, "zzz", prompt_fn=lambda *a, **k: "") == "continue"
    assert s.config.level == "mid"


# --- Loading a profile must pass the same gate as typing a level ------------
# apply_choice's `l` branch replaced the whole config wholesale, and the
# option-2 gate fired only when an operator TYPED a level. Press L, load a
# profile with level: full, press R -- a completed run with
# acknowledgements: []. The gate now lives in gate_level(), shared by both.

from pathlib import Path

import yaml
from sweeper.ui.menu import gate_level


def _profile(tmp_path, level, name="p.profile"):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\nshop.acc.example\n")
    path = tmp_path / name
    path.write_text(yaml.safe_dump({
        "targets_file": str(t), "outdir": str(tmp_path / "out"),
        "level": level, "auth_mode": "unauth", "stages": [], "proxy": "",
        "rate_override": 0, "time_limit": "", "subdomain_enum": False,
        "preflight_timeout": 3.0,
    }))
    return path


def test_loading_a_full_profile_with_the_wrong_phrase_is_refused(tmp_path):
    s = state(tmp_path)
    original = s.config
    p = _profile(tmp_path, "full")
    answers = iter([str(p), "i acknowledge"])
    apply_choice(s, "l", prompt_fn=lambda *a, **k: next(answers))
    assert s.config is original, "the profile was applied despite the refusal"
    assert s.config.level == "mid"
    assert s.acknowledgements == []


def test_loading_a_full_profile_declining_confirmation_is_refused(tmp_path):
    s = state(tmp_path)
    original = s.config
    p = _profile(tmp_path, "full")
    answers = iter([str(p), "I ACKNOWLEDGE", "n"])
    apply_choice(s, "l", prompt_fn=lambda *a, **k: next(answers))
    assert s.config is original
    assert s.config.level == "mid"
    assert s.acknowledgements == []


def test_loading_a_full_profile_with_the_exact_phrase_applies_it(tmp_path):
    s = state(tmp_path)
    p = _profile(tmp_path, "full")
    answers = iter([str(p), "I ACKNOWLEDGE", "yes"])
    apply_choice(s, "l", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.level == "full"
    assert len(s.acknowledgements) == 1
    assert s.acknowledgements[0]["level"] == "full"
    assert s.acknowledgements[0]["phrase"] == "I ACKNOWLEDGE"
    assert s.acknowledgements[0]["via"] == "menu"


def test_loading_a_high_profile_without_confirmation_is_refused(tmp_path):
    s = state(tmp_path)
    original = s.config
    p = _profile(tmp_path, "high")
    answers = iter([str(p), "n"])
    apply_choice(s, "l", prompt_fn=lambda *a, **k: next(answers))
    assert s.config is original
    assert s.config.level == "mid"
    assert s.acknowledgements == []


def test_loading_a_high_profile_with_confirmation_applies_it(tmp_path):
    s = state(tmp_path)
    p = _profile(tmp_path, "high")
    answers = iter([str(p), "y"])
    apply_choice(s, "l", prompt_fn=lambda *a, **k: next(answers))
    assert s.config.level == "high"
    assert len(s.acknowledgements) == 1
    assert s.acknowledgements[0]["level"] == "high"
    assert s.acknowledgements[0]["via"] == "menu"


@pytest.mark.parametrize("level", ["low", "mid"])
def test_loading_an_ordinary_profile_prompts_only_for_the_path(tmp_path, level):
    """No gate prompt at all for low/mid: exactly one prompt is consumed."""
    s = state(tmp_path)
    p = _profile(tmp_path, level)
    asked = []

    def prompt_fn(msg="", *a, **k):
        asked.append(msg)
        return str(p) if len(asked) == 1 else pytest.fail(
            f"unexpected second prompt: {msg!r}"
        )

    apply_choice(s, "l", prompt_fn=prompt_fn)
    assert s.config.level == level
    assert len(asked) == 1


def test_loading_a_missing_profile_leaves_the_config_alone(tmp_path):
    s = state(tmp_path)
    original = s.config
    apply_choice(s, "l", prompt_fn=lambda *a, **k: str(tmp_path / "nope.profile"))
    assert s.config is original


# --- A malformed profile must not kill the REPL -----------------------------
# load_profile raises ValueError on a bad level/auth_mode and KeyError on a
# missing required key. Both used to escape apply_choice and run_menu,
# ending the session on what is otherwise a routine, recoverable mistake.


def test_malformed_profile_level_does_not_crash_the_repl(tmp_path):
    s = state(tmp_path)
    original = s.config
    bad = tmp_path / "bad.profile"
    bad.write_text("targets_file: /tmp/t.txt\nlevel: apocalyptic\n")
    action = apply_choice(s, "l", prompt_fn=lambda *a, **k: str(bad))
    assert action == "continue"
    assert s.config is original


def test_profile_missing_required_key_does_not_crash_the_repl(tmp_path):
    """load_profile raises KeyError for a profile with no targets_file."""
    s = state(tmp_path)
    original = s.config
    bad = tmp_path / "bad2.profile"
    bad.write_text("level: mid\n")
    action = apply_choice(s, "l", prompt_fn=lambda *a, **k: str(bad))
    assert action == "continue"
    assert s.config is original


# --- Enumerating exception types is exactly what missed this ---------------
# menu.py used to catch (ValueError, KeyError, OSError). A YAML syntax error
# raises yaml.parser.ParserError; a scalar profile raises AttributeError; a
# list-valued targets_file raises TypeError. All three killed the REPL and
# lost the operator's settings despite the catch already existing. Now
# load_profile wraps everything in ProfileError and apply_choice catches
# only that -- the rule is "any failure to load a profile", not an
# enumeration.


def test_broken_yaml_syntax_does_not_crash_the_repl(tmp_path):
    s = state(tmp_path)
    original = s.config
    bad = tmp_path / "bad.profile"
    bad.write_text("targets_file: [unterminated\n  level: mid\n")
    action = apply_choice(s, "l", prompt_fn=lambda *a, **k: str(bad))
    assert action == "continue"
    assert s.config is original


def test_scalar_profile_does_not_crash_the_repl(tmp_path):
    s = state(tmp_path)
    original = s.config
    bad = tmp_path / "bad.profile"
    bad.write_text("just a plain scalar string\n")
    action = apply_choice(s, "l", prompt_fn=lambda *a, **k: str(bad))
    assert action == "continue"
    assert s.config is original


def test_list_valued_targets_file_does_not_crash_the_repl(tmp_path):
    s = state(tmp_path)
    original = s.config
    bad = tmp_path / "bad.profile"
    bad.write_text("targets_file: [a, b]\n")
    action = apply_choice(s, "l", prompt_fn=lambda *a, **k: str(bad))
    assert action == "continue"
    assert s.config is original


# --- gate_level itself: one gate, identical behaviour from either caller ----

@pytest.mark.parametrize("level", ["low", "mid"])
def test_gate_level_passes_ordinary_levels_without_prompting(tmp_path, level):
    s = state(tmp_path)
    assert gate_level(s, level, prompt_fn=lambda *a, **k: pytest.fail(
        "gate_level prompted for an ordinary level"))


def test_gate_level_records_the_acknowledgement_once(tmp_path):
    s = state(tmp_path)
    answers = iter(["I ACKNOWLEDGE", "yes"])
    assert gate_level(s, "full", prompt_fn=lambda *a, **k: next(answers))
    assert len(s.acknowledgements) == 1


def test_gate_level_refuses_a_near_miss_phrase(tmp_path):
    s = state(tmp_path)
    answers = iter(["I Acknowledge", "yes"])
    assert not gate_level(s, "full", prompt_fn=lambda *a, **k: next(answers))
    assert s.acknowledgements == []


def test_gate_level_high_records_the_acknowledgement(tmp_path):
    s = state(tmp_path)
    assert gate_level(s, "high", prompt_fn=lambda *a, **k: "y")
    assert len(s.acknowledgements) == 1
    assert s.acknowledgements[0]["level"] == "high"
    assert s.acknowledgements[0]["via"] == "menu"
    assert s.acknowledgements[0]["at"]


def test_gate_level_high_declined_records_nothing(tmp_path):
    s = state(tmp_path)
    assert not gate_level(s, "high", prompt_fn=lambda *a, **k: "n")
    assert s.acknowledgements == []


# --- Defence in depth: no exception from apply_choice may kill the session -
# apply_choice already handles the failure modes known about today. A REPL
# that dies on a bad input and discards the operator's configuration is a
# bug regardless of which exception caused it -- run_menu itself must not
# be able to die because of *any* exception from apply_choice, known or not.


def test_run_menu_survives_an_unexpected_exception_from_apply_choice(tmp_path, monkeypatch):
    import sweeper.ui.menu as menu_mod

    s = state(tmp_path)
    s.config.proxy = "http://keep-me:8080"
    calls = {"n": 0}

    def flaky_apply_choice(state_, key, prompt_fn):
        calls["n"] += 1
        if calls["n"] == 1:
            # Not one of ProfileError/ValueError/KeyError/OSError -- an
            # exception type nobody enumerated for this call site.
            raise AttributeError("boom, not one of the expected types")
        return "quit"

    monkeypatch.setattr(menu_mod, "apply_choice", flaky_apply_choice)
    ran = []
    menu_mod.run_menu(s, prompt_fn=lambda msg="> ": "",
                      runner_fn=lambda st: ran.append(st))

    assert calls["n"] == 2, "run_menu must have looped past the exception"
    assert not ran, "the loop must not have treated the crash as a run"
    assert s.config.proxy == "http://keep-me:8080", "operator settings were lost"


def test_run_menu_survives_a_profileerror_shaped_exception_and_still_quits(tmp_path, monkeypatch):
    """Sanity check that the loop terminates normally once a real 'quit' is
    returned after the exception, rather than looping forever."""
    import sweeper.ui.menu as menu_mod

    s = state(tmp_path)
    answers = iter([RuntimeError("first call blows up"), "quit"])

    def flaky_apply_choice(state_, key, prompt_fn):
        nxt = next(answers)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    monkeypatch.setattr(menu_mod, "apply_choice", flaky_apply_choice)
    # If run_menu did not return, this test would hang; pytest's default
    # timeout is absent here, so a real hang would need a signal-based guard
    # -- but the exception path always either continues the loop or reaches
    # a genuine 'quit'/'run', both of which end iteration for a two-item
    # answers iterator (StopIteration on a third call would itself raise).
    menu_mod.run_menu(s, prompt_fn=lambda msg="> ": "", runner_fn=lambda st: None)
