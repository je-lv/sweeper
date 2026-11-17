from pathlib import Path

import pytest
from sweeper import app
from sweeper.artifacts import ArtifactKind
from sweeper.context import RunConfig, RunContext


def cfg(tmp_path, **kw):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    return RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)


def test_every_stage_is_registered(tmp_path):
    # The roster is written out rather than derived from ALL_STAGES on
    # purpose: this is the guard that a stage cannot quietly disappear from
    # a run, and a test that reads the same tuple it is checking would pass
    # just as happily with one of them deleted.
    #
    # subdomain_enum=True: subfinder is opt-in (see build_stages' gate and
    # the Global Constraint that subdomain enumeration output is never
    # scanned without explicit operator confirmation) -- with the default
    # config it is correctly excluded, so asserting the full roster requires
    # explicitly opting in, the same as test_subfinder_included_when_enum_enabled
    # and test_every_stage_passes_contract_validation below.
    names = {s.name for s in app.build_stages(
        cfg(tmp_path, level="full", subdomain_enum=True)
    )}
    assert names == {
        "subfinder", "dnsx", "dnssec", "maildns", "cdncheck", "naabu", "nmap",
        "nmap_udp",
        "tlsx", "httpx", "vhost", "content", "katana", "jsrecon", "arjun",
        "nuclei",
    }


def test_pipeline_order_respects_data_dependencies(tmp_path):
    order = [s.name for s in app.build_stages(cfg(tmp_path))]
    assert order.index("naabu") < order.index("httpx")
    assert order.index("httpx") < order.index("katana")
    assert order.index("httpx") < order.index("nuclei")
    assert order.index("naabu") < order.index("nmap")


def test_pure_consumers_run_after_every_enricher_of_the_kind_they_consume(tmp_path):
    """The property registry.order() exists to guarantee, asserted BY ROLE.

    nuclei is a pure consumer of HTTP_SERVICE and produces the findings the
    whole report is built from; scanning a pool that katana/vhost/jsrecon/
    arjun had not yet contributed to would silently under-report coverage.
    Deliberately derived from consumes/produces rather than hardcoding
    today's twelve names: a stage added or renamed later is covered without
    editing this test, which is exactly the failure mode registry.order's
    docstring calls "correctness by alphabet".
    """
    from sweeper.artifacts import ArtifactKind

    stages = app.build_stages(cfg(tmp_path, subdomain_enum=True))
    names = [s.name for s in stages]
    checked = 0
    for kind in ArtifactKind:
        enrichers = [s.name for s in stages
                     if s.consumes == kind and kind in s.produces]
        pure_consumers = [s.name for s in stages
                          if s.consumes == kind and kind not in s.produces]
        for consumer in pure_consumers:
            for enricher in enrichers:
                assert names.index(enricher) < names.index(consumer), (
                    f"{consumer} (pure consumer of {kind.name}) runs before "
                    f"{enricher}, which can still add {kind.name} artifacts -- "
                    f"{consumer} would see an incomplete pool"
                )
                checked += 1
    assert checked, "no pure-consumer/enricher pair was exercised"


def test_subfinder_excluded_unless_enum_enabled(tmp_path):
    names = {s.name for s in app.build_stages(cfg(tmp_path, subdomain_enum=False))}
    assert "subfinder" not in names


def test_subfinder_included_when_enum_enabled(tmp_path):
    names = {s.name for s in app.build_stages(cfg(tmp_path, subdomain_enum=True))}
    assert "subfinder" in names


def test_subfinder_by_explicit_stage_name_is_not_treated_as_a_typo(tmp_path):
    """--stages subfinder without --subdomain-enum is a deliberate policy
    exclusion (dropped AFTER the unknown-name check), never mistaken for an
    unknown stage name."""
    names = {s.name for s in app.build_stages(
        cfg(tmp_path, stages=["subfinder"], subdomain_enum=False))}
    assert names == set()


def test_every_stage_passes_contract_validation(tmp_path):
    from sweeper.stages import registry
    for s in app.build_stages(cfg(
        tmp_path, level="full", subdomain_enum=True,
    )):
        assert registry.validate(s) == [], f"{s.name} violates the contract"


def test_all_stages_define_all_four_levels(tmp_path):
    for cls in app.ALL_STAGES:
        s = cls()
        assert set(s.levels) >= {"low", "mid", "high", "full"}, s.name


def test_level_gated_stages_are_only_planned_where_they_run(tmp_path):
    low = {s.name for s in app.build_stages(cfg(tmp_path, level="low"))}
    mid = {s.name for s in app.build_stages(cfg(tmp_path, level="mid"))}
    high = {s.name for s in app.build_stages(cfg(tmp_path, level="high"))}

    assert {"vhost", "arjun", "maildns", "jsrecon"}.isdisjoint(low)
    assert "jsrecon" in mid
    assert {"vhost", "arjun", "maildns"}.isdisjoint(mid)
    assert {"vhost", "arjun", "maildns", "jsrecon"} <= high


def test_explicit_level_disabled_stage_is_a_hard_error(tmp_path):
    with pytest.raises(ValueError, match="not enabled at level"):
        app.build_stages(cfg(
            tmp_path, level="mid", stages=["arjun"],
        ))


def test_unknown_stage_name_still_raises_loudly(tmp_path):
    with pytest.raises(ValueError, match="unknown stage name"):
        app.build_stages(cfg(tmp_path, stages=["dnsx", "naabu", "htpx"]))


def test_build_stages_returns_a_valid_order_with_no_cycle(tmp_path):
    """registry.order() raises ValueError("cycle...") if it cannot linearize
    the stages; a successful call with every one of them is itself the proof
    there is no cycle among them.

    Counted from ALL_STAGES rather than written out, so adding a stage does
    not fail here for the uninteresting reason that a literal went stale --
    the assertion is about the ORDERING being total, not about how many
    stages exist.
    """
    order = app.build_stages(cfg(
        tmp_path, level="full", subdomain_enum=True,
    ))
    assert len(order) == len(app.ALL_STAGES)
    assert {s.name for s in order} == {c().name for c in app.ALL_STAGES}


def test_custom_template_dir_must_exist(tmp_path):
    from sweeper import preflight
    from sweeper.context import RunContext
    ctx = RunContext.create(cfg(tmp_path, custom_templates="/nonexistent/templates"))
    errs = preflight.validate_custom_templates(ctx)
    assert errs and "not found" in errs[0]


def test_custom_template_dir_that_exists_passes_when_no_nuclei_binary(tmp_path, monkeypatch):
    """Without a nuclei binary to run -validate against, existence alone is
    all that can be checked -- and that must not itself be an error."""
    from sweeper import binaries, preflight
    from sweeper.context import RunContext
    templates = tmp_path / "templates"; templates.mkdir()
    monkeypatch.setattr(binaries, "resolve", lambda name: None)
    ctx = RunContext.create(cfg(tmp_path, custom_templates=str(templates)))
    assert preflight.validate_custom_templates(ctx) == []


def test_auth_mode_without_credentials_is_rejected(tmp_path):
    from sweeper import preflight
    from sweeper.context import RunContext
    ctx = RunContext.create(cfg(tmp_path, auth_mode="auth"))
    report = preflight.run_preflight(ctx, [])
    assert report.ok is False
    assert any("auth" in e.lower() for e in report.errors)


def test_menu_configured_auth_reaches_the_run(tmp_path, monkeypatch):
    """Drives the actual operator path: main() -> menu option 7 -> R(un).

    A test that bypasses this (calling run_preflight or execute() directly
    with auth_bundle=...) proves nothing about whether the menu's SecretBundle
    ever reaches execute() -- that gap is exactly how this defect hid.
    """
    import sweeper.binaries as binaries
    from sweeper.binaries import BinaryStatus

    t = tmp_path / "t.txt"; t.write_text("acc.example\n")

    # No real scanning tool has to exist on the test machine: force every
    # binary identity check to fail so preflight disables every stage
    # (MISSING_BINARY, not an error) and the run completes as a legitimate
    # no-op. What is under test is whether ctx.auth is populated and the run
    # is not rejected by preflight's auth-mode check -- not stage execution.
    monkeypatch.setattr(
        binaries, "verify",
        lambda name: BinaryStatus(name=name, ok=False, reason="test: disabled"),
    )

    prompts = iter([
        "7",                     # menu: auth credentials
        "m",                     # manual entry
        "",                      # cookie header, blank
        "Bearer testtoken123",   # Authorization header
        "r",                     # run
        "q",                     # quit after the run completes
    ])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(prompts))

    captured = {}
    real_execute = app.execute

    def spy_execute(config, on_progress=None, acknowledgements=None, auth_bundle=None):
        ctx, results = real_execute(config, on_progress=on_progress,
                                    acknowledgements=acknowledgements,
                                    auth_bundle=auth_bundle)
        captured["ctx"] = ctx
        return ctx, results

    monkeypatch.setattr(app, "execute", spy_execute)

    code = app.main(["-t", str(t), "-o", str(tmp_path / "out"), "--auth", "unauth"])

    assert code == 0
    ctx = captured["ctx"]
    assert ctx.auth is not None
    assert not ctx.auth.is_empty()
    assert ctx.auth.headers.get("Authorization") == "Bearer testtoken123"
    assert not ctx.aborted_reason.startswith("preflight failed: auth mode")


# --- custom_templates must actually reach nuclei's argv, not merely parse --
# sweeper/stages/nuclei.py has always read ctx.config.custom_templates via a
# getattr fallback (context.py was off-limits to that task). Before this
# task RunConfig had no such field at all: an operator supplying
# --custom-templates got no error and no effect. These pin the field
# existing on RunConfig, the CLI flag setting it, and the value actually
# landing in the command nuclei is invoked with.

def test_custom_templates_field_defaults_empty(tmp_path):
    assert cfg(tmp_path).custom_templates == ""


def test_custom_template_path_reaches_the_nuclei_command(tmp_path):
    from sweeper.context import RunContext
    from sweeper.stages.nuclei import NucleiStage

    templates = tmp_path / "custom-templates"
    templates.mkdir()
    ctx = RunContext.create(cfg(tmp_path, custom_templates=str(templates)))
    cmd = NucleiStage().build_command(ctx)
    assert "-t" in cmd
    assert str(templates) == cmd[cmd.index("-t") + 1]


def test_no_custom_templates_means_no_dash_t_in_nuclei_command(tmp_path):
    from sweeper.context import RunContext
    from sweeper.stages.nuclei import NucleiStage

    ctx = RunContext.create(cfg(tmp_path))
    cmd = NucleiStage().build_command(ctx)
    assert "-t" not in cmd


def test_cli_custom_templates_flag_reaches_runconfig(tmp_path, monkeypatch):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    templates = tmp_path / "custom-templates"; templates.mkdir()
    captured = {}

    def fake_execute(config, on_progress=None, acknowledgements=None, auth_bundle=None):
        captured["config"] = config
        raise SystemExit(0)

    monkeypatch.setattr(app, "execute", fake_execute)
    app.main(["-t", str(t), "-o", str(tmp_path / "out"), "--no-menu",
             "--custom-templates", str(templates)])
    assert captured["config"].custom_templates == str(templates)


# --- arjun exposes credentials to `ps`: the operator must be warned --------
# arjun's --headers has no file-based form (unlike katana's -H <file>), so
# on an authenticated run with arjun selected, live credentials sit in
# arjun's argv, visible to any local user via `ps` for the process
# lifetime. Nothing can redact `ps` after the fact, so the operator must be
# told at run start, and it must be recorded in the manifest -- a
# decide-and-inform situation, not a silent config note.

def _disable_all_binaries(monkeypatch):
    import sweeper.binaries as binaries
    from sweeper.binaries import BinaryStatus
    monkeypatch.setattr(
        binaries, "verify",
        lambda name: BinaryStatus(name=name, ok=False, reason="test: disabled"),
    )


def test_arjun_ps_warning_fires_when_auth_and_arjun_are_selected(tmp_path, monkeypatch):
    from sweeper.auth import SecretBundle

    _disable_all_binaries(monkeypatch)
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    bundle = SecretBundle(headers={"Authorization": "Bearer testtoken123"})

    ctx, results = app.execute(
        cfg(tmp_path, level="high", auth_mode="auth", stages=["arjun"]),
        auth_bundle=bundle,
    )

    assert any("arjun" in w and "ps" in w for w in ctx.warnings)

    import json
    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert any("arjun" in w and "ps" in w for w in manifest["warnings"])


def test_arjun_ps_warning_does_not_fire_without_auth(tmp_path, monkeypatch):
    _disable_all_binaries(monkeypatch)
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")

    ctx, results = app.execute(cfg(
        tmp_path, level="high", stages=["arjun"],
    ))

    assert ctx.warnings == []


def test_arjun_ps_warning_does_not_fire_without_arjun_selected(tmp_path, monkeypatch):
    from sweeper.auth import SecretBundle

    _disable_all_binaries(monkeypatch)
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    bundle = SecretBundle(headers={"Authorization": "Bearer testtoken123"})

    ctx, results = app.execute(
        cfg(tmp_path, auth_mode="auth", stages=["nuclei"]),
        auth_bundle=bundle,
    )

    assert ctx.warnings == []


# --- THE AUTH INVARIANT ----------------------------------------------------
# ctx.auth carries credentials if and only if config.auth_mode == "auth".
# run.json's "auth_mode" and the report's "**Auth:**" line render
# config.auth_mode verbatim, so the moment the two disagree the deliverable
# asserts traffic that is not what was sent -- and the operator who switched
# back to "unauth" for a baseline pass keeps sending credentials to the
# target. Enforced on RunContext.auth's setter (context.AuthModeViolation),
# not at any one call site.


def test_auth_is_attached_if_and_only_if_auth_mode_is_auth(tmp_path, monkeypatch):
    """The biconditional itself, both directions, driven through execute()."""
    from sweeper.auth import SecretBundle

    _disable_all_binaries(monkeypatch)
    bundle = SecretBundle(headers={"Authorization": "Bearer testtoken123"})

    for n, (auth_mode, supplied, expect_auth) in enumerate([
        ("auth", bundle, True),          # credentials + auth mode  -> attached
        ("unauth", bundle, False),       # credentials + unauth     -> withheld
        ("unauth", None, False),         # none + unauth            -> nothing
    ]):
        case = tmp_path / f"case{n}"
        case.mkdir()
        ctx, _ = app.execute(
            cfg(case, auth_mode=auth_mode, stages=["nuclei"]),
            auth_bundle=supplied,
        )
        assert (ctx.auth is not None) is expect_auth, (auth_mode, supplied)
        # The invariant, restated against what the deliverable actually says.
        assert (ctx.auth is not None) == (ctx.config.auth_mode == "auth"
                                          and expect_auth)
        if not expect_auth:
            assert ctx.secret_file is None


def test_runcontext_refuses_credentials_when_auth_mode_is_unauth(tmp_path):
    """The structural backstop: assignment itself is the choke point, so a
    future caller wired up without an auth_mode check cannot reintroduce
    this by omission."""
    from sweeper.auth import SecretBundle
    from sweeper.context import AuthModeViolation, RunContext

    ctx = RunContext.create(cfg(tmp_path))          # default auth_mode unauth
    with pytest.raises(AuthModeViolation):
        ctx.auth = SecretBundle(headers={"Authorization": "Bearer tok"})
    assert ctx.auth is None

    # Not a ValueError: main()'s and _runner's `except ValueError` must not
    # be able to swallow a credential leak and print a friendly message.
    assert not issubclass(AuthModeViolation, ValueError)


def test_runcontext_allows_empty_bundle_in_either_mode(tmp_path):
    """An empty bundle is not credentials -- it is what "the operator
    cleared them" looks like, and it must not be refused."""
    from sweeper.auth import SecretBundle
    from sweeper.context import RunContext

    ctx = RunContext.create(cfg(tmp_path))
    ctx.auth = SecretBundle()
    ctx.auth = None
    assert ctx.auth is None


def test_baseline_pass_after_an_auth_pass_sends_no_credentials(tmp_path, monkeypatch):
    """The exact operator sequence, end to end.

    Configure credentials at option 7 (auth_mode flips to "auth"), then
    switch option 3 back to "unauth" for an unauthenticated baseline pass --
    ordinary pentest workflow. The second run must send nothing: no
    ctx.auth, no secret-file on disk, no live token in any stage's argv, and
    a manifest that agrees with itself.
    """
    import json

    from sweeper.auth import SecretBundle
    from sweeper.ui.menu import MenuState, apply_choice

    _disable_all_binaries(monkeypatch)
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    config = RunConfig(targets_file=t, outdir=tmp_path / "out", level="high",
                       stages=["arjun", "nuclei"])
    state = MenuState(config)

    answers = iter(["m", "", "Bearer testtoken123"])
    apply_choice(state, "7", prompt_fn=lambda *a, **k: next(answers))
    assert state.config.auth_mode == "auth"
    assert state.auth is not None and not state.auth.is_empty()

    # ... and now the baseline pass.
    apply_choice(state, "3", prompt_fn=lambda *a, **k: "unauth")
    assert state.config.auth_mode == "unauth"

    ctx, results = app.execute(state.config, auth_bundle=state.auth)

    assert ctx.auth is None, "credentials reached an unauth run"
    assert ctx.secret_file is None, "a secret-file was written for an unauth run"
    assert not (ctx.run_dir / "auth" / "secrets.yaml").exists()

    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["auth_mode"] == "unauth"
    # The whole run directory must not contain the live token anywhere.
    for path in ctx.run_dir.rglob("*"):
        if path.is_file():
            assert "testtoken123" not in path.read_text(
                encoding="utf-8", errors="replace"), path

    # And the operator was told, rather than it happening silently.
    assert any("auth_mode" in w and "NO credentials" in w for w in ctx.warnings)


def test_credentials_withheld_warning_reaches_the_manifest(tmp_path, monkeypatch):
    import json

    from sweeper.auth import SecretBundle

    _disable_all_binaries(monkeypatch)
    ctx, _ = app.execute(
        cfg(tmp_path, auth_mode="unauth", stages=["nuclei"]),
        auth_bundle=SecretBundle(headers={"Authorization": "Bearer tok"}),
    )
    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert any("NO credentials" in w for w in manifest["warnings"])


# --- the menu must tell the operator which state they are in ---------------

def test_creds_label_has_three_distinct_states(tmp_path):
    from sweeper.auth import SecretBundle
    from sweeper.ui.menu import MenuState, creds_label

    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    st = MenuState(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    assert creds_label(st) == "none"

    st.config.auth_mode = "auth"
    st.auth = SecretBundle(headers={"Authorization": "Bearer tok"})
    assert creds_label(st) == "configured"

    st.config.auth_mode = "unauth"
    label = creds_label(st)
    assert "NOT in use" in label, label
    assert label != "configured"


def test_switching_to_unauth_with_credentials_stored_tells_the_operator(tmp_path, capsys):
    from sweeper.auth import SecretBundle
    from sweeper.ui.menu import MenuState, apply_choice

    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    st = MenuState(RunConfig(targets_file=t, outdir=tmp_path / "out",
                             auth_mode="auth"))
    st.auth = SecretBundle(headers={"Authorization": "Bearer tok"})

    apply_choice(st, "3", prompt_fn=lambda *a, **k: "unauth")
    out = capsys.readouterr().out
    assert "RETAINED" in out
    assert "not be sent" in out.lower()
    # Retained, not discarded.
    assert st.auth is not None and not st.auth.is_empty()


def test_clearing_credentials_drops_auth_mode_back_to_unauth(tmp_path, capsys):
    """Otherwise the operator strands themselves on a run preflight refuses
    for having auth mode set with no credentials -- immediately after
    deliberately clearing them."""
    from sweeper.auth import SecretBundle
    from sweeper.ui.menu import MenuState, apply_choice

    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    st = MenuState(RunConfig(targets_file=t, outdir=tmp_path / "out",
                             auth_mode="auth"))
    st.auth = SecretBundle(headers={"Authorization": "Bearer tok"})

    answers = iter(["m", "", ""])          # manual, blank cookie, blank auth
    apply_choice(st, "7", prompt_fn=lambda *a, **k: next(answers))

    assert st.config.auth_mode == "unauth"
    assert "cleared" in capsys.readouterr().out.lower()


# --- a `nuclei -validate` timeout must fail LOUD and LEAVE A RECORD --------
# run_preflight() is called from execute() BEFORE the try: that wraps
# run_stages, so a TimeoutExpired escaping validate_custom_templates
# propagated out of execute() uncaught: no run.json, no report -- the one
# outcome every other preflight failure path avoids. Interactively it was
# worse: _runner catches only SystemExit/ValueError and run_menu's guard
# wraps apply_choice rather than runner_fn, so the REPL died with a raw
# traceback and discarded every setting the operator had entered.
# `nuclei -validate` has been observed hanging on a trivially small
# directory through local port contention, so this is operational, not
# theoretical.


def _templates_that_time_out(tmp_path, monkeypatch):
    import subprocess

    from sweeper import binaries, preflight

    templates = tmp_path / "templates"; templates.mkdir()
    monkeypatch.setattr(binaries, "resolve",
                        lambda name: tmp_path / "fake-nuclei")

    def hang(*a, **kw):
        raise subprocess.TimeoutExpired(cmd="nuclei -validate", timeout=120)

    monkeypatch.setattr(preflight.subprocess, "run", hang)
    return templates


def test_template_validation_timeout_is_a_preflight_error_not_a_crash(tmp_path, monkeypatch):
    from sweeper import preflight
    from sweeper.context import RunContext

    templates = _templates_that_time_out(tmp_path, monkeypatch)
    ctx = RunContext.create(cfg(tmp_path, custom_templates=str(templates)))
    errs = preflight.validate_custom_templates(ctx)
    assert errs and "timed out" in errs[0]


def test_template_validation_timeout_still_writes_manifest_and_report(tmp_path, monkeypatch):
    """Fails loud AND leaves a record -- this codebase's bar for every other
    preflight failure path."""
    import json

    _disable_all_binaries(monkeypatch)
    templates = _templates_that_time_out(tmp_path, monkeypatch)

    with pytest.raises(SystemExit) as exc:
        app.execute(cfg(tmp_path, custom_templates=str(templates)))
    assert exc.value.code == 2

    run_dir = next((tmp_path / "out").iterdir())
    assert (run_dir / "run.json").exists(), "no manifest left behind"
    assert (run_dir / "report.md").exists(), "no report left behind"

    manifest = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["aborted"] is True
    assert "timed out" in manifest["aborted_reason"]
    assert "RUN ABORTED" in (run_dir / "report.md").read_text(encoding="utf-8")


def test_template_validation_timeout_does_not_kill_the_repl(tmp_path, monkeypatch):
    """The interactive half: the operator keeps their settings."""
    seen = {}

    def fake_run_menu(state, prompt_fn, runner_fn):
        state.config.proxy = "http://keep-me:8080"
        runner_fn(state)                 # must not raise
        seen["proxy"] = state.config.proxy

    _disable_all_binaries(monkeypatch)
    templates = _templates_that_time_out(tmp_path, monkeypatch)
    monkeypatch.setattr("sweeper.ui.menu.run_menu", fake_run_menu)

    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    rc = app.main(["-t", str(t), "-o", str(tmp_path / "out"),
                   "--custom-templates", str(templates)])

    assert rc == 0
    assert seen["proxy"] == "http://keep-me:8080", "operator settings were lost"


def test_unrunnable_nuclei_binary_is_reported_not_raised(tmp_path, monkeypatch):
    from sweeper import binaries, preflight
    from sweeper.context import RunContext

    templates = tmp_path / "templates"; templates.mkdir()
    monkeypatch.setattr(binaries, "resolve", lambda name: tmp_path / "nope")

    def boom(*a, **kw):
        raise OSError("Exec format error")

    monkeypatch.setattr(preflight.subprocess, "run", boom)
    ctx = RunContext.create(cfg(tmp_path, custom_templates=str(templates)))
    errs = preflight.validate_custom_templates(ctx)
    assert errs and "could not run nuclei -validate" in errs[0]


# --- warnings must reach the human-readable report, not just run.json ------

def test_arjun_ps_warning_appears_in_the_markdown_report(tmp_path, monkeypatch):
    from sweeper.auth import SecretBundle

    _disable_all_binaries(monkeypatch)
    ctx, _ = app.execute(
        cfg(tmp_path, level="high", auth_mode="auth", stages=["arjun"]),
        auth_bundle=SecretBundle(headers={"Authorization": "Bearer tok"}),
    )
    report = (ctx.run_dir / "report.md").read_text(encoding="utf-8")
    assert "RUN WARNING" in report
    assert "arjun" in report
    assert "process list" in report or "ps" in report


def test_clean_run_report_has_no_warning_banner(tmp_path, monkeypatch):
    _disable_all_binaries(monkeypatch)
    ctx, _ = app.execute(cfg(tmp_path, stages=["nuclei"]))
    assert "RUN WARNING" not in (ctx.run_dir / "report.md").read_text(encoding="utf-8")


# --- the menu path must supply a progress display ---------------------------
# Progress wiring first landed on the CLI path only, so an operator running
# through the menu -- the normal interactive path -- still saw several minutes
# of total silence. The same shape as the auth defect above: a feature wired on
# one path, tested on that path, and absent from the one people actually use.
# This asserts on_progress is non-None at the execute() boundary, which is the
# only thing that makes the display appear, rather than on rendered frames
# (those need a TTY and would make this a terminal test, not a wiring test).

def test_menu_run_supplies_a_progress_callback(tmp_path, monkeypatch):
    import sweeper.binaries as binaries
    from sweeper.binaries import BinaryStatus

    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    monkeypatch.setattr(
        binaries, "verify",
        lambda name: BinaryStatus(name=name, ok=False, reason="test: disabled"),
    )

    prompts = iter(["r", "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(prompts))

    seen = {}
    real_execute = app.execute

    def spy_execute(config, on_progress=None, acknowledgements=None, auth_bundle=None):
        seen["on_progress"] = on_progress
        return real_execute(config, on_progress=on_progress,
                            acknowledgements=acknowledgements,
                            auth_bundle=auth_bundle)

    monkeypatch.setattr(app, "execute", spy_execute)
    code = app.main(["-t", str(t), "-o", str(tmp_path / "out")])

    assert code == 0
    assert "on_progress" in seen, "menu never reached execute()"
    assert seen["on_progress"] is not None, (
        "the menu path ran without a progress display -- an operator sees "
        "nothing for the duration of the run"
    )


# --- A stage that reads artifact BODIES must run after one that finds them --
# The B7 defect: jsrecon and katana are both HTTP_SERVICE enrichers, so
# registry.order() made them peers and broke the tie alphabetically. jsrecon
# ran first, saw only httpx's bare scheme://host:port URLs -- no path, no
# content_type -- and its candidate list was EMPTY on every default run,
# while the report said "All selected stages completed". The property below
# is the candidate list, not the ordering: asserting "katana before jsrecon"
# would go green again the moment someone renames a stage or changes how
# candidates are selected, which is exactly how this shipped.

FIXTURES = Path(__file__).parent / "fixtures"


def _feed(ctx, stage):
    """Replay stage's recorded real output into the store, as a run would.

    Returns True if a fixture existed. The path is derived from the stage's
    own declared name and raw_suffix -- the same pair ctx.raw_path() uses --
    so a stage whose output format changes cannot quietly stop contributing
    here while this test keeps passing.
    """
    fixture = FIXTURES / f"{stage.name}.{getattr(stage, 'raw_suffix', 'jsonl')}"
    if not fixture.exists():
        return False
    for item in stage.parse(fixture):
        if getattr(item, "kind", None) is ArtifactKind.HTTP_SERVICE:
            ctx.store.add(item)
    return True


def test_jsrecon_has_candidates_on_a_default_pipeline(tmp_path):
    """Walk the real default pipeline in its real order; when jsrecon's turn
    comes, its candidate list must not be empty.

    Only stages ordered BEFORE jsrecon contribute, which is the whole point:
    anything katana finds after jsrecon has run is invisible to it.
    """
    config = cfg(tmp_path)
    stages = app.build_stages(config)
    ctx = RunContext.create(config)
    jsrecon = next(s for s in stages if s.name == "jsrecon")

    contributors = []
    for stage in stages:
        if stage.name == "jsrecon":
            break
        if _feed(ctx, stage):
            contributors.append(stage.name)

    assert "httpx" in contributors, "fixture set no longer exercises the run"
    candidates = jsrecon.js_urls(ctx)
    assert candidates, (
        "jsrecon's candidate list is empty on a default pipeline: every "
        "HTTP_SERVICE artifact available to it by the time it runs "
        f"({sorted(ctx.store.values(ArtifactKind.HTTP_SERVICE))}) came from "
        f"{contributors}, and none is identifiable as JavaScript. The stage "
        "would report success having read nothing."
    )


def test_the_jsrecon_candidates_come_from_a_stage_ordered_before_it(tmp_path):
    """The same property from the supply side, and the reason it holds.

    Feeding ONLY the stages ordered before jsrecon must be what makes its
    candidate list non-empty -- so if a future change reorders the pipeline
    such that the JS-tagging stage lands after jsrecon, this fails even if
    some other fixture happens to contain a .js URL.
    """
    config = cfg(tmp_path)
    stages = app.build_stages(config)
    before = [s.name for s in stages[:[s.name for s in stages].index("jsrecon")]]

    # Every stage that declares it provides a facet jsrecon requires must be
    # ordered before it. Derived from the declarations, not from the name
    # "katana", so a replacement crawler is covered without editing this.
    from sweeper.stages import registry
    jsrecon = next(s for s in stages if s.name == "jsrecon")
    needed = registry.facets(jsrecon, "requires_facets")
    suppliers = [s.name for s in stages
                 if s.name != jsrecon.name
                 and registry.facets(s, "provides_facets") & needed]
    assert suppliers, "no stage declares it supplies what jsrecon requires"
    for supplier in suppliers:
        assert supplier in before, (
            f"{supplier} supplies a facet jsrecon requires but runs after it"
        )
