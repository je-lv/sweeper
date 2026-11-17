import json
import os
import stat
from datetime import datetime
from pathlib import Path

import pytest
from sweeper.artifacts import Finding
from sweeper.context import RUN_DIR_MODE, RunConfig, RunContext, new_run_dir
from sweeper.stages.base import Coverage, FailureClass, StageResult
from sweeper.useragents import USER_AGENTS


def cfg(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n# a comment\n\n  spaced.example  \n")
    return RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)


def test_new_run_dir_is_timestamped_and_created(tmp_path):
    d = new_run_dir(tmp_path / "out")
    assert d.exists()
    assert d.parent.name == "out"
    assert len(d.name) == 15 and d.name[8] == "-"   # YYYYmmdd-HHMMSS


# --- the run directory must not be writable or readable by other accounts --
# Everything in a run directory is sensitive, and a group-writable run
# directory is also what would let another local account swap a not-yet-created
# file for a symlink out. mkdir()'s mode argument is masked by the umask, so
# these assert the mode on disk, at the umasks that actually differ: 002 is
# normal on a shared-group box and is the dangerous one.

@pytest.mark.parametrize("umask", [0o002, 0o022, 0o077])
def test_new_run_dir_is_owner_only_at_any_umask(tmp_path, umask):
    old = os.umask(umask)
    try:
        d = new_run_dir(tmp_path / "out")
        assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    finally:
        os.umask(old)


@pytest.mark.parametrize("umask", [0o002, 0o022, 0o077])
def test_created_parent_directories_are_owner_only_too(tmp_path, umask):
    """A loose intermediate directory is just as exploitable as a loose run
    directory: parents=True creates them, so they get the same mode."""
    old = os.umask(umask)
    try:
        d = new_run_dir(tmp_path / "deep" / "nested" / "out")
        for created in (d.parent, d.parent.parent, d.parent.parent.parent):
            assert stat.S_IMODE(os.stat(created).st_mode) == 0o700
    finally:
        os.umask(old)


def test_preexisting_outdir_is_not_relaxed_or_tightened(tmp_path):
    """Only directories this code creates are chmod'ed. Silently changing the
    mode of an operator's existing recon/ tree is not ours to do."""
    out = tmp_path / "out"
    out.mkdir(mode=0o755)
    os.chmod(out, 0o755)
    d = new_run_dir(out)
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o755
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_raw_dir_is_owner_only(tmp_path):
    """Raw tool output can echo back an Authorization header."""
    old = os.umask(0o002)
    try:
        ctx = RunContext.create(cfg(tmp_path))
        assert stat.S_IMODE(os.stat(ctx.run_dir / "raw").st_mode) == 0o700
    finally:
        os.umask(old)


def test_run_dir_mode_constant_is_owner_only():
    assert RUN_DIR_MODE == 0o700


def test_load_targets_strips_comments_and_blanks(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    assert ctx.load_targets() == ["acc.example", "spaced.example"]


def test_scope_is_seeded_from_targets_file(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    assert ctx.scope.allows("acc.example") is True
    assert ctx.scope.allows("unrelated.example") is False


def test_targets_file_is_copied_verbatim(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    copied = ctx.run_dir / "targets.txt"
    assert copied.exists()
    assert "# a comment" in copied.read_text()


def test_raw_path_is_under_raw_dir(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    p = ctx.raw_path("dnsx", "jsonl")
    assert p.parent.name == "raw"
    assert p.name == "dnsx.jsonl"


def test_manifest_records_an_absent_tool_version_as_null(tmp_path):
    """A tool that reports no version must serialise as null, never "None".

    trufflehog prints "trufflehog dev" and arjun has no version flag, so
    binaries.verify returns version=None for them. The manifest is the
    evidence trail for which tool version produced which finding, so absence
    has to read as absence — the string "None" would look like a version.
    """
    ctx = RunContext.create(cfg(tmp_path))
    ctx.tool_versions["nuclei"] = "3.11.0"
    ctx.tool_versions["arjun"] = None
    ctx.write_manifest([])
    raw = (ctx.run_dir / "run.json").read_text()
    m = json.loads(raw)
    assert m["tool_versions"]["nuclei"] == "3.11.0"
    assert m["tool_versions"]["arjun"] is None
    assert '"None"' not in raw


def test_log_appends_to_sweep_log(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    ctx.log("hello")
    assert "hello" in (ctx.run_dir / "sweep.log").read_text()


def test_manifest_records_versions_status_and_refusals(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    ctx.tool_versions["dnsx"] = "1.2.3"
    ctx.scope.filter(["evil.test"])
    ctx.write_manifest([
        StageResult(stage="dnsx", status="complete", artifacts=4),
        StageResult(stage="naabu", status="skipped",
                    failure=FailureClass.NO_INPUT, reason="no hosts"),
    ])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["tool_versions"]["dnsx"] == "1.2.3"
    assert m["stages"]["naabu"]["failure"] == "NO_INPUT"
    assert m["scope"]["refusals"][0]["target"] == "evil.test"
    assert m["level"] == "mid"
    # skipped + NO_INPUT is a correct outcome: nothing to consume, not a gap.
    assert m["degraded"] is False


# --- discoveries_refused: a separate manifest key from refusals ------------
# Routine tool discoveries outside scope (runner.py's admission control) must
# not be recorded under "refusals" -- that key means "the operator supplied
# an out-of-scope target". They get their own key so a reader (and any
# future tooling) cannot conflate the two.


def test_manifest_records_discoveries_refused_separately_from_refusals(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    ctx.scope.filter(["operator-supplied-evil.example"])
    ctx.scope.record_discovery_refusal(
        stage="subfinder", kind="HOST",
        value="discovered-evil.example", host="discovered-evil.example",
    )
    ctx.write_manifest([])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["scope"]["refusals"][0]["target"] == "operator-supplied-evil.example"
    assert m["scope"]["discoveries_refused"] == [
        {"stage": "subfinder", "kind": "HOST",
         "value": "discovered-evil.example", "host": "discovered-evil.example"}
    ]
    # Neither list's entries appear in the other.
    assert not any(r["target"] == "discovered-evil.example"
                   for r in m["scope"]["refusals"])


def test_many_discoveries_refused_do_not_affect_degraded(tmp_path):
    """A subfinder run turning up 200 out-of-scope subdomains is a
    successful run, not a degraded one -- this accounting must not feed
    is_degraded (which reads `results` and `coverage`, neither of which
    discoveries_refused touches)."""
    ctx = RunContext.create(cfg(tmp_path))
    for i in range(200):
        ctx.scope.record_discovery_refusal(
            stage="subfinder", kind="HOST",
            value=f"evil{i}.example", host=f"evil{i}.example",
        )
    ctx.write_manifest([StageResult(stage="subfinder", status="complete", artifacts=0)])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert len(m["scope"]["discoveries_refused"]) == 200
    assert m["degraded"] is False


def test_context_picks_one_user_agent_per_run(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    assert ctx.user_agent in USER_AGENTS
    # Stable for the life of the run: every stage must send the same one.
    assert {ctx.user_agent for _ in range(20)} == {ctx.user_agent}


def test_context_honors_fixed_user_agent(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("example.com\n")
    expected = "Mozilla/5.0 fixed-engagement-agent"
    ctx = RunContext.create(RunConfig(
        targets_file=t, outdir=tmp_path / "out", user_agent=expected,
    ))
    assert ctx.user_agent == expected


def test_manifest_records_the_user_agent_that_was_sent(tmp_path):
    """A reader must be able to tell exactly what was sent, and replay it."""
    ctx = RunContext.create(cfg(tmp_path))
    ctx.write_manifest([StageResult(stage="httpx", status="complete")])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["user_agent"] in USER_AGENTS
    assert m["user_agent"] == ctx.user_agent


def test_manifest_marks_run_degraded_when_a_stage_is_skipped(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    ctx.write_manifest([
        StageResult(stage="naabu", status="skipped",
                    failure=FailureClass.MISSING_BINARY, reason="not found"),
    ])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["degraded"] is True


def test_manifest_marks_run_degraded_when_a_failed_stage_carries_no_input(tmp_path):
    """A failed stage is never a nothing-to-consume case, whatever its class.

    Exempting it would let a run where a stage failed be read as full
    coverage, which is exactly what the degraded flag exists to prevent.
    """
    ctx = RunContext.create(cfg(tmp_path))
    ctx.write_manifest([
        StageResult(stage="httpx", status="failed",
                    failure=FailureClass.NO_INPUT, reason="crashed mid-run"),
    ])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["degraded"] is True


def test_manifest_is_not_degraded_when_every_stage_completes(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    ctx.write_manifest([
        StageResult(stage="dnsx", status="complete", artifacts=4),
        StageResult(stage="httpx", status="complete", artifacts=2),
    ])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["degraded"] is False


# --- Stale acknowledgements must not outlive their level -------------------
# Acknowledge `full`, then load a `mid` profile: the `full` record must not
# land in that run's manifest -- it no longer describes what actually ran,
# and it over-attests an authorisation that was never exercised for THIS run.


def test_manifest_filters_out_an_acknowledgement_for_a_different_level(tmp_path):
    ctx = RunContext.create(cfg(tmp_path, level="mid"))
    ctx.acknowledgements = [
        {"level": "full", "phrase": "I ACKNOWLEDGE", "via": "menu",
         "at": "2026-07-29T00:00:00Z"},
    ]
    ctx.write_manifest([])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["level"] == "mid"
    assert m["acknowledgements"] == []


def test_manifest_keeps_an_acknowledgement_matching_the_final_level(tmp_path):
    ctx = RunContext.create(cfg(tmp_path, level="full"))
    ack = {"level": "full", "phrase": "I ACKNOWLEDGE", "via": "menu",
           "at": "2026-07-29T00:00:00Z"}
    ctx.acknowledgements = [ack]
    ctx.write_manifest([])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["acknowledgements"] == [ack]


def test_manifest_keeps_only_the_acknowledgement_matching_the_final_level(tmp_path):
    """Mixed acknowledgements: only the one for the run's actual level survives."""
    ctx = RunContext.create(cfg(tmp_path, level="high"))
    stale = {"level": "full", "phrase": "I ACKNOWLEDGE", "via": "menu",
             "at": "2026-07-29T00:00:00Z"}
    current = {"level": "high", "phrase": "y", "via": "menu",
               "at": "2026-07-29T00:00:01Z"}
    ctx.acknowledgements = [stale, current]
    ctx.write_manifest([])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["acknowledgements"] == [current]


# --- The coverage denominator: the manifest must show what was requested --
# is_degraded can only react to StageResults that exist. A refused target or
# a stage that never made it into `results` are invisible to `any()` over
# results alone -- Coverage is the denominator that catches them, and it
# must be visible in the manifest, not just folded into the boolean.


def test_manifest_records_the_coverage_denominator(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    ctx.coverage = Coverage(targets_requested=2, targets_permitted=1,
                            stages_requested=["dnsx", "naabu"])
    ctx.write_manifest([StageResult(stage="dnsx", status="complete")])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["coverage"] == {
        "targets_requested": 2,
        "targets_permitted": 1,
        "stages_requested": ["dnsx", "naabu"],
    }


def test_manifest_is_degraded_when_coverage_shows_a_refused_target(tmp_path):
    """The exact shape of the mechanism finding: every stage in the
    manifest can read 'complete' and the run is still degraded, because a
    target the scope guard refused never became a StageResult at all."""
    ctx = RunContext.create(cfg(tmp_path))
    ctx.coverage = Coverage(targets_requested=2, targets_permitted=1,
                            stages_requested=["dnsx"])
    ctx.write_manifest([StageResult(stage="dnsx", status="complete")])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["stages"]["dnsx"]["status"] == "complete"
    assert m["degraded"] is True


def test_manifest_is_degraded_when_a_requested_stage_has_no_result(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["dnsx", "naabu"])
    ctx.write_manifest([StageResult(stage="dnsx", status="complete")])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert "naabu" not in m["stages"]
    assert m["degraded"] is True


def test_manifest_not_degraded_when_coverage_is_full_and_default_unset(tmp_path):
    """A caller that never sets ctx.coverage (its zero/empty default) must
    not have that absence itself read as a gap."""
    ctx = RunContext.create(cfg(tmp_path))
    ctx.write_manifest([StageResult(stage="dnsx", status="complete")])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["coverage"] == {
        "targets_requested": 0, "targets_permitted": 0, "stages_requested": [],
    }
    assert m["degraded"] is False


def test_new_run_dir_never_reuses_an_existing_directory(tmp_path, monkeypatch):
    """Two runs in the same wall-clock second must not share a directory.

    The clock is frozen so the collision is forced rather than hoped for.
    """
    fixed = datetime(2026, 7, 29, 12, 0, 0)

    class FrozenClock:
        @staticmethod
        def now(tz=None):
            return fixed if tz is None else datetime.now(tz)

    monkeypatch.setattr("sweeper.context.datetime", FrozenClock)

    out = tmp_path / "out"
    first = new_run_dir(out)
    (first / "run.json").write_text("first run")

    second = new_run_dir(out)
    third = new_run_dir(out)

    assert first.name == "20260729-120000"
    assert second.name == "20260729-120000-2"
    assert third.name == "20260729-120000-3"
    assert len({first, second, third}) == 3
    assert second.exists() and third.exists()
    # the first run's audit trail survives the later runs
    assert (first / "run.json").read_text() == "first run"


# --- the manifest's finding count must equal what the store holds ----------
# Previously result.findings counted every Finding a stage YIELDED, which
# could exceed what ctx.store actually kept -- an internal contradiction in
# a document (run.json) that is client-facing evidence. These pin the fix at
# the manifest layer: the number written to disk must never be larger than
# reality, with or without a collision in play.


def test_manifest_finding_count_matches_the_store_with_no_collisions(tmp_path):
    ctx = RunContext.create(cfg(tmp_path))
    ctx.store.add_finding(Finding(stage="dnsx", severity="high", title="A",
                                  target="acc.example", template_id="t-a"))
    ctx.store.add_finding(Finding(stage="dnsx", severity="low", title="B",
                                  target="acc.example", template_id="t-b"))
    result = StageResult(stage="dnsx", status="complete", findings=2)
    ctx.write_manifest([result])
    m = json.loads((ctx.run_dir / "run.json").read_text())
    assert m["stages"]["dnsx"]["findings"] == 2
    assert m["findings_stored"] == len(ctx.store.findings) == 2
    assert m["stages"]["dnsx"]["collisions"] == 0
    assert m["finding_collisions"] == []


def test_manifest_finding_count_matches_the_store_with_a_collision(tmp_path):
    """A stage whose matcher fails to distinguish two different findings
    must not have the manifest claim it stored both -- the store only kept
    one, and the manifest's number must not exceed that.
    """
    ctx = RunContext.create(cfg(tmp_path))
    ctx.store.add_finding(Finding(stage="dnsx", severity="high", title="First",
                                  target="acc.example", template_id="t-a",
                                  evidence="one"))
    ctx.store.add_finding(Finding(stage="dnsx", severity="high", title="Second",
                                  target="acc.example", template_id="t-a",
                                  evidence="two"))
    # Only the first was ever actually stored -- StageResult.findings must
    # reflect that (this is what runner.py now guarantees; set directly here
    # since write_manifest is being unit-tested in isolation from run_stages).
    result = StageResult(stage="dnsx", status="complete", findings=1)
    ctx.write_manifest([result])
    m = json.loads((ctx.run_dir / "run.json").read_text())

    assert len(ctx.store.findings) == 1
    assert m["stages"]["dnsx"]["findings"] == 1
    assert m["findings_stored"] == 1
    assert m["stages"]["dnsx"]["collisions"] == 1
    assert len(m["finding_collisions"]) == 1
    # No number anywhere claims more findings than the store actually holds.
    assert m["stages"]["dnsx"]["findings"] <= m["findings_stored"]


def test_manifest_finding_collisions_carry_identity_never_values(tmp_path):
    """sweep.log and run.json must never carry a Finding's evidence or
    matcher -- matcher can itself be a secret fingerprint once
    secrets-detection stages set it. Only field NAMES may appear.
    """
    ctx = RunContext.create(cfg(tmp_path))
    secret_evidence = "AKIAABCDEFGHIJKLMNOP-super-secret-value"
    ctx.store.add_finding(Finding(stage="secrets", severity="critical", title="Key",
                                  target="acc.example", template_id="t-key",
                                  evidence=secret_evidence, matcher="matcher-secret"))
    ctx.store.add_finding(Finding(stage="secrets", severity="critical", title="Key",
                                  target="acc.example", template_id="t-key",
                                  evidence="a completely different secret",
                                  matcher="matcher-secret"))
    ctx.write_manifest([StageResult(stage="secrets", status="complete", findings=1)])
    manifest_text = (ctx.run_dir / "run.json").read_text(encoding="utf-8")
    log = (ctx.run_dir / "sweep.log").read_text(encoding="utf-8")
    assert secret_evidence not in manifest_text
    assert "matcher-secret" not in manifest_text
    assert secret_evidence not in log
    assert "matcher-secret" not in log
    # But the collision is still there, and still actionable by identity.
    manifest = json.loads(manifest_text)
    assert manifest["finding_collisions"][0]["differing_fields"] == ["evidence"]


# --- the manifest carries the WHOLE RunConfig (B6) -------------------------
#
# run.json used to record only level, auth_mode, targets_file and proxy, so
# --resume rebuilt its config from those four and silently dropped the
# operator's custom templates (unrecoverable -- nothing else records them),
# their per-stage time limit, and their rate override, which fell back to the
# level default: a measured 20x increase over a rate chosen for a client
# no-DoS rule.

def test_manifest_records_every_run_config_field(tmp_path):
    """Enumerated from dataclasses.fields, so a field added to RunConfig and
    forgotten in to_manifest() fails here rather than going missing from
    every resumed run."""
    import dataclasses
    ctx = RunContext.create(cfg(tmp_path))
    ctx.write_manifest([])
    recorded = json.loads((ctx.run_dir / "run.json").read_text())["config"]
    assert set(recorded) == {f.name for f in dataclasses.fields(RunConfig)}


def test_run_config_round_trips_through_the_manifest(tmp_path):
    original = cfg(tmp_path, level="high", rate_override=50, time_limit="45m",
                   subdomain_enum=True, verify_secrets=True,
                   proxy="http://127.0.0.1:8080", stages=["dnsx", "naabu"],
                   custom_templates="/srv/client-templates",
                   triage_file=tmp_path / "triage.json")
    assert RunConfig.from_manifest(original.to_manifest()) == original


def test_run_config_survives_json(tmp_path):
    """to_manifest() output must be JSON-serialisable: Path fields are the
    reason this is not free."""
    original = cfg(tmp_path, triage_file=tmp_path / "triage.json")
    blob = json.loads(json.dumps(original.to_manifest()))
    assert RunConfig.from_manifest(blob) == original


@pytest.mark.parametrize("field,bad", [
    ("level", 12),                 # a number where a level string belongs
    ("stages", "dnsx,naabu"),      # a string where a list belongs
    ("stages", [1, 2]),            # a list of the wrong element type
    ("rate_override", True),       # bool is an int subclass: must not pass
    ("rate_override", "50"),
    ("subdomain_enum", 1),         # ...and the mirror image
    ("time_limit", 45),
    ("triage_file", 7),
    ("preflight_timeout", "3.0"),
])
def test_a_manifest_value_of_the_wrong_shape_falls_back_to_the_default(
        tmp_path, field, bad):
    """Fail SOFT per field, and CLOSED: a truncated or hand-edited run.json
    must not make a run directory unresumable, and must never pass raw JSON
    through into a RunConfig field."""
    data = cfg(tmp_path).to_manifest()
    data[field] = bad
    restored = RunConfig.from_manifest(data)
    assert getattr(restored, field) == getattr(cfg(tmp_path), field)


def test_from_manifest_overrides_win_over_the_recorded_values(tmp_path):
    """resume pins targets_file and outdir to the run directory: the
    manifest's targets_file may since have been edited, moved, or repointed
    at a different engagement."""
    data = cfg(tmp_path).to_manifest()
    pinned = tmp_path / "run" / "targets.txt"
    restored = RunConfig.from_manifest(data, targets_file=pinned)
    assert restored.targets_file == pinned


def test_from_manifest_tolerates_a_missing_or_junk_block(tmp_path):
    t = tmp_path / "t.txt"
    assert RunConfig.from_manifest({}, targets_file=t).level == "mid"
    assert RunConfig.from_manifest(None, targets_file=t).level == "mid"
