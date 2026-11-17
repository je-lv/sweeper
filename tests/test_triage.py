import json
import pytest
from sweeper.artifacts import Finding
from sweeper.triage import TriageState, STATUSES


def f(template_id="t1", target="acc.example", severity="high"):
    return Finding(stage="nuclei", severity=severity, title="X",
                   target=target, template_id=template_id)


def test_unknown_finding_defaults_to_new(tmp_path):
    t = TriageState(tmp_path / "triage.json")
    assert t.get(f().id) == "new"


def test_set_and_get_roundtrip(tmp_path):
    t = TriageState(tmp_path / "triage.json")
    t.set(f().id, "false-positive", note="publishable key")
    assert t.get(f().id) == "false-positive"


def test_state_persists_across_instances(tmp_path):
    p = tmp_path / "triage.json"
    TriageState(p).set(f().id, "accepted-risk")
    assert TriageState(p).get(f().id) == "accepted-risk"


def test_invalid_status_rejected(tmp_path):
    t = TriageState(tmp_path / "triage.json")
    with pytest.raises(ValueError, match="status"):
        t.set(f().id, "probably-fine")


def test_apply_annotates_findings(tmp_path):
    t = TriageState(tmp_path / "triage.json")
    finding = f()
    t.set(finding.id, "false-positive")
    [annotated] = t.apply([finding])
    assert annotated.triage == "false-positive"


def test_apply_leaves_untriaged_as_new(tmp_path):
    t = TriageState(tmp_path / "triage.json")
    [annotated] = t.apply([f()])
    assert annotated.triage == "new"


def test_notes_preserved(tmp_path):
    p = tmp_path / "triage.json"
    TriageState(p).set(f().id, "false-positive", note="expected public key")
    assert TriageState(p).note(f().id) == "expected public key"


def test_statuses_are_the_documented_four():
    assert set(STATUSES) == {"new", "confirmed", "false-positive", "accepted-risk"}


def test_corrupt_state_file_does_not_crash(tmp_path):
    p = tmp_path / "triage.json"
    p.write_text("{ not json")
    assert TriageState(p).get(f().id) == "new"


def test_empty_file_treated_as_no_state(tmp_path):
    p = tmp_path / "triage.json"
    p.write_text("")
    t = TriageState(p)
    assert t.get(f().id) == "new"
    assert t.load_error is None


def test_corrupt_state_file_is_flagged_loudly(tmp_path, caplog):
    p = tmp_path / "triage.json"
    p.write_text("{ not json")
    with caplog.at_level("WARNING"):
        t = TriageState(p)
    assert t.load_error is not None
    assert "not valid JSON" in t.load_error
    assert any("triage" in rec.message for rec in caplog.records)


def test_unknown_schema_version_is_treated_as_unreadable(tmp_path):
    # A future version of this tool may add fields we do not understand.
    # Refuse to guess at the shape rather than mis-parse it.
    p = tmp_path / "triage.json"
    p.write_text(json.dumps({"schema_version": 999, "findings": {}}))
    t = TriageState(p)
    assert t.get(f().id) == "new"
    assert t.load_error is not None


def test_corrupt_file_is_backed_up_before_first_overwrite(tmp_path):
    p = tmp_path / "triage.json"
    p.write_text("{ not json")
    t = TriageState(p)
    t.set(f().id, "confirmed")
    backup = tmp_path / "triage.json.corrupt"
    assert backup.exists()
    assert backup.read_text() == "{ not json"
    # The live file now holds valid, current state.
    assert TriageState(p).get(f().id) == "confirmed"


def test_re_triage_replaces_the_note_rather_than_keeping_the_old_one(tmp_path):
    # A note explaining a false-positive verdict must not silently linger
    # and read as the rationale for a later, different verdict.
    p = tmp_path / "triage.json"
    t = TriageState(p)
    finding_id = f().id
    t.set(finding_id, "false-positive", note="looks like test data")
    t.set(finding_id, "confirmed")
    assert t.note(finding_id) == ""


def test_set_records_an_auditable_timestamp_and_operator(tmp_path):
    t = TriageState(tmp_path / "triage.json")
    finding_id = f().id
    t.set(finding_id, "accepted-risk", note="client accepted")
    meta = t.meta(finding_id)
    assert meta["status"] == "accepted-risk"
    assert meta["note"] == "client accepted"
    assert meta["updated_at"]
    assert meta["updated_by"]


def test_saved_file_is_owner_only(tmp_path):
    p = tmp_path / "triage.json"
    TriageState(p).set(f().id, "confirmed")
    mode = p.stat().st_mode & 0o777
    assert mode == 0o600


def test_apply_does_not_mutate_the_input_findings(tmp_path):
    # Rendering a report must not have the side effect of changing run
    # state. ctx.store.findings hands out the SAME Finding instances the
    # store holds; apply() must return copies, not edit those in place.
    t = TriageState(tmp_path / "triage.json")
    finding = f()
    t.set(finding.id, "confirmed", note="looked at it")
    [annotated] = t.apply([finding])
    assert annotated is not finding
    assert finding.triage == "new"
    assert finding.triage_note == ""
    assert annotated.triage == "confirmed"
    assert annotated.triage_note == "looked at it"
