import json
from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.scope import ScopeGuard
from sweeper.store import ArtifactStore


def test_add_and_get_roundtrip(tmp_path):
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example"))
    s.add(Artifact(ArtifactKind.HOST, "b.example"))
    assert {a.value for a in s.get(ArtifactKind.HOST)} == {"a.example", "b.example"}


def test_duplicate_artifacts_are_deduped(tmp_path):
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"src": "file"}))
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"src": "subfinder"}))
    assert len(s.get(ArtifactKind.HOST)) == 1


def test_add_merges_new_meta_keys_into_an_existing_artifact(tmp_path):
    """First write wins per KEY, not per artifact.

    The old per-artifact rule silently defeated every stage that annotates a
    host it did not discover: app.prepare() seeds each target as a HOST
    before any stage runs, so cdncheck/tlsx/httpx/nmap re-yielding that host
    with richer meta hit an existing key and lost the enrichment entirely.
    """
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"src": "targets-file"}))
    s.add(Artifact(ArtifactKind.HOST, "a.example",
                   meta={"cdn": True, "cdn_name": "cloudflare"}))

    host = s.get(ArtifactKind.HOST)[0]
    assert host.meta == {"src": "targets-file", "cdn": True,
                         "cdn_name": "cloudflare"}


def test_first_writer_of_a_key_wins_on_conflict(tmp_path):
    """A later stage never overwrites a key another stage already set.

    Last-wins would let a late stage silently replace an earlier, possibly
    finding-relevant fact with nothing recording the change. Disagreement
    between two tools is real signal, but it needs somewhere to be recorded
    rather than being silently resolved in favour of whoever ran last.
    """
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"ip": "1.1.1.1"}))
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"ip": "2.2.2.2"}))
    assert s.get(ArtifactKind.HOST)[0].meta["ip"] == "1.1.1.1"


def test_list_metadata_is_union_merged_for_multi_address_coverage(tmp_path):
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.PORT, "a.example:443",
                   meta={"ips": ["192.0.2.1"]}))
    s.add(Artifact(ArtifactKind.PORT, "a.example:443",
                   meta={"ips": ["192.0.2.2", "192.0.2.1"]}))
    assert s.get(ArtifactKind.PORT)[0].meta["ips"] == [
        "192.0.2.1", "192.0.2.2",
    ]


def test_meta_merge_does_not_duplicate_the_artifact(tmp_path):
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"src": "file"}))
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"cdn": True}))
    assert len(s.get(ArtifactKind.HOST)) == 1
    assert s.values(ArtifactKind.HOST) == ["a.example"]


def test_enrichment_before_first_flush_is_written_once_already_merged(tmp_path):
    """No re-emitted row is needed when nothing was on disk yet."""
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"src": "file"}))
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"cdn": True}))
    s.flush()
    rows = [json.loads(l)
            for l in (tmp_path / "artifacts" / "hosts.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["meta"] == {"src": "file", "cdn": True}


def test_enrichment_after_flush_is_re_emitted_so_disk_matches_memory(tmp_path):
    """Append-only plus post-flush enrichment makes this file a journal.

    The row cannot be edited in place without abandoning the append-only
    guarantee, so the current state is re-appended and the LAST row for a
    value is the current one. Leaving it out would mean the on-disk evidence
    trail contradicts the store — stale data presenting as current.
    """
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"src": "file"}))
    s.flush()
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"cdn": True}))
    s.flush()

    rows = [json.loads(l)
            for l in (tmp_path / "artifacts" / "hosts.jsonl").read_text().splitlines()]
    assert [r["value"] for r in rows] == ["a.example", "a.example"]
    assert rows[0]["meta"] == {"src": "file"}
    assert rows[-1]["meta"] == {"src": "file", "cdn": True}


def test_a_redundant_add_after_flush_emits_no_new_row(tmp_path):
    """Only a real change re-emits; re-adding identical meta is still a no-op."""
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"src": "file"}))
    s.flush()
    s.add(Artifact(ArtifactKind.HOST, "a.example", meta={"src": "file"}))
    s.flush()
    rows = (tmp_path / "artifacts" / "hosts.jsonl").read_text().splitlines()
    assert len(rows) == 1


def test_get_empty_kind_returns_empty_list(tmp_path):
    s = ArtifactStore(tmp_path)
    assert s.get(ArtifactKind.PORT) == []


def test_flush_writes_jsonl(tmp_path):
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.PORT, "a.example:443"))
    s.flush()
    p = tmp_path / "artifacts" / "ports.jsonl"
    assert p.exists()
    rows = [json.loads(l) for l in p.read_text().splitlines()]
    assert rows[0]["value"] == "a.example:443"


def test_findings_deduped_by_id_and_flushed(tmp_path):
    s = ArtifactStore(tmp_path)
    f = Finding(stage="dnsx", severity="high", title="AXFR",
                target="ns1.example", template_id="dns-axfr")
    s.add_finding(f)
    s.add_finding(f)
    s.flush()
    rows = (tmp_path / "artifacts" / "findings.jsonl").read_text().splitlines()
    assert len(rows) == 1
    assert json.loads(rows[0])["severity"] == "high"


def test_flush_is_idempotent(tmp_path):
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example"))
    s.flush()
    s.flush()
    rows = (tmp_path / "artifacts" / "hosts.jsonl").read_text().splitlines()
    assert len(rows) == 1


def test_flush_appends_only_new_artifacts(tmp_path):
    """A second flush after new data appends just the delta, in insertion order."""
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example"))
    s.flush()
    s.add(Artifact(ArtifactKind.HOST, "b.example"))
    s.flush()
    rows = [json.loads(l)
            for l in (tmp_path / "artifacts" / "hosts.jsonl").read_text().splitlines()]
    assert [r["value"] for r in rows] == ["a.example", "b.example"]


def test_artifact_flush_does_not_rewrite_existing_file(tmp_path):
    """Flush must append, never rewrite.

    A sentinel written between the two flushes survives an append-only
    implementation and is destroyed by one that reopens in 'w' mode and
    dumps the whole list each time.
    """
    p = tmp_path / "artifacts" / "hosts.jsonl"
    s = ArtifactStore(tmp_path)
    s.add(Artifact(ArtifactKind.HOST, "a.example"))
    s.flush()

    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"sentinel": True}) + "\n")

    s.add(Artifact(ArtifactKind.HOST, "b.example"))
    s.flush()

    rows = [json.loads(l) for l in p.read_text().splitlines()]
    assert len(rows) == 3
    assert rows[1] == {"sentinel": True}
    assert [r["value"] for r in rows if "value" in r] == ["a.example", "b.example"]


def _finding(template_id: str) -> Finding:
    return Finding(stage="dnsx", severity="high", title="AXFR",
                   target="ns1.example", template_id=template_id)


def test_flush_appends_only_new_findings(tmp_path):
    """Findings have their own flush bookkeeping; it must also be a delta."""
    s = ArtifactStore(tmp_path)
    s.add_finding(_finding("dns-axfr"))
    s.flush()
    s.add_finding(_finding("dns-takeover"))
    s.flush()
    rows = [json.loads(l)
            for l in (tmp_path / "artifacts" / "findings.jsonl").read_text().splitlines()]
    assert [r["template_id"] for r in rows] == ["dns-axfr", "dns-takeover"]


def test_finding_flush_does_not_rewrite_existing_file(tmp_path):
    """Same append-only guarantee as artifacts, on the findings code path."""
    p = tmp_path / "artifacts" / "findings.jsonl"
    s = ArtifactStore(tmp_path)
    s.add_finding(_finding("dns-axfr"))
    s.flush()

    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"sentinel": True}) + "\n")

    s.add_finding(_finding("dns-takeover"))
    s.flush()

    rows = [json.loads(l) for l in p.read_text().splitlines()]
    assert len(rows) == 3
    assert rows[1] == {"sentinel": True}
    assert [r["template_id"] for r in rows
            if "template_id" in r] == ["dns-axfr", "dns-takeover"]


# --- Finding id collisions: the defect this task fixes ---------------------
#
# Before this change, add_finding() was a plain `self._findings.setdefault
# (finding.id, finding)`. Two Findings with the same (stage, target,
# template_id) and no distinguishing matcher hash to the same id, and
# setdefault silently kept whichever was submitted first -- no error, no
# count, nothing in the manifest. In a pentest report that is a real
# finding quietly missing from a client deliverable, which is why the tests
# below check both halves: a resubmission of the SAME finding must still
# dedupe (run-to-run diffing depends on that), and a collision between TWO
# DIFFERENT findings must now be impossible to miss.

def _finding_with(template_id="dns-axfr", evidence="", first_seen="",
                   severity="high", target="ns1.example", matcher=""):
    return Finding(stage="dnsx", severity=severity, title="AXFR",
                    target=target, template_id=template_id,
                    matcher=matcher, evidence=evidence, first_seen=first_seen)


def test_identical_finding_resubmitted_is_still_deduped_to_one(tmp_path):
    """The setdefault behaviour this replaces must not regress."""
    s = ArtifactStore(tmp_path)
    a = _finding_with(evidence="same")
    b = _finding_with(evidence="same")
    assert a.id == b.id
    s.add_finding(a)
    s.add_finding(b)
    assert len(s.findings) == 1
    assert s.finding_collisions == []


def test_first_seen_difference_alone_is_not_a_collision(tmp_path):
    """A rerun that finds the same issue again must not look like a bug.

    first_seen is a timestamp; two submissions of the same finding will
    almost always carry different first_seen values, and that must not be
    treated as two different findings.
    """
    s = ArtifactStore(tmp_path)
    a = _finding_with(evidence="same", first_seen="2026-01-01T00:00:00Z")
    b = _finding_with(evidence="same", first_seen="2026-06-01T00:00:00Z")
    assert a.id == b.id
    s.add_finding(a)
    s.add_finding(b)
    assert len(s.findings) == 1
    assert s.finding_collisions == []


def test_two_different_findings_sharing_an_id_are_surfaced_not_dropped(tmp_path):
    """The bug this task fixes: same id, different content.

    This is what a stage with an under-specified matcher produces (two
    private IPs on one host, two weak ciphers on one endpoint, before
    dnsx.py/tlsx.py were fixed to give each a distinguishing matcher). The
    second finding must not silently vanish: it must be counted in
    finding_collisions and logged to sweep.log.
    """
    s = ArtifactStore(tmp_path)
    kept = _finding_with(evidence="10.0.0.5")
    dropped = _finding_with(evidence="192.168.1.9")
    assert kept.id == dropped.id  # the actual defect: same id, different fact

    s.add_finding(kept)
    s.add_finding(dropped)

    # First-submitted is kept, deterministically -- but the collision is
    # now impossible to miss.
    assert len(s.findings) == 1
    assert s.findings[0] is kept
    assert len(s.finding_collisions) == 1
    collision = s.finding_collisions[0]
    assert collision["id"] == kept.id
    assert collision["stage"] == "dnsx"
    assert collision["target"] == "ns1.example"
    assert collision["template_id"] == "dns-axfr"
    assert collision["differing_fields"] == ["evidence"]

    log = (tmp_path / "sweep.log").read_text(encoding="utf-8")
    assert "FINDING ID COLLISION" in log
    assert kept.id in log
    assert "evidence" in log


def test_finding_collision_never_logs_evidence_matcher_or_secret_material(tmp_path):
    """A collision between two findings whose evidence carries a live
    secret must not write that secret to sweep.log or the run manifest.

    This is the exact failure this project has already fixed once for argv
    (runner._redact_command), for SecretBundle's __repr__, and for the
    nuclei secret file's permissions: a control that redacts at the point
    data EXITS a structure only works if every future exit point remembers
    to call it. Logging finding.evidence (or finding.matcher, which a
    secrets-detecting stage may legitimately set TO the secret value, so
    that two different secrets don't collide onto one id) would silently
    reopen that hole for the collision path specifically. Assert on the
    literal secret value, not on log format, so a future change to the
    message wording can't hide a regression here.
    """
    SECRET = "sk_live_9f3c2b7a1e4d6a8b0c2e4f6a8b0c2e4f"

    s = ArtifactStore(tmp_path)
    kept = _finding_with(evidence=f"leaked-key={SECRET}", matcher=SECRET)
    dropped = _finding_with(evidence=f"leaked-key={SECRET}-rotated",
                             matcher=SECRET)
    assert kept.id == dropped.id

    s.add_finding(kept)
    s.add_finding(dropped)
    assert len(s.finding_collisions) == 1

    log = (tmp_path / "sweep.log").read_text(encoding="utf-8")
    assert SECRET not in log

    # The in-memory collision record itself must not carry the secret
    # either -- anything that later serialises finding_collisions (a test,
    # a future manifest writer) inherits the redaction for free only if the
    # record never held the value in the first place.
    assert SECRET not in json.dumps(s.finding_collisions)

    # Full defence in depth: build a real manifest off this store and
    # confirm the secret does not reach run.json either.
    config = RunConfig(targets_file=tmp_path / "targets.txt")
    ctx = RunContext(config, tmp_path, s, ScopeGuard(set()))
    ctx.write_manifest([])
    manifest_text = (tmp_path / "run.json").read_text(encoding="utf-8")
    assert SECRET not in manifest_text


def test_finding_diff_fields_ignores_first_seen_and_raw_ref():
    from sweeper.artifacts import finding_diff_fields
    a = _finding_with(evidence="same")
    a.raw_ref = "raw/dnsx.jsonl#L1"
    a.first_seen = "2026-01-01T00:00:00Z"
    b = _finding_with(evidence="same")
    b.raw_ref = "raw/dnsx.jsonl#L9"
    b.first_seen = "2026-06-01T00:00:00Z"
    assert finding_diff_fields(a, b) == []

    b.evidence = "different"
    assert finding_diff_fields(a, b) == ["evidence"]


# --- restore_finding_collisions (B6) ---------------------------------------

def test_restored_collisions_are_visible_to_every_consumer(tmp_path):
    """A collision cannot be re-derived from findings.jsonl -- only the FIRST
    of a colliding pair is ever written there -- so a resumed run that does
    not take the record back reports zero collisions for a run that had them,
    erasing the undercount warning the manifest, both reports and diff.py all
    read off this one list."""
    store = ArtifactStore(tmp_path)
    store.restore_finding_collisions([
        {"id": "abc", "stage": "dnsx", "target": "acc.example",
         "template_id": "tpl", "differing_fields": ["evidence"]},
    ])
    assert [c["stage"] for c in store.finding_collisions] == ["dnsx"]


def test_restore_finding_collisions_ignores_junk_rows(tmp_path):
    """The input is a JSON file that may have been truncated by the very
    crash the resume exists to recover from."""
    store = ArtifactStore(tmp_path)
    store.restore_finding_collisions(None)
    store.restore_finding_collisions(["not a dict", 7, None, {"stage": "ok"}])
    assert store.finding_collisions == [{"stage": "ok"}]


def test_restored_collisions_do_not_become_findings(tmp_path):
    store = ArtifactStore(tmp_path)
    store.restore_finding_collisions([{"stage": "dnsx"}])
    assert store.findings == []


# --- mark_all_flushed (O3.1) -----------------------------------------------
#
# The control this section guards: `resume.restore_store()` repopulates a
# FRESH ArtifactStore from a previous run's artifacts/*.jsonl, and that store's
# flushed high-water marks all start at 0. Without mark_all_flushed() the next
# flush() re-appends every restored row to the very file it was read from, so
# each resume doubles the journal. That is not cosmetic: findings.jsonl is what
# diff.py loads and what the manifest's `findings_stored` is reconciled
# against, and hosts/ports/services.jsonl are the run's evidence trail.
#
# Both halves are pinned deliberately -- the body here, the call site in
# tests/test_resume.py -- because deleting either one on its own reproduces
# the duplication.

#: Every kind that has a file of its own, derived from the enum rather than
#: listed, so a new ArtifactKind is covered here the day it is added.
_PERSISTED_KINDS = [k for k in ArtifactKind if k is not ArtifactKind.FINDING]


def _seed(store):
    """One artifact of every persisted kind, plus one finding."""
    for kind in _PERSISTED_KINDS:
        store.add(Artifact(kind, f"{kind.name.lower()}.example",
                           meta={"src": "first-run"}))
    store.add_finding(Finding(stage="dnsx", severity="low", title="t",
                              target="acc.example", template_id="tpl"))


def _journal(run_dir):
    """Every artifact file's rows, keyed by filename."""
    d = run_dir / "artifacts"
    return {p.name: p.read_text(encoding="utf-8").splitlines()
            for p in sorted(d.iterdir())} if d.is_dir() else {}


def test_mark_all_flushed_stops_a_restored_store_duplicating_the_journal(tmp_path):
    """Replay of what resume does: read the rows back into a fresh store,
    declare them persisted, flush. Nothing may be appended."""
    first = ArtifactStore(tmp_path)
    _seed(first)
    first.flush()
    before = _journal(tmp_path)
    # Guard against the test passing because nothing was ever written.
    assert len(before) == len(_PERSISTED_KINDS) + 1
    assert all(len(rows) == 1 for rows in before.values()), before

    resumed = ArtifactStore(tmp_path)
    _seed(resumed)                    # what restore_store() does, in effect
    resumed.mark_all_flushed()
    resumed.flush()

    assert _journal(tmp_path) == before


def test_mark_all_flushed_covers_findings_as_well_as_artifacts(tmp_path):
    """findings.jsonl is written by a separate branch of flush() with its own
    high-water mark, so it needs its own assertion: a duplicated finding row
    inflates every count reconciled against that file."""
    first = ArtifactStore(tmp_path)
    _seed(first)
    first.flush()

    resumed = ArtifactStore(tmp_path)
    _seed(resumed)
    resumed.mark_all_flushed()
    resumed.flush()

    rows = _journal(tmp_path)["findings.jsonl"]
    assert len(rows) == 1


def test_mark_all_flushed_leaves_later_enrichment_still_re_emitted(tmp_path):
    """The high-water mark is not the only state it has to set.

    A restored value must also land in `_flushed_values`, or a stage that
    ENRICHES a restored artifact during the resumed run is never marked dirty
    and its corrected meta never reaches disk -- the on-disk row keeps saying
    something the store has since corrected, which is the exact
    stale-data-presenting-as-current failure flush()'s journal design exists
    to prevent.
    """
    first = ArtifactStore(tmp_path)
    _seed(first)
    first.flush()

    resumed = ArtifactStore(tmp_path)
    _seed(resumed)
    resumed.mark_all_flushed()
    resumed.add(Artifact(ArtifactKind.HOST, "host.example",
                         meta={"cdn_name": "cloudflare"}))
    resumed.flush()

    rows = [json.loads(l) for l in _journal(tmp_path)["hosts.jsonl"]]
    assert len(rows) == 2, "the enriched row was not re-emitted"
    assert rows[-1]["meta"] == {"src": "first-run", "cdn_name": "cloudflare"}


def test_mark_all_flushed_discards_a_pending_re_emit(tmp_path):
    """"Everything currently held is already persisted" has to include the
    dirty set: a row still queued for re-emission is, by that declaration,
    already on disk, and re-emitting it would append a duplicate."""
    store = ArtifactStore(tmp_path)
    store.add(Artifact(ArtifactKind.HOST, "host.example", meta={"src": "a"}))
    store.flush()
    store.add(Artifact(ArtifactKind.HOST, "host.example", meta={"cdn": True}))

    store.mark_all_flushed()
    store.flush()

    assert len(_journal(tmp_path)["hosts.jsonl"]) == 1
