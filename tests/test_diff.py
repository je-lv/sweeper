import json
import re
from pathlib import Path

from sweeper.diff import diff_runs, load_findings, load_run, render_diff


def make_run(tmp_path, name, findings):
    d = tmp_path / name / "artifacts"
    d.mkdir(parents=True)
    with (d / "findings.jsonl").open("w") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")
    return tmp_path / name


def finding(template_id, target="acc.example", severity="high", **kw):
    from sweeper.artifacts import Finding
    import dataclasses
    return dataclasses.asdict(
        Finding(stage=kw.pop("stage", "nuclei"), severity=severity,
                title=kw.pop("title", template_id),
                target=target, template_id=template_id, **kw))


def write_manifest(run_dir, *, complete=("nuclei",), incomplete=(),
                   degraded=None, aborted_reason="", findings_stored=None,
                   collisions=(), level="mid", auth_mode="unauth",
                   scope=("acc.example",), omit=()):
    """A manifest in RunContext.write_manifest's shape.

    test_reads_the_real_manifest_written_by_runcontext pins this helper's
    key names against the real writer, so a rename there fails a test here
    rather than silently making every run look unreadable.

    `level`, `auth_mode` and `scope` are how far the run REACHED; two runs
    only compare cleanly when the newer one reached at least as far. `omit`
    drops the named top-level keys entirely, for the manifest-does-not-say
    cases.
    """
    stages = {n: {"status": "complete", "failure": "NONE", "reason": ""}
              for n in complete}
    stages.update({n: {"status": "failed", "failure": "TRANSPORT",
                       "reason": "boom"} for n in incomplete})
    if findings_stored is None:
        path = Path(run_dir) / "artifacts" / "findings.jsonl"
        findings_stored = (
            len([ln for ln in path.read_text().splitlines() if ln.strip()])
            if path.exists() else 0
        )
    manifest = {
        "level": level,
        "auth_mode": auth_mode,
        "scope": {"allowed": sorted(scope), "refusals": [],
                  "extensions": [], "discoveries_refused": []},
        "degraded": bool(incomplete) if degraded is None else degraded,
        "aborted": bool(aborted_reason),
        "aborted_reason": aborted_reason,
        "coverage": {"targets_requested": 1, "targets_permitted": 1,
                     "stages_requested": list(complete) + list(incomplete)},
        "stages": stages,
        "findings_stored": findings_stored,
        "finding_collisions": [
            {"id": "x", "stage": s, "target": "acc.example",
             "template_id": "t", "differing_fields": ["evidence"]}
            for s in collisions
        ],
    }
    for key in omit:
        manifest.pop(key, None)
    (Path(run_dir) / "run.json").write_text(json.dumps(manifest) + "\n")
    return Path(run_dir)


def clean_run(tmp_path, name, findings, **kw):
    """A run whose manifest says every stage completed -- the only shape in
    which an absence is real evidence."""
    return write_manifest(make_run(tmp_path, name, findings), **kw)


# --------------------------------------------------------------------------
# The brief's cases: loading, and the three-way classification.
# --------------------------------------------------------------------------

def test_load_findings_reads_jsonl(tmp_path):
    run = make_run(tmp_path, "r1", [finding("a")])
    assert [f.template_id for f in load_findings(run)] == ["a"]


def test_new_findings_detected(tmp_path):
    a = make_run(tmp_path, "r1", [finding("a")])
    b = make_run(tmp_path, "r2", [finding("a"), finding("b")])
    d = diff_runs(a, b)
    assert [f.template_id for f in d.new] == ["b"]


def test_fixed_findings_detected(tmp_path):
    a = make_run(tmp_path, "r1", [finding("a"), finding("b")])
    b = make_run(tmp_path, "r2", [finding("a")])
    assert [f.template_id for f in diff_runs(a, b).fixed] == ["b"]


def test_persisting_findings_detected(tmp_path):
    a = make_run(tmp_path, "r1", [finding("a")])
    b = make_run(tmp_path, "r2", [finding("a")])
    d = diff_runs(a, b)
    assert [f.template_id for f in d.persisting] == ["a"]
    assert d.new == [] and d.fixed == []


def test_same_template_different_target_is_a_new_finding(tmp_path):
    a = make_run(tmp_path, "r1", [finding("a", target="one.example")])
    b = make_run(tmp_path, "r2", [finding("a", target="two.example")])
    d = diff_runs(a, b)
    assert len(d.new) == 1 and len(d.fixed) == 1


def test_missing_findings_file_is_treated_as_empty(tmp_path):
    a = tmp_path / "empty"; a.mkdir()
    b = make_run(tmp_path, "r2", [finding("a")])
    assert len(diff_runs(a, b).new) == 1


# render_diff emits "## NEW (n)" / "## FIXED (n)" / "## PERSISTING (n)"
# unconditionally, and always writes several paragraphs of caveat prose. So
# `"NEW" in text` and `"b" in text` are both true of a render that lists
# nothing at all -- which is how the previous version of the test below
# passed while asserting nothing about the data. Everything here is read out
# of the SECTION the group heading opens, and the ids are long enough that no
# heading or caveat sentence can contain one by accident.

_HEADING = re.compile(r"^## ([A-Z]+) \((\d+)")


def _sections(text):
    """The rendered diff split at its group headings: {label: (count, body)}.

    Anything before the first heading (title, run line, caveats) is dropped
    on purpose -- that is the prose the old assertions were accidentally
    matching against.
    """
    out, label, count, buf = {}, None, None, []
    for line in text.splitlines():
        m = _HEADING.match(line)
        if m:
            if label is not None:
                out[label] = (count, "\n".join(buf))
            label, count, buf = m.group(1), int(m.group(2)), []
        elif label is not None:
            buf.append(line)
    if label is not None:
        out[label] = (count, "\n".join(buf))
    return out


def test_render_lists_each_finding_under_its_own_group(tmp_path):
    """Every group lists exactly its own findings and nobody else's. A render
    that drops a group's items, or swaps two groups' labels, fails here."""
    a = clean_run(tmp_path, "r1", [finding("shared-tpl"), finding("gone-tpl")])
    b = clean_run(tmp_path, "r2", [finding("shared-tpl"), finding("arrived-tpl")])

    sections = _sections(render_diff(diff_runs(a, b)))
    expected = {"NEW": "arrived-tpl", "FIXED": "gone-tpl",
                "PERSISTING": "shared-tpl"}
    assert set(sections) == set(expected)

    for label, (count, body) in sections.items():
        assert count == 1, f"{label} heading says {count}"
        assert expected[label] in body, f"{label} does not list its finding"
        for other, template_id in expected.items():
            if other != label:
                assert template_id not in body, (
                    f"{label} lists {template_id}, which belongs to {other}")


def test_render_group_heading_counts_match_what_the_group_lists(tmp_path):
    """The count in the heading is the number a reader trusts without
    counting the bullets. Uneven group sizes, so a heading that prints any
    single group's size for all three cannot pass."""
    a = clean_run(tmp_path, "r1", [finding("keep-tpl"),
                                   finding("gone-one"), finding("gone-two")])
    b = clean_run(tmp_path, "r2", [finding("keep-tpl"), finding("new-one"),
                                   finding("new-two"), finding("new-three")])

    sections = _sections(render_diff(diff_runs(a, b)))
    assert {k: v[0] for k, v in sections.items()} == {
        "NEW": 3, "FIXED": 2, "PERSISTING": 1}
    for label, (count, body) in sections.items():
        listed = [l for l in body.splitlines() if l.startswith("- ")]
        assert count == len(listed), (
            f"{label} heading says {count} but lists {len(listed)}")


def test_render_of_an_empty_group_lists_nothing_under_it(tmp_path):
    """Zero is a claim too: 'FIXED (0)' with a bullet under it would be the
    report contradicting itself in adjacent lines."""
    a = clean_run(tmp_path, "r1", [finding("shared-tpl")])
    b = clean_run(tmp_path, "r2", [finding("shared-tpl")])

    sections = _sections(render_diff(diff_runs(a, b)))
    for label in ("NEW", "FIXED"):
        count, body = sections[label]
        assert count == 0
        assert [l for l in body.splitlines() if l.startswith("- ")] == []
    assert sections["PERSISTING"][0] == 1


def test_argument_order_decides_which_side_is_new(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("a")])
    b = clean_run(tmp_path, "r2", [finding("b")])
    forward, backward = diff_runs(a, b), diff_runs(b, a)
    assert [f.template_id for f in forward.new] == ["b"]
    assert [f.template_id for f in backward.new] == ["a"]


# --------------------------------------------------------------------------
# findings.jsonl is a JOURNAL (see ArtifactStore.flush): a value may appear
# more than once and the LAST row for it is current.
# --------------------------------------------------------------------------

def test_repeated_id_collapses_to_the_last_row(tmp_path):
    run = make_run(tmp_path, "r1", [
        finding("a", evidence="stale"),
        finding("a", evidence="current"),
    ])
    loaded = load_findings(run)
    assert len(loaded) == 1
    assert loaded[0].evidence == "current"


def test_repeated_id_does_not_inflate_a_group(tmp_path):
    a = clean_run(tmp_path, "r1", [], findings_stored=0)
    b = clean_run(tmp_path, "r2", [finding("a"), finding("a")],
                  findings_stored=1)
    assert len(diff_runs(a, b).new) == 1


# --------------------------------------------------------------------------
# A row this loader cannot turn into a Finding is a HOLE in one side of the
# comparison: it makes a finding look fixed (or look new) purely because it
# could not be read. Never silently swallowed.
# --------------------------------------------------------------------------

def test_unparseable_line_is_counted_and_surfaced(tmp_path):
    run = make_run(tmp_path, "r1", [finding("a")])
    with (run / "artifacts" / "findings.jsonl").open("a") as fh:
        fh.write("{not json at all\n")
    summary = load_run(run)
    assert summary.unreadable_lines == 1
    d = diff_runs(run, make_run(tmp_path, "r2", []))
    assert any("could not be read" in c for c in d.caveats)


def test_row_with_an_invalid_severity_is_counted_not_dropped_silently(tmp_path):
    run = make_run(tmp_path, "r1", [finding("a")])
    row = finding("b"); row["severity"] = "apocalyptic"
    with (run / "artifacts" / "findings.jsonl").open("a") as fh:
        fh.write(json.dumps(row) + "\n")
    summary = load_run(run)
    assert len(summary.findings) == 1
    assert summary.unreadable_lines == 1


def test_unknown_field_from_a_newer_schema_does_not_drop_the_finding(tmp_path):
    """A run written by a sweeper with an extra Finding field must still
    diff. Dropping those rows would report every one of them as fixed."""
    row = finding("a"); row["cvss_score"] = 9.8
    run = make_run(tmp_path, "r1", [row])
    summary = load_run(run)
    assert [f.template_id for f in summary.findings] == ["a"]
    assert "cvss_score" in summary.unknown_fields
    d = diff_runs(run, make_run(tmp_path, "r2", []))
    assert any("cvss_score" in c for c in d.caveats)


def test_id_is_recomputed_from_the_identity_fields(tmp_path):
    """A row carrying a stale or absent id still diffs against a fresh run,
    and the disagreement is reported rather than hidden."""
    row = finding("a"); row["id"] = "0" * 40
    a = make_run(tmp_path, "r1", [row])
    b = make_run(tmp_path, "r2", [finding("a")])
    d = diff_runs(a, b)
    assert d.new == [] and d.fixed == []
    assert [f.template_id for f in d.persisting] == ["a"]
    assert load_run(a).id_mismatches == 1
    assert any("id" in c for c in d.caveats)


# --------------------------------------------------------------------------
# Absence is only evidence when the run actually looked. Everything below is
# the guard against "12 findings fixed" being printed about a run that never
# ran the stage that would have found them.
# --------------------------------------------------------------------------

def test_a_clean_pair_of_runs_produces_no_caveats(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("a"), finding("b")])
    b = clean_run(tmp_path, "r2", [finding("a"), finding("c")])
    d = diff_runs(a, b)
    assert d.caveats == []
    assert d.reliable is True
    assert d.unverified_fixed == [] and d.unverified_new == []
    assert "NOT FULLY EVIDENCE-BACKED" not in render_diff(d)


def test_a_run_that_found_nothing_is_not_treated_as_suspect(tmp_path):
    """A clean run never creates artifacts/findings.jsonl at all -- flush()
    only opens it when there is a row. A caveat on every clean retest would
    train the operator to ignore the banner that matters."""
    a = clean_run(tmp_path, "r1", [finding("a")])
    b = tmp_path / "r2"
    (b / "artifacts").mkdir(parents=True)
    write_manifest(b, findings_stored=0)
    d = diff_runs(a, b)
    assert load_run(b).file_present is False
    assert d.caveats == []
    assert d.reliable is True
    assert [f.template_id for f in d.fixed] == ["a"]
    assert d.unverified_fixed == []


def test_absent_findings_file_is_still_flagged_when_the_run_claims_findings(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("a")])
    b = tmp_path / "r2"
    (b / "artifacts").mkdir(parents=True)
    write_manifest(b, findings_stored=4)
    d = diff_runs(a, b)
    assert d.reliable is False
    assert [f.template_id for f in d.unverified_fixed] == ["a"]


def test_finding_from_a_stage_that_did_not_complete_is_not_reported_fixed(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("a", stage="nuclei")])
    b = clean_run(tmp_path, "r2", [], complete=(), incomplete=("nuclei",))
    d = diff_runs(a, b)
    assert [f.template_id for f in d.fixed] == ["a"]
    assert [f.template_id for f in d.unverified_fixed] == ["a"]
    assert d.reliable is False
    text = render_diff(d)
    assert "UNVERIFIED" in text.upper()
    assert "nuclei" in text


def test_a_stage_missing_from_the_older_run_makes_its_findings_unverified_new(tmp_path):
    a = clean_run(tmp_path, "r1", [], complete=("httpx",), findings_stored=0)
    b = clean_run(tmp_path, "r2", [finding("a", stage="nuclei")],
                  complete=("httpx", "nuclei"))
    d = diff_runs(a, b)
    assert [f.template_id for f in d.new] == ["a"]
    assert [f.template_id for f in d.unverified_new] == ["a"]


def test_only_the_affected_stage_is_unverified(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("a", stage="nuclei"),
                                   finding("t", stage="tlsx")],
                  complete=("nuclei", "tlsx"))
    b = clean_run(tmp_path, "r2", [], complete=("tlsx",), incomplete=("nuclei",))
    d = diff_runs(a, b)
    assert sorted(f.template_id for f in d.fixed) == ["a", "t"]
    assert [f.template_id for f in d.unverified_fixed] == ["a"]


def test_a_persisting_finding_is_never_unverified(tmp_path):
    """Presence is self-evidencing: both runs saw it, whatever else broke."""
    a = clean_run(tmp_path, "r1", [finding("a")])
    b = clean_run(tmp_path, "r2", [finding("a")],
                  complete=(), incomplete=("nuclei",))
    d = diff_runs(a, b)
    assert [f.template_id for f in d.persisting] == ["a"]
    assert d.unverified_fixed == [] and d.unverified_new == []


def test_aborted_newer_run_is_led_with(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("a")])
    b = clean_run(tmp_path, "r2", [], complete=(),
                  aborted_reason="preflight failed: nuclei missing")
    d = diff_runs(a, b)
    assert d.reliable is False
    assert any("ABORT" in c.upper() for c in d.caveats)
    text = render_diff(d)
    assert "NOT FULLY EVIDENCE-BACKED" in text
    assert "preflight failed" in text
    # and the one finding that vanished is not presented as remediated
    assert [f.template_id for f in d.unverified_fixed] == ["a"]


def test_degraded_run_is_flagged_even_when_every_stage_it_recorded_completed(tmp_path):
    """A refused target degrades a run without failing any stage."""
    a = clean_run(tmp_path, "r1", [finding("a")])
    b = clean_run(tmp_path, "r2", [finding("a")], degraded=True)
    d = diff_runs(a, b)
    assert any("degraded" in c.lower() for c in d.caveats)


def test_missing_manifest_means_nothing_is_evidence_backed(tmp_path):
    a = make_run(tmp_path, "r1", [finding("a")])
    b = make_run(tmp_path, "r2", [finding("b")])
    d = diff_runs(a, b)
    assert d.reliable is False
    assert any("run.json" in c for c in d.caveats)
    assert [f.template_id for f in d.unverified_fixed] == ["a"]
    assert [f.template_id for f in d.unverified_new] == ["b"]


def test_unreadable_manifest_is_not_treated_as_a_complete_run(tmp_path):
    b = clean_run(tmp_path, "r2", [finding("a")])
    (b / "run.json").write_text("{ truncated json")
    a = clean_run(tmp_path, "r1", [finding("a"), finding("b")])
    d = diff_runs(a, b)
    assert d.reliable is False
    assert [f.template_id for f in d.unverified_fixed] == ["b"]


def test_findings_file_shorter_than_the_manifest_count_is_flagged(tmp_path):
    """A crash between the last flush and the manifest, or a truncated copy:
    the file under-represents what the run found."""
    a = clean_run(tmp_path, "r1", [finding("a"), finding("b")])
    b = clean_run(tmp_path, "r2", [finding("a")], findings_stored=7)
    d = diff_runs(a, b)
    assert load_run(b).truncated is True
    assert any("7" in c for c in d.caveats)
    assert [f.template_id for f in d.unverified_fixed] == ["b"]


def test_a_collision_in_the_newer_run_makes_that_stage_unverified(tmp_path):
    """A collision means a different finding was dropped from that stage's
    output -- so that stage's absences are an undercount, not a fix."""
    a = clean_run(tmp_path, "r1", [finding("a", stage="nuclei"),
                                   finding("t", stage="tlsx")],
                  complete=("nuclei", "tlsx"))
    b = clean_run(tmp_path, "r2", [], complete=("nuclei", "tlsx"),
                  collisions=("nuclei",))
    d = diff_runs(a, b)
    assert [f.template_id for f in d.unverified_fixed] == ["a"]
    assert any("collision" in c.lower() for c in d.caveats)


# --------------------------------------------------------------------------
# ...and "the run actually looked" is not only about which stages ran. A
# retest pointed at fewer hosts, run at a lower level, or run without
# credentials did not look for what it does not report, however cleanly
# every stage completed. This is the falsely-attested-remediation case: a
# `full` -> `mid` retest never runs -dast, an `auth` -> `unauth` retest never
# reaches the login, and a dropped target is never scanned at all.
# --------------------------------------------------------------------------

def test_a_retest_at_a_lower_level_cannot_attest_a_fix(tmp_path):
    """The -dast finding a `full` run produced is not re-tested by a `mid`
    retest, which never runs -dast at all."""
    a = clean_run(tmp_path, "r1", [finding("dast-only")], level="full")
    b = clean_run(tmp_path, "r2", [], level="mid", findings_stored=0)
    d = diff_runs(a, b)
    assert [f.template_id for f in d.fixed] == ["dast-only"]
    assert [f.template_id for f in d.unverified_fixed] == ["dast-only"]
    assert d.reliable is False
    assert any("level" in c.lower() and "full" in c for c in d.caveats)
    assert "UNVERIFIED" in render_diff(d).upper()


def test_a_retest_at_a_higher_level_is_not_penalised(tmp_path):
    """Reaching FURTHER than the baseline is not a caveat -- crying wolf over
    it would train the operator past the banner that matters."""
    a = clean_run(tmp_path, "r1", [finding("a")], level="mid")
    b = clean_run(tmp_path, "r2", [], level="full", findings_stored=0)
    d = diff_runs(a, b)
    assert d.caveats == []
    assert d.reliable is True
    assert [f.template_id for f in d.fixed] == ["a"]
    assert d.unverified_fixed == []


def test_levels_are_compared_by_ORDER_not_by_inequality(tmp_path):
    """Every ordered pair of levels, rather than the two the fix was written
    against: a fix is attestable exactly when the retest ran at or above the
    baseline's level."""
    from sweeper.stages.base import LEVELS
    for i, older in enumerate(LEVELS):
        for j, newer in enumerate(LEVELS):
            a = clean_run(tmp_path, f"a-{older}-{newer}", [finding("x")],
                          level=older)
            b = clean_run(tmp_path, f"b-{older}-{newer}", [], level=newer,
                          findings_stored=0)
            d = diff_runs(a, b)
            assert bool(d.unverified_fixed) is (j < i), (older, newer)


def test_an_unauthenticated_retest_cannot_attest_a_behind_login_fix(tmp_path):
    """The IDOR the credentialed run found is unreachable to a retest with no
    credentials, so its absence there is not remediation."""
    a = clean_run(tmp_path, "r1", [finding("idor")], auth_mode="auth")
    b = clean_run(tmp_path, "r2", [], auth_mode="unauth", findings_stored=0)
    d = diff_runs(a, b)
    assert [f.template_id for f in d.fixed] == ["idor"]
    assert [f.template_id for f in d.unverified_fixed] == ["idor"]
    assert d.reliable is False
    assert any("UNAUTHENTICATED" in c for c in d.caveats)


def test_an_authenticated_retest_of_an_unauth_baseline_is_not_penalised(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("a")], auth_mode="unauth")
    b = clean_run(tmp_path, "r2", [], auth_mode="auth", findings_stored=0)
    d = diff_runs(a, b)
    assert d.caveats == []
    assert d.unverified_fixed == []


def test_a_target_dropped_from_scope_is_not_reported_fixed(tmp_path):
    """Per finding, not per run: the retest still gets to attest the host it
    did re-test."""
    a = clean_run(tmp_path, "r1", [finding("a", target="acc.example"),
                                   finding("b", target="old.example")],
                  scope=("acc.example", "old.example"))
    b = clean_run(tmp_path, "r2", [], scope=("acc.example",),
                  findings_stored=0)
    d = diff_runs(a, b)
    assert sorted(f.template_id for f in d.fixed) == ["a", "b"]
    assert [f.template_id for f in d.unverified_fixed] == ["b"]
    assert d.reliable is False
    assert any("old.example" in c for c in d.caveats)


def test_a_retest_with_a_wider_scope_is_not_penalised(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("a")], scope=("acc.example",))
    b = clean_run(tmp_path, "r2", [], findings_stored=0,
                  scope=("acc.example", "extra.example"))
    d = diff_runs(a, b)
    assert d.caveats == []
    assert d.unverified_fixed == []


def test_a_wildcard_retest_covers_a_bare_baseline_entry(tmp_path):
    """Scopes compare by what they REACH, not as strings. A set difference
    would read this widening (`acc.example` -> `*.acc.example`) as the
    baseline entry having been dropped."""
    a = clean_run(tmp_path, "r1", [finding("a", target="acc.example")],
                  scope=("acc.example",))
    b = clean_run(tmp_path, "r2", [], scope=("*.acc.example",),
                  findings_stored=0)
    d = diff_runs(a, b)
    assert d.caveats == []
    assert d.unverified_fixed == []


def test_dropping_a_wildcard_for_its_base_host_is_a_narrowing(tmp_path):
    """The converse: `*.acc.example` -> `acc.example` stops reaching every
    subdomain, and the findings on them were not re-tested."""
    a = clean_run(tmp_path, "r1", [finding("a", target="shop.acc.example"),
                                   finding("b", target="acc.example")],
                  scope=("*.acc.example",))
    b = clean_run(tmp_path, "r2", [], scope=("acc.example",),
                  findings_stored=0)
    d = diff_runs(a, b)
    assert [f.template_id for f in d.unverified_fixed] == ["a"]
    assert any("*.acc.example" in c for c in d.caveats)


def test_a_manifest_that_does_not_record_its_reach_cannot_attest_a_fix(tmp_path):
    """Fail-closed, as everywhere else here: an absent `level`, `auth_mode`
    or `scope` is UNKNOWN reach, never assumed-equal reach."""
    for key in ("level", "auth_mode", "scope"):
        a = clean_run(tmp_path, f"a-{key}", [finding("x")])
        b = clean_run(tmp_path, f"b-{key}", [], findings_stored=0,
                      omit=(key,))
        d = diff_runs(a, b)
        assert [f.template_id for f in d.unverified_fixed] == ["x"], key
        assert d.reliable is False, key


def test_an_unrecognised_level_is_not_treated_as_a_level(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("x")], level="full")
    b = clean_run(tmp_path, "r2", [], level="ludicrous", findings_stored=0)
    d = diff_runs(a, b)
    assert [f.template_id for f in d.unverified_fixed] == ["x"]


def test_a_narrowed_retest_still_reports_what_it_saw_as_persisting(tmp_path):
    """Presence is self-evidencing whatever the reach was."""
    a = clean_run(tmp_path, "r1", [finding("a")], level="full",
                  auth_mode="auth")
    b = clean_run(tmp_path, "r2", [finding("a")], level="mid")
    d = diff_runs(a, b)
    assert [f.template_id for f in d.persisting] == ["a"]
    assert d.unverified_fixed == [] and d.unverified_new == []


def test_the_reach_caveat_leads_rather_than_footnotes(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("x")], level="full")
    b = clean_run(tmp_path, "r2", [], level="mid", findings_stored=0)
    text = render_diff(diff_runs(a, b))
    assert text.index("NOT FULLY EVIDENCE-BACKED") < text.index("## FIXED")
    assert "level" in text.lower()


# --------------------------------------------------------------------------
# Rendering.
# --------------------------------------------------------------------------

def test_render_orders_findings_worst_first(tmp_path):
    a = clean_run(tmp_path, "r1", [], findings_stored=0)
    b = clean_run(tmp_path, "r2", [
        finding("i", severity="info"),
        finding("m", severity="medium"),
        finding("c", severity="critical"),
    ])
    text = render_diff(diff_runs(a, b))
    assert (text.index("[critical]") < text.index("[medium]")
            < text.index("[info]"))


def test_render_counts_match_the_groups(tmp_path):
    a = clean_run(tmp_path, "r1", [finding("a"), finding("b")])
    b = clean_run(tmp_path, "r2", [finding("a"), finding("c"), finding("d")])
    d = diff_runs(a, b)
    text = render_diff(d)
    assert f"NEW ({len(d.new)}" in text and len(d.new) == 2
    assert f"FIXED ({len(d.fixed)}" in text and len(d.fixed) == 1
    assert f"PERSISTING ({len(d.persisting)}" in text


def test_render_escapes_scanner_supplied_backticks(tmp_path):
    """Titles, targets and template ids come from scanner templates and HTTP
    responses. Same invariant the Markdown report holds: balanced backticks
    on every line, or a stray one lets the rest of the line escape as prose.
    """
    a = clean_run(tmp_path, "r1", [], findings_stored=0)
    b = clean_run(tmp_path, "r2", [
        finding("tpl`id", target="ev`il.example", title="a `backtick title"),
    ])
    text = render_diff(diff_runs(a, b))
    odd = [ln for ln in text.splitlines() if ln.count("`") % 2]
    assert not odd, f"unbalanced backticks on: {odd}"


def test_render_survives_an_empty_diff(tmp_path):
    a = clean_run(tmp_path, "r1", [], findings_stored=0)
    b = clean_run(tmp_path, "r2", [], findings_stored=0)
    text = render_diff(diff_runs(a, b))
    assert "NEW (0)" in text and "FIXED (0)" in text


# --------------------------------------------------------------------------
# The manifest reader is pointed at the real writer, not only at this file's
# fixture, so a key rename in context.py cannot silently make every run look
# unreadable (which would mark every comparison unverified -- noisy, but the
# opposite mistake, a stale key defaulting to "complete", would be silent).
# --------------------------------------------------------------------------

def test_reads_the_real_manifest_written_by_runcontext(tmp_path):
    from sweeper.artifacts import Finding
    from sweeper.context import RunConfig, RunContext
    from sweeper.stages.base import Coverage, FailureClass, StageResult

    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(
        RunConfig(targets_file=targets, outdir=tmp_path / "out",
                  level="high", auth_mode="auth"))
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["nuclei", "httpx", "tlsx"])
    ctx.store.add_finding(Finding(stage="nuclei", severity="high", title="X",
                                  target="acc.example", template_id="a"))
    ctx.store.flush()
    ctx.write_manifest([
        StageResult(stage="nuclei", status="complete"),
        StageResult(stage="httpx", status="failed",
                    failure=FailureClass.TRANSPORT, reason="boom"),
    ])

    summary = load_run(ctx.run_dir)
    assert summary.status.readable is True
    assert summary.status.degraded is True
    assert summary.truncated is False
    assert [f.template_id for f in summary.findings] == ["a"]
    assert summary.covers("nuclei") is True
    assert summary.covers("httpx") is False    # failed
    assert summary.covers("tlsx") is False     # requested, never recorded

    # The REACH keys, read from the real writer for the same reason: a rename
    # of "level", "auth_mode" or "scope"/"allowed" in context.py would
    # otherwise leave every run looking like it recorded no reach at all --
    # and while that fails closed (everything unverified), the same drift in
    # a manifest READER that defaulted instead would be silent and in the
    # attest-a-fix direction.
    assert summary.status.level == "high"
    assert summary.status.auth_mode == "auth"
    assert summary.status.scope_allowed == frozenset({"acc.example"})
    assert summary.covers_target("acc.example") is True
    assert summary.covers_target("https://acc.example/app") is True
    assert summary.covers_target("shop.acc.example") is False
    assert summary.covers_target("elsewhere.example") is False
