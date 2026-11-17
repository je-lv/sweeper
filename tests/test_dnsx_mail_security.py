"""SPF and DMARC: the records must be ASKED FOR, and their ABSENCE reported.

Two defects, both found against a live scope on 2026-08-05, both of the
shape this project keeps producing -- a stage that ran, exited 0, and was
structurally incapable of reporting something a reader would assume it
checked.

1. DMARC WAS NEVER QUERIED. It lives at `_dmarc.<domain>`, a name nobody
   puts in a targets file, and build_command only ever wrote the scope
   hosts. analyse_dmarc() could therefore only fire on records recovered
   from a zone transfer -- and a correctly configured zone refuses AXFR,
   so on any well-run estate the control had no reachable input at all.
   The scope under test refuses AXFR, publishes no DMARC, and produced no
   finding.

2. ABSENCE WAS NEVER REPORTED. analyse_spf and analyse_dmarc only fire on
   a record that EXISTS and is weak (`+all`, `p=none`). A domain
   publishing neither got silence, which reads identically to a domain
   that passed. Missing SPF was reported only when MX records existed --
   see test_missing_spf_is_reported_even_without_mx for why that gate is
   wrong for a spoofing finding.

MEASURED, not assumed (dnsx 1.2.3 via 1.1.1.1): a name with no answer
produces NO ROW AT ALL -- `_dmarc.google.com` returns a row with txt,
`_dmarc.<unsigned scope host>` returns nothing. So the parser cannot see
absence in the rows; it infers it from the base hosts that DID answer.
"""

import json

from sweeper.artifacts import Finding
from sweeper.stages.dnsx import DnsxStage, dmarc_name


def parse_rows(tmp_path, rows):
    p = tmp_path / "dnsx.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return list(DnsxStage().parse(p))


def findings(items):
    return [i for i in items if isinstance(i, Finding)]


def ids(items):
    return {f.template_id for f in findings(items)}


# --- the query itself ---------------------------------------------------

def test_dmarc_name_is_derived_from_a_host():
    assert dmarc_name("acc.example") == "_dmarc.acc.example"


def test_build_command_asks_for_the_dmarc_name(tmp_path):
    """The defect in one assertion: without this the record is unreachable
    on any zone that correctly refuses AXFR."""
    from sweeper.artifacts import Artifact, ArtifactKind
    from sweeper.context import RunConfig, RunContext

    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "o",
                                      level="high"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    DnsxStage().build_command(ctx)

    written = (ctx.run_dir / "raw" / "dnsx-input.txt").read_text().split()
    assert "acc.example" in written
    assert "_dmarc.acc.example" in written


def test_derived_dmarc_names_come_only_from_permitted_hosts(tmp_path):
    """Scope first, derive second.

    The derived name must never be a way to reach a host the allowlist
    refused -- so it is built from the ALREADY-FILTERED list, and an
    out-of-scope host contributes no _dmarc name.
    """
    from sweeper.artifacts import Artifact, ArtifactKind
    from sweeper.context import RunConfig, RunContext

    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "o",
                                      level="high"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "evil.test"))
    DnsxStage().build_command(ctx)

    written = (ctx.run_dir / "raw" / "dnsx-input.txt").read_text()
    assert "evil.test" not in written
    assert "_dmarc.evil.test" not in written


# --- absence ------------------------------------------------------------

def test_missing_dmarc_is_reported(tmp_path):
    """The base host answers; no _dmarc row comes back at all."""
    out = parse_rows(tmp_path, [
        {"host": "acc.example", "a": ["1.2.3.4"], "status_code": "NOERROR"},
    ])
    assert "dns-dmarc-missing" in ids(out)


def test_published_dmarc_produces_no_absence_finding(tmp_path):
    """The control. Without it this passes for a parser that flags every
    host it is given."""
    out = parse_rows(tmp_path, [
        {"host": "acc.example", "a": ["1.2.3.4"], "status_code": "NOERROR"},
        {"host": "_dmarc.acc.example",
         "txt": ["v=DMARC1; p=reject; rua=mailto:x@acc.example"]},
    ])
    assert "dns-dmarc-missing" not in ids(out)


def test_a_weak_published_dmarc_is_still_reported_as_weak(tmp_path):
    """p=none must not be silently upgraded to "present, therefore fine"."""
    out = parse_rows(tmp_path, [
        {"host": "acc.example", "a": ["1.2.3.4"]},
        {"host": "_dmarc.acc.example", "txt": ["v=DMARC1; p=none"]},
    ])
    got = ids(out)
    assert "dns-dmarc-weak" in got
    assert "dns-dmarc-missing" not in got


def test_dmarc_finding_targets_the_domain_not_the_underscore_name(tmp_path):
    """A client reads the target column. `_dmarc.acc.example` is a record
    location, not the asset the finding is about."""
    out = parse_rows(tmp_path, [
        {"host": "acc.example", "a": ["1.2.3.4"]},
        {"host": "_dmarc.acc.example", "txt": ["v=DMARC1; p=none"]},
    ])
    weak = [f for f in findings(out) if f.template_id == "dns-dmarc-weak"]
    assert weak and weak[0].target == "acc.example"


def test_missing_spf_is_reported_even_without_mx(tmp_path):
    """The MX gate was wrong for this finding.

    Missing SPF was reported only when the host also published MX. But
    spoofing uses the domain in the message envelope, not the domain's
    ability to RECEIVE mail: a domain with no MX and no SPF can still be
    forged in From:, which is exactly why the guidance is to publish
    `v=spf1 -all` on non-mail domains. The scope under test has no MX and
    no SPF, and produced nothing.
    """
    out = parse_rows(tmp_path, [
        {"host": "acc.example", "a": ["1.2.3.4"], "status_code": "NOERROR"},
    ])
    assert "dns-spf-missing" in ids(out)


def test_published_spf_produces_no_absence_finding(tmp_path):
    out = parse_rows(tmp_path, [
        {"host": "acc.example", "a": ["1.2.3.4"],
         "txt": ["v=spf1 include:_spf.acc.example -all"]},
    ])
    assert "dns-spf-missing" not in ids(out)


def test_the_underscore_name_is_not_itself_audited_for_spf_or_caa(tmp_path):
    """`_dmarc.acc.example` is a record location this stage created. It
    must not turn into its own findings -- that would triple the DNS
    findings on every run and put a name the operator never scoped into
    the report's target column."""
    out = parse_rows(tmp_path, [
        {"host": "acc.example", "a": ["1.2.3.4"],
         "txt": ["v=spf1 -all"]},
        {"host": "_dmarc.acc.example", "txt": ["v=DMARC1; p=reject"]},
    ])
    targets = {f.target for f in findings(out)}
    assert not any(t.startswith("_dmarc.") for t in targets), targets


def test_absence_findings_carry_a_verification_command(tmp_path):
    """Same requirement as CAA and DNSSEC: these go into client reports."""
    out = parse_rows(tmp_path, [
        {"host": "acc.example", "a": ["1.2.3.4"]},
    ])
    for tid in ("dns-spf-missing", "dns-dmarc-missing"):
        f = [x for x in findings(out) if x.template_id == tid][0]
        blob = f"{f.evidence} {f.description} {f.remediation}"
        assert "dig" in blob, tid
        assert "acc.example" in blob, tid


# --- a requested host that produced no row ------------------------------

def test_a_requested_host_that_dnsx_dropped_is_reported(tmp_path):
    """dnsx SILENTLY OMITS hosts, and the stage still says `complete`.

    Found on the live scope 2026-08-05 and reproduced deterministically:
    with `-auto-wildcard` in the flag set, one of three scoped hosts came
    back with no row at all (3/3 without the flag, 2/3 with it, every
    run). That host resolves perfectly well -- it is served by wildcard
    DNS, which is what the flag filters.

    The consequence is the worst kind: every DNS finding for that host --
    CAA, SPF, DMARC, private IP, dangling CNAME -- silently did not exist,
    the stage reported `complete`, and the only clue was a findings count
    that nobody had a denominator for. It also made a real finding LOOK
    like a per-host distinction: two hosts flagged for missing CAA read as
    "the third one publishes CAA", when in fact the third was never
    examined.

    The scan's own input file is the denominator, and it sits next to the
    raw output.
    """
    raw = tmp_path / "dnsx.jsonl"
    raw.write_text(json.dumps(
        {"host": "seen.acc.example", "a": ["1.2.3.4"]}) + "\n")
    (tmp_path / "dnsx-input.txt").write_text(
        "seen.acc.example\ndropped.acc.example\n_dmarc.seen.acc.example\n")

    out = list(DnsxStage().parse(raw))
    gap = [f for f in findings(out) if f.template_id == "dns-host-no-answer"]
    assert gap, "a scoped host that produced no row must not vanish silently"
    assert gap[0].target == "dropped.acc.example"


def test_a_dmarc_helper_name_with_no_row_is_not_reported_as_a_gap(tmp_path):
    """`_dmarc.X` returning nothing is the NORMAL case -- it is how "no
    DMARC published" looks, and it already has its own finding. Reporting
    it as a coverage gap as well would fire on every correctly-scanned
    host in every run."""
    raw = tmp_path / "dnsx.jsonl"
    raw.write_text(json.dumps(
        {"host": "seen.acc.example", "a": ["1.2.3.4"]}) + "\n")
    (tmp_path / "dnsx-input.txt").write_text(
        "seen.acc.example\n_dmarc.seen.acc.example\n")

    out = list(DnsxStage().parse(raw))
    assert not [f for f in findings(out)
                if f.template_id == "dns-host-no-answer"]


def test_no_input_file_means_no_gap_findings(tmp_path):
    """parse() is called directly by many tests and by --resume against
    older run dirs. Without the denominator it must report nothing rather
    than guess."""
    raw = tmp_path / "dnsx.jsonl"
    raw.write_text(json.dumps({"host": "a.acc.example", "a": ["1.2.3.4"]}) + "\n")
    out = list(DnsxStage().parse(raw))
    assert not [f for f in findings(out)
                if f.template_id == "dns-host-no-answer"]


# --- DMARC is evaluated at the organizational domain ------------------------
#
# Found 2026-08-05 while adding the maildns stage: checkdmarc answers "A
# DMARC record does not exist for this domain OR ITS PARENT DOMAINS", and
# this stage only ever asked about the host itself. RFC 7489 6.6.3 says a
# receiver that finds no record at `_dmarc.<host>` retries at the
# organizational domain, so a subdomain with no record of its own is still
# covered by its parent's policy.
#
# The consequence is the worst kind this project produces: on any scope of
# subdomains under a parent that DOES publish DMARC, EVERY dns-dmarc-missing
# finding is confidently wrong -- a control reported as absent in a client
# deliverable while it is published and enforcing.

def test_a_policy_at_the_parent_is_not_reported_as_missing(tmp_path):
    """The defect. `shop.acc.example` publishes no _dmarc record of its own
    and IS covered, because receivers retry at the organizational domain."""
    out = parse_rows(tmp_path, [
        {"host": "shop.acc.example", "a": ["93.184.216.34"]},
        {"host": dmarc_name("acc.example"),
         "txt": ["v=DMARC1; p=reject; rua=mailto:d@acc.example"]},
    ])

    assert "dns-dmarc-missing" not in ids(findings(out)), (
        "a subdomain covered by its parent's policy was reported as having "
        "no DMARC")


def test_the_effective_policy_is_reported_against_the_in_scope_host(tmp_path):
    """A parent publishing p=none leaves the subdomain in monitor-only mode.
    The weakness is real and belongs on the name the client put in scope,
    with evidence naming where the policy actually lives -- reporting it
    against the parent would put an out-of-scope name in the target column.
    """
    out = parse_rows(tmp_path, [
        {"host": "shop.acc.example", "a": ["93.184.216.34"]},
        {"host": dmarc_name("acc.example"), "txt": ["v=DMARC1; p=none"]},
    ])

    weak = [f for f in findings(out) if f.template_id == "dns-dmarc-weak"]
    assert weak, ids(findings(out))
    assert weak[0].target == "shop.acc.example"
    assert "acc.example" in weak[0].evidence


def test_the_host_s_own_policy_wins_over_the_parent(tmp_path):
    """RFC 7489: the record at the host itself is used if present, and the
    parent is only consulted when it is absent. A strict subdomain policy
    under a lax parent must not be reported as lax."""
    out = parse_rows(tmp_path, [
        {"host": "shop.acc.example", "a": ["93.184.216.34"]},
        {"host": dmarc_name("shop.acc.example"), "txt": ["v=DMARC1; p=reject"]},
        {"host": dmarc_name("acc.example"), "txt": ["v=DMARC1; p=none"]},
    ])

    assert "dns-dmarc-weak" not in ids(findings(out))
    assert "dns-dmarc-missing" not in ids(findings(out))


def test_absence_is_still_reported_when_no_ancestor_publishes_one(tmp_path):
    """The regression guard. Narrowing this check must not disarm it -- the
    live scope publishes nothing at any level, and that is a real finding."""
    out = parse_rows(tmp_path, [
        {"host": "shop.acc.example", "a": ["93.184.216.34"]},
    ])

    assert "dns-dmarc-missing" in ids(findings(out))


def test_the_parent_names_are_actually_queried(tmp_path):
    """Inheritance cannot be seen if the ancestor was never asked about."""
    from sweeper.artifacts import Artifact, ArtifactKind
    from sweeper.context import RunConfig, RunContext
    t = tmp_path / "t.txt"
    t.write_text("shop.acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "shop.acc.example"))

    DnsxStage().build_command(ctx)
    queried = (ctx.run_dir / "raw" / "dnsx-input.txt").read_text().split()

    assert dmarc_name("shop.acc.example") in queried
    assert dmarc_name("acc.example") in queried


def test_the_walk_stops_before_the_public_suffix(tmp_path):
    """This project has no public-suffix list, so the ancestor walk stops at
    two labels rather than guessing an apex. Querying `_dmarc.example` is
    pointless; querying `_dmarc.com` invites attributing a public-suffix
    (PSD) policy to a domain that does not have one."""
    from sweeper.stages.dnsx import dmarc_lookup_chain
    chain = dmarc_lookup_chain("a.b.shop.acc.example")

    assert chain[0] == "a.b.shop.acc.example"
    assert chain[-1] == "acc.example"
    assert "example" not in chain
