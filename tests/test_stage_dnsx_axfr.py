"""Zone-transfer parsing, and the two controls it makes reachable.

WHY THIS EXISTS. dnsx deliberately did NOT request -axfr, with a comment
saying so: parse() had no handling for the key, and requesting a flag whose
result is discarded costs queries and throws away the most severe DNS finding
there is. That was the right call while the output shape was unverified. This
lands the parsing with a fixture captured from the real binary (dnsx 1.2.3
against a lab serving AXFR on every zone), so the flag can be requested and
the result actually read.

TWO CONTROLS COME BACK TO LIFE WITH IT. analyse_dmarc() has existed since the
stage was written and could never fire: DMARC lives at `_dmarc.<domain>`, a
name nothing ever put in the target list, so the code path had no reachable
input. Same for secrets published in TXT. A zone transfer returns both, so
parsing it is what turns two pieces of dead code into working controls --
the same class as the "controls with no test that could fail" pass.

SHAPE, measured not assumed: `axfr` is an object with `host` and `chain`,
where chain entries are ordinary dnsx record rows for the zone, and the SAME
entry repeats once per nameserver that answered. Records are flattened onto
the zone apex rather than kept under their own names, which is a real
limitation of dnsx's output and is asserted here so nobody "fixes" the
attribution into something the data cannot support.
"""
from pathlib import Path

from sweeper.artifacts import ArtifactKind, Finding
from sweeper.stages.dnsx import DnsxStage, analyse_caa, analyse_soa
from sweeper.stages.base import LEVELS

FIX = Path(__file__).parent / "fixtures" / "dnsx-axfr.jsonl"


def parsed():
    return list(DnsxStage().parse(FIX))


def findings():
    return [x for x in parsed() if isinstance(x, Finding)]


def records():
    return [x for x in parsed()
            if getattr(x, "kind", None) is ArtifactKind.DNS_RECORD]


def test_successful_zone_transfer_is_a_high_finding():
    f = [x for x in findings() if x.template_id == "dns-zone-transfer"]
    assert f, "a zone that transfers to anyone must be reported"
    assert all(x.severity == "high" for x in f)


def test_one_finding_per_zone_not_per_nameserver_that_answered():
    """The chain repeats the same records once per responding NS.

    Without dedup a two-nameserver zone reports the same transfer twice --
    and worse, every record in it twice.
    """
    zones = [x.target for x in findings()
             if x.template_id == "dns-zone-transfer"]
    assert len(zones) == len(set(zones)), f"duplicate zone findings: {zones}"


def test_transferred_records_become_artifacts():
    vals = [r.value for r in records()]
    assert any("acc.example NS ns1.acc.example" in v for v in vals), vals[:10]


def test_transferred_records_are_deduped():
    vals = [r.value for r in records()]
    assert len(vals) == len(set(vals)), "the repeated chain produced duplicates"


def test_dmarc_policy_none_in_the_zone_is_reported():
    """The control that could never fire before AXFR parsing.

    analyse_dmarc() only ever sees TXT for names in the target list, and
    nobody lists `_dmarc.<domain>`. A zone transfer returns it.
    """
    f = [x for x in findings() if x.template_id == "dns-dmarc-weak"]
    assert f, "p=none is published in this zone and must be reported"


def test_a_strict_dmarc_record_in_the_same_zone_is_not_reported():
    """The zone publishes p=none AND p=reject; only the weak one is a finding.

    Without this the test above passes for a parser that flags every DMARC
    record it sees.
    """
    weak = [x for x in findings() if x.template_id == "dns-dmarc-weak"]
    assert all("p=none" in x.evidence.lower().replace(" ", "")
               or "p=none" in x.evidence.lower()
               for x in weak), [x.evidence for x in weak]


def test_permissive_spf_in_the_zone_is_reported():
    f = [x for x in findings() if x.template_id == "dns-spf-permissive"]
    assert f, "v=spf1 +all is published in this zone"


def test_secrets_published_in_txt_are_reported_as_dnsx_findings():
    """EXPECTED: an AWS key pair and a Stripe key sit in this zone's TXT.

    Attributed to dnsx, not jsrecon: the finding's stage is what a reader
    uses to know where to go looking, and scan_text's default would have
    blamed the JavaScript stage for a DNS record.
    """
    secrets = [x for x in findings() if x.template_id.startswith("secret-")]
    assert secrets, "TXT-published credentials must be reported"
    assert all(x.stage == "dnsx" for x in secrets), \
        [(x.stage, x.template_id) for x in secrets]


def test_secret_evidence_is_redacted():
    """Same rule as every other secret this tool records."""
    secrets = [x for x in findings() if x.template_id.startswith("secret-")]
    joined = " ".join(x.evidence for x in secrets)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in joined


def test_axfr_findings_carry_a_raw_ref():
    for f in findings():
        assert f.raw_ref, f"{f.template_id} has no evidence pointer"


def test_a_host_that_does_not_transfer_produces_no_finding(tmp_path):
    """Precision: -axfr is asked of EVERY queried name, not just apexes.

    A non-apex name has no zone to hand over, so dnsx returns the row with
    no `axfr` key at all. Confirmed against the real binary and the lab:
    querying www/api/git under a zone that DOES transfer at its apex yields
    zero zone-transfer findings. Without this guard the obvious
    implementation -- treat the presence of the key as the finding -- reports
    one transfer per hostname in the scope.
    """
    raw = tmp_path / "dnsx.jsonl"
    raw.write_text(
        '{"host":"www.acc.example","a":["93.184.216.34"],"status_code":"NOERROR"}\n'
        # Present but empty: a refused transfer, which is the SECURE state.
        '{"host":"api.acc.example","a":["93.184.216.35"],"axfr":{"chain":[]}}\n'
    )
    out = [x for x in DnsxStage().parse(raw)
           if isinstance(x, Finding) and x.template_id == "dns-zone-transfer"]
    assert out == [], "a refused or absent transfer is not a finding"


def test_axfr_is_requested_at_mid_and_above():
    stage = DnsxStage()
    for level in ("mid", "high", "full"):
        assert "-axfr" in stage.levels[level], level


def test_axfr_is_requested_at_low_too():
    """Replaces test_axfr_is_not_requested_at_low.

    Operator decision 2026-08-04. A zone transfer is one query to a
    nameserver built to answer queries, and an open one is the highest-value
    DNS finding there is -- excluding it from `low` meant the cheapest run
    was also the one that could not report it. What a zone publishes does
    not depend on scan depth.
    """
    assert "-axfr" in DnsxStage().levels["low"]


def test_every_level_still_only_requests_flags_parse_reads():
    """The original guard, unchanged in INTENT: nothing is queried that the
    parser then throws away.

    It used to spell that as "-soa and -caa are never requested", which was
    true only while parse() ignored them. Both are read now -- CAA as a
    record plus analyse_caa, SOA via analyse_soa -- so the denylist would
    have blocked the improvement it existed to protect. The invariant itself
    lives in test_stage_dnsx.py::test_every_record_flag_requested_is_actually_parsed;
    this asserts the pair that made the migration safe, exactly as it did
    for -axfr.
    """
    stage = DnsxStage()
    for level, args in stage.levels.items():
        assert "-caa" in args, level
        assert "-soa" in args, level
    raw_caa = list(analyse_caa("acc.example", ['0 issue "*"']))
    raw_soa = list(analyse_soa("acc.example", [{"ns": "ns1.corp.local"}]))
    assert raw_caa and raw_soa, "the flags are requested but nothing reads them"
