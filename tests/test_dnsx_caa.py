"""CAA, and the records that were never queried.

The stage asked for a, aaaa, cname, mx, ns, txt. That leaves DNS-layer
infrastructure findings unreachable no matter how well the parser works:

  * CAA. Its absence means ANY public CA may issue for the domain, which is
    the control that stops a mis-issued certificate. Not queried, so never
    reported.
  * SOA. Carries the zone's admin contact and refresh policy, and a SOA
    naming an internal host discloses infrastructure.
  * PTR / SRV. Service and reverse mappings, both ordinary recon surface.

`-recon` would ask for everything at once, but it also turns on AXFR at every
level, and zone transfer is deliberately a mid+ behaviour here.
"""
import json
from pathlib import Path

from sweeper.artifacts import Finding
from sweeper.stages.dnsx import DnsxStage


def parse_rows(tmp_path, rows):
    p = tmp_path / "dnsx.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return list(DnsxStage().parse(p))


def findings(items):
    return [i for i in items if isinstance(i, Finding)]


def test_caa_is_queried_at_every_level():
    levels = DnsxStage().levels
    for name, flags in levels.items():
        assert "-caa" in flags, f"{name} does not query CAA"


def test_soa_is_queried_at_every_level():
    for name, flags in DnsxStage().levels.items():
        assert "-soa" in flags, f"{name} does not query SOA"


def test_a_domain_with_no_caa_record_is_reported(tmp_path):
    out = parse_rows(tmp_path, [{"host": "client.example", "a": ["93.184.216.34"]}])
    f = [x for x in findings(out) if x.template_id == "dns-caa-missing"]
    assert len(f) == 1
    assert f[0].target == "client.example"
    assert f[0].severity == "info"


def test_a_domain_with_a_caa_record_is_not_reported(tmp_path):
    out = parse_rows(tmp_path, [
        {"host": "client.example", "a": ["93.184.216.34"],
         "caa": ['0 issue "letsencrypt.org"']},
    ])
    assert not [x for x in findings(out) if x.template_id == "dns-caa-missing"]


def test_caa_records_are_emitted_as_records(tmp_path):
    out = parse_rows(tmp_path, [
        {"host": "client.example", "caa": ['0 issue "letsencrypt.org"']},
    ])
    values = [a.value for a in out if not isinstance(a, Finding)]
    assert any("CAA" in v and "letsencrypt.org" in v for v in values)


def test_a_caa_that_permits_any_issuer_is_flagged(tmp_path):
    """`issue ";"` is the documented way to forbid issuance; a wildcard
    issue value that names no CA authorises everyone, which is the same
    posture as having no CAA at all while looking like a control."""
    out = parse_rows(tmp_path, [
        {"host": "client.example", "caa": ['0 issue "*"']},
    ])
    f = [x for x in findings(out) if x.template_id == "dns-caa-permissive"]
    assert len(f) == 1


def test_only_hosts_that_answered_are_assessed_for_caa(tmp_path):
    """A host that returned no records at all did not resolve. Reporting
    "no CAA" for it states a finding about a host we never reached."""
    out = parse_rows(tmp_path, [{"host": "dead.client.example"}])
    assert not [x for x in findings(out) if x.template_id == "dns-caa-missing"]


def test_soa_naming_a_private_host_is_reported(tmp_path):
    out = parse_rows(tmp_path, [
        {"host": "client.example", "a": ["93.184.216.34"],
         "soa": [{"ns": "ns1.internal.corp.local", "mailbox": "root.client.example"}]},
    ])
    f = [x for x in findings(out) if x.template_id == "dns-soa-internal-host"]
    assert len(f) == 1


# --- report-ready wording and verification -----------------------------

def test_missing_caa_finding_is_reportable_verbatim(tmp_path):
    """Operator requirement 2026-08-05: these findings go into client
    reports as written, so the title states the RISK rather than the
    observation. "No CAA record published" describes what was seen;
    "Increased risk of false certificate creation..." is what a client is
    being told, and is the wording used in delivered reports.
    """
    out = parse_rows(tmp_path, [{"host": "acc.example", "a": ["1.2.3.4"]}])
    f = [x for x in findings(out) if x.template_id == "dns-caa-missing"]
    assert f, "a host with no CAA must still be reported"
    assert f[0].title == ("Increased risk of false certificate creation "
                          "due to not using CAA")


def test_missing_caa_finding_carries_the_commands_that_verify_it(tmp_path):
    """Two commands, because that is how the check is confirmed by hand:
    the dig CAA query, and the type257 cross-check against a second
    resolver -- a CAA record absent from one view and present in another
    is a real answer, and one command cannot show it.
    """
    out = parse_rows(tmp_path, [{"host": "acc.example", "a": ["1.2.3.4"]}])
    f = [x for x in findings(out) if x.template_id == "dns-caa-missing"][0]
    blob = f"{f.evidence} {f.description} {f.remediation}"
    assert "dig" in blob
    assert "CAA" in blob
    assert "type257" in blob
    assert "acc.example" in blob
