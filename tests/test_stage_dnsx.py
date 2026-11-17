from pathlib import Path
import pytest
from sweeper import binaries, preflight
from sweeper.artifacts import ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.dnsx import DnsxStage, analyse_spf, analyse_dmarc, is_private

FIX = Path(__file__).parent / "fixtures" / "dnsx.jsonl"


def parsed():
    return list(DnsxStage().parse(FIX))


def records():
    return [x for x in parsed()
            if getattr(x, "kind", None) is ArtifactKind.DNS_RECORD]


def findings():
    return [x for x in parsed() if isinstance(x, Finding)]


def test_stage_satisfies_contract():
    assert registry.validate(DnsxStage()) == []


def test_produces_includes_findings():
    assert ArtifactKind.FINDING in DnsxStage().produces


def test_a_records_parsed():
    vals = [r.value for r in records()]
    assert "acc.example A 93.184.216.34" in vals


def test_empty_mx_entry_is_skipped():
    assert not any(" MX " in r.value and r.value.endswith(" ") for r in records())
    assert not any(r.value == "acc.example MX " for r in records())


def test_ns_records_parsed():
    vals = [r.value for r in records()]
    assert "acc.example NS ns1.acc.example" in vals


def test_private_ip_in_public_dns_is_a_medium_finding():
    f = [x for x in findings()
         if x.template_id == "dns-private-ip" and x.target == "internal.acc.example"]
    assert len(f) == 1
    assert f[0].severity == "medium"
    assert f[0].target == "internal.acc.example"


def test_two_distinct_private_ips_on_one_host_produce_two_findings():
    """Regression guard for the collision defect this task fixes.

    Before matcher=ip, both records hashed to the SAME finding id (stage,
    target, template_id were identical and matcher defaulted to ""), so
    ArtifactStore.add_finding's plain setdefault kept only whichever was
    submitted first and the second vanished with no error. A host leaking
    two private addresses is a strictly worse finding than leaking one, and
    both must reach the report.
    """
    f = [x for x in findings()
         if x.template_id == "dns-private-ip" and x.target == "multihomed.acc.example"]
    assert len(f) == 2
    assert {x.matcher for x in f} == {"10.0.0.5", "192.168.1.9"}
    assert len({x.id for x in f}) == 2, "distinct IPs must not collide onto one id"


def test_private_ip_finding_ids_are_stable_across_runs():
    """The exact test Plan 3's diffing depends on: rebuild the same finding
    set twice and assert identical ids, so matcher=ip does not reintroduce
    the timestamp/ordering instability finding_id's docstring warns against.
    """
    first = {x.id for x in findings() if x.template_id == "dns-private-ip"}
    second = {x.id for x in findings() if x.template_id == "dns-private-ip"}
    assert first == second
    assert len(first) >= 2


def test_missing_spf_is_low():
    """A host that publishes MX but no SPF is genuinely spoofable."""
    f = [x for x in findings()
         if x.template_id == "dns-spf-missing" and x.target == "mail.acc.example"]
    assert f and f[0].severity == "low"


def test_missing_spf_is_reported_without_mx_too():
    """Replaces test_missing_spf_not_reported_without_mx.

    That test encoded an MX gate: missing SPF was reported only on a host
    that also published MX, on the reasoning that a host which cannot
    RECEIVE mail does not need SPF and firing on every CDN alias would
    flood the report.

    The reasoning does not hold for a spoofing finding. Forgery uses the
    domain in the message envelope, and a domain with no MX can be forged
    in From: exactly as easily -- which is why the published guidance for
    a non-mail domain is `v=spf1 -all` rather than no record at all. The
    gate was found on a live scope (2026-08-05) that has no MX, no SPF and
    no DMARC, and produced no mail-security finding of any kind.

    The flooding concern is real but belongs to scope, not to this check:
    what is scanned is the operator's allowlist, not an unbounded
    enumeration.
    """
    targets = [x.target for x in findings()
               if x.template_id == "dns-spf-missing"]
    assert "nospf.acc.example" in targets


def test_permissive_spf_is_medium():
    f = [x for x in findings() if x.template_id == "dns-spf-permissive"]
    assert f and f[0].severity == "medium"
    assert f[0].target == "weak.acc.example"


def test_valid_spf_produces_no_spf_finding():
    ids = [x.template_id for x in findings() if x.target == "acc.example"]
    assert "dns-spf-missing" not in ids
    assert "dns-spf-permissive" not in ids


def test_third_party_cname_flagged_as_takeover_candidate():
    f = [x for x in findings() if x.template_id == "dns-dangling-cname"]
    assert f and f[0].severity == "high"
    assert "cname.acc.example" in [x.target for x in f]


def test_takeover_match_requires_a_dns_label_boundary():
    """Lookalike siblings are independently owned, not vendor-zone resources.

    A bare endswith() reports fakegithub.io as a github.io takeover
    primitive, which would be wrong in a client report.
    """
    targets = [x.target for x in findings()
               if x.template_id == "dns-dangling-cname"]
    for host in ("fake.acc.example", "shop.acc.example", "tm.acc.example"):
        assert host not in targets


def test_takeover_match_tolerates_a_trailing_dot():
    targets = [x.target for x in findings()
               if x.template_id == "dns-dangling-cname"]
    assert "fqdn.acc.example" in targets


def test_every_record_flag_requested_is_actually_parsed():
    """Requesting a flag parse() ignores costs queries and discards the result.

    Written as the general invariant rather than a hand-kept denylist of
    flags. The denylist version named -soa and -caa, and when parse() learned
    to read them the test kept asserting they must never be requested -- a
    guard that had turned into a block on the very improvement it was meant
    to protect. -axfr had already left it the same way.

    Record-type flags map to a RECORD_KEYS entry (emitted as DNS_RECORD) or
    to a named analyser; behavioural flags do not query a record type at all.
    """
    from sweeper.stages.dnsx import RECORD_KEYS
    BEHAVIOURAL = {"-auto-wildcard", "-axfr"}
    ANALYSED = {"-soa"}            # parsed by analyse_soa, not a DNS_RECORD
    for level, args in DnsxStage().levels.items():
        for flag in args:
            if flag in BEHAVIOURAL or flag in ANALYSED:
                continue
            key = flag.lstrip("-")
            assert key in RECORD_KEYS, (
                f"{flag} requested at {level} but parse() never reads it"
            )


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("dnsx") is None,
                    reason="dnsx not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    """Ask dnsx itself whether each level's flag set parses.

    A flag that takes a value but is passed bare — as -wd was — makes the
    binary emit "flag needs an argument", one of preflight's
    ARG_ERROR_MARKERS, which aborts the ENTIRE run before a single target is
    touched. Probing the real binary catches that and any future defect in
    the same family (unknown flag, missing value, unparseable value) without
    hardcoding flag names, unlike the literal-name check above.
    """
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out",
                                      level=level))
    err = preflight.validate_arguments(DnsxStage(), ctx)
    assert err == "", f"dnsx rejected the {level!r} flag set: {err}"


def test_findings_carry_raw_ref():
    assert all(x.raw_ref.startswith("raw/dnsx.jsonl#L") for x in findings())


def test_is_private_detects_rfc1918():
    assert is_private("10.0.14.22") is True
    assert is_private("192.168.1.1") is True
    assert is_private("172.16.5.4") is True
    assert is_private("93.184.216.34") is False


def test_analyse_spf_helpers():
    assert analyse_spf("acc", "v=spf1 -all") is None
    assert analyse_spf("acc", "v=spf1 +all").template_id == "dns-spf-permissive"
    assert analyse_dmarc("acc", "v=DMARC1; p=none").template_id == "dns-dmarc-weak"
    assert analyse_dmarc("acc", "v=DMARC1; p=reject") is None
