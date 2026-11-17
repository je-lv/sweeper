"""DNSSEC validation state, which no other stage could reach.

dnsx cannot answer this. Its full record set is
a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa -- there is no DNSKEY, no DS,
no RRSIG, and no flag to set the DO bit or read the AD flag. So the DNS
stage completed cleanly on a scope that is unsigned from the TLD down and
said nothing about it, which is this project's recurring defect: a stage
that runs, exits 0 and is structurally incapable of seeing something a
reader would assume it checked.

`delv` answers it directly, and does the whole chain walk itself -- which
is why this stage asks about the SCOPE HOST rather than trying to work out
the registrable domain. There is no public-suffix list in this project, so
any apex derivation would be a guess; "is the answer for this name
validated" is both the operationally meaningful question and the one the
operator asks by hand.

The three output shapes below are MEASURED against delv 9.20 via 8.8.8.8,
not assumed:

    ; unsigned answer              -> the scope, 2026-08-05
    ; fully validated              -> cloudflare.com
    ;; resolution failed: failure  -> dnssec-failed.org
"""

import pytest

from sweeper.artifacts import ArtifactKind
from sweeper.stages.base import LEVELS
from sweeper.stages.dnssec import (
    DnssecStage,
    SIGNED,
    UNSIGNED,
    BOGUS,
    classify_delv,
    analyse_dnssec,
)

UNSIGNED_OUT = """; unsigned answer
shop.acc.example. 600\tIN A 203.0.113.10
"""

SIGNED_OUT = """; fully validated
acc.example.\t\t300 IN A 104.16.132.229
acc.example.\t\t300 IN RRSIG A 13 2 300 (
\t\t\t\t20260806104154 20260804084154 34505 acc.example.
"""

BOGUS_OUT = ";; resolution failed: failure\n"


# --- classification -----------------------------------------------------

def test_unsigned_answer_is_classified_unsigned():
    assert classify_delv(UNSIGNED_OUT) == UNSIGNED


def test_fully_validated_is_classified_signed():
    assert classify_delv(SIGNED_OUT) == SIGNED


def test_resolution_failure_is_classified_bogus():
    """A validating resolver could not resolve the name AT ALL.

    Distinct from unsigned, and worse: the zone is signed but the chain is
    broken, so every validating resolver on the internet refuses the
    answer. That is an availability fault, not a hardening gap.
    """
    assert classify_delv(BOGUS_OUT) == BOGUS


def test_empty_output_is_not_reported_as_unsigned():
    """delv that produced nothing (timeout, missing binary, killed) must
    not be read as evidence of anything.

    Reporting "no DNSSEC" from silence is exactly how a tool that never
    ran produces a confident finding -- the same shape as the three
    invalid tripwire results during lab validation.
    """
    assert classify_delv("") is None
    assert classify_delv("   \n") is None


# --- findings -----------------------------------------------------------

def test_unsigned_zone_is_a_finding():
    out = list(analyse_dnssec("acc.example", UNSIGNED, ref="raw/dnssec.txt#L1"))
    assert len(out) == 1
    f = out[0]
    assert f.stage == "dnssec"
    assert f.template_id == "dns-dnssec-absent"
    assert "DNSSEC" in f.title


def test_signed_zone_produces_no_finding():
    """The control. Without it this stage passes for one that flags
    everything it is given."""
    assert list(analyse_dnssec("acc.example", SIGNED)) == []


def test_broken_chain_outranks_a_merely_absent_one():
    """Severity has to separate these two: absent is a hardening gap the
    client may accept, broken means the name does not resolve for anyone
    validating and needs fixing today."""
    absent = list(analyse_dnssec("acc.example", UNSIGNED))[0]
    broken = list(analyse_dnssec("acc.example", BOGUS))[0]
    order = ["info", "low", "medium", "high", "critical"]
    assert order.index(broken.severity) > order.index(absent.severity)
    assert broken.template_id == "dns-dnssec-bogus"


def test_finding_carries_the_command_that_reproduces_it():
    """An operator has to be able to re-run the check by hand before it
    goes in a client report -- and a reader has to be able to verify it."""
    f = list(analyse_dnssec("acc.example", UNSIGNED))[0]
    blob = f"{f.evidence} {f.description} {f.remediation}"
    assert "delv" in blob
    assert "acc.example" in blob


def test_unknown_state_produces_no_finding():
    """None in, nothing out -- silence is never evidence."""
    assert list(analyse_dnssec("acc.example", None)) == []


# --- stage contract -----------------------------------------------------

def test_stage_consumes_hosts_and_produces_findings():
    s = DnssecStage()
    assert s.consumes is ArtifactKind.HOST
    assert ArtifactKind.FINDING in s.produces


def test_stage_runs_at_every_level():
    """Same reasoning as dnsx and tlsx: whether a zone is signed is a
    configuration fact, and it does not become more true at `high`."""
    s = DnssecStage()
    for level in LEVELS:
        assert level in s.levels, level
        assert s.levels[level], f"dnssec would not run at {level}"


# --- "resolution failed" means two different things ---------------------

NCACHE_NXRRSET_OUT = ";; resolution failed: ncache nxrrset\n"
NCACHE_NXDOMAIN_OUT = ";; resolution failed: ncache nxdomain\n"
TIMEOUT_OUT = ";; resolution failed: timed out\n"


def test_a_negative_answer_is_not_a_broken_chain():
    """MEASURED 2026-08-05, and a false positive in the first cut of this
    stage.

    delv prints `;; resolution failed:` for a genuine validation failure
    AND for an ordinary negative answer. Against a real in-scope name that
    simply has no A record, it printed `resolution failed: ncache
    nxrrset` -- and the first version of classify_delv read any
    "resolution failed" as BOGUS, which would have put a medium-severity
    "DNSSEC validation fails, the name does not resolve for validating
    resolvers" into a client report about a name whose DNSSEC is fine and
    which simply has no address record.

    `ncache` is BIND's negative-cache marker. It is not a chain problem.
    """
    assert classify_delv(NCACHE_NXRRSET_OUT) is None
    assert classify_delv(NCACHE_NXDOMAIN_OUT) is None


def test_a_timeout_is_not_a_broken_chain():
    """Unknown is not bogus. A query that did not complete is evidence of
    nothing -- the same rule as empty output."""
    assert classify_delv(TIMEOUT_OUT) is None


def test_a_real_validation_failure_is_still_bogus():
    """The control: narrowing the match must not disarm the check.
    dnssec-failed.org, measured."""
    assert classify_delv(";; resolution failed: failure\n") == BOGUS


def test_a_negative_answer_produces_no_finding():
    """End to end: nothing classified means nothing reported."""
    assert list(analyse_dnssec("acc.example",
                               classify_delv(NCACHE_NXRRSET_OUT))) == []
