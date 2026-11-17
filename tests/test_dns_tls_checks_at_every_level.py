"""Every DNS and TLS check runs at every level, `low` included.

Operator decision, 2026-08-04. These two stages answer questions about
configuration -- what a zone publishes, what a certificate asserts -- and
the answer does not get more or less true at a higher level. A `low` run
that reports a healthy TLS posture because it never asked is worse than
one that takes longer.

The concrete defect this closes: tlsx's `low` was `[]`. tlsx splats its
level list into the argv (unlike jsrecon, the one stage where an empty
list means "off" -- jsrecon.py:390), so `low` ran tlsx with `-json
-silent` and no check flags at all. It connected, handshook, exited 0,
reported `complete`, and was structurally incapable of producing a
finding.

dnsx's `low` had the record types but not `-axfr`, so a zone transfer --
the single highest-value DNS finding there is -- was unreachable below
`mid`.
"""

import pytest

from sweeper.stages.dnsx import DnsxStage
from sweeper.stages.tlsx import TlsxStage

LEVELS = ("low", "mid", "high", "full")

#: The checks that decide what each stage can SEE, as opposed to flags that
#: only tune output. If a level omits one of these, that level cannot report
#: the corresponding class of defect no matter what the target does.
TLS_CHECKS = ("-expired", "-self-signed", "-mismatched", "-untrusted",
              "-revoked", "-tls-version", "-cipher", "-wildcard-cert",
              "-probe-status", "-cipher-enum", "-version-enum", "-tls-chain")

DNS_CHECKS = ("-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-caa",
              "-soa", "-ptr", "-srv", "-axfr", "-auto-wildcard")


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("check", TLS_CHECKS)
def test_tlsx_runs_every_check_at_every_level(level, check):
    assert check in TlsxStage.levels[level], (
        f"tlsx cannot detect {check} at level {level}")


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("check", DNS_CHECKS)
def test_dnsx_runs_every_check_at_every_level(level, check):
    assert check in DnsxStage.levels[level], (
        f"dnsx cannot detect {check} at level {level}")


def test_tlsx_low_is_not_an_empty_flag_set():
    """The specific regression: an empty list here is not 'off' for this
    stage, it is 'run the tool and ask it nothing'."""
    assert TlsxStage.levels["low"], "tlsx at low would ask for no checks"


@pytest.mark.parametrize("level", LEVELS)
def test_cipher_enum_keeps_its_type_restriction(level):
    """-cipher-enum without -cipher-type defaults to enumerating ALL
    ciphers -- many more handshakes per endpoint for output the analysis
    discards. The restriction must travel with it to every level."""
    flags = TlsxStage.levels[level]
    assert "-cipher-type" in flags
    assert flags[flags.index("-cipher-type") + 1] == "insecure,weak"
