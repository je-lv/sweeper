"""The TLS checks tlsx can do and the stage was not asking for.

The stage requested -expired -self-signed -mismatched -tls-version -cipher
(+ -wildcard-cert at high). That reports the NEGOTIATED cipher and version
only, which silently misses the finding class an operator actually asks for:
a server that PREFERS TLS 1.2 with AES-GCM but still ACCEPTS TLS 1.0 or RC4
reports clean, because the one handshake tlsx made was a good one.

tlsx already supports the rest; nothing here needs a new tool:

  -untrusted    certificate not chaining to a trusted root
  -revoked      certificate revoked
  -cipher-enum  every cipher the server accepts, not just the chosen one
  -tls-chain    the chain, so an incomplete one can be seen
  -hash sha1    certificate fingerprint, for weak-signature reporting
"""
from sweeper.stages.tlsx import TlsxStage


def flags(level):
    return TlsxStage().levels[level]


def test_untrusted_certificates_are_requested_from_mid(tmp_path):
    for level in ("mid", "high", "full"):
        assert "-untrusted" in flags(level), level


def test_revoked_certificates_are_requested_from_mid(tmp_path):
    for level in ("mid", "high", "full"):
        assert "-revoked" in flags(level), level


def test_cipher_enumeration_is_requested_at_every_level(tmp_path):
    """The negotiated cipher alone cannot show that a weak one is ACCEPTED.

    Enumeration used to be restricted to high/full because it is many
    handshakes per endpoint. Operator decision 2026-08-04 extended it to
    every level: a server that accepts RC4 accepts it under `low` too, and
    a level that cannot see that reports a clean TLS posture it never
    checked. The handshake cost is real and is documented on
    TlsxStage.levels; bound it with --time-limit / --rate.
    """
    for level in ("low", "mid", "high", "full"):
        assert "-cipher-enum" in flags(level), level


def test_cipher_enumeration_asks_for_the_weak_ones(tmp_path):
    """-cipher-enum without -cipher-type returns everything including the
    secure ciphers, which is a much larger handshake count for output the
    weak-cipher analysis then filters away anyway."""
    for level in ("high", "full"):
        joined = " ".join(flags(level))
        assert "-cipher-type" in joined, level
        assert "insecure" in joined or "weak" in joined, level


def test_the_certificate_chain_is_requested_at_high(tmp_path):
    for level in ("high", "full"):
        assert "-tls-chain" in flags(level), level


def test_low_asks_every_certificate_question(tmp_path):
    """Replaces test_low_stays_a_single_handshake.

    That test asserted `low` made ONE handshake and requested no
    enumeration or chain retrieval. It passed against a `low` whose flag
    list was `[]` -- which for this stage does not mean "off" (only
    jsrecon treats an empty list that way) but "run tlsx and ask it
    nothing". So the property it protected was real, and the cost of it
    was a level that could not report a single certificate defect.

    Operator decision 2026-08-04: correctness at every level beats a quiet
    `low`. The handshake cost moved to --time-limit / --rate, which bound
    every stage uniformly, instead of being hidden in a flag list.
    """
    for check in ("-cipher-enum", "-tls-chain", "-revoked", "-expired",
                  "-self-signed", "-mismatched"):
        assert check in flags("low"), check


# --- the new fields must actually be read -------------------------------
import json as _json
from sweeper.stages.tlsx import TlsxStage as _T


def _parse(tmp_path, row):
    p = tmp_path / "tlsx.jsonl"
    p.write_text(_json.dumps(row) + "\n")
    return list(_T().parse(p))


def _ids(out):
    return {f.template_id for f in out}


def test_an_untrusted_certificate_is_reported(tmp_path):
    out = _parse(tmp_path, {"host": "a.example", "port": "443",
                            "untrusted": True, "issuer_cn": "Internal CA"})
    assert "tls-untrusted" in _ids(out)


def test_a_revoked_certificate_is_reported_as_high(tmp_path):
    out = _parse(tmp_path, {"host": "a.example", "port": "443",
                            "revoked": True, "serial": "ab:cd"})
    f = next(x for x in out if x.template_id == "tls-revoked")
    assert f.severity == "high"


def test_an_accepted_obsolete_version_is_reported_even_when_1_2_negotiated(tmp_path):
    """The finding this whole change exists for: the handshake tlsx made was
    a good one, and the server still accepts TLS 1.0."""
    out = _parse(tmp_path, {"host": "a.example", "port": "443",
                            "tls_version": "tls12",
                            "version_enum": ["tls12", "tls10"]})
    assert "tls-obsolete-version-supported" in _ids(out)
    assert "tls-obsolete-version" not in _ids(out), "negotiated version was fine"


def test_missing_tls13_is_reported_only_when_enumeration_ran(tmp_path):
    assert "tls-13-unsupported" in _ids(_parse(tmp_path, {
        "host": "a.example", "port": "443", "version_enum": ["tls12"]}))
    # No enumeration at this level -> no claim about 1.3.
    assert "tls-13-unsupported" not in _ids(_parse(tmp_path, {
        "host": "a.example", "port": "443", "tls_version": "tls12"}))


def test_each_accepted_weak_cipher_is_its_own_finding(tmp_path):
    out = _parse(tmp_path, {
        "host": "a.example", "port": "443",
        "cipher_enum": [{"version": "tls12", "ciphers": {
            "insecure": ["TLS_RSA_WITH_RC4_128_SHA"],
            "weak": ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]}}]})
    weak = [f for f in out if f.template_id == "tls-weak-cipher-accepted"]
    assert len(weak) == 2, "one finding per accepted cipher"
    assert {f.severity for f in weak} == {"high", "medium"}


def test_empty_cipher_enumeration_reports_nothing(tmp_path):
    out = _parse(tmp_path, {"host": "a.example", "port": "443",
                            "cipher_enum": [{"version": "tls13", "ciphers": {}}]})
    assert "tls-weak-cipher-accepted" not in _ids(out)
