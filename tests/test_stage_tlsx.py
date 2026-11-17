from pathlib import Path

import pytest

from sweeper import binaries, preflight
from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.tlsx import TlsxStage

FIX = Path(__file__).parent / "fixtures" / "tlsx.jsonl"


def findings():
    return [f for f in TlsxStage().parse(FIX) if isinstance(f, Finding)]


def test_contract():
    assert registry.validate(TlsxStage()) == []


def test_expired_certificate_is_medium():
    f = [x for x in findings() if x.template_id == "tls-expired"]
    assert f and f[0].severity == "medium"
    assert f[0].target == "old.acc.example:443"


def test_self_signed_and_mismatch_both_reported():
    ids = {x.template_id for x in findings() if x.target.startswith("legacy")}
    assert "tls-self-signed" in ids
    assert "tls-hostname-mismatch" in ids


def test_obsolete_protocol_flagged():
    f = [x for x in findings() if x.template_id == "tls-obsolete-version"]
    assert f and f[0].severity == "medium"


def test_weak_cipher_flagged():
    ids = {x.template_id for x in findings()}
    assert "tls-weak-cipher" in ids


def test_healthy_host_produces_no_findings():
    assert not any(x.target.startswith("acc.example:") for x in findings())


def test_two_distinct_weak_ciphers_on_one_endpoint_produce_two_findings():
    """Regression guard for the collision defect this task fixes.

    Before matcher=cipher, both rows for dualcipher.acc.example:443 hashed
    to the SAME finding id (stage, target and template_id were identical
    and matcher defaulted to ""), so ArtifactStore.add_finding's plain
    setdefault kept only the first-submitted cipher and the second vanished
    silently. An endpoint offering two weak ciphers is a worse finding than
    offering one, and a pentest report must not undercount it.
    """
    f = [x for x in findings()
         if x.template_id == "tls-weak-cipher"
         and x.target == "dualcipher.acc.example:443"]
    assert len(f) == 2
    assert {x.matcher for x in f} == {
        "TLS_RSA_WITH_RC4_128_SHA", "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    }
    assert len({x.id for x in f}) == 2, "distinct ciphers must not collide onto one id"


def test_two_distinct_obsolete_versions_on_one_endpoint_produce_two_findings():
    """Same collision class as weak-cipher, for tls-obsolete-version.

    tlsx can emit one row per TLS version it probed; a server that still
    accepts both TLS 1.0 and TLS 1.1 is worse than one accepting only one
    of them, and both must reach the report.
    """
    f = [x for x in findings()
         if x.template_id == "tls-obsolete-version"
         and x.target == "multiversion.acc.example:443"]
    assert len(f) == 2
    assert {x.matcher for x in f} == {"tls10", "tls11"}
    assert len({x.id for x in f}) == 2


def test_weak_cipher_finding_ids_are_stable_across_runs():
    """Pins the exact property Plan 3's run-diffing depends on."""
    first = {x.id for x in findings() if x.template_id == "tls-weak-cipher"}
    second = {x.id for x in findings() if x.template_id == "tls-weak-cipher"}
    assert first == second
    assert len(first) >= 2


def test_cbc_sha_only_cipher_is_flagged_as_weak():
    """Regression guard for the WEAK_CIPHER_TOKENS defect.

    "TLS_RSA_WITH_AES_128_CBC_SHA" (cbc-only.acc.example in the fixture)
    carries NONE of the other weak markers (no RC4, 3DES, DES_, NULL,
    EXPORT, MD5) -- only the _CBC_SHA suffix. A non-raw "_CBC_SHA\\b"
    literal interprets \\b as a backspace character (0x08), which can never
    appear in a real cipher name, so that whole weak-cipher class went
    silently undetected. Verified directly against the buggy token below
    before trusting the fix: with the old non-raw string this assertion
    fails.
    """
    f = [x for x in findings() if x.target == "cbc-only.acc.example:443"]
    ids = {x.template_id for x in f}
    assert ids == {"tls-weak-cipher"}, (
        "the _CBC_SHA-only cipher must be caught by the weak-cipher check "
        "even with no other weak marker present"
    )


def test_weak_cipher_tokens_is_a_raw_string_and_the_old_form_fails():
    """Pins the defect concretely: prove the literal old (non-raw) token
    could never have matched a real cipher, and that the module's actual
    token does.
    """
    from sweeper.stages.tlsx import WEAK_CIPHER_TOKENS

    cipher = "TLS_RSA_WITH_AES_128_CBC_SHA"
    old_broken_tokens = ("RC4", "3DES", "DES_", "NULL", "EXPORT", "MD5",
                         "_CBC_SHA\b")  # non-raw: \b is a literal backspace
    assert not any(tok.strip("\\b") in cipher for tok in old_broken_tokens), (
        "sanity check: the old non-raw token must NOT match a real cipher"
    )
    assert any(tok.strip("\\b") in cipher for tok in WEAK_CIPHER_TOKENS), (
        "the module's WEAK_CIPHER_TOKENS must actually match a _CBC_SHA-only cipher"
    )


def ctx_for(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)
    )
    ctx.store.add(Artifact(ArtifactKind.PORT, "acc.example:443",
                            meta={"host": "acc.example", "port": "443"}))
    return ctx


def test_targets_go_through_a_file_not_bare_argv(tmp_path):
    cmd = TlsxStage().build_command(ctx_for(tmp_path))
    assert "-l" in cmd
    infile = Path(cmd[cmd.index("-l") + 1])
    assert infile.suffix == ".txt"
    assert "acc.example" not in cmd  # not present as a bare positional arg
    assert "acc.example:443" in infile.read_text()


def test_every_resolved_address_is_scanned(tmp_path):
    assert "-scan-all-ips" in TlsxStage().build_command(ctx_for(tmp_path))


def test_every_open_port_is_offered_to_tlsx(tmp_path):
    """Deliberately REPLACES an earlier assertion that :22 was excluded.

    That earlier rule selected ports with
    `meta["tls"] or value.endswith((":443", ":8443"))`, whose first half
    never fires -- naabu does no TLS detection and reports False for every
    port -- so it was a hardcoded two-port list. Against a lab serving a
    different broken certificate on each of 443/8443/9443/10443 it silently
    dropped :9443 (hostname mismatch) and :10443 (TLS 1.0/1.1, no forward
    secrecy) from the only stage that can judge them.

    The saving it bought was never real: tlsx defaults to 300-way
    concurrency with a 5s timeout and emits nothing for a port that does not
    speak TLS, so an SSH port costs one timed-out handshake among hundreds
    running at once. Deciding in advance which ports can carry TLS is the
    assumption that lost two real findings, and TLS on an unexpected port is
    exactly the thing recon should surface.
    """
    ctx = ctx_for(tmp_path)
    for port in ("22", "9443", "10443"):
        ctx.store.add(Artifact(ArtifactKind.PORT, f"acc.example:{port}",
                               meta={"host": "acc.example", "port": port}))
    cmd = TlsxStage().build_command(ctx)
    contents = Path(cmd[cmd.index("-l") + 1]).read_text()
    assert "acc.example:443" in contents
    assert "acc.example:9443" in contents
    assert "acc.example:10443" in contents
    assert "acc.example:22" in contents


def test_no_mutation_flags_at_any_level():
    """Only `full` may mutate request parameters; tlsx has no such flags at
    any level -- it is read-only certificate/handshake inspection.
    """
    for level in LEVELS:
        args = " ".join(TlsxStage().levels[level]).lower()
        assert "-d " not in args and "-data" not in args


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("tlsx") is None,
                    reason="tlsx not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    ctx = ctx_for(tmp_path, level=level)
    err = preflight.validate_arguments(TlsxStage(), ctx)
    assert err == "", f"tlsx rejected the {level!r} flag set: {err}"


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("tlsx") is None,
                    reason="tlsx not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_with_an_empty_port_store(tmp_path, level):
    """Matches preflight's real calling shape: it validates every stage's
    build_command() before naabu/nmap have produced any PORT artifacts.
    """
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      level=level))
    err = preflight.validate_arguments(TlsxStage(), ctx)
    assert err == "", f"tlsx rejected the {level!r} flag set with no ports: {err}"
