"""tlsx stage — certificate and TLS configuration findings."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..artifacts import ArtifactKind, Finding

OBSOLETE_VERSIONS = {"ssl30", "tls10", "tls11"}
# Every token is matched as a plain substring of the cipher name (see
# parse() below) -- there is no regex engine involved, so "\b" is never a
# regex word-boundary here. It IS meaningful as a literal two-character
# suffix marker ("\" + "b") that parse()'s `tok.strip("\\b")` strips back
# off before the `in` check, giving "_CBC_SHA" the same shape as every
# other token in this tuple.
#
# That only works if this string literal is RAW. A prior non-raw
# "_CBC_SHA\b" let Python's own escape processing turn \b into a single
# backspace character (0x08) before .strip("\\b") ever ran -- strip()
# removes leading/trailing characters that are '\' or 'b', and 0x08 is
# neither, so the backspace survived and the resulting token
# ("_CBC_SHA\x08") could never appear in any real cipher name. The whole
# _CBC_SHA weak-cipher class went silently undetected; a fixture whose
# cipher also contained RC4 (a different token) hid the bug because that
# token still matched. See test_cbc_sha_only_cipher_is_flagged_as_weak,
# which isolates a cipher carrying ONLY the _CBC_SHA marker.
WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES_", "NULL", "EXPORT", "MD5", r"_CBC_SHA\b")


class TlsxStage:
    name = "tlsx"
    #: This tool takes an operator-supplied resolver; see
    #: sweeper.resolvers and run.json's "resolver" block.
    honors_resolver = True
    requires = ["tlsx"]
    consumes = ArtifactKind.PORT
    produces = {ArtifactKind.FINDING}
    optional = True
    # Identical at every level, `low` included (operator decision,
    # 2026-08-04). A certificate's validity is a configuration fact, not a
    # depth-of-scan one: whether it is expired, self-signed, misnamed or
    # revoked is equally true under `low`.
    #
    # `low` was previously `[]`. That is NOT this stage's off switch --
    # jsrecon is the only stage where an empty level list means "do not
    # run" (jsrecon.py:390); tlsx splats its list into the argv, so `low`
    # ran the tool with `-json -silent` and asked it nothing. It connected,
    # handshook, exited 0 and reported `complete` while being structurally
    # incapable of producing a finding. Against the lab's four planted
    # certificate defects, `low` found none of them.
    #
    # -untrusted and -revoked are properties of the SAME handshake, so they
    # cost nothing extra: a certificate that does not chain to a trusted
    # root, or that the CA has revoked, is as serious as the expired one
    # next to it and was simply not asked for.
    #
    # -cipher-enum changes what this stage can SEE. -cipher reports the
    # cipher the server chose; a server that prefers TLS 1.2 with AES-GCM
    # and still ACCEPTS RC4 or 3DES reports clean under it, because the
    # one handshake made was a good one. Enumeration asks which ciphers
    # are accepted at all, which is the question "weak cipher supported"
    # actually means.
    #
    # COST, and the one thing to know before running this at `low`:
    # enumeration is dozens of handshakes per SERVICE, and it is the only
    # part of this set that is not a single connection. It used to start at
    # `high` for exactly that reason. `low` is no longer the cheapest
    # possible TLS pass -- bound it with --time-limit / --rate like any
    # other stage, or drop the stage, if a quiet run matters more than
    # cipher coverage.
    #
    # -cipher-type insecure,weak rather than the default `all`: the secure
    # ciphers are many more handshakes per endpoint for output the analysis
    # then discards. The restriction must travel with -cipher-enum wherever
    # it goes.
    _CHECKS = ["-expired", "-self-signed", "-mismatched", "-untrusted",
               "-revoked", "-tls-version", "-cipher", "-wildcard-cert",
               "-probe-status", "-cipher-enum", "-cipher-type",
               "insecure,weak", "-version-enum", "-tls-chain"]
    levels = {
        "low":  list(_CHECKS),
        "mid":  list(_CHECKS),
        "high": list(_CHECKS),
        "full": list(_CHECKS),
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        from ..rate import interval
        infile = ctx.run_dir / "raw" / "tlsx-input.txt"
        infile.parent.mkdir(parents=True, exist_ok=True)
        # EVERY open port, not a guessed subset. The old selection was
        # `a.meta.get("tls") or a.value.endswith((":443", ":8443"))`, whose
        # first half never fires: meta["tls"] comes from naabu, which does no
        # TLS detection and reports False for everything (verified across a
        # full run -- 56 PORT artifacts, none with tls=true). So it was a
        # hardcoded two-port list, and it silently removed every other port
        # from the one stage able to judge them. Against a lab serving a
        # different broken certificate per port it missed :9443 (hostname
        # mismatch) and :10443 (TLS 1.0/1.1, no forward secrecy) outright.
        #
        # TLS on a non-standard port is a thing to FIND, not to assume away.
        # tlsx is the tool whose job is deciding what speaks TLS: it emits
        # nothing for a port that does not (verified -- :80 in a mixed list
        # produces no row and no error), and it defaults to 300-way
        # concurrency with a 5s timeout, so asking about a plain-HTTP port
        # costs one timed-out handshake among hundreds running at once.
        ports = [a.value for a in ctx.store.get(ArtifactKind.PORT)]
        permitted, _ = ctx.scope.filter(ports)
        infile.write_text("\n".join(permitted) + "\n", encoding="utf-8")
        from .. import resolvers
        throttle = []
        if ctx.config.rate_override:
            # tlsx has no global requests/second flag. Serialize both target
            # and cipher workers and pace each connection; this is slower
            # than a native token bucket but safely respects the ceiling.
            throttle = ["-c", "1", "-cec", "1", "-delay",
                        interval(ctx.config.rate_override)]
        return [str(binaries.resolve("tlsx")), "-l", str(infile),
                "-json", "-silent", "-duc", "-scan-all-ips",
                *self.levels[ctx.config.level],
                *throttle,
                *resolvers.flag_args(ctx)]

    def parse(self, raw_path: Path) -> Iterator[Finding]:
        for lineno, line in enumerate(
            Path(raw_path).read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            target = f"{row.get('host','')}:{row.get('port','')}"
            ref = f"raw/tlsx.jsonl#L{lineno}"

            def make(severity, title, template_id, evidence, description,
                     remediation, matcher=""):
                return Finding(stage="tlsx", severity=severity, title=title,
                               target=target, template_id=template_id,
                               matcher=matcher,
                               evidence=evidence, raw_ref=ref,
                               description=description, remediation=remediation)

            # tls-expired / tls-self-signed / tls-hostname-mismatch: no
            # matcher. Each fires at most once per JSON row (a plain `if`,
            # not a loop over a list), and every row for one target:port
            # describes the SAME TLS handshake against the SAME certificate
            # -- expired/self_signed/mismatched and the evidence built from
            # subject_cn/not_after/host cannot legitimately differ between
            # two rows for the same host:port within one run, because the
            # server presents one certificate regardless of which cipher or
            # protocol version tlsx negotiated to observe it. A second row
            # for the same target here is a true duplicate (byte-identical
            # content), which the store's dedupe path already handles
            # correctly -- not a collision.
            if row.get("expired"):
                yield make("medium", "Expired TLS certificate", "tls-expired",
                           f"not_after={row.get('not_after','')}",
                           "The presented certificate is past its expiry date.",
                           "Renew the certificate and automate renewal.")
            if row.get("self_signed"):
                yield make("medium", "Self-signed TLS certificate", "tls-self-signed",
                           f"subject_cn={row.get('subject_cn','')}",
                           "The certificate is not issued by a trusted CA, so clients "
                           "cannot distinguish it from an interception certificate.",
                           "Issue the certificate from a trusted CA.")
            if row.get("mismatched"):
                yield make("medium", "Certificate hostname mismatch",
                           "tls-hostname-mismatch",
                           f"subject_cn={row.get('subject_cn','')} host={row.get('host','')}",
                           "The certificate does not cover the hostname it is served on.",
                           "Reissue with the correct SAN entries.")
            if row.get("untrusted"):
                yield make("medium", "Untrusted TLS certificate", "tls-untrusted",
                           f"issuer_cn={row.get('issuer_cn','')}",
                           "The certificate does not chain to a trusted root, so "
                           "clients cannot verify the server's identity and cannot "
                           "tell it apart from an interception certificate.",
                           "Serve the full chain from a publicly trusted CA.")
            if row.get("revoked"):
                yield make("high", "Revoked TLS certificate", "tls-revoked",
                           f"serial={row.get('serial','')}",
                           "The certificate has been revoked by its issuer. A "
                           "revoked certificate is often revoked because its "
                           "private key was compromised.",
                           "Replace the certificate with a newly issued one and "
                           "rotate the private key.")

            # WHAT THE SERVER ACCEPTS, not what it happened to negotiate.
            #
            # tls_version/cipher below describe the ONE handshake tlsx made.
            # A server that prefers TLS 1.2 with AES-GCM and still accepts
            # TLS 1.0 or RC4 is clean by that measure -- which is the whole
            # finding class "weak protocol supported" is about. version_enum
            # and cipher_enum come from probing every version and cipher, so
            # they answer the question actually being asked.
            offered = [str(v).lower() for v in (row.get("version_enum") or [])]
            for offered_version in offered:
                if offered_version in OBSOLETE_VERSIONS:
                    yield make(
                        "medium",
                        f"Obsolete TLS version supported ({offered_version})",
                        "tls-obsolete-version-supported",
                        f"version_enum={offered_version}",
                        "The server still accepts a protocol version below "
                        "TLS 1.2, even if it prefers a newer one. A client -- "
                        "or an attacker downgrading one -- can negotiate it.",
                        "Disable TLS 1.1 and below; require TLS 1.2 or 1.3.",
                        matcher=offered_version)
            # Reported only when enumeration actually ran: an empty list from
            # a level that never asked would otherwise read as "TLS 1.3 is
            # missing" on every endpoint at low/mid.
            if offered and "tls13" not in offered:
                yield make("info", "TLS 1.3 not supported",
                           "tls-13-unsupported",
                           f"version_enum={','.join(offered)}",
                           "The server does not offer TLS 1.3, forgoing its "
                           "improved handshake and its removal of the legacy "
                           "cipher suites older versions still permit.",
                           "Enable TLS 1.3 alongside TLS 1.2.")

            for entry in row.get("cipher_enum") or []:
                enum_version = str(entry.get("version") or "").lower()
                buckets = entry.get("ciphers") or {}
                # {"insecure": [...], "weak": [...]} -- keyed by the same
                # -cipher-type names that were requested.
                names = []
                if isinstance(buckets, dict):
                    for bucket, items in buckets.items():
                        for name in items or []:
                            names.append((bucket, str(name)))
                elif isinstance(buckets, list):
                    names = [("", str(n)) for n in buckets]
                for bucket, name in names:
                    yield make(
                        "medium" if bucket != "insecure" else "high",
                        f"Weak cipher suite accepted ({name})",
                        "tls-weak-cipher-accepted",
                        f"{enum_version} {bucket} {name}".strip(),
                        "The server accepts a cipher suite classified as weak "
                        "or insecure. Acceptance is what matters here, not "
                        "preference: a downgrade forces the weakest suite the "
                        "server will agree to.",
                        "Restrict the cipher list to modern AEAD suites.",
                        matcher=f"{enum_version}:{name}")

            version = (row.get("tls_version") or "").lower()
            if version in OBSOLETE_VERSIONS:
                # matcher=version: tlsx can emit more than one JSON row for
                # the same host:port when it probes multiple TLS versions
                # (e.g. -tls-version against a server that still accepts
                # both TLS 1.0 and TLS 1.1) -- two DIFFERENT obsolete
                # versions offered by the same endpoint, which is a worse
                # finding than one, and each is worth its own line in the
                # report. Without a matcher those two rows share (stage,
                # target, template_id) and only the first survives
                # store.add_finding. version is intrinsic to the probe and
                # identical on a rerun against an unchanged server.
                yield make("medium", f"Obsolete TLS version negotiated ({version})",
                           "tls-obsolete-version", f"tls_version={version}",
                           "Protocol versions below TLS 1.2 have known weaknesses "
                           "and are deprecated.",
                           "Disable TLS 1.1 and below; require TLS 1.2 or 1.3.",
                           matcher=version)
            cipher = row.get("cipher") or ""
            if any(tok.strip("\\b") in cipher for tok in WEAK_CIPHER_TOKENS):
                # matcher=cipher: same reasoning as tls-obsolete-version --
                # multiple probes against one host:port (different TLS
                # versions, or -cipher enumerating what an endpoint accepts)
                # can each negotiate a different weak cipher. Two distinct
                # weak ciphers offered by one endpoint is the concrete
                # defect this task starts from ("kept evidence='RC4...', the
                # other is silently gone"); the cipher name is intrinsic to
                # the negotiation and stable across an identical rerun.
                yield make("medium", "Weak TLS cipher suite offered",
                           "tls-weak-cipher", f"cipher={cipher}",
                           "The negotiated cipher suite uses an algorithm considered "
                           "weak or deprecated.",
                           "Restrict the cipher list to modern AEAD suites.",
                           matcher=cipher)
