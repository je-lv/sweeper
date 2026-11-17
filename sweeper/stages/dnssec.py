"""dnssec stage — is the answer for this name cryptographically validated?

WHY THIS IS ITS OWN STAGE. dnsx cannot answer it. Its complete record set
is a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa: no DNSKEY, no DS, no RRSIG,
and no flag to set the DO bit or read the AD flag. So `dnsx` ran against a
scope that is unsigned from the TLD down, completed, exited 0 and reported
nothing -- and a reader with the DNS stage in front of them would
reasonably assume DNS posture had been assessed. That is this project's
recurring defect, and adding a flag could not fix it.

WHY IT ASKS ABOUT THE SCOPE HOST, NOT THE ZONE APEX. DNSSEC is a property
of a zone, so the instinct is to walk up to the registrable domain and ask
there. This project has no public-suffix list, so every apex derivation
would be a guess (`.co.uk`, `.com.au`, and every provider-owned suffix
break the count-the-labels heuristic). `delv` already walks the chain from
the root itself, so asking about the host gives the operationally
meaningful answer -- "is DNS for the name I am scanning protected" -- with
no guessing, and matches what an operator runs by hand.

OUTPUT SHAPES, MEASURED against delv 9.20 via 8.8.8.8 on 2026-08-05, not
assumed:

    ; unsigned answer              the scope under test
    ; fully validated              cloudflare.com
    ;; resolution failed: failure  dnssec-failed.org

The third is the one worth keeping apart: the zone IS signed, the chain is
broken, and every validating resolver on the internet therefore refuses the
answer outright. That is an availability fault today, not a hardening gap
to schedule, so it carries a higher severity and its own template id.

SILENCE IS NEVER EVIDENCE. classify_delv returns None for empty output, and
analyse_dnssec yields nothing for None. A delv that timed out, was killed,
or is not installed must never become "this domain has no DNSSEC" -- that
is the shape of the three invalid tripwire verdicts during lab validation,
where a tool that never ran and a tool that behaved produced identical
silence.
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Iterator

from ..artifacts import ArtifactKind, Finding

#: Validation states. Strings rather than an enum so they land in the raw
#: evidence file as-is and read plainly in a diff.
SIGNED = "signed"
UNSIGNED = "unsigned"
BOGUS = "bogus"

#: Public validating resolver. The operator's --resolver is deliberately
#: NOT used here: a split-horizon or internal nameserver commonly does not
#: validate at all, and asking one that does not would report every name as
#: unsigned. This question is about the PUBLIC chain of trust, so it is put
#: to a resolver known to validate -- the same reason the manual check is
#: written `delv @8.8.8.8`.
VALIDATING_RESOLVER = "8.8.8.8"

#: delv walks the chain itself and can sit through several round trips.
QUERY_TIMEOUT_S = 20


#: `;; resolution failed:` does NOT mean the chain is broken. delv prints
#: it for ordinary negative answers too, and for queries that never
#: completed. Measured 2026-08-05:
#:
#:     resolution failed: failure        dnssec-failed.org  -> really bogus
#:     resolution failed: ncache nxrrset name with no A record
#:     resolution failed: ncache nxdomain name does not exist
#:
#: `ncache` is BIND's negative-cache marker: a perfectly healthy answer
#: that happens to be "no". Reading it as a broken chain put a
#: medium-severity outage finding on a name whose DNSSEC is fine -- caught
#: against a real in-scope name, which is why the match is a denylist of
#: the benign reasons rather than a bare "resolution failed".
_NOT_A_CHAIN_FAILURE = ("ncache", "timed out", "timeout",
                        "no servers could be reached", "not found")


def classify_delv(output: str) -> str | None:
    """SIGNED / UNSIGNED / BOGUS, or None when delv said nothing usable.

    None means UNKNOWN, and unknown is never reported. A query that did
    not complete, or that completed with a negative answer, is evidence of
    nothing -- the same rule as empty output.
    """
    text = (output or "").strip()
    if not text:
        return None
    lowered = text.lower()
    # Checked before "unsigned": a bogus answer can carry both markers.
    if "resolution failed" in lowered:
        if any(benign in lowered for benign in _NOT_A_CHAIN_FAILURE):
            return None
        return BOGUS
    if "fully validated" in lowered:
        return SIGNED
    if "unsigned answer" in lowered:
        return UNSIGNED
    return None


def verify_command(host: str) -> str:
    """The by-hand command that reproduces this finding.

    Carried in the finding itself because these go into client reports:
    the reader has to be able to re-run the check, and the operator has to
    be able to double-check it before sending.
    """
    return f"delv @{VALIDATING_RESOLVER} +dnssec +multi {host}"


def analyse_dnssec(host: str, state: str | None,
                   ref: str = "") -> Iterator[Finding]:
    cmd = verify_command(host)
    if state == UNSIGNED:
        yield Finding(
            stage="dnssec", severity="low",
            title="Confidentiality and integrity at risk due to "
                  "absence of DNSSEC",
            target=host, template_id="dns-dnssec-absent",
            matcher=host, raw_ref=ref,
            evidence=f"{cmd} -> ; unsigned answer",
            description=(
                "The zone serving this name is not signed with DNSSEC, so a "
                "resolver cannot verify that an answer came from the zone's "
                "operator and was not altered in transit. An attacker able "
                "to poison a cache or answer off-path can direct the name to "
                "an address of their choosing; the client sees no error. "
                "That also undermines any control that trusts DNS, including "
                "domain-validated certificate issuance."),
            remediation=(
                "Sign the zone and publish a DS record in the parent so the "
                "chain of trust reaches it from the root. Verify with "
                f"`{cmd}`, which must report `; fully validated`."),
        )
    elif state == BOGUS:
        yield Finding(
            stage="dnssec", severity="medium",
            title="DNSSEC validation fails — the name does not resolve for "
                  "validating resolvers",
            target=host, template_id="dns-dnssec-bogus",
            matcher=host, raw_ref=ref,
            evidence=f"{cmd} -> ;; resolution failed",
            description=(
                "The zone is signed but the chain of trust does not "
                "validate — commonly a DS record left behind after a key "
                "rollover, or expired signatures. Every validating resolver "
                "refuses the answer, so the name is unreachable for a large "
                "share of the internet rather than merely unprotected. This "
                "is an outage, not a hardening gap."),
            remediation=(
                "Compare the DS in the parent against the current DNSKEY and "
                "check signature validity dates, then correct or withdraw "
                f"the DS. Verify with `{cmd}`."),
        )


class DnssecStage:
    name = "dnssec"
    #: Deliberately not the operator's --resolver; see VALIDATING_RESOLVER.
    honors_resolver = False
    #: Unlike every other False in this codebase, this one is a CHOICE
    #: rather than a tool limitation -- delv takes @resolver perfectly
    #: well. Recorded as such so a reader of run.json's system_dns bucket
    #: does not file it alongside "this tool cannot".
    resolver_note = (
        "delv accepts a resolver, but this stage deliberately queries a "
        "known-validating public resolver (8.8.8.8) instead of --resolver: "
        "DNSSEC is a property of the PUBLIC chain of trust, and a "
        "split-horizon or internal nameserver that does not validate would "
        "make every name look unsigned.")
    requires = ["delv"]
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.FINDING}
    optional = True
    in_process = True
    writes_own_raw = True
    raw_suffix = "txt"

    # Every level, `low` included, for the same reason dnsx and tlsx run
    # their full check set everywhere: whether a zone is signed is a
    # configuration fact that does not become more true at `high`. The cost
    # is one query per host against a public resolver.
    _CHECKS = ["+dnssec", "+multi"]
    levels = {
        "low":  list(_CHECKS),
        "mid":  list(_CHECKS),
        "high": list(_CHECKS),
        "full": list(_CHECKS),
    }

    def build_command(self, ctx) -> list[str]:
        # This stage runs in-process (one delv per host); the runner does
        # not execute this argv. Preflight and a few tests still call it,
        # so it returns something that always succeeds.
        return ["/bin/true"]

    def _hosts(self, ctx) -> list[str]:
        permitted, _ = ctx.scope.filter(ctx.store.values(ArtifactKind.HOST))
        return permitted

    def run_in_process(self, ctx) -> Path:
        """Query each in-scope host and write our own raw evidence.

        The raw file is the transcript an operator re-reads: host, verdict,
        and the exact command, so a finding in a client report can be
        reproduced from the run directory alone.
        """
        from .. import binaries

        raw_path = ctx.raw_path(self.name)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        binary = binaries.resolve("delv")
        flags = self.levels[ctx.config.level]
        from ..rate import pause_seconds
        pacing = pause_seconds(ctx.config.rate_override)

        with raw_path.open("w", encoding="utf-8") as fh:
            for index, host in enumerate(self._hosts(ctx)):
                if index and pacing:
                    time.sleep(pacing)
                cmd = [str(binary), f"@{VALIDATING_RESOLVER}", *flags, host]
                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True,
                        timeout=QUERY_TIMEOUT_S,
                        # Same rule as every other child this project
                        # spawns: never inherit sweeper's stdin. See
                        # docs/LIVE-PREFLIGHT.md on the naabu "flake".
                        stdin=subprocess.DEVNULL,
                    )
                    output = f"{proc.stdout}\n{proc.stderr}"
                except (subprocess.TimeoutExpired, OSError) as exc:
                    # Recorded, not silently dropped, and NOT classified:
                    # a query that did not complete is not evidence that a
                    # zone is unsigned.
                    output = f";; sweeper: delv did not complete ({exc})"
                fh.write(f"### {host}\n$ {' '.join(cmd)}\n{output.strip()}\n\n")
        return raw_path

    def parse(self, raw_path: Path) -> Iterator[Finding]:
        text = Path(raw_path).read_text(encoding="utf-8")
        host = ""
        buf: list[str] = []
        lineno = 0
        start = 1

        def flush():
            if host:
                yield from analyse_dnssec(
                    host, classify_delv("\n".join(buf)),
                    ref=f"raw/dnssec.txt#L{start}")

        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.startswith("### "):
                yield from flush()
                host = line[4:].strip()
                buf = []
                start = lineno
            else:
                buf.append(line)
        yield from flush()
