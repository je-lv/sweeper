"""maildns stage — evaluating the mail records dnsx can only retrieve.

WHY THIS IS ITS OWN STAGE. dnsx returns TXT strings. Everything that
decides whether a published policy actually authenticates anything happens
after that string is in hand, and dnsx has no way to do it:

  - **SPF is a program, not a string.** Its mechanisms resolve further DNS
    names, and a record whose evaluation exceeds TEN lookups is INVALID:
    receivers return permerror and treat the domain as unauthenticated.
    dnsx sees `v=spf1 ... -all`, finds nothing wrong with it, and the
    report says the domain publishes SPF. It publishes a record that
    authenticates nothing, which is worse than publishing none, because it
    looks handled.
  - **DMARC resolves at the ORGANIZATIONAL domain.** A subdomain with no
    `_dmarc` record of its own inherits its parent's policy. dnsx queries
    `_dmarc.<host>` and infers absence from an empty answer, so on any
    scope of subdomains under a parent that DOES publish DMARC, every
    dns-dmarc-missing finding it emits is wrong. `dmarc.location` in this
    tool's output is the name the policy was actually found at, which is
    the only thing that settles it.
  - **A report destination has to authorize itself.** `rua=` pointing at a
    domain that has not published an accepting record means every report
    is silently discarded — a control that reads as configured and is not.

ABSENCE STAYS WITH dnsx, which already emits dns-spf-missing and
dns-dmarc-missing at every level. This stage runs only at `high`, so
re-reporting absence here would double every absence finding in the report
the moment an operator selects a deeper level -- the same finding, twice,
from two stages, which is how a reader loses confidence in a count.

NO SMTP. checkdmarc opens connections to the target's mail exchangers to
test STARTTLS unless told not to. `--skip-tls` is passed unconditionally
and is not an operator option: a web scope's rules of engagement do not
cover the client's mail servers, and no stage sends traffic nobody asked
for.

ONE QUERY THIS STAGE MAKES THAT THE SCOPE DOES NOT NAME. Resolving DMARC
correctly REQUIRES asking the organizational domain, which is by definition
a name above the scoped host. It is a DNS question put to a resolver about
a public record, not traffic to client infrastructure -- the same shape as
the `_dmarc.` names dnsx already derives -- and without it the answer is
the wrong answer.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..artifacts import Artifact, ArtifactKind, Finding

#: Filename for the domain-list sidecar, following the "-input.txt beside
#: raw/<stage>.json" idiom naabu/dnsx/httpx/cdncheck already use.
INPUT_SIDECAR = "maildns-input.txt"

#: RFC 7208 §4.6.4. A record whose evaluation needs more than this many DNS
#: lookups MUST be treated as permerror by receivers, so exceeding it is an
#: invalid record rather than an inefficient one.
SPF_MAX_LOOKUPS = 10

#: checkdmarc says this when nothing is published. Absence is dnsx's to
#: report (see the module docstring), so it is matched to be SKIPPED here
#: rather than turned into a finding. Substring, not equality: the DMARC
#: form appends "or its parent domains" when the org-domain walk also came
#: back empty.
_ABSENT = "does not exist"


def _is_absent(section: dict) -> bool:
    return _ABSENT in str(section.get("error") or "")


def analyse_spf(domain: str, spf: dict) -> Iterator[Finding]:
    if not isinstance(spf, dict) or _is_absent(spf):
        return
    lookups = spf.get("dns_lookups")
    if isinstance(lookups, int) and lookups > SPF_MAX_LOOKUPS:
        yield Finding(
            stage="maildns", severity="medium",
            title="SPF record exceeds the DNS lookup limit",
            target=domain, template_id="mail-spf-lookup-limit",
            matcher=str(spf.get("record") or ""),
            evidence=f"{lookups} DNS lookups (limit {SPF_MAX_LOOKUPS}): "
                     f"{spf.get('record')}",
            description=(
                f"Evaluating this SPF record needs {lookups} DNS lookups, "
                f"and RFC 7208 caps it at {SPF_MAX_LOOKUPS}. Receivers "
                "return permerror and treat mail from this domain as "
                "unauthenticated, so the record authenticates nothing "
                "while appearing to be configured."),
            remediation=(
                "Reduce the include/redirect chain below the limit, e.g. by "
                "flattening rarely-changing includes or removing senders "
                "that no longer send for this domain."),
        )
    elif spf.get("record") and spf.get("valid") is False:
        # A record that is present and does not validate for some other
        # reason. Same consequence as the lookup limit -- permerror -- but
        # kept apart because the remediation is different.
        yield Finding(
            stage="maildns", severity="medium",
            title="SPF record is published but invalid",
            target=domain, template_id="mail-spf-invalid",
            matcher=str(spf.get("record")),
            evidence=f"{spf.get('error')}: {spf.get('record')}",
            description=("The published SPF record does not parse, so "
                         "receivers return permerror and treat mail from "
                         "this domain as unauthenticated."),
            remediation="Correct the record so it validates.",
        )
    for warning in spf.get("warnings") or []:
        yield Finding(
            stage="maildns", severity="low",
            title="SPF record warning",
            target=domain, template_id="mail-spf-warning",
            matcher=str(warning), evidence=str(warning),
            description=str(warning),
            remediation="Review the record against RFC 7208.",
        )


def analyse_dmarc(domain: str, dmarc: dict) -> Iterator[Finding]:
    if not isinstance(dmarc, dict) or _is_absent(dmarc):
        return
    location = dmarc.get("location")
    if dmarc.get("record") and dmarc.get("valid") is False:
        yield Finding(
            stage="maildns", severity="medium",
            title="DMARC record is published but invalid",
            target=domain, template_id="mail-dmarc-invalid",
            matcher=str(dmarc.get("record")),
            evidence=f"{dmarc.get('error')}: {dmarc.get('record')}",
            description=("The published DMARC record does not parse, so "
                         "receivers cannot apply the policy it states."),
            remediation="Correct the record so it validates.",
        )
    if location and location != domain:
        # NOT a defect -- this is the correction to dnsx's blind spot, and
        # the operator needs it in the report or they will read
        # dns-dmarc-missing on this name and believe it.
        yield Finding(
            stage="maildns", severity="info",
            title="DMARC policy inherited from the organizational domain",
            target=domain, template_id="mail-dmarc-inherited",
            matcher=str(location),
            evidence=f"policy found at {location}: {dmarc.get('record')}",
            description=(
                f"This name publishes no _dmarc record of its own and is "
                f"covered by the policy at {location}, because DMARC is "
                "evaluated at the organizational domain. Any finding that "
                "reports DMARC as absent for this name is describing the "
                "missing record, not a missing policy."),
            remediation=(
                "None required. Publish a subdomain policy (sp=) only if "
                "this name needs to differ from the parent."),
        )
    for warning in dmarc.get("warnings") or []:
        yield Finding(
            stage="maildns", severity="low",
            title="DMARC record warning",
            target=domain, template_id="mail-dmarc-warning",
            matcher=str(warning), evidence=str(warning),
            description=str(warning),
            remediation=(
                "Review the record against RFC 7489. A report destination "
                "in another domain must publish a record accepting reports "
                "for this one, or the reports are discarded."),
        )


def analyse_receiving_domain(domain: str, entry: dict) -> Iterator[Finding]:
    """A domain that ACCEPTS mail and authenticates none of its own.

    dnsx holds both halves of this -- it queries mx, and it reports the two
    absences -- and never puts them together. The pair is what turns a
    hardening note into a live one: the domain is operational mail
    infrastructure, and anyone on the internet may send as it.
    """
    hosts = [h.get("hostname") for h in (entry.get("mx") or {}).get("hosts", [])
             if isinstance(h, dict) and h.get("hostname")]
    if not hosts:
        return
    if not _is_absent(entry.get("spf") or {}):
        return
    if not _is_absent(entry.get("dmarc") or {}):
        return
    yield Finding(
        stage="maildns", severity="medium",
        title="Domain receives mail but publishes no sender authentication",
        target=domain, template_id="mail-no-sender-auth-with-mx",
        matcher=",".join(sorted(hosts)),
        evidence="MX: " + ", ".join(hosts) + " — no SPF, no DMARC",
        description=(
            "This domain publishes mail exchangers, so it is live mail "
            "infrastructure rather than a parked name, and publishes "
            "neither SPF nor DMARC. Every receiver is left to decide for "
            "itself whether mail claiming to come from this domain is "
            "genuine: some quarantine it, some deliver it to the inbox."),
        remediation=(
            "Publish SPF ending in -all, then DMARC at p=none with rua "
            "reporting, and raise to p=reject once the reports are clean."),
    )


class MaildnsStage:
    name = "maildns"
    enabled_levels = frozenset({"high", "full"})
    #: Same limitation as nmap, and declared the same way. checkdmarc's -n
    #: takes ADDRESSES and always queries port 53, so it cannot express a
    #: resolver on another port -- and passing the bare address anyway would
    #: query port 53 of the right host, which is a different service or
    #: nothing at all, while run.json vouched for the operator's setting.
    #: Claiming a capability the argv does not deliver is worse than not
    #: having it, because the manifest actively asserts it.
    honors_resolver = False
    resolver_note = (
        "checkdmarc's -n takes addresses only and always queries port 53, so "
        "it cannot express a resolver on another port; mail records are read "
        "through the system resolver. The records this stage evaluates (MX, "
        "SPF, DMARC at the organizational domain) are public DNS, and dnsx -- "
        "which does honour --resolver -- already reports their ABSENCE at "
        "every level, so a split-horizon scope still gets the baseline "
        "finding through the operator's own nameserver.")
    requires = ["checkdmarc"]
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.FINDING}
    optional = True
    raw_suffix = "json"

    # high and full only. Every check is DNS and cheap, but it is a SECOND
    # tool over names dnsx has already queried, and what it buys is depth of
    # evaluation rather than a baseline fact -- which is exactly the line
    # `high` draws elsewhere in this file set.
    levels = {
        "low":  [],
        "mid":  [],
        "high": ["--skip-tls"],
        "full": ["--skip-tls"],
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        from ..rate import pause_seconds
        infile = ctx.run_dir / "raw" / INPUT_SIDECAR
        infile.parent.mkdir(parents=True, exist_ok=True)
        permitted, _ = ctx.scope.filter(ctx.store.values(ArtifactKind.HOST))
        infile.write_text("\n".join(permitted) + "\n", encoding="utf-8")
        # checkdmarc 5.17.4: a single positional argument that is a path is
        # read as a domain LIST, which keeps argv bounded on a large scope.
        # -f json prints one JSON array to stdout, which the runner captures
        # as this stage's raw file.
        pacing = []
        if ctx.config.rate_override:
            pacing = ["--wait", str(pause_seconds(
                ctx.config.rate_override,
            ))]
        return [str(binaries.resolve("checkdmarc")),
                *self.levels[ctx.config.level],
                *pacing,
                "-f", "json",
                str(infile)]

    def parse(self, raw_path: Path) -> Iterator[Artifact | Finding]:
        raw_path = Path(raw_path)
        try:
            text = raw_path.read_text(encoding="utf-8")
        except OSError:
            # A stage whose tool never ran must yield nothing rather than
            # raise: the runner already records the failure, and a raised
            # parse turns one broken tool into a dead run.
            return
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            # Silence is never evidence -- see the dnssec stage's docstring
            # for the three invalid tripwire verdicts this rule comes from.
            return
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list):
            return
        for entry in data:
            if not isinstance(entry, dict):
                continue
            domain = entry.get("domain")
            if not domain:
                continue
            yield from analyse_spf(domain, entry.get("spf") or {})
            yield from analyse_dmarc(domain, entry.get("dmarc") or {})
            yield from analyse_receiving_domain(domain, entry)
