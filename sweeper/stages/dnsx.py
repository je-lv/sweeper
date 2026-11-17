"""dnsx stage — resolution plus DNS-layer findings.

This stage emits FINDINGs as well as records. DNS misconfiguration is a
real finding class (zone transfer, dangling CNAME, private addressing,
weak mail policy) and is invisible if the stage only reports records.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Iterator

from ..artifacts import Artifact, ArtifactKind, Finding
from ..secrets_rules import scan_text

RECORD_KEYS = ("a", "aaaa", "cname", "mx", "ns", "txt", "caa",
               "ptr", "srv")

# Records that prove the host answered at all. A host that returned NOTHING
# did not resolve, and "this domain publishes no CAA" said about a name we
# never reached is a finding about our own DNS, not about the target.
ANSWER_KEYS = ("a", "aaaa", "cname", "mx", "ns", "txt", "soa", "caa")

# A CAA `issue` value that names no specific CA. `issue ";"` is the documented
# way to FORBID issuance; a bare "*" authorises every public CA, which is the
# same posture as publishing no CAA at all while looking like a control.
CAA_ANY_ISSUER = ("*", "")

# Hosting providers where a CNAME to a non-existent resource is a classic
# subdomain-takeover primitive.
TAKEOVER_SUFFIXES = (
    "s3.amazonaws.com", "cloudfront.net", "herokuapp.com", "github.io",
    "azurewebsites.net", "cloudapp.net", "trafficmanager.net", "fastly.net",
    "netlify.app", "shopify.com", "wpengine.com", "pantheonsite.io",
    "surge.sh", "bitbucket.io", "readthedocs.io", "ghost.io",
)


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


#: DMARC's fixed location. A record for `acc.example` lives at
#: `_dmarc.acc.example`, which is why the policy was unreachable until the
#: name was asked for explicitly: nobody writes it in a targets file, and
#: the only other way it ever arrived was a zone transfer -- which a
#: correctly configured zone refuses, so the better the client's DNS, the
#: less chance this control had of ever firing.
DMARC_PREFIX = "_dmarc."


def dmarc_name(host: str) -> str:
    return f"{DMARC_PREFIX}{host}"


def is_dmarc_name(host: str) -> bool:
    return host.startswith(DMARC_PREFIX)


def dmarc_lookup_chain(host: str) -> list[str]:
    """The names a receiver consults for this host's DMARC policy, nearest
    first.

    RFC 7489 §6.6.3: a receiver that finds no record at `_dmarc.<host>`
    RETRIES at the organizational domain. So a subdomain publishing nothing
    of its own is still covered by its parent's policy, and this stage --
    which asked only about the host itself -- reported every such name as
    having no DMARC. On a scope of subdomains under a parent that publishes
    one, that is a control reported as absent in a client deliverable while
    it is published and enforcing. The worst shape a finding can take.

    WHERE IT STOPS, AND WHY NOT AT THE APEX. Finding the organizational
    domain properly needs a public suffix list, and this project has none
    (see the dnssec stage for the same constraint: `.co.uk`, `.com.au` and
    every provider-owned suffix break a label count). So the walk stops two
    labels from the end and takes the NEAREST record found, which is the
    receiver's own rule. For `shop.acc.example.co.uk` that still includes
    `acc.example.co.uk`, the real organizational domain, and finds its
    record before reaching anything above it.

    The one case it gets wrong: a domain whose organizational domain
    publishes nothing while the public suffix above it publishes a PSD
    policy (RFC 9091) -- `_dmarc.co.uk` -- would be read as the domain's
    own. It is never queried, because the walk stops before it.
    """
    labels = host.strip(".").split(".")
    return [".".join(labels[i:]) for i in range(max(1, len(labels) - 1))]


def base_of(host: str) -> str:
    """The asset a `_dmarc.` record is about.

    Findings are reported against the domain, not the record location: a
    client reading the target column wants `acc.example`, not a name they
    never put in scope and that this stage invented.
    """
    return host[len(DMARC_PREFIX):] if is_dmarc_name(host) else host


def spf_verify_command(host: str) -> str:
    return f"dig +short TXT {host} | grep -i spf1"


def dmarc_verify_command(host: str) -> str:
    return f"dig +short TXT {dmarc_name(host)}"


def analyse_spf(host: str, txt: str) -> Finding | None:
    if not txt.lower().startswith("v=spf1"):
        return None
    if re.search(r"[+?]all\b", txt, re.I):
        return Finding(
            # matcher=txt: a host publishing MORE THAN ONE SPF record (a
            # misconfiguration in its own right, but a real one operators
            # do ship) can have more than one record independently judged
            # permissive here. Without a matcher every one of them shares
            # (stage, target, template_id) and collides onto a single id --
            # exactly the class this fix exists to close. The full record
            # text is intrinsic to the record itself and identical on a
            # rerun against the same DNS answer, so it keeps finding_id
            # stable across runs while still telling two distinct records
            # apart. See sweeper.artifacts.finding_id's docstring.
            stage="dnsx", severity="medium", title="Permissive SPF policy",
            target=host, template_id="dns-spf-permissive", matcher=txt,
            evidence=txt,
            description="The SPF record ends in +all or ?all, which permits any "
                        "host to send mail for this domain.",
            remediation="End the SPF record with -all (fail) or ~all (softfail).",
        )
    return None


def analyse_dmarc(host: str, txt: str, found_at: str | None = None) -> Finding | None:
    """Judge the policy that APPLIES to `host`, wherever it is published.

    `found_at` names the domain the record was actually found at, which is
    `host` itself unless the policy was inherited from the organizational
    domain (see dmarc_lookup_chain). It goes in the evidence rather than the
    target: the weakness applies to the scoped host, and an operator who
    reads "p=none" against a name they scoped needs to be told the record
    lives one level up or they will look for it in the wrong zone.
    """
    if "v=dmarc1" not in txt.lower():
        return None
    if re.search(r"\bp\s*=\s*none\b", txt, re.I):
        source = (f"{txt}  (published at {dmarc_name(found_at)}, inherited "
                  f"by {host})") if found_at and found_at != host else txt
        return Finding(
            # matcher=txt: same reasoning as analyse_spf above -- more than
            # one DMARC-looking TXT record on one host must not collapse
            # onto one id.
            stage="dnsx", severity="low", title="DMARC policy set to none",
            target=host, template_id="dns-dmarc-weak", matcher=txt,
            evidence=source,
            description=(
                "DMARC is published in monitor-only mode, so failing "
                "mail is still delivered."
                + ("" if not found_at or found_at == host else
                   f" The policy is not published on this name: it is "
                   f"inherited from {found_at}, which is where a receiver "
                   f"finds it and where it has to be changed.")),
            remediation="Move to p=quarantine, then p=reject once reporting is clean.",
        )
    return None


def analyse_caa(host: str, caa_values: list, ref: str = "") -> Iterator[Finding]:
    """CAA is the control that stops a mis-issued certificate.

    With no CAA record, ANY public CA may issue for the domain: an attacker
    who can pass one CA's domain-validation check -- via a hijacked DNS
    answer, an exposed .well-known path, or a mail alias -- gets a
    browser-trusted certificate for the name. Publishing CAA restricts that
    to the CAs the owner names.

    Reported at `info`: it is a hardening gap rather than a live
    vulnerability, and on most estates it is a finding the client can fix
    the same day.
    """
    values = [str(v).strip() for v in (caa_values or []) if str(v).strip()]
    if not values:
        # Title states the RISK, not the observation: these findings go
        # into client reports as written, and "No CAA record published"
        # describes what the scanner saw rather than what the client is
        # being told. Two verification commands, because that is how the
        # check is confirmed by hand -- the CAA query, and a type257
        # cross-check against a second resolver, since a record absent in
        # one view and present in another is a real answer that one
        # command cannot reveal.
        verify = (f"dig +nocmd {host} CAA +multiline +noall +answer  "
                  f"# cross-check: dig @8.8.8.8 {host} type257")
        yield Finding(
            stage="dnsx", severity="info",
            title="Increased risk of false certificate creation due to "
                  "not using CAA",
            target=host, template_id="dns-caa-missing",
            matcher=host, raw_ref=ref,
            evidence=f"{verify} -> no CAA record returned",
            description="The domain publishes no CAA record, so any public "
                        "certificate authority may issue certificates for it. "
                        "A CAA record restricts issuance to named CAs and "
                        "limits the impact of a domain-validation bypass.",
            remediation=(
                "Publish a CAA record naming only the CAs authorised to "
                f"issue for this domain. Verify with `{verify}`."),
        )
        return
    for value in values:
        issuer = ""
        m = re.search(r'\b(issue|issuewild)\s+"([^"]*)"', value, re.I)
        if m:
            issuer = m.group(2).strip()
        # `;` is the documented "no CA may issue" value -- a deliberate and
        # correct posture, not a weakness.
        if m and issuer in CAA_ANY_ISSUER:
            yield Finding(
                stage="dnsx", severity="low",
                title="CAA record authorises any certificate authority",
                target=host, template_id="dns-caa-permissive",
                matcher=value, evidence=value, raw_ref=ref,
                description="The CAA record names no specific CA, so it "
                            "permits issuance by any authority. This is the "
                            "same exposure as publishing no CAA at all, while "
                            "appearing to be a control.",
            )


def analyse_soa(host: str, soa_values: list, ref: str = "") -> Iterator[Finding]:
    """A SOA naming an internal host discloses infrastructure.

    dnsx renders SOA as objects (`ns`, `mailbox`) rather than a flat string,
    so both fields are checked: an internal nameserver name or an admin
    mailbox on a .local/.internal/.corp domain tells an attacker what the
    estate looks like behind the edge.
    """
    INTERNAL_MARKERS = (".local", ".internal", ".corp", ".lan", ".intranet",
                        ".home", ".localdomain")
    for entry in soa_values or []:
        if isinstance(entry, dict):
            parts = [str(entry.get("ns") or ""), str(entry.get("mailbox") or "")]
        else:
            parts = [str(entry)]
        for part in parts:
            low = part.lower().rstrip(".")
            if low.endswith(INTERNAL_MARKERS) or is_private(low):
                yield Finding(
                    stage="dnsx", severity="low",
                    title="SOA record names an internal host",
                    target=host, template_id="dns-soa-internal-host",
                    matcher=part, evidence=part, raw_ref=ref,
                    description="The zone's SOA record references a hostname "
                                "on an internal-only domain, disclosing "
                                "internal infrastructure naming to anyone who "
                                "queries public DNS.",
                )
                return


def parse_axfr(row: dict, zone: str, ref: str,
               seen_records: set[str] | None = None,
               seen_findings: set[tuple] | None = None,
               ) -> Iterator[Artifact | Finding]:
    """Everything a successful zone transfer tells us.

    SHAPE, measured against dnsx 1.2.3 rather than assumed (see
    tests/fixtures/dnsx-axfr.jsonl): `axfr` is an object with `host` and
    `chain`, where each chain entry is an ordinary dnsx record row, and the
    SAME entry repeats once per nameserver that answered the transfer. A
    two-nameserver zone therefore returns every record twice — hence the
    dedupe below, without which one zone reports its whole contents two or
    three times over.

    ATTRIBUTION, and its honest limit: dnsx flattens the transferred records
    onto the zone apex instead of keeping each under its own name, so a TXT
    record that really lives at `_dmarc.<zone>` arrives labelled with the
    zone. Findings derived here are therefore targeted at the ZONE, which is
    the most specific thing the data actually supports. Do not "fix" this
    into per-name attribution: the names are not in the output to recover.

    WHAT IT UNLOCKS. analyse_dmarc() has existed since this stage was
    written and could never fire, because DMARC lives at `_dmarc.<domain>`
    and nothing ever put that name in a target list. Same for credentials
    published in TXT. A zone transfer returns both, so reading it turns two
    pieces of unreachable code into working controls.
    """
    axfr = row.get("axfr") or {}
    chain = axfr.get("chain") or []
    if not chain:
        return

    # Shared with parse()'s own record loop, not private to this function:
    # the chain re-states the apex records that the top-level row already
    # yielded, so a set scoped to the transfer alone still emits every apex
    # record twice -- once as a lookup, once as a transfer.
    if seen_records is None:
        seen_records = set()
    # Distinct records the TRANSFER returned, counted independently of
    # seen_records: that set is shared with the caller, so a record already
    # emitted as a lookup is suppressed from the output but is still part of
    # what the zone handed over, and the evidence must say so.
    chain_records: set[str] = set()
    # Also shared with the caller, for the same reason seen_records is: the
    # transfer restates apex TXT that the ordinary lookup already analysed.
    if seen_findings is None:
        seen_findings = set()
    pending: list[Finding] = []

    for entry in chain:
        entry_host = entry.get("host") or zone
        for key in RECORD_KEYS:
            for value in entry.get(key) or []:
                if not value or not str(value).strip():
                    continue
                record = f"{entry_host} {key.upper()} {value}"
                chain_records.add(record)
                if record in seen_records:
                    continue
                seen_records.add(record)
                yield Artifact(
                    ArtifactKind.DNS_RECORD, record,
                    meta={"host": entry_host, "type": key.upper(),
                          "value": value, "src": "axfr"},
                )

        for txt in entry.get("txt") or []:
            if not txt:
                continue
            for finding in (analyse_spf(entry_host, txt),
                            analyse_dmarc(entry_host, txt)):
                if finding:
                    pending.append(finding)
            # stage="dnsx", not the default: a finding's stage is what tells
            # a reader which evidence file to open, and an AWS key published
            # in a DNS TXT record blamed on the JavaScript stage sends them
            # to the wrong one entirely.
            pending.extend(scan_text(txt, entry_host, stage="dnsx"))

    # The transfer itself, before the contents. Routed through `pending` like
    # every other finding here so it goes through the SAME dedupe: the
    # repeated chain must not turn one misconfiguration into three, and
    # neither must two dnsx rows that happen to name the same zone.
    pending.insert(0, Finding(
        stage="dnsx", severity="high",
        title="Unrestricted DNS zone transfer (AXFR)",
        target=zone, template_id="dns-zone-transfer",
        evidence=f"AXFR succeeded against {zone}: "
                 f"{len(chain_records)} distinct records returned",
        raw_ref=ref,
        description="The zone's nameservers answer AXFR from any client, "
                    "handing over every record in the zone. That discloses "
                    "the full internal inventory the zone describes -- "
                    "hostnames, addresses and TXT contents that were never "
                    "meant to be enumerable.",
        remediation="Restrict AXFR to the zone's secondary nameservers "
                    "(allow-transfer / TSIG) and deny it to everyone else.",
    ))

    for finding in pending:
        key = (finding.template_id, finding.target, finding.matcher)
        if key in seen_findings:
            continue
        seen_findings.add(key)
        finding.raw_ref = ref
        yield finding


class DnsxStage:
    name = "dnsx"
    #: This tool takes an operator-supplied resolver; see
    #: sweeper.resolvers and run.json's "resolver" block.
    honors_resolver = True
    requires = ["dnsx"]
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.DNS_RECORD, ArtifactKind.FINDING}
    optional = False
    # -soa and -caa are still deliberately NOT requested: parse() has no
    # handling for those keys, and requesting a flag whose result is
    # discarded costs queries and throws the answer away. -axfr WAS in that
    # group for the same reason and has now left it — parse_axfr below reads
    # it, against a fixture captured from the real binary (see
    # tests/fixtures/dnsx-axfr.jsonl), which is the condition that comment
    # set for requesting it.
    #
    # Not at `low`: that level is documented as safe recon, and a zone
    # transfer is a different kind of request from a lookup — it asks a
    # nameserver to hand over its entire zone, it is logged as such, and it
    # is the kind of thing a client's DNS team notices. It is read-only, so
    # it belongs well below the `full` line, but not in the level chosen for
    # an unfamiliar estate.
    # Identical at every level, `low` included (operator decision,
    # 2026-08-04). DNS answers a configuration question -- what the zone
    # publishes -- and that answer does not change with scan depth. The
    # cost is a handful of extra queries per host against a nameserver
    # built to answer them, which is not what `low` exists to keep small.
    #
    # What this un-hides below `mid`: -axfr. An open zone transfer is the
    # highest-value DNS finding there is, and it was unreachable at `low`.
    #
    # -auto-wildcard, NOT -wd. Verified against dnsx 1.2.3: -wd takes a
    # string (a domain for manual wildcard filtering), so passing it bare
    # emits "flag needs an argument: -wd" — which preflight correctly
    # classifies as ARG_ERROR and aborts the whole run on. -auto-wildcard
    # is the valueless automatic-detection flag actually wanted here.
    _CHECKS = ["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
               "-caa", "-soa", "-ptr", "-srv",
               "-auto-wildcard", "-axfr"]
    levels = {
        "low":  list(_CHECKS),
        "mid":  list(_CHECKS),
        "high": list(_CHECKS),
        "full": list(_CHECKS),
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        from ..rate import replace_value_flag
        binary = binaries.resolve("dnsx")
        hosts_file = ctx.run_dir / "raw" / "dnsx-input.txt"
        hosts_file.parent.mkdir(parents=True, exist_ok=True)
        permitted, _ = ctx.scope.filter(ctx.store.values(ArtifactKind.HOST))
        # SCOPE FIRST, DERIVE SECOND. The `_dmarc.` names are built from the
        # ALREADY-FILTERED list, so a derived name can never become a way to
        # query a host the allowlist refused. They are asked for because
        # DMARC lives nowhere else (see DMARC_PREFIX): without them the
        # policy check has no reachable input on any zone that correctly
        # refuses AXFR.
        #
        # The chain, not just the host: a policy inherited from the
        # organizational domain is invisible if the ancestor is never asked
        # about, and inheritance is the receiver's own rule. See
        # dmarc_lookup_chain. Deduplicated because a scope of sibling
        # subdomains shares every ancestor, and asking once is enough.
        derived: list[str] = []
        for host in permitted:
            if is_dmarc_name(host):
                continue
            for name in dmarc_lookup_chain(host):
                candidate = dmarc_name(name)
                if candidate not in derived:
                    derived.append(candidate)
        queried = list(permitted) + derived
        hosts_file.write_text("\n".join(queried) + "\n", encoding="utf-8")
        from .. import resolvers
        flags = replace_value_flag(
            self.levels[ctx.config.level], ("-rl", "-rate-limit"),
            "-rl", ctx.config.rate_override,
        )
        return [
            str(binary), "-l", str(hosts_file), "-json", "-silent", "-duc",
            *flags,
            # The stage this matters most to: without it every name in a
            # split-horizon scope resolves NXDOMAIN and the stage completes
            # successfully having found nothing.
            *resolvers.flag_args(ctx),
        ]

    def parse(self, raw_path: Path) -> Iterator[Artifact | Finding]:
        # Record dedupe spans the WHOLE file, not one row: a zone transfer
        # re-states the apex records the ordinary lookup already returned,
        # and dnsx emits a row per queried name, so several names in one zone
        # each carry the same transferred contents.
        seen_records: set[str] = set()
        # Same span, same reason, for FINDINGS. A zone transfer re-states the
        # apex TXT the ordinary lookup already analysed, so the permissive
        # SPF record in it was reported twice -- once from the lookup, once
        # from the transfer. Keyed the way store.add_finding computes a
        # finding id, so two entries that collapse there are collapsed here
        # rather than being handed over as if they were separate evidence.
        seen_findings: set[tuple] = set()

        def once(finding):
            key = (finding.template_id, finding.target, finding.matcher)
            if key in seen_findings:
                return []
            seen_findings.add(key)
            return [finding]

        # ABSENCE IS INVISIBLE IN THE ROWS. Measured against dnsx 1.2.3: a
        # name with no answer produces NO ROW AT ALL -- `_dmarc.google.com`
        # comes back with txt, `_dmarc.<host with no DMARC>` comes back with
        # nothing whatsoever. So "no DMARC" cannot be read off a row; it is
        # inferred from the base hosts that DID answer, after the whole file
        # has been walked. Same for SPF, which is a TXT record on the host
        # itself that simply is not there.
        answered: list[tuple[str, str]] = []   # (base host, its row ref)
        spf_present: set[str] = set()
        #: domain a policy was FOUND AT -> (its record text, its row ref).
        #: Collected rather than judged in place, because which in-scope host
        #: a policy applies to is not knowable until the whole file is
        #: walked: an ancestor's record covers every scoped subdomain that
        #: publishes none of its own, and the finding belongs on those
        #: subdomains -- not on the ancestor, which the client may never have
        #: put in scope and would not expect in a target column.
        dmarc_records: dict[str, tuple[str, str]] = {}

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

            host = row.get("host", "")
            ref = f"raw/dnsx.jsonl#L{lineno}"

            # A `_dmarc.` row is a RECORD LOCATION this stage asked for, not
            # an asset in the client's scope. It carries exactly one thing
            # worth reading -- the policy -- and must not be walked through
            # the ordinary audit below, or every run would grow a
            # private-IP/CAA/takeover finding set for a name the operator
            # never scoped, reported against a target they would not
            # recognise.
            if is_dmarc_name(host):
                domain = base_of(host)
                for txt in row.get("txt") or []:
                    if "v=dmarc1" not in str(txt).lower():
                        continue
                    dmarc_records.setdefault(domain, (str(txt), ref))
                continue

            # ANSWER_KEYS for the same reason the CAA check uses it (see
            # its constant): a host that returned NOTHING did not resolve,
            # and "this domain publishes no SPF" said about a name we never
            # reached is a finding about our own DNS, not the target's.
            #
            # The ref is kept with the host because an absence finding still
            # needs an evidence pointer: the row where the host ANSWERED is
            # what proves it resolved and returned no SPF, which is exactly
            # the evidence for "there is none".
            if host and any(row.get(k) for k in ANSWER_KEYS):
                answered.append((host, ref))
                for txt in row.get("txt") or []:
                    if str(txt).lower().startswith("v=spf1"):
                        spf_present.add(host)

            for key in RECORD_KEYS:
                for value in row.get(key) or []:
                    if not value or not str(value).strip():
                        continue      # dnsx emits "" for null MX
                    record = f"{host} {key.upper()} {value}"
                    if record in seen_records:
                        continue
                    seen_records.add(record)
                    yield Artifact(
                        ArtifactKind.DNS_RECORD, record,
                        meta={"host": host, "type": key.upper(), "value": value},
                    )

            # CAA and SOA assessment, but ONLY for a host that actually
            # answered. A row with no records at all is a name that did not
            # resolve, and "publishes no CAA" said about a host we never
            # reached is a finding about our own DNS rather than the target.
            if any(row.get(k) for k in ANSWER_KEYS):
                yield from analyse_caa(host, row.get("caa") or [], ref)
                yield from analyse_soa(host, row.get("soa") or [], ref)

            for ip in row.get("a") or []:
                if is_private(ip):
                    yield Finding(
                        # matcher=ip: a host that leaks MORE THAN ONE
                        # private address (multi-homed internal host, split
                        # DNS bleeding through, etc.) is a genuinely worse
                        # finding than leaking one, and each address is its
                        # own piece of evidence for the report. Without a
                        # matcher every private A record on this host shares
                        # (stage, target, template_id) and only the first
                        # one submitted survives store.add_finding -- the
                        # rest vanish with no error. The ip string itself is
                        # intrinsic to the record and unchanged on a rerun
                        # against the same DNS answer, so this keeps
                        # finding_id stable across runs (see finding_id's
                        # docstring) while making two distinct IPs hash
                        # differently.
                        stage="dnsx", severity="medium",
                        title="Private address published in public DNS",
                        target=host, template_id="dns-private-ip", matcher=ip,
                        evidence=f"{host} A {ip}", raw_ref=ref,
                        description="An RFC1918 address is resolvable publicly, "
                                    "disclosing internal network structure.",
                        remediation="Serve internal records from split-horizon DNS.",
                    )

            for cname in row.get("cname") or []:
                # Require a DNS label boundary. A bare endswith() matches any
                # domain that merely ends with the vendor string —
                # "fakegithub.io" would be reported as a github.io takeover
                # primitive. Same suffix-confusion class as the scope guard.
                cn = cname.lower().rstrip(".")
                if any(cn == s or cn.endswith("." + s) for s in TAKEOVER_SUFFIXES):
                    yield Finding(
                        # matcher=cn: a host can carry more than one CNAME
                        # entry (dnsx returns a list), and two different
                        # dangling targets on one host are two independent
                        # takeover candidates, not one. cn is already
                        # normalised (lowercased, trailing dot stripped)
                        # above, so it is stable across runs even if a
                        # rerun's raw answer differs only in case or
                        # trailing-dot form.
                        stage="dnsx", severity="high",
                        title="CNAME to third-party host — takeover candidate",
                        target=host, template_id="dns-dangling-cname",
                        matcher=cn,
                        evidence=f"{host} CNAME {cname}", raw_ref=ref,
                        description="The record delegates to a third-party service. "
                                    "If the resource is unclaimed the name can be "
                                    "taken over.",
                        remediation="Confirm the target is claimed, or remove the record.",
                    )

            txts = [t for t in (row.get("txt") or []) if t]
            spf = [t for t in txts if t.lower().startswith("v=spf1")]
            # Missing SPF is emitted after the whole file is read, not here:
            # see the absence pass at the end of parse(). The MX gate that
            # used to live at this point was wrong for a spoofing finding --
            # forgery uses the domain in the envelope, not the domain's
            # ability to RECEIVE mail, which is why the guidance for a
            # non-mail domain is to publish `v=spf1 -all` rather than
            # nothing at all.
            for t in spf:
                f = analyse_spf(host, t)
                if f:
                    f.raw_ref = ref
                    yield from once(f)
            for t in txts:
                f = analyse_dmarc(host, t)
                if f:
                    f.raw_ref = ref
                    yield from once(f)

            yield from parse_axfr(row, host, ref, seen_records, seen_findings)

        # --- coverage pass: hosts we asked about and never heard back -----
        # dnsx SILENTLY OMITS a host it decides not to report. Measured on
        # a live scope 2026-08-05: with -auto-wildcard, one of three scoped
        # hosts produced no row at all, deterministically (3/3 rows without
        # the flag, 2/3 with it). The host resolves; it is served by
        # wildcard DNS, which is what the flag filters.
        #
        # Every DNS finding for that host silently did not exist, and the
        # stage still reported `complete`. Worse, the absence MASQUERADED
        # as a result: two hosts flagged for missing CAA read as "the third
        # publishes CAA", when the third was never examined at all.
        #
        # The input file this stage wrote is the denominator. It sits next
        # to the raw output, and its absence (older run dirs, direct parse()
        # calls in tests) means no gap findings rather than guesses.
        input_file = Path(raw_path).parent / "dnsx-input.txt"
        if input_file.exists():
            answered_names = {h for h, _ in answered} | {
                dmarc_name(d) for d in dmarc_records}
            for line in input_file.read_text(encoding="utf-8").splitlines():
                name = line.strip()
                # A `_dmarc.` name with no row is the NORMAL case -- it is
                # what "no DMARC published" looks like, and it already has
                # its own finding above. Reporting it here as well would
                # fire on every correctly-scanned host in every run.
                if not name or is_dmarc_name(name) or name in answered_names:
                    continue
                yield from once(Finding(
                    stage="dnsx", severity="info",
                    title="Host was queried but returned no DNS answer — "
                          "not assessed",
                    target=name, template_id="dns-host-no-answer",
                    matcher=name, raw_ref="raw/dnsx-input.txt",
                    evidence=f"{name} appears in dnsx-input.txt with no "
                             f"corresponding row in dnsx.jsonl",
                    description=(
                        "This host was in scope and was queried, but dnsx "
                        "returned no record for it, so NO DNS finding of any "
                        "kind could be produced about it — CAA, SPF, DMARC "
                        "and CNAME checks all had no input. A known cause is "
                        "-auto-wildcard suppressing a host served by wildcard "
                        "DNS. Treat this host's DNS posture as unassessed "
                        "rather than clean."),
                    remediation=(
                        f"Query it directly to establish its posture: "
                        f"`dig +short {name} ANY`, and re-run dnsx without "
                        f"-auto-wildcard if the name resolves."),
                ))

        # --- absence pass -------------------------------------------------
        # Runs once the whole file has been walked, because absence has no
        # row of its own to hang off. `answered` holds only base hosts that
        # actually resolved, so a name that does not exist at all cannot
        # produce a mail-security finding about a domain that is not there.
        for domain, host_ref in dict(answered).items():
            if domain not in spf_present:
                cmd = spf_verify_command(domain)
                yield from once(Finding(
                    stage="dnsx", severity="low",
                    title="Domain spoofing possible due to absence of SPF",
                    target=domain, template_id="dns-spf-missing",
                    raw_ref=host_ref,
                    evidence=f"{cmd} -> no SPF record returned",
                    description=(
                        "The domain publishes no SPF record, so no receiving "
                        "mail server can tell which hosts are permitted to "
                        "send on its behalf. Mail forged from this domain "
                        "has no mechanism to be rejected on that basis. This "
                        "applies whether or not the domain receives mail: "
                        "forgery uses the sender domain, not its MX."),
                    remediation=(
                        "Publish an SPF record listing the permitted senders "
                        "and ending in -all, or `v=spf1 -all` if the domain "
                        f"sends no mail at all. Verify with `{cmd}`."),
                ))
            # The NEAREST published policy in this domain's lookup chain,
            # which is the one a receiver applies -- the host's own record
            # if it has one, otherwise the organizational domain's. Only
            # when the whole chain is empty is the policy genuinely absent.
            found_at = next((name for name in dmarc_lookup_chain(domain)
                             if name in dmarc_records), None)
            if found_at is not None:
                record, record_ref = dmarc_records[found_at]
                weak = analyse_dmarc(domain, record, found_at=found_at)
                if weak:
                    weak.raw_ref = record_ref
                    yield from once(weak)
            else:
                cmd = dmarc_verify_command(domain)
                yield from once(Finding(
                    stage="dnsx", severity="low",
                    title="Domain spoofing possible due to absence of DMARC",
                    target=domain, template_id="dns-dmarc-missing",
                    raw_ref=host_ref,
                    evidence=f"{cmd} -> no DMARC record returned",
                    description=(
                        "No DMARC policy is published at "
                        f"{dmarc_name(domain)}, so a receiving server has no "
                        "instruction on what to do with mail that fails SPF "
                        "or DKIM alignment, and the domain owner receives no "
                        "reports of forgery attempts."),
                    remediation=(
                        "Publish a DMARC record starting at p=none with rua "
                        "reporting, then raise to p=quarantine and p=reject "
                        f"once reports are clean. Verify with `{cmd}`."),
                ))
