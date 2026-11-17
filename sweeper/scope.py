# sweeper/scope.py
"""Allowlist enforcement.

Checked before every request-issuing subprocess, not only at input parse
time. subfinder produces hosts that were never in the targets file and
katana can follow offsite links; both can reach unauthorized systems.

Default-deny. A bare entry matches only itself; subdomains require an
explicit "*." wildcard entry.

"*.acc.example" matches the apex "acc.example" as well as every subdomain,
and does NOT match itself.

The apex half is a real scope decision and is recorded here rather than left
implicit. The stricter reading -- a wildcard covers only what is strictly
below it, so an operator wanting the apex writes it on its own line -- is the
safer default in the abstract, because scope is then exactly what the
operator typed. It is not the reading in force, for two reasons:

  * The apex is what "*.acc.example" means in an RoE. Every consumer of that
    notation an operator meets (certificate SANs, DNS provider UIs, every
    scope grant written in prose) reads it as "this domain and everything
    under it". Narrowing it would silently drop the primary host of the
    engagement from a run whose targets file was accepted without complaint
    -- a scanner that quietly scans less than authorised is its own kind of
    defect, and the one an operator is least likely to notice.

  * The semantic is mirrored in two other places that derive from
    ScopeGuard.allowed: katana's -cs crawl-scope regexes
    (stages/katana.py::_host_pattern) and diff's cross-run coverage probe
    (diff.py::_entry_uncovered). Narrowing it here alone would leave the
    crawler and the retest-coverage comparison believing something the guard
    no longer believes, which is worse than either reading applied
    consistently.

If it is ever narrowed, all three must change together, and a targets file
of "*.acc.example" alone must then fail preflight with a message that says
the apex is no longer included -- not with the generic no-permitted-targets
error.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

# A spec written using only the characters an IPv4 address can contain, plus
# the hyphen. nmap and naabu both read "10.0.0.1-5" and "10.0.0-255.1" as
# octet RANGES, not as hostnames -- yet both are syntactically valid DNS
# labels, so a hostname grammar admits them. The alphabetic test is what
# separates the two readings: an IPv4-shaped spec with a hyphen in it is a
# range, while "host-1.acc.example" contains letters, is resolved as a name
# by both tools, and is one host. IPv6 has no equivalent range syntax in any
# of the twelve tools; its multi-host form is CIDR, which ipaddress proves.
_NUMERIC_SPEC = re.compile(r"[0-9.-]+\Z")

# What may stand in front of a "*." entry's base for the host to be a
# SUBDOMAIN of it: one or more DNS labels. Two separate defects live here.
#
# (1) The left label boundary. The match has to be host == base or
#     host.endswith("." + base); the leading dot is load-bearing. Drop it and
#     "evil-acc.example" ends with "acc.example", so an allowlist of
#     "*.acc.example" admits a domain an attacker can register. Requiring the
#     part before the base to be label-shaped states that boundary as a
#     property rather than leaving it implicit in one "." inside a string
#     concatenation.
#
# (2) The entry matching itself. normalize("*.acc.example") is
#     "*.acc.example" -- unchanged, because urlsplit has no opinion about
#     "*" -- and that string ends with ".acc.example", so a plain endswith()
#     test says the wildcard LINE is in scope. app.prepare() then seeds it as
#     a HOST artifact: every HOST-consuming stage issues one query for a
#     hostname that cannot resolve, targets_permitted counts it, and the
#     client's asset inventory lists "*.acc.example" among the hosts scanned.
#     "*" is not a DNS label character, so the same property excludes it with
#     no special case for the marker.
#
# Underscore is admitted because real hosts use it (_dmarc, SRV/DKIM names,
# and Windows environments) and refusing it would silently drop them from a
# scope the operator granted.
_WILDCARD_PREFIX = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\Z")


def normalize(target: str) -> str:
    """Reduce a URL / host:port / bare host to a comparable hostname.

    Everything is routed through urlsplit, including bare hosts, by
    prefixing "//" when no scheme is present. Hand-rolling the host:port
    split is how scope bypasses happen: "acc.example:80@evil.test" splits
    on the first colon to "acc.example" and is admitted, while the string
    actually passed downstream still addresses evil.test. urlsplit's
    .hostname correctly treats everything before the last "@" as userinfo,
    strips the port, lowercases, and handles bracketed IPv6.
    """
    t = target.strip()
    if not t:
        return ""
    if "://" not in t:
        t = "//" + t
    try:
        host = urlsplit(t).hostname or ""
    except ValueError:          # malformed authority, e.g. bad IPv6 literal
        return ""
    return host.rstrip(".")


def multi_host_error(target: str) -> str:
    """Why `target` reaches more hosts than its allowlist entry covers, or "".

    The allowlist stores one hostname per entry, because normalize() reduces
    every input to one hostname. That is sound for the forms an operator
    normally writes -- a bare host, host:port, a URL -- where the line and
    the entry denote the same single host. It is NOT sound for a line the
    scanners expand: naabu, nmap and dnsx all read CIDR natively, so
    "127.0.0.0/30" puts ONE host ("127.0.0.0", all normalize() can salvage)
    in the allowlist and sweeps four. The three that are not in the allowlist
    are scanned, then refused by admission control on the way back in, and
    filed under discoveries_refused -- the one bucket that by design never
    marks a run degraded. Unauthorised hosts scanned, their findings dropped,
    and a report that says "1 requested, 1 in scope. No findings."

    So this is the question the allowlist cannot answer for itself: does this
    line reach further than the entry it produces? A non-empty return means
    yes, and the caller must refuse -- see run_preflight, which refuses the
    whole run, and allows()/__init__ below, which refuse the line.

    Refusing rather than expanding is deliberate. Expansion is only defined
    for ranges small enough to enumerate: a /16 is 65k allowlist entries and
    an IPv6 /64 cannot be enumerated at all, so an expanding implementation
    still has to refuse somewhere and merely moves the cliff. More
    fundamentally, expanding would widen scope on the operator's behalf from
    a line that proves authorisation for exactly nothing -- the opposite of
    what a pentest tool should do with an ambiguous grant.

    A leading "*." is exempt, and is the sanctioned way to say "many hosts".
    It also denotes more than one host, but unlike a CIDR the ENTRY covers
    every one of them: _is_permitted() matches the base and any subdomain of
    it, so nothing this line causes to be scanned can fall outside scope.
    That is the property this function is really testing -- not "how many
    hosts is this?" but "are all of them in the allowlist entry?"
    """
    raw = (target or "").strip()
    if not raw:
        # An empty line is not a scope problem; _parse_targets drops it and
        # run_preflight's empty-targets check is what speaks to a file of
        # nothing but blanks.
        return ""
    if raw.startswith("*."):
        return ""

    if "://" in raw:
        # A URL's authority is unambiguous and its path is a path: nothing
        # after the host widens the host set, so "http://10.0.0.0/24" is one
        # host with an odd path, not a network. Only the hostname is checked.
        candidates = [normalize(raw)]
    else:
        # A schemeless line has no path, so anything normalize() discarded
        # ("/30", "/126") was host-set syntax, not a URL path. Both the raw
        # line and the salvaged hostname are checked: the raw line carries
        # the CIDR suffix, and the hostname is what survives a :port suffix
        # ("10.0.0.1-5:80" -> "10.0.0.1-5").
        candidates = [raw, normalize(raw)]

    for spec in candidates:
        if not spec:
            continue
        try:
            # strict=False so a host-bit-set form ("10.0.0.1/24") is read as
            # the network it addresses rather than raising. Proven by the
            # stdlib for BOTH families instead of pattern-matched, so an
            # IPv6 prefix is caught by the same line as an IPv4 one.
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            net = None
        if net is not None and net.num_addresses > 1:
            return (f"CIDR notation covering {net.num_addresses} addresses "
                    f"({net})")
        if "*" in spec:
            return "a wildcard matching every host in a range"
        if "," in spec:
            return "a comma-separated list of more than one target"
        if "-" in spec and _NUMERIC_SPEC.match(spec):
            return "an address range (nmap/naabu octet-range syntax)"
    return ""


def _normalize_allowlist_entry(entry: str) -> str:
    """Normalize one allowlist entry exactly as allows()/extend() normalize
    the strings they compare it against.

    A bare .strip().lower().rstrip(".") here is not the same transform as
    normalize(): it does not route host:port or scheme-prefixed forms
    through urlsplit. "127.0.0.1:8080" and "http://127.0.0.1/app" are the
    two most ordinary ways an operator writes a targets file entry, and
    storing them verbatim while allows() compares fully normalized hosts
    means the allowlist refuses its own entries.

    The "*." wildcard marker is preserved: only the base after it is run
    through normalize(), then the prefix is reattached, so
    "*.ACC.EXAMPLE:9090" and "acc.example" land in the same comparable form.
    """
    entry = (entry or "").strip()
    if not entry:
        return ""
    if multi_host_error(entry):
        # Dropped, not stored narrowed. The alternative is what shipped: a
        # "/30" entry silently became the single host normalize() salvaged
        # from it, so the allowlist claimed to authorise a network and
        # actually authorised one address of it. An entry that cannot be
        # stored faithfully must not be stored at all -- with it dropped,
        # every host in the range is out of scope and a targets file
        # containing nothing else fails run_preflight's no-permitted-targets
        # check on top of its explicit multi-host error. ("*." entries are
        # exempt inside multi_host_error and reach the branch below.)
        return ""
    if entry.startswith("*."):
        base = normalize(entry[2:])
        return f"*.{base}" if base else ""
    return normalize(entry)


class ScopeGuard:
    def __init__(self, allowed: set[str]) -> None:
        self.allowed = {
            n for n in (_normalize_allowlist_entry(a) for a in allowed) if n
        }
        self.refusals: list[dict] = []
        self.extensions: list[dict] = []
        # Separate from `refusals` on purpose. `refusals` means "the
        # operator supplied a target outside scope" -- noteworthy, possibly
        # an RoE problem. `discoveries_refused` means "a tool discovered
        # something outside scope and admission control correctly did not
        # let it into the store" -- expected, routine, and on some runs
        # (subfinder finding hundreds of subdomains) the normal case. See
        # record_discovery_refusal().
        self.discoveries_refused: list[dict] = []

    def _is_permitted(self, host: str) -> bool:
        """The membership test alone, with no side effects.

        Shared by allows() (which records a refusal) and permits_discovery()
        (which deliberately does not) so the two call paths can never
        disagree about what is in scope -- only about what they do with a
        `False` result.

        A "*." entry matches the base itself and any subdomain of it. The
        apex is deliberately included -- see the module docstring for why
        that choice was made and what the alternative would cost.
        """
        if not host:
            return False
        for entry in self.allowed:
            if entry.startswith("*."):
                base = entry[2:]
                if host == base:
                    return True
                suffix = "." + base
                # endswith(suffix), NOT endswith(base): see _WILDCARD_PREFIX.
                # The prefix test is what makes the boundary explicit and
                # what stops the entry from matching itself.
                if (host.endswith(suffix)
                        and _WILDCARD_PREFIX.match(host[:-len(suffix)])):
                    return True
            elif host == entry:
                return True
        return False

    def allows(self, target: str) -> bool:
        """Decide, and record every refusal.

        Logging lives here rather than in filter() because allows() is the
        call path later stages use for one-off checks (jsrecon, fetch_js).
        A refusal that is never recorded is an attempted excursion that is
        invisible in the run manifest, which defeats the audit purpose.
        """
        if (target or "").strip().startswith("*."):
            # A "*." line is a scope DECLARATION, not a target. It is not a
            # host -- nothing resolves it -- so it must not be admitted and
            # seeded as one (see _WILDCARD_PREFIX for what admitting it did).
            #
            # Refused, but deliberately NOT recorded in self.refusals. That
            # list means "the operator supplied a target that is outside
            # scope", and the markdown report prints it under "Out-of-scope
            # targets refused — worth checking against the rules of
            # engagement". The operator's own DNS-scope grant is the exact
            # opposite of an excursion, and putting it there would raise a
            # false RoE alarm in a client deliverable. It is not silent: the
            # line still lands in filter()'s `refused` list, which
            # app.prepare() logs, and the grant itself is visible where it
            # belongs -- in self.allowed, which run.json records.
            return False
        host = normalize(target)
        # Checked BEFORE membership, because membership cannot see the
        # problem: normalize("127.0.0.0/30") is "127.0.0.0", which a targets
        # file listing that network puts in the allowlist, so the line
        # matches its own entry and is admitted -- and then app.prepare()
        # seeds the RAW line as a HOST artifact and naabu sweeps all four.
        # A line that reaches past its own entry is out of scope by
        # definition, whatever the entry says. See multi_host_error.
        permitted = not multi_host_error(target) and self._is_permitted(host)
        if not permitted:
            self._record_refusal(target, host)
        return permitted

    def _record_refusal(self, target: str, host: str) -> None:
        if any(r["normalized"] == host for r in self.refusals):
            return
        self.refusals.append({"target": target, "normalized": host})

    def permits_discovery(self, host: str) -> bool:
        """Admission-control check for one artifact's already-extracted,
        already-normalized host (see runner.py's per-ArtifactKind host
        extraction).

        Unlike allows(), this NEVER writes to self.refusals. It is the
        choke point runner.py calls for every artifact a stage's parse()
        yields, which can run into the hundreds for a single discovery
        stage -- routing that volume through the operator-target-refusal
        list would flood it and conflate two different meanings. Call
        record_discovery_refusal() for the separate accounting.
        """
        return self._is_permitted(host)

    def record_discovery_refusal(self, *, stage: str, kind: str,
                                  value: str, host: str) -> None:
        """Accounting for a discovery admission control refused.

        Kept entirely apart from `refusals`: this list is what the report
        labels "discovered, not scanned" rather than "out-of-scope targets
        refused", and it must never feed into anything that treats a large
        count here as run degradation (a subfinder run turning up 200
        out-of-scope subdomains is a *successful* run). Deduped by host
        alone, matching _record_refusal's dedup rule, so a host discovered
        repeatedly (e.g. once per port) is recorded once.
        """
        if any(r["host"] == host for r in self.discoveries_refused):
            return
        self.discoveries_refused.append(
            {"stage": stage, "kind": kind, "value": value, "host": host}
        )

    def filter(self, targets: list[str]) -> tuple[list[str], list[str]]:
        """Split by scope. Refusals are recorded by allows()."""
        permitted, refused = [], []
        for t in targets:
            (permitted if self.allows(t) else refused).append(t)
        return permitted, refused

    def extend(self, hosts: list[str], reason: str) -> None:
        """Widen scope. Only ever called with operator-confirmed input."""
        if not reason:
            raise ValueError("extending scope requires a recorded reason")
        for h in hosts:
            # Same rule as __init__: an entry that cannot be stored
            # faithfully is not stored. extend() is the audited widening
            # path, so letting a CIDR through here would put a scope
            # widening in run.json's extensions[] that reads as one host and
            # authorises none of the others in the range. Every caller today
            # passes resolved hostnames (subfinder output), so this is a
            # backstop, not a filter that fires in normal use.
            if multi_host_error(h):
                continue
            n = normalize(h)
            if n:
                self.allowed.add(n)
                self.extensions.append({"host": n, "reason": reason})
