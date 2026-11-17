"""katana stage — crawling.

Form submission (-aff) is enabled ONLY at full. On a web application,
submitting forms can create orders, apply coupons, or mutate state. That is the
state change `high` is specifically defined not to make.

jsluice is embedded in katana v1.6.1, so -jc -jsl covers JS endpoint
extraction without a separate LinkFinder-class tool.

Authenticated crawling reads ctx.auth from a FILE, not literal -H argv.
Verified against `katana -h`: `-H, -headers string[]` is documented as
"custom header/cookie to include in all http request in header:value
format (file)" -- goflags' "(file)" suffix means the flag also accepts a
path to a file of "header: value" lines. A file of
"Authorization: Bearer ..." / "Cookie: ..." lines
passed via -H is rendered into every crawled request's raw headers exactly
as if it had been passed inline, and mixing a literal `-H "k: v"` with a
`-H <file>` in the same command works too (both were exercised against
katana v1.6.1 directly, not inferred from --help). Routing the live
Authorization/Cookie values through that file instead of argv is layer 2
of the katana credential-leak fix (Task 3.5's runner-level redaction of
sweep.log/run.json is layer 1); redaction alone cannot protect argv from
`ps`, which is exactly why this layer exists. See _write_auth_header_file
below.

Crawl scope is NOT katana's default. katana defaults to
`-field-scope rdn` -- the REGISTRABLE DOMAIN of each seed -- which is
strictly broader than the ScopeGuard built from the targets file, and it
is the crawler itself that widens it: the guard's admission choke point
in runner.py only discards the RESULTS, long after the GET has left the
machine. A targets file of "shop.acc.example" therefore produced live
requests to "internal-admin.acc.example" (verified against a two-vhost
local fixture; see tests/test_stage_katana.py::
test_real_crawl_does_not_touch_a_sibling_host_under_the_same_domain).
At `full` those requests also carry -aff, so forms were filled and
submitted on a host that was never authorized. That is the single worst
thing this tool can do, so every level -- `low` included -- now passes a
crawl scope derived from ctx.scope.allowed. See _write_crawl_scope_file.

Redirects are NOT bounded by any scope flag katana has, so they are
disabled outright (-dr) and re-derived from the response instead. Measured
against v1.6.1 with a two-vhost lab (see tests): with -cs pinned to the
seed host, a 302 was still followed to a sibling under the same
registrable domain AND to an unrelated registrable domain
("evil.test") -- so the redirect hop escapes not merely the ScopeGuard
but katana's OWN -field-scope rdn default. -cos (out-of-scope regex),
-fs (custom field-scope regex) and -e (exclude filter) were each measured
on the same lab and none of them is consulted on the hop either; -dr is
the only control that closes it. There is therefore no flag combination
meaning "follow same-scope redirects, refuse others", and because this is
a scope escape the fallback is REFUSE, so -dr goes on at every level.

The cost of -dr is real and is paid back in parse(), not waved away: a
same-host redirect (a login landing on /dashboard, /admin -> /admin/, an
index redirect) is ordinary and wanted, and -dr stops katana walking it.
What -dr does give us is BETTER evidence of the hop -- when katana follows
a redirect it discards the intermediate response entirely (measured: the
302 row comes back with no `response` object at all), whereas with -dr the
302 is recorded in full, Location header included. So parse() reads that
Location back out and yields the destination as a discovered artifact.
That routes the follow/refuse decision to runner.py's admission choke
point, which -- unlike katana -- fails closed and records what it refused.
Net: an in-scope redirect destination still reaches ctx.store and every
downstream stage, an out-of-scope one is refused and counted instead of
silently fetched, and the only thing actually lost is katana's own
recursive crawl PAST the redirect within the same run. See
_redirect_target below.

That readback needs -duf to work at all, which is not obvious and was
measured rather than assumed. katana's duplicate-content filter is on by
default, and it does not suppress the duplicate ROW -- it suppresses the
`response` OBJECT on every page after the first with identical content.
Redirect bodies are almost always empty, so every 302 in an application is
"identical content" to every other: on an 8-redirect lab exactly ONE
destination came back, the other seven rows arriving with no response and
therefore no Location. With -duf all eight came back. -duf is safe to
carry under the no-DoS term because it is an OUTPUT filter and not a crawl
filter -- the same lab sent exactly 25 requests with it and 25 without, and
emitted 25 rows either way; the only thing that changes is how many of
those rows carry their response.

Raw request/response echo is omitted (-or). katana's jsonl otherwise
carries request.raw, which is the literal wire bytes of every request --
including the Authorization and Cookie headers from _write_auth_header_file
below. _redact_command only covers argv, so the live bearer token and
session cookie landed in cleartext in raw/katana.jsonl, which is the
evidence trail operators archive and hand on; the 0700 run dir contains it
today but does not survive the archive. -or was A/B'd against the real
binary on the same crawl (see tests): it removes request.raw/response.raw
and nothing else -- the endpoint set, response.status_code and
response.headers that parse() reads are byte-identical with and without
it. -eof raw produces the same output and was measured too; -or is
preferred only because it is the dedicated documented flag.

Concurrency/rate: katana's own defaults (-c 10, -rl 150/s) are not
unbounded, unlike ffuf's -rate-0-by-default that vhost.py's docstring
warns about -- but they are still tuned for "crawl fast", not for "sit
under an application's ordinary WAF/rate-limit thresholds", so mid/high/
full set explicit, escalating caps anyway, matching the convention
naabu.py and vhost.py set for the client's no-DoS rules-of-engagement
term. `full` is deliberately the LOWEST of the three, not the highest:
every request full sends can also SUBMIT a form (-aff), so a request there
is a potential real-world mutation (an order, a coupon redemption), not
merely network load -- throttling harder as invasiveness increases is the
opposite of naabu's/vhost's escalation, and that inversion is deliberate,
not a typo. `low` is left at katana's own bare defaults (no extra flags at
all, see KatanaStage.levels) rather than an explicit cap: low never
crawls anything but the seed URLs (no -jc/-jsl, no -aff, no -fx), and
katana's built-in 150/s default is itself already a bound, just not one
this stage writes out -- there is nothing else here to bound tighter.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterator
from urllib.parse import urljoin, urlsplit

from .. import useragents
from ..artifacts import Artifact, ArtifactKind
from ..scope import normalize as normalize_host

# An RE2 expression that cannot match anything: an empty character class is
# rejected by the parser, but "not (whitespace or non-whitespace)" is a
# well-formed class with no members. Emitted when the allowlist is empty so
# the scope file is NEVER empty -- katana treats an empty -cs file as "no
# in-scope constraint supplied" and falls straight back to its rdn default,
# which is the fail-OPEN direction (measured against katana v1.6.1). A file
# holding this line instead crawls only the seeds themselves.
NEVER_MATCHES = r"[^\s\S]"

# Characters a hostname label may contain, for the wildcard case. Deliberately
# NOT "." or a dot-inclusive wildcard: -cs matches against the WHOLE URL
# string, so a permissive class there ("[^/]*" or ".*") lets the subdomain
# part run past the authority and match a target hostname sitting in a path or
# query -- "http://evil.test/?next=http://acc.example" -- which is a scope
# bypass, not a crawl. "." is in the class because a multi-label prefix
# ("a.b.acc.example") is exactly what a "*." entry permits; ":", "@", "/",
# "?" and "#" are all excluded, so a match can never leave the host field.
_LABEL_CHARS = r"[A-Za-z0-9_\-.]"


def _host_pattern(entry: str) -> str:
    """Regex fragment matching exactly the hostnames one allowlist entry
    permits, mirroring ScopeGuard._is_permitted.

    A bare entry matches only itself. A "*." entry matches the base and any
    subdomain of it, which is `host == base or host.endswith("." + base)`
    written as a regex.

    IPv6 gets brackets: scope.normalize() stores the hostname unbracketed
    ("::1"), but the URL katana matches against renders it bracketed
    ("http://[::1]:8080/"), so the two forms have to be reconciled here or
    every IPv6 target silently falls out of scope. A "*." prefix on an IPv6
    literal is meaningless -- an address has no subdomains -- so it is
    dropped rather than turned into a pattern that matches nothing.
    """
    base = entry[2:] if entry.startswith("*.") else entry
    if ":" in base:                       # IPv6 literal
        return r"\[" + re.escape(base) + r"\]"
    if entry.startswith("*."):
        return r"(?:" + _LABEL_CHARS + r"*\.)?" + re.escape(base)
    return re.escape(base)


def crawl_scope_regexes(allowed) -> list[str]:
    """The -crawl-scope regex list for an allowlist: one anchored URL regex
    per entry, plus a never-matching fallback if there are no entries.

    Anchoring is what makes this safe. Each regex pins the scheme at the
    start of the URL, the host immediately after "://", and requires the
    host to be followed by an optional port and then a URL delimiter or the
    end of the string. That is what rejects the userinfo masquerade
    "http://acc.example@evil.test/" -- the character after the host is "@",
    which is neither a port nor a delimiter -- and it is the same reading
    scope.normalize() gives that URL (evil.test, refused).

    Commas are structurally absent from what this builds (no {n,m}
    quantifiers, and hostnames cannot contain one), and that matters: -cs is
    a comma-separated goflags slice, so a comma anywhere in a regex would be
    split into two fragments, each an invalid expression. An invalid -cs
    regex does not make katana exit non-zero -- it makes katana crawl
    NOTHING, silently, with status 0 (measured on v1.6.1), which preflight
    cannot see. test_no_generated_regex_contains_a_comma guards that.
    """
    patterns = [
        r"^(?i:https?://" + _host_pattern(entry) + r"\.?(?::\d+)?(?:[/?#]|$))"
        for entry in sorted(allowed)
    ]
    return patterns or [NEVER_MATCHES]


def _write_crawl_scope_file(ctx) -> Path:
    """Write the crawl-scope regexes for katana's -cs to a file.

    A FILE rather than inline argv, for the same reason the seed list is a
    file: preflight neutralises a stage's real targets by substituting the
    argument SHAPES it recognises, one of which is a "*.txt" path. These
    regexes are built from the allowlist, so inline they would put every
    target hostname in argv, where `ps` shows it to any local user and where
    that substitution does not reach. preflight's fail-closed backstop
    (TargetLeakInProbe) would NOT have objected -- it searches for the
    target as a literal string and a regex-escaped hostname
    ("acc\\.example") does not contain one -- so the guard's silence here is
    a reason to use the file form, not a licence to skip it. katana's -h
    does not advertise "(file)" for -cs
    the way it does for -H, but the file form was confirmed live against
    v1.6.1: a scope file whose regex widened the crawl to a second vhost did
    widen it, while the same path passed to -fs was used as a literal regex
    and read no file at all. That asymmetry is why this is -cs and not -fs.
    """
    path = ctx.run_dir / "raw" / "katana-scope.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(crawl_scope_regexes(ctx.scope.allowed)) + "\n",
                    encoding="utf-8")
    return path


def _write_auth_header_file(ctx) -> Path:
    """Write ctx.auth's headers/cookies to a file katana reads with -H, so
    the live values never appear in argv at all -- visible via `ps` to any
    local user, which no amount of log/manifest redaction can fix.

    Same PERMISSION discipline as auth.to_nuclei_secret_file: owner-only
    (0o600) set on the descriptor between truncation and the write, so
    there is no window where the file is world-readable, and O_NOFOLLOW so
    a symlink planted at the leaf cannot redirect the credential
    elsewhere.

    Containment differs, and deliberately: to_nuclei_secret_file takes a
    CALLER-SUPPLIED path, so it must resolve() it and verify it sits under
    run_dir. This path is not caller-supplied -- it is constructed here
    from ctx.run_dir and two literal components, so it is contained by
    construction and there is no untrusted input for a check to validate.
    Adding a resolve()+parents check here would assert something already
    guaranteed one line above it. The intermediate directories are covered
    by new_run_dir() creating the run directory 0o700, so no other account
    can write inside it to plant that symlink in the first place.
    """
    path = ctx.run_dir / "auth" / "katana-headers.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{key}: {value}" for key, value in ctx.auth.headers.items()]
    if ctx.auth.cookies:
        lines.append(f"Cookie: {ctx.auth.cookie_header()}")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fd, 0o600)
        fh.write("\n".join(lines) + "\n")
    return path


def _header(headers: dict, name: str) -> str:
    """Case-insensitive header lookup. katana renders header names in Go's
    canonical form ("Content-Type", "Location"), but nothing in its output
    contract promises that, and getting it wrong fails silently: an empty
    content_type breaks jsrecon's javascript filter, and an unread Location
    turns a refused redirect into lost coverage rather than a visible error.
    """
    if not isinstance(headers, dict):
        return ""
    target = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == target:
            return value if isinstance(value, str) else ""
    return ""


def _redirect_target(endpoint: str, response: dict) -> str:
    """The absolute URL a recorded 3xx points at, or "" if there is nothing
    safe to follow up.

    We pass -dr, so katana records redirects instead of walking them (see the
    module docstring). Reading the destination back out here is what keeps
    -dr from costing coverage: the URL is yielded as an ordinary discovery
    and runner.py's admission choke point decides whether it is in scope,
    which is the decision katana declined to make.

    Fails closed and quietly, four ways:

    * only 3xx. A `Location` on a 200 is not a redirect the client would
      have followed, so treating it as one would invent traffic the crawl
      never implied.
    * only http/https. A `Location: mailto:`, `javascript:` or `tel:` is not
      an HTTP_SERVICE and must not be typed as one; urljoin resolves those
      to a non-http scheme, which this rejects.
    * never the request itself. A self-redirect (a 302 to its own URL, which
      real sites emit on cookie-setting loops) would otherwise yield a
      duplicate of the row we just emitted.
    * urljoin raises ValueError on a malformed authority ("https://[::1/x"),
      exactly as urlsplit does. parse() is a generator consumed inside
      runner.py's broad try/except, so an escaping exception does not lose
      one row -- it terminates the generator and every artifact from every
      LATER line with it, surfacing only as a generic PARSE_ERROR. Returning
      "" instead costs one redirect and keeps the crawl.
    """
    status = response.get("status_code")
    if not isinstance(status, int) or not 300 <= status < 400:
        return ""
    location = _header(response.get("headers") or {}, "Location")
    if not location:
        return ""
    try:
        resolved = urljoin(endpoint, location)
        scheme = urlsplit(resolved).scheme.lower()
    except ValueError:
        return ""
    if scheme not in ("http", "https") or resolved == endpoint:
        return ""
    return resolved


class KatanaStage:
    name = "katana"
    #: This tool takes an operator-supplied resolver; see
    #: sweeper.resolvers and run.json's "resolver" block.
    honors_resolver = True
    requires = ["katana"]
    consumes = ArtifactKind.HTTP_SERVICE
    produces = {ArtifactKind.HTTP_SERVICE}
    # What a crawled endpoint carries that a bare httpx origin does not:
    # the URL has a real path, and parse() reads Content-Type off the
    # response into meta (see the comment there). Both are declared because
    # both are things a LATER stage may need to have been done -- jsrecon
    # requires exactly these. See registry.order's FACETS section.
    #
    # No requires_facets: katana crawls from a bare origin quite happily,
    # which is precisely what makes it a supplier here rather than a peer.
    provides_facets = frozenset({"content_type", "url_path"})
    optional = True
    levels = {
        # No extra flags at all: katana's own defaults (depth 3, -jc/-jsl
        # and -aff both off, concurrency 10, rate-limit 150/s). See the
        # module docstring for why that default rate-limit is an
        # acceptable bound at this level even though it is not spelled out
        # here.
        "low":  [],
        # JS-only harvest: depth 1, no form handling. Read-only.
        "mid":  ["-d", "1", "-jc", "-jsl", "-c", "5", "-rl", "15"],
        # Full crawl, form EXTRACTION only — never submission. Read-only.
        "high": ["-d", "3", "-jc", "-jsl", "-fx", "-kf", "all", "-c", "8", "-rl", "30"],
        # -aff submits forms. Only here -- and throttled BELOW high's rate
        # because every request here can mutate state (place an order,
        # apply a coupon), not just cost the target CPU. See module
        # docstring.
        "full": ["-d", "3", "-jc", "-jsl", "-fx", "-kf", "all", "-aff",
                 "-c", "3", "-rl", "5"],
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        from ..rate import replace_value_flag
        infile = ctx.run_dir / "raw" / "katana-input.txt"
        infile.parent.mkdir(parents=True, exist_ok=True)
        permitted, _ = ctx.scope.filter(ctx.store.values(ArtifactKind.HTTP_SERVICE))
        infile.write_text("\n".join(permitted) + "\n", encoding="utf-8")
        flags = replace_value_flag(
            self.levels[ctx.config.level], ("-rl", "-rate-limit"),
            "-rl", ctx.config.rate_override,
        )
        cmd = [str(binaries.resolve("katana")), "-list", str(infile),
               "-jsonl", "-silent", "-duc", *flags]
        # Unconditional, and outside self.levels on purpose: `low` carries no
        # level flags at all, and it is the level most likely to be run
        # against an unfamiliar client estate. Every level crawls within the
        # allowlist or the stage has no business running. This NARROWS
        # katana's own -field-scope rdn default rather than replacing it
        # (-no-scope is deliberately not passed): if this regex were ever
        # wrong, the crawl is still bounded by the seed's registrable domain
        # instead of by nothing.
        cmd += ["-cs", str(_write_crawl_scope_file(ctx))]
        # Also unconditional, and for the same reason -cs is: no scope flag
        # katana has is consulted on a redirect hop (-cs, -cos, -fs and -e
        # were each measured against v1.6.1 and none of them is), so a single
        # 302 anywhere in the application sends a live request to a host of
        # the redirect author's choosing -- past the allowlist and past
        # katana's own rdn default. -dr is the only control that closes it,
        # and a scope escape fails closed. parse() reads the Location back
        # out of the recorded 302 so the destination is still DISCOVERED; it
        # is the choke point in runner.py, not katana, that then decides
        # whether it may be visited. See the module docstring.
        cmd += ["-dr"]
        # Without this, -dr's readback recovers almost nothing: katana's
        # duplicate-content filter drops the `response` object (not the row)
        # from every page whose body matches one already seen, and redirect
        # bodies are empty, so all but the FIRST 302 in a crawl arrive with
        # no Location to read. Measured: 1 of 8 destinations recovered
        # without it, 8 of 8 with it. It is an output filter, not a crawl
        # filter -- request count was identical either way -- so it adds no
        # traffic and does not bear on the no-DoS term.
        cmd += ["-duf"]
        # request.raw is the literal wire bytes of every request, so it holds
        # the Authorization/Cookie values that -H deliberately keeps out of
        # argv -- writing them straight back into raw/katana.jsonl, the file
        # operators archive. Measured A/B against the real binary: -or drops
        # only request.raw/response.raw, leaving the status_code and headers
        # parse() reads untouched.
        cmd += ["-or"]
        cmd += useragents.header_args_for(ctx.user_agent)
        if ctx.config.proxy:
            cmd += ["-proxy", ctx.config.proxy]
        if getattr(ctx, "auth", None) and not ctx.auth.is_empty():
            # A FILE path, not ctx.auth.header_args() rendered into argv --
            # see _write_auth_header_file's docstring and the module
            # docstring above. The live Authorization/Cookie values are
            # written to that file, never to this command line.
            cmd += ["-H", str(_write_auth_header_file(ctx))]
        from .. import resolvers
        cmd += resolvers.flag_args(ctx)
        return cmd

    def parse(self, raw_path: Path) -> Iterator[Artifact]:
        for line in Path(raw_path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            endpoint = (row.get("request") or {}).get("endpoint", "")
            if not endpoint:
                continue
            response = row.get("response") or {}
            # katana nests content type inside response.headers; there is no
            # top-level response.content_type. Verified against katana v1.6.1 —
            # reading the wrong key leaves it permanently empty, which breaks
            # jsrecon's javascript filter downstream.
            headers = response.get("headers") or {}
            content_type = _header(headers, "Content-Type")
            yield Artifact(
                ArtifactKind.HTTP_SERVICE, endpoint,
                meta={"src": "katana",
                      # The choke point in runner.py (_meta_host_or_value)
                      # scope-checks THIS field for every HTTP_SERVICE
                      # artifact, not the URL string. katana crawls follow
                      # links and can discover URLs on hosts that were
                      # never authorized (see the katana.jsonl fixture's
                      # cdn.other.example row) -- setting it explicitly,
                      # the way every other producer in this codebase does
                      # (httpx, vhost), is what lets the choke point judge
                      # the right host instead of falling back to parsing
                      # `endpoint` itself. An out-of-scope discovery is
                      # refused into ctx.scope.discoveries_refused, not
                      # dropped silently and not treated as a run failure
                      # -- see runner.py's admission control.
                      #
                      # scope.normalize(), not a bare urlsplit().hostname:
                      # normalize() already wraps that call in `except
                      # ValueError` for a malformed authority (a crawled
                      # "https://[::1/x" raises "Invalid IPv6 URL"), and it
                      # is the SAME function the choke point normalizes
                      # with, so the two cannot drift. Letting that
                      # ValueError escape would be far worse than one bad
                      # row: parse() is a generator consumed inside
                      # runner.py's broad try/except, so the exception
                      # terminates the whole generator and every artifact
                      # from every LATER line is lost, reported only as a
                      # generic PARSE_ERROR. Normalizing to "" instead
                      # makes admission control refuse just this row and
                      # record it, naming the offending value, while the
                      # rest of the crawl still lands.
                      "host": normalize_host(endpoint),
                      "method": (row.get("request") or {}).get("method", "GET"),
                      "status_code": response.get("status_code", 0),
                      "content_type": content_type,
                      "has_params": "?" in endpoint},
            )
            # We told katana not to walk this redirect (-dr), so the
            # destination is a DISCOVERY, not something we fetched: no
            # status_code and no content_type are known for it, and claiming
            # any would put a fact in the evidence trail that no request
            # backs. It goes through the same admission choke point as every
            # other crawled URL, so an off-scope destination -- the whole
            # reason -dr is on -- is refused and counted there rather than
            # requested here. See _redirect_target.
            target = _redirect_target(endpoint, response)
            if target:
                yield Artifact(
                    ArtifactKind.HTTP_SERVICE, target,
                    meta={"src": "katana",
                          "host": normalize_host(target),
                          "method": "GET",
                          "status_code": 0,
                          "content_type": "",
                          "has_params": "?" in target,
                          # Provenance: this URL was never requested by this
                          # stage. Without it the manifest cannot tell a
                          # crawled endpoint from an unvisited redirect
                          # destination, and a reader would reasonably assume
                          # every HTTP_SERVICE katana emitted was fetched.
                          "discovered_via": "redirect",
                          "redirect_from": endpoint},
                )
