"""jsrecon stage — endpoints and secrets from accessible JavaScript.

Two outputs: endpoints harvested from JS (fed downstream as HTTP_SERVICE)
and credentials found in client-served code (emitted as FINDING).

trufflehog verification is DISABLED by default. Verifying a credential
means calling the provider's API with the client's secret, which is a data
egress decision, not a scanner default.

Why this stage fetches JS itself instead of shelling out to one binary:
no external tool both fetches a URL list AND extracts endpoints/secrets
from the result in a single command the way naabu/httpx/katana each wrap
one binary that does their whole job. jsrecon is therefore the one stage
in this project whose real work happens as Python code (fetch_js) rather
than inside a subprocess runner.py executes.

That used to be smuggled through the ordinary build_command -> subprocess
-> parse() shape (build_command doing the real fetch and returning a
no-op ["/bin/true"] argv) so runner.py needed no special case. The cost
of that trick was the actual defect this module was reworked to close:
the runner captured /bin/true's empty stdout as this stage's raw
evidence file, so ctx.raw_path("jsrecon") existed but was always empty
even though real JS bundles had been fetched to disk under raw/js/ --
the evidence trail did not reach the one place a report reads it from.

`in_process = True` (see stages/base.py's Stage protocol) is the fix:
runner.py's run_stages() special-cases any stage with that flag, calling
`run_in_process(ctx) -> Path` instead of build_command()+subprocess, and
using the returned Path as this stage's raw evidence file directly. This
IS a special case in runner.py now, not a trick that avoids needing one --
see run_stages()'s `if getattr(stage, "in_process", False):` branch.
build_command() is kept, unchanged in spirit, purely because preflight
calls it on every stage (see below) and a handful of tests call it
directly; it is no longer what the runner uses to drive a real run.

Both build_command() and run_in_process() share one fetch-and-log helper
(_fetch_and_log) rather than each fetching independently, so the
sweep.log observability described in fetch_js's docstring -- naming every
URL that was NOT read, with its status -- fires on the path the runner
actually takes in a real run (run_in_process), not only when a test calls
build_command() by hand.

Calling build_command() is still safe under preflight for a STRUCTURAL
reason, not a lucky one. preflight.run_preflight() calls build_command()
for every stage exactly once, for ALL stages, before run_stages() executes
ANY of them (see app.execute(): `report = preflight.run_preflight(ctx,
stages)` happens before the `run_stages(...)` call). At the moment
preflight's call reaches this method, ctx.store therefore holds only the
HOST artifacts app.prepare() seeded from the targets file -- no stage has
produced an HTTP_SERVICE artifact yet, katana included. `js_urls()` is
unconditionally empty then, so fetch_js() iterates zero times, and no
packet leaves this process during preflight's call. The real fetch
happens only in run_stages' later call to run_in_process, by which point
httpx -- a pure producer of HTTP_SERVICE, and therefore ordered before
every HTTP_SERVICE consumer including this stage, see registry.order()'s
docstring -- has already run and populated the pool.

Every URL fetch_js actually fetches is checked with ctx.scope.allows(),
the exact "one-off checks" call path scope.py's own docstring names this
stage as using: "the call path later stages use for one-off checks
(jsrecon, fetch_js)". EVERY REDIRECT HOP is checked the same way, by
_ScopedRedirectHandler -- see its docstring for why the stdlib default
made the pre-request check on the first URL worthless. That is defence in
depth, not the only check --
runner.py's admission choke point (see katana.py's parse() for the longer
explanation of why meta["host"] matters there) independently scope-checks
every HTTP_SERVICE artifact this stage's parse() goes on to yield, so an
out-of-scope endpoint harvested from in-scope JS still cannot enter
ctx.store even if the scope check here were ever removed.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterator
from urllib.parse import urljoin, urlsplit

from .. import chunks
from ..artifacts import Artifact, ArtifactKind, Finding
from ..scope import normalize as normalize_host
from ..secrets_rules import scan_text

ENDPOINT_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-./]{4,}?)["']""")
ABSOLUTE_RE = re.compile(r"""["'](https?://[a-zA-Z0-9_\-./:]{8,}?)["']""")

# fetch_js issues these requests itself, sequentially, from Python -- not
# through a rate-limited external binary the way every other stage's
# traffic goes, so nothing on a command line bounds them. This is this
# stage's equivalent of naabu's -rate / vhost's -t -rate / katana's -c -rl:
# an explicit cap plus a fixed inter-request pause, so a page that links
# hundreds of .js bundles cannot turn into hundreds of rapid-fire
# sequential requests against one host. There is one flat value rather
# than one per level because JS harvesting does not get more invasive at
# higher levels the way a crawl's depth or a fuzz list's width does --
# levels only gate whether it runs at all (see JsreconStage.levels; off at
# "low").
# Raised from 40 when chunk discovery landed. 40 was chosen when the only
# candidates were .js URLs a crawler had already found -- a page links a
# handful. A code-split application legitimately has far more: the real Vite
# build this was measured against ships 66 chunks behind ONE entry bundle
# (see sweeper/chunks.py), so a cap of 40 would read half an application and
# report the rest as skipped-over-cap.
#
# Raised again from 120 once bundle_identity landed, because what a request
# BUYS changed. Under 120 the live SPA scope spent its budget like this:
#
#     before dedup:   9 read + 111 copies/dead references  = 120
#     after dedup:   66 read +  54 dead references         = 120,
#                    288 copies collapsed, and 92 DISTINCT bundles left over
#
# The cap was written to bound requests against one host while the requests
# were mostly waste. Now that copies cost nothing, a cap that stops short
# stops short of real application code -- 92 files that hold the endpoints
# and secrets this stage exists to find. 400 covers the 212 distinct bundles
# that scope presented, with headroom for the chunks reading them discovers.
# At REQUEST_PAUSE_S apart that is ~80s of paced, sequential requests, which
# is still comfortably the bounded, polite traffic the cap exists to keep it
# to -- and the pause, not the cap, is what makes it polite.
MAX_JS_FILES = 400
REQUEST_PAUSE_S = 0.2

# The second, absolute bound. MAX_JS_FILES counts requests ISSUED, so a URL
# refused by scope costs nothing against it -- correct, since no packet is
# sent, but on its own it lets the worklist grow without limit: every bundle
# read may contribute up to chunks.MAX_PER_BUNDLE more candidates. This caps
# how many candidates the loop will CONSIDER at all, so a hostile or simply
# enormous bundle graph cannot turn into an unbounded queue and an unbounded
# record list. Reached only in pathological cases; a normal application is
# bounded by MAX_JS_FILES long before this.
#
# Raised with MAX_JS_FILES, and it has to move WITH it or it becomes the next
# invisible wall: a duplicate costs no request but still costs a candidate
# slot (it has to be popped before it can be recognised as one), and on the
# live scope 288 of 500 slots went to copies. Leaving this at 500 would hand
# a larger request budget a queue that runs out before it can spend it.
MAX_JS_CANDIDATES = 1500


#: A build tool's content hash: eight or more hex characters as a whole
#: dot/slash/dash-delimited segment. `runtime.2b676e486f3abf28.js`,
#: `app.9f8e7d6c.js`. Anchored to delimiters so `bootstrap4` and
#: `dataTables` cannot match on a run of incidentally-hex letters.
_HEX_FINGERPRINT_RE = re.compile(r"[./-][0-9a-f]{8,}[./-]")

#: Vite/Rollup/esbuild emit base62 fingerprints rather than hex --
#: `_nuxt/DE3bru81.js`. Requiring all three character classes is what
#: separates a fingerprint from an ordinary CamelCase filename:
#: `dataTables` has no digit, `bootstrap4` has no uppercase.
_BASE62_FINGERPRINT_RE = re.compile(r"[./-][A-Za-z0-9_-]{8,}\.[a-z]+$")

#: Directories a bundler owns outright. Everything under them is generated
#: application code, whatever the filename looks like.
#:
#: Deliberately excludes generic paths like `/static/js/` and `/js/`: those
#: are hand-authored conventions and are precisely where vendored libraries
#: get dropped, so treating them as bundler output promotes the candidates
#: this ordering exists to demote.
_BUILD_DIRS = ("/_nuxt/", "/_next/", "/chunks/", "/build/", "/dist/")

#: Public, unmodified third-party code. Worth deprioritising because the
#: request budget is the scarce resource: a vendored library holds no
#: client endpoints and no client secrets, so a slot spent on one is a slot
#: not spent on application code. Matched against the FILENAME only, so a
#: path like /js/jquery-plugins/our-app.js is not caught by it.
_VENDOR_NAMES = (
    "jquery", "bootstrap", "datatables", "popper", "moment", "lodash",
    "underscore", "backbone", "modernizr", "polyfill", "select2", "slick",
    "owl.carousel", "fancybox", "tinymce", "ckeditor", "chart.min",
    "d3.min", "swiper", "flatpickr", "datetimepicker", "jquery-ui",
)


def _is_build_artifact(url: str) -> bool:
    path = urlsplit(url).path
    if any(d in path for d in _BUILD_DIRS):
        return True
    if _HEX_FINGERPRINT_RE.search(path):
        return True
    name = path.rsplit("/", 1)[-1]
    if _BASE62_FINGERPRINT_RE.search("/" + name):
        # Require the mixed-class shape a fingerprint has and a word does
        # not; the regex alone would accept `application-logic.js`.
        token = name.rsplit(".", 2)[0] if name.count(".") >= 2 else ""
        if (token and len(token) >= 8
                and any(c.isupper() for c in token)
                and any(c.islower() for c in token)
                and any(c.isdigit() for c in token)):
            return True
    return False


def _is_vendored(url: str) -> bool:
    name = urlsplit(url).path.rsplit("/", 1)[-1].lower()
    return any(v in name for v in _VENDOR_NAMES)


def _is_fingerprint(segment: str) -> bool:
    """Does this dot-delimited filename segment carry a build hash?

    Two shapes, matching the two families of bundler: a hex digest
    (webpack, Angular -- `b6eecf01882a734d`) or a mixed-class base62 one
    (Vite, Rollup, esbuild -- `DE3bru81`). Eight characters minimum in
    both, which is the shortest digest any of them emits.

    Requiring all three character classes for the base62 shape is what
    keeps ordinary words out: `bootstrap` has no digit or uppercase,
    `dataTables` no digit, `bootstrap4` no uppercase. `deadbeef` would
    match the hex shape -- and should, an eight-hex-character filename
    segment is a hash by every reasonable reading.
    """
    if len(segment) < 8:
        return False
    if all(c in "0123456789abcdef" for c in segment):
        return True
    return (segment.replace("-", "").replace("_", "").isalnum()
            and any(c.isupper() for c in segment)
            and any(c.islower() for c in segment)
            and any(c.isdigit() for c in segment))


def bundle_identity(url: str) -> str | None:
    """What two URLs must share to be the same bytes, or None.

    A build hash IS a content identity: `main.b6eecf01882a734d.js` names
    its own contents, so the same fingerprinted filename on the same origin
    is the same file whatever route prefix precedes it. That is the whole
    licence for skipping a request, so it is deliberately narrow --
    `/admin/app.js` and `/shop/app.js` share a name and nothing else, and
    return None here.

    Scoped to the ORIGIN, not just the filename. Endpoints extracted from a
    bundle resolve against the URL it was served from, so reading one
    host's copy and skipping another's would attribute the second host's
    attack surface to the first: a reporting defect dressed as a saving.
    """
    parts = urlsplit(url)
    name = parts.path.rsplit("/", 1)[-1]
    if not name:
        return None
    # Everything but the extension: `main.b6ee....js` -> [main, b6ee....],
    # `DE3bru81.js` -> [DE3bru81].
    segments = name.split(".")[:-1] if "." in name else [name]
    if not any(_is_fingerprint(s) for s in segments):
        return None
    return f"{parts.scheme}://{parts.netloc}/{name}"


def canonical_copy_first(urls: list[str]) -> list[str]:
    """Within one bundle identity, try the least-prefixed path first.

    A catch-all's copy is the real path with a route prefix in front of it
    (`/trade-in/main.<hash>.js` is what `<script src="main.<hash>.js">`
    resolves to on the /trade-in page), so the genuine file is the
    shallowest member of its group. Trying it first is what makes the
    duplicate skip land on the copies rather than on the original.

    Groups keep their DISCOVERY position -- only the order within a group
    changes, and a URL carrying no fingerprint is a group of one and never
    moves. Crawler order remains the tiebreaker everywhere it is still the
    best evidence available, exactly as prioritise_candidates leaves it.
    """
    first_seen: dict[str, int] = {}
    for i, url in enumerate(urls):
        first_seen.setdefault(bundle_identity(url) or f"\0{i}", i)

    def key(item: tuple[int, str]) -> tuple:
        i, url = item
        ident = bundle_identity(url) or f"\0{i}"
        path = urlsplit(url).path
        return (first_seen[ident], path.count("/"), len(url), url)

    return [url for _, url in sorted(enumerate(urls), key=key)]


def prioritise_candidates(urls: list[str]) -> list[str]:
    """Order candidates so the request budget buys application code.

    MAX_JS_FILES bounds REQUESTS ISSUED, and a request is spent whatever
    comes back -- including the `text/html` an SPA's catch-all returns for
    a dead `<script src>` reference. The 2026-08-04 live run spent 111 of
    120 requests that way and read 9 real bundles out of 500 candidates.

    So the cap is not the defect; the order it is spent in is. Raising it
    would not help, because dead references scale with the crawl. Three
    tiers, stable within each so the crawler's own order survives where
    there is nothing to separate two candidates:

      0  fingerprinted or bundler-emitted -- generated application code
      1  everything else
      2  recognisably vendored third-party libraries

    Reorders only. Every candidate is returned, because a dropped one
    would be invisible -- the opposite of the skipped-over-cap record,
    which exists so an unread bundle is always something the operator can
    see.
    """
    def tier(url: str) -> int:
        # Fingerprint first: `polyfills.44569d5ebcab3acb.js` is a build
        # artifact that happens to carry a vendor word, and it is the
        # build artifact that matters.
        if _is_build_artifact(url):
            return 0
        if _is_vendored(url):
            return 2
        return 1

    return sorted(urls, key=tier)


def _safe_urljoin(base: str, path: str) -> str:
    """urljoin that returns "" instead of raising on a malformed base.

    urljoin parses `base` with urlsplit internally, so it raises
    ValueError("Invalid IPv6 URL") on an authority like "https://[::1/x" --
    exactly the class scope.normalize() already guards against. Raising
    here would kill the whole analyse_js generator mid-iteration and
    discard every remaining endpoint and finding from the file, so this
    fails to a value the caller can skip instead.
    """
    try:
        return urljoin(base, path)
    except ValueError:
        return ""


def extract_endpoints(text: str) -> list[str]:
    """Relative paths referenced as string literals in JS."""
    seen, out = set(), []
    for m in ENDPOINT_RE.finditer(text):
        path = m.group(1)
        if len(path) < 5 or path.endswith((".png", ".jpg", ".svg", ".css", ".woff")):
            continue
        if path not in seen:
            seen.add(path)
            out.append(path)
    return out


def analyse_js(text: str, source_url: str) -> Iterator[Artifact | Finding]:
    # Both loops route their host through scope.normalize() rather than a
    # bare urlsplit().hostname: normalize() already wraps that call in
    # `except ValueError` for a malformed authority ("https://[::1/x"
    # raises "Invalid IPv6 URL"), and reusing it keeps ONE convention for
    # deriving a host from a URL rather than inventing a second one that
    # can drift from the choke point's. A URL that normalizes to "" is
    # still EMITTED, with host="": runner.py's admission control then
    # refuses it, records it in discoveries_refused naming the offending
    # value, and logs it -- so a malformed row is visible and fails closed
    # instead of terminating this generator and silently discarding every
    # endpoint and finding that would have followed it.
    for path in extract_endpoints(text):
        url = _safe_urljoin(source_url, path)
        if not url:
            continue
        yield Artifact(ArtifactKind.HTTP_SERVICE, url,
                       meta={"src": "jsrecon", "from": source_url,
                             # See katana.py's parse() for why this field
                             # matters: runner.py's admission choke point
                             # scope-checks meta["host"], not the URL
                             # string, for every HTTP_SERVICE artifact.
                             # _safe_urljoin above can resolve a path
                             # against source_url onto source_url's own
                             # host, which is usually in-scope (it is where
                             # the JS was fetched from) -- but a
                             # protocol-relative path ("//evil.test/x")
                             # resolves onto a DIFFERENT host, and the
                             # ABSOLUTE_RE branch below can name one
                             # outright. That host is what has to be
                             # judged, not source_url's.
                             "host": normalize_host(url)})
    for m in ABSOLUTE_RE.finditer(text):
        url = m.group(1)
        yield Artifact(ArtifactKind.HTTP_SERVICE, url,
                       meta={"src": "jsrecon", "from": source_url,
                             "host": normalize_host(url)})
    yield from scan_text(text, source=source_url)


def _looks_like_js(artifact: Artifact) -> bool:
    """Is this HTTP_SERVICE artifact worth fetching as JavaScript?

    A property (content-type OR filename shape) rather than an enumeration
    of producing stages, so a future HTTP_SERVICE producer this stage has
    never heard of still gets picked up correctly as long as it tags
    content_type the way httpx and katana already do.
    """
    content_type = str(artifact.meta.get("content_type", "")).lower()
    if "javascript" in content_type or "ecmascript" in content_type:
        return True
    try:
        return urlsplit(artifact.value).path.endswith(".js")
    except ValueError:
        # Malformed authority (e.g. "https://[::1/x"). Not fetchable, and
        # raising here would abort the whole candidate list in
        # build_command's comprehension rather than skip one entry.
        return False


class JsreconStage:
    name = "jsrecon"
    enabled_levels = frozenset({"mid", "high", "full"})
    #: jsrecon fetches with the Python stdlib, which offers no resolver
    #: override; it uses the system resolver.
    honors_resolver = False
    resolver_note = 'jsrecon fetches with the Python stdlib, which offers no resolver override; it uses the system resolver.'
    requires = []          # uses katana/httpx output plus stdlib; trufflehog optional
    consumes = ArtifactKind.HTTP_SERVICE
    produces = {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING}
    # An HTTP_SERVICE artifact EXISTING is not enough for this stage: it
    # only fetches ones it can identify as JavaScript, and _looks_like_js
    # identifies them from exactly these two properties. httpx -- the only
    # pure producer of HTTP_SERVICE -- emits bare scheme://host:port,
    # carrying neither, so without this declaration registry.order() left
    # jsrecon a peer of katana, tie-broke alphabetically, ran it first and
    # handed it a candidate list that was empty on every default run. See
    # registry.order's FACETS section.
    #
    # These are the two disjuncts of _looks_like_js, one name each,
    # because either one alone makes a candidate fetchable.
    requires_facets = frozenset({"content_type", "url_path"})
    optional = True
    # See stages/base.py's Stage protocol. Real work is fetch_js, run from
    # Python, not a subprocess -- see the module docstring.
    in_process = True
    levels = {
        "low":  [],
        "mid":  ["--js"],
        "high": ["--js"],
        "full": ["--js"],
    }

    def trufflehog_command(self, ctx, js_dir: Path) -> list[str]:
        from .. import binaries
        binary = binaries.resolve("trufflehog")
        cmd = [str(binary) if binary else "trufflehog",
               "filesystem", str(js_dir), "--json"]
        if not getattr(ctx.config, "verify_secrets", False):
            cmd.append("--no-verification")
        return cmd

    def __init__(self) -> None:
        # One record per candidate JS URL from the most recent fetch (see
        # fetch_js). Kept on the instance -- the precedent SubfinderStage's
        # pending_hosts sets -- so a caller or test can inspect exactly
        # which bundles were read and which were not, without scraping
        # sweep.log. Never holds response content.
        self.fetch_records: list[dict] = []

    def _js_dir(self, ctx) -> Path:
        return ctx.raw_path(self.name).parent / "js"

    def js_urls(self, ctx) -> list[str]:
        """In-scope HTTP_SERVICE artifacts worth fetching as JavaScript.

        Reuses _looks_like_js (a property: content-type OR filename shape)
        rather than re-deriving a weaker check here -- see that function's
        docstring for why, including its malformed-URL handling. Sorted and
        deduped so this stage's candidate list -- and therefore the order
        bundles are numbered in -- is deterministic across runs.
        """
        out = []
        for a in ctx.store.get(ArtifactKind.HTTP_SERVICE):
            if _looks_like_js(a) and ctx.scope.allows(a.value):
                out.append(a.value)
        return sorted(set(out))

    def _fetch_and_log(self, ctx) -> Path:
        """Fetch in-scope JS (level-gated; off entirely at "low"), then log
        every candidate's outcome to sweep.log -- see fetch_js's and
        _log_fetch_records' docstrings for why that observability matters.

        Shared by build_command() (the preflight probe / the shape a few
        tests call directly) and run_in_process() (what the runner actually
        calls on a real run -- see the module docstring) so this fires on
        BOTH paths rather than only firing for whichever one happens to
        have real HTTP_SERVICE candidates in the store at the time.

        Tolerates a fetch_js substitute that doesn't return the documented
        list[dict] shape (a test double promising only the on-disk side
        effect): logging degrades to "nothing to say" rather than raising,
        because a stage that raises turns "complete" into "failed" for
        every caller, which is a worse failure than one missing log line.
        """
        js_dir = self._js_dir(ctx)
        if self.levels[ctx.config.level]:   # off entirely at "low"
            urls = self.js_urls(ctx)
            records = fetch_js(ctx, urls, js_dir)
            self.fetch_records = records if isinstance(records, list) else []
            self._log_fetch_records(ctx)
        else:
            self.fetch_records = []
        return js_dir

    def build_command(self, ctx) -> list[str]:
        # See the module docstring for why real network I/O living here,
        # rather than in the returned argv, is safe under preflight: the
        # store holds no HTTP_SERVICE artifacts yet at preflight time, so
        # js_urls() is empty and fetch_js() touches nothing.
        self._fetch_and_log(ctx)
        # This stage fetches JS itself rather than shelling out; a few
        # tests and preflight still call build_command() directly, so it
        # still needs to return a command -- a no-op that always succeeds.
        # The runner itself no longer executes this argv for a real run;
        # see run_in_process() and the module docstring.
        return ["/bin/true"]

    def run_in_process(self, ctx) -> Path:
        """Fetch JS, then write OUR OWN raw evidence file.

        This is what closes the gap build_command()'s trick left: the
        runner used to capture /bin/true's empty stdout as this stage's
        raw file while the real evidence sat, unindexed, under raw/js/.
        Here the runner uses the Path this method returns directly (see
        runner.py's `if getattr(stage, "in_process", False):` branch), so
        the evidence trail actually reaches ctx.raw_path("jsrecon").

        Reads the fetched bundles back off js_dir rather than trusting
        fetch_js's return value for their content -- _fetch_and_log's
        logging already covers what fetch_js *reports*; this covers what
        it actually *wrote*, which is what parse() goes on to analyse.
        """
        js_dir = self._fetch_and_log(ctx)
        raw_path = ctx.raw_path(self.name)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        with raw_path.open("w", encoding="utf-8") as fh:
            for js_file in sorted(js_dir.glob("*.js")) if js_dir.is_dir() else ():
                url_file = js_file.with_suffix(".url")
                url = (url_file.read_text(encoding="utf-8").strip()
                       if url_file.exists() else js_file.name)
                text = js_file.read_text(encoding="utf-8", errors="replace")
                fh.write(json.dumps({
                    "url": url, "bytes": len(text), "file": js_file.name,
                }) + "\n")
        return raw_path

    def _log_fetch_records(self, ctx) -> None:
        """Put every unread bundle in sweep.log, naming the URL and status.

        This is the observability half of the auth fix. A bundle we could
        not read is a COVERAGE gap, and this project's recurring defect is
        exactly that gap presenting as a clean result -- "no secrets found"
        must not be reachable by never having read the file. Each failure
        gets its own line naming the URL, so an operator can re-check it by
        hand; the summary line gives the read/total ratio at a glance.

        Deliberately logs URL, status and (for a wrong content type) the
        Content-Type only. Never the response body: on an authenticated run
        the bodies of exactly these files are where the credentials are,
        and sweep.log lives for the life of the run directory. Same stance
        as store.add_finding's collision log and the runner's argv
        redaction.
        """
        if not self.fetch_records:
            return
        read = [r for r in self.fetch_records if r["status"] == _STATUS_OK]
        # Neither read nor unread: the same bundle at another path, whose
        # bytes ARE in the analysis. Counted with the unread ones -- 380 of
        # them on the 2026-08-05 live run -- would describe a coverage gap
        # that does not exist and bury the few real ones under it.
        duplicates = [r for r in self.fetch_records
                      if r["status"] == _STATUS_DUPLICATE]
        unread = [r for r in self.fetch_records
                  if r["status"] not in (_STATUS_OK, _STATUS_DUPLICATE)]
        for record in unread:
            detail = f" ({record['detail']})" if record["detail"] else ""
            ctx.log(f"{self.name}: JS NOT READ — {record['url']} "
                    f"[{record['status']}]{detail}")
        ctx.log(f"{self.name}: read {len(read)} of "
                f"{len(self.fetch_records)} candidate JS bundle(s); "
                f"{len(unread)} unread")
        if duplicates:
            # One line, not one per copy: the operator needs to know the
            # request budget was not spent on them and that their contents
            # are covered, not to read 380 URLs. The per-copy records are
            # in the manifest for anyone who wants them.
            ctx.log(f"{self.name}: {len(duplicates)} further candidate(s) "
                    "were duplicates — the same content-hashed bundle(s) "
                    "under another path, read once rather than once per path")
        for record in read:
            # A bundle that WAS read but only after credentials were
            # withheld at a cross-origin redirect. Not a failure, but the
            # operator needs it: on an authenticated run that bundle was
            # fetched anonymously, so "no secrets found" in it means less
            # than it does for the others.
            if record["detail"]:
                ctx.log(f"{self.name}: {record['url']} — {record['detail']}")
        if any(r["status"].startswith("http-4") or r["status"] == _STATUS_NOT_JS
               for r in unread):
            # The specific shape that means "authentication did not reach
            # the bundle", called out by name so it is not buried among
            # ordinary transport errors.
            ctx.log(f"{self.name}: some bundles were refused or returned a "
                    "non-JavaScript body — if this is an authenticated run, "
                    "the session may not have been accepted; endpoints and "
                    "secrets in those bundles were NOT analysed")

    def parse(self, raw_path: Path) -> Iterator[Artifact | Finding]:
        # Populated by build_command()'s call to fetch_js, immediately
        # before this runs, on the SAME ctx (same run_dir, so the same
        # js_dir) -- see run_stages() in runner.py, which calls
        # build_command() and then parse() on the same stage instance back
        # to back. Not populated at all during preflight's call to
        # build_command (see module docstring), so an empty/missing js_dir
        # here is the ordinary case for a preflight probe, not an error.
        js_dir = Path(raw_path).parent / "js"
        if not js_dir.is_dir():
            return
        for js_file in sorted(js_dir.glob("*.js")):
            url_file = js_file.with_suffix(".url")
            source = (url_file.read_text(encoding="utf-8").strip()
                      if url_file.exists() else js_file.name)
            text = js_file.read_text(encoding="utf-8", errors="replace")
            yield from analyse_js(text, source)


def _auth_headers(ctx) -> dict[str, str]:
    """ctx.auth rendered as request headers, or {} on an unauthenticated run.

    Held in memory and handed straight to urllib -- never logged, never
    written to disk, never included in a FetchRecord. See fetch_js.
    """
    auth = getattr(ctx, "auth", None)
    if auth is None or auth.is_empty():
        return {}
    headers = dict(auth.headers)
    if auth.cookies:
        headers["Cookie"] = auth.cookie_header()
    return headers


# One record per candidate URL fetch_js considered. `status` is a short,
# fixed vocabulary ("ok", "http-401", "not-javascript", "refused-by-scope",
# "error"); `detail` carries an exception type name, a Content-Type, or the
# HOST of a refused redirect, and is NEVER response content -- an
# authenticated bundle's body is exactly where the secrets are, so it must
# not reach a log line or the manifest.
#
# "refused-by-scope" deliberately covers BOTH ways a fetch can leave scope:
# the candidate URL itself being out of scope, and an in-scope candidate
# redirecting to a host that is not. They are the same event from the
# operator's point of view -- "we did not read this bundle because reading
# it would have left scope" -- and reusing the existing vocabulary value
# means _log_fetch_records, the coverage summary and the report all surface
# the redirect case with no change. Only `detail` distinguishes them, and
# it names the refused HOST rather than the full Location URL: a Location
# can carry a token in its query string, and this record is written to
# sweep.log and the manifest.
_STATUS_OK = "ok"
_STATUS_NOT_JS = "not-javascript"
_STATUS_REFUSED = "refused-by-scope"
_STATUS_CAPPED = "skipped-over-cap"
# The same content-hashed bundle already read from another path on this
# origin. Distinct from _STATUS_CAPPED because its bytes WERE analysed:
# reporting it as unread would invent a coverage gap that does not exist,
# which is the mirror image of the defect every other status here guards.
_STATUS_DUPLICATE = "duplicate-of"

# A redirect chain is bounded so a server that redirects forever cannot
# hang the run. urllib's HTTPRedirectHandler already caps at 10 hops (and 4
# repeats of one URL), so this is a tightening, not a missing bound: five
# hops is far more than a real CDN handoff needs, and every extra hop is
# another host this stage has to scope-check.
MAX_REDIRECTS = 5

# Stripped from a redirected request whenever the credential origin
# changes. This is the floor, not the list: _ScopedRedirectHandler is
# additionally given the actual header names _auth_headers() produced for
# THIS run, so an operator whose session lives in a bespoke header
# ("X-Api-Key", a signed "X-Amz-*" header) is protected by the same rule
# without anyone having to extend an enumeration here.
_CREDENTIAL_HEADERS = frozenset({
    "authorization", "cookie", "proxy-authorization",
})


def _origin(url: str) -> tuple[str, str, int | None] | None:
    """(scheme, host, port) for credential-origin comparison, or None.

    Ports are resolved to their scheme default so "https://h/" and
    "https://h:443/" compare equal. Returns None -- which compares unequal
    to every real origin, so the caller fails closed and strips -- for a
    malformed authority or a URL with no host.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:          # malformed authority / bad port
        return None
    host = normalize_host(url)
    if not host:
        return None
    scheme = (parts.scheme or "").lower()
    if port is None:
        port = {"http": 80, "https": 443}.get(scheme)
    return (scheme, host, port)


def _strip_credentials(req, names: frozenset[str] | set[str]) -> list[str]:
    """Remove every credential-bearing header from `req`, in place.

    Both header stores are cleared. urllib keeps two -- `headers`, which
    HTTPRedirectHandler.redirect_request copies onto the next hop, and
    `unredirected_hdrs`, which it does not -- and stripping only the one
    that is copied would leave a fix that silently stops working if a
    caller ever sets credentials with add_unredirected_header instead.
    Matching is case-insensitive because urllib capitalizes header names.
    """
    removed: list[str] = []
    for store in (req.headers, req.unredirected_hdrs):
        for key in list(store):
            if key.lower() in names:
                del store[key]
                removed.append(key)
    return removed


class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-check scope on every hop and never carry credentials off-origin.

    urllib's default handler does neither, which made fetch_js's
    pre-request ctx.scope.allows() check worthless the moment a server
    answered 302: the handler copies the WHOLE header dict -- Authorization
    and Cookie included -- onto a request to the new host, whatever host
    that is. `requests` drops them across a host change; urllib does not
    (verified against CPython 3.13's HTTPRedirectHandler.redirect_request,
    whose `newheaders` comprehension filters only Content-Length and
    Content-Type). On a web application an in-scope bundle redirecting to a
    CDN or object store is ordinary, so this could hand a live bearer token
    and session cookie to a third party that was never in the
    allowlist -- a scope escape and a credential disclosure at once.

    Two independent rules, because they answer two different questions:

      * MAY WE GO THERE AT ALL? ctx.scope.allows(newurl). Returning None
        from redirect_request makes urllib stop before it opens the new
        URL, so nothing at all is sent to the refused host -- not a
        credential-free request, not a HEAD, nothing. urllib then falls
        through to HTTPDefaultErrorHandler, which raises HTTPError for the
        3xx; fetch_js reads `self.refusal` to record that as
        "refused-by-scope" rather than as a bare "http-302".

      * MAY THESE CREDENTIALS GO THERE? _origin() equality. Asked
        separately and answered more strictly, because "in scope" and
        "the origin these credentials were issued for" are not the same
        set: an allowlist with "*.acc.example" puts a hundred hosts in
        scope, and the client's session belongs to exactly one of them.
        Scheme and port are part of the origin, so an https->http
        downgrade on the same host also strips -- that redirect would put
        the session cookie on the wire in cleartext.

    Over-stripping degrades to a 401 or a login page, which fetch_js
    already records as a COVERAGE gap the operator can see and re-check by
    hand. Under-stripping is a credential disclosure to an uninvolved
    party that nothing in the run would ever show. The asymmetry is why
    both rules fail closed.
    """

    max_redirections = MAX_REDIRECTS
    max_repeats = MAX_REDIRECTS

    def __init__(self, ctx, credential_headers=()) -> None:
        self.ctx = ctx
        self.credential_headers = (
            _CREDENTIAL_HEADERS | {h.lower() for h in credential_headers}
        )
        self.refusal: str = ""
        self.stripped: list[str] = []

    def reset(self) -> None:
        """Clear per-URL state. fetch_js reuses one handler for the whole
        candidate list (urllib keeps its own hop counter on the Request,
        not here), so this must run before each candidate or one URL's
        refusal would be reported against the next one's record."""
        self.refusal = ""
        self.stripped = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = _origin(newurl)
        if target is None or target[0] not in ("http", "https"):
            # urllib's own http_error_302 already rejects everything but
            # http/https/ftp; this closes ftp and any unparseable Location.
            self.refusal = "redirect to a non-HTTP or unparseable location"
            return None
        if not self.ctx.scope.allows(newurl):
            # allows() is also what RECORDS the refusal in
            # ctx.scope.refusals, so an attempted excursion via redirect
            # shows up in the run manifest and not only in this record.
            self.refusal = f"redirect to {target[1]}"
            return None
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        if _origin(req.full_url) != target:
            if _strip_credentials(new, self.credential_headers):
                self.stripped.append(target[1])
        return new


def _urlopen(opener, req, timeout):
    """The single outbound-request seam for this stage.

    fetch_js goes through an opener rather than urllib.request.urlopen
    because urlopen has no way to accept a handler: it uses the process
    -global opener, and install_opener() would mutate urllib for every
    other consumer in the process. One named function so tests have one
    place to substitute.
    """
    return opener.open(req, timeout=timeout)


def fetch_js(ctx, urls: list[str], js_dir: Path, timeout: int = 20) -> list[dict]:
    """Download in-scope JS bundles for offline analysis.

    Returns ONE RECORD PER CANDIDATE URL, not just a success count. A
    silent `except: continue` here is the defect this project keeps
    producing: on an authenticated run the bundles that matter most are
    precisely the ones behind the login wall, and a 401 (or a 200 that is
    actually the login page) would otherwise leave "no secrets found"
    indistinguishable from "we never read the file". The caller logs these
    records and keeps them for inspection.

    Requests carry ctx.auth's headers/cookies when the run is
    authenticated. Without them katana can crawl behind a session and hand
    this stage a URL it then fetches anonymously -- reading a login page
    instead of the bundle, and finding nothing in it.

    Sequential, never concurrent, capped at MAX_JS_FILES with a
    REQUEST_PAUSE_S pause between requests -- see the module-level
    constants' docstring. Every URL is independently checked with
    ctx.scope.allows() regardless of what the caller already filtered,
    because allows() is also what RECORDS the check in ctx.scope.refusals;
    skipping it here would let a URL reach this loop uncounted if a future
    caller ever passed an unfiltered list.

    Redirects go through _ScopedRedirectHandler, not urllib's default: see
    that class's docstring. The consequence here is that the URL checked
    before the request is not the only URL checked, and that a bundle
    reached via a redirect is attributed on disk to the URL it was actually
    served from (resp.url) rather than to the one we asked for -- relative
    endpoints in it resolve against the final URL, and evidence that says
    it came from the in-scope URL when the bytes came from elsewhere is the
    mis-attribution half of this defect.
    """
    js_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    # The worklist grows as bundles are read: a code-split front end ships
    # ONE entry bundle in its HTML and loads the rest at runtime, so a
    # crawler that follows <script src> hands this stage a single file and
    # misses the application. Measured against a real Vite build: 66 JS
    # files on disk, 1 referenced from index.html, 65 recoverable from the
    # entry bundle. See sweeper/chunks.py.
    # Ordered, not just listed: MAX_JS_FILES bounds requests ISSUED, and a
    # dead reference costs one exactly like a real bundle does. See
    # prioritise_candidates -- on an SPA catch-all origin the unordered
    # worklist spends the whole budget before reaching application code.
    # Chunks discovered later are appended by the reader below; they are
    # already build artifacts by construction, so they need no reordering.
    # canonical_copy_first runs BEFORE the tiering so that where two
    # candidates are the same bundle, the one actually requested is the one
    # at the real path -- see read_by_identity below.
    queue = prioritise_candidates(canonical_copy_first(list(urls)))
    queued = set(queue)
    # identity -> the URL whose bytes were read for it. Populated only on a
    # SUCCESSFUL read, never on an attempt: an SPA with a <base href> emits
    # `<script src="main.<hash>.js">` on every route, so the shallowest path
    # can be the dead one while the real file sits under /static/. Claiming
    # on the attempt would skip the only readable copy and then report the
    # bundle as read -- this stage's own recurring defect, self-inflicted.
    read_by_identity: dict[str, str] = {}
    auth_headers = _auth_headers(ctx)
    headers = {"User-Agent": ctx.user_agent, **auth_headers}
    redirects = _ScopedRedirectHandler(ctx, auth_headers)
    # build_opener drops urllib's default HTTPRedirectHandler when handed
    # an instance of a subclass of it, so this REPLACES the leaking
    # handler rather than stacking another one behind it.
    handlers = [redirects]
    proxy = ctx.config.proxy if hasattr(ctx, "config") else ""
    if proxy:
        # urllib otherwise consults process environment proxy settings, which
        # is neither deterministic nor the proxy recorded in run.json.
        # Explicitly route both schemes through the operator's listener so
        # every JS request and redirect is visible in the same Burp history
        # as the external HTTP stages.
        handlers.insert(0, urllib.request.ProxyHandler({
            "http": proxy,
            "https": proxy,
        }))
    opener = urllib.request.build_opener(*handlers)
    from ..rate import pause_seconds
    # A few pure fetch_js callers use the documented minimal context shape
    # (scope + user_agent) rather than a RunContext. Real RunContext objects
    # must still expose rate_override directly; only the absence of config
    # itself falls back to the stage's conservative built-in pause.
    rate_override = ctx.config.rate_override if hasattr(ctx, "config") else 0
    request_pause = pause_seconds(
        rate_override, REQUEST_PAUSE_S,
    )
    i = 0
    saved = 0
    considered = 0
    while queue:
        url = queue.pop(0)
        considered += 1
        if considered > MAX_JS_CANDIDATES:
            # The absolute bound. Recorded like every other unread URL so
            # the reason a bundle went unread is never invisible.
            records.append({"url": url, "status": _STATUS_CAPPED,
                            "detail": "candidate limit reached"})
            continue
        if i >= MAX_JS_FILES:
            # Recorded, not silently truncated: an operator has to be able
            # to see that the cap -- not the target -- is why a bundle went
            # unread. Drained rather than sliced because the list is no
            # longer fixed at entry; discovered chunks land here too.
            records.append({"url": url, "status": _STATUS_CAPPED, "detail": ""})
            continue
        if not ctx.scope.allows(url):
            records.append({"url": url, "status": _STATUS_REFUSED, "detail": ""})
            continue
        # After the scope check, so a URL is still counted and recorded as
        # refused whether or not we would have fetched it, and before the
        # request, which is the whole point: the 2026-08-05 live run spent
        # 111 of 120 requests on route-prefixed copies of nine bundles.
        identity = bundle_identity(url)
        if identity is not None and identity in read_by_identity:
            records.append({"url": url, "status": _STATUS_DUPLICATE,
                            "detail": read_by_identity[identity]})
            continue
        if i:
            time.sleep(request_pause)
        # `i` counts REQUESTS ISSUED, and is what the cap and the pause are
        # measured in. `saved` numbers the files on disk and is incremented
        # only on a bundle actually written, so bundle0000 is the first
        # bundle read rather than the first candidate offered -- the numbers
        # stay contiguous even when a candidate is refused or is not JS.
        i += 1
        redirects.reset()
        try:
            req = urllib.request.Request(url, headers=headers)
            with _urlopen(opener, req, timeout=timeout) as resp:
                content_type = (resp.headers.get("Content-Type") or "").lower()
                body = resp.read().decode("utf-8", errors="replace")
                final_url = getattr(resp, "url", None) or url
        except urllib.error.HTTPError as exc:
            if redirects.refusal:
                # An in-scope bundle that redirected out of scope. urllib
                # surfaces this as the 3xx, but "http-302" would read as a
                # transport oddity; it is a scope refusal, and the same
                # one the operator already knows how to act on.
                records.append({"url": url, "status": _STATUS_REFUSED,
                                "detail": redirects.refusal})
                continue
            # The authenticated-bundle case: 401/403 means we reached the
            # file and were refused, which is a COVERAGE gap, not a clean
            # "nothing here". exc.code only -- no response body.
            detail = ("redirect not followed" if 300 <= exc.code < 400
                      else "")
            records.append({"url": url, "status": f"http-{exc.code}",
                            "detail": detail})
            continue
        except (urllib.error.URLError, OSError, ValueError) as exc:
            records.append({"url": url, "status": "error",
                            "detail": type(exc).__name__})
            continue
        if "html" in content_type:
            # A 200 that is actually a login page or an error page. Parsing
            # it as JavaScript finds nothing and looks identical to a clean
            # bundle, which is precisely the ambiguity these records exist
            # to remove. Content-Type only -- never the body.
            records.append({"url": url, "status": _STATUS_NOT_JS,
                            "detail": content_type})
            continue
        (js_dir / f"bundle{saved:04d}.js").write_text(body, encoding="utf-8")
        (js_dir / f"bundle{saved:04d}.url").write_text(final_url, encoding="utf-8")
        saved += 1
        # Claimed here, on bytes actually on disk. Keyed on the CANDIDATE
        # url's identity rather than final_url's: a copy of this candidate
        # is what the next duplicate will be, and a redirect that renamed
        # the file does not change which candidates it stands in for.
        if identity is not None:
            read_by_identity[identity] = url

        # The bundle's own chunk references, resolved against the URL it was
        # SERVED from (final_url, not the candidate) so a relative path
        # resolves the way the browser would have. Appended to the same
        # worklist, so a discovered chunk gets the identical treatment as a
        # crawled one: its own scope check, its own record, the same cap and
        # the same pacing. Chunks reference further chunks, and the queue
        # handles that naturally -- MAX_JS_FILES is what bounds the walk.
        for chunk_url in chunks.candidates(body, final_url):
            if chunk_url in queued:
                continue
            queued.add(chunk_url)
            queue.append(chunk_url)
        # `url` stays the CANDIDATE url so the record list remains one row
        # per candidate; the detail names the origin credentials were
        # withheld from, so a bundle fetched anonymously after a cross-
        # origin hop is not mistaken for one fetched with the session.
        detail = ""
        if redirects.stripped:
            detail = ("credentials withheld across redirect to "
                      + ", ".join(sorted(set(redirects.stripped))))
        records.append({"url": url, "status": _STATUS_OK, "detail": detail})
    return records
