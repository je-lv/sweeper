"""arjun stage — hidden parameter discovery.

Crawling only finds parameters that appear in HTML or JS. Parameters like
?debug=1 or ?admin=true appear in neither and are found only by guessing
names, which is what arjun does. Its output is what makes dast worth
running at full.

arjun writes ITS OWN result file (-oJ), so this stage declares
raw_suffix="json" and writes_own_raw=True -- same reasoning as vhost.py,
see Task 3.5's runner change and stages/base.py's Stage protocol. Before
that fix, arjun's stdout (\\r-terminated progress text) was captured into
a raw/arjun.jsonl the tool never wrote to, its own parser's
`except json.JSONDecodeError: return` silently swallowed the resulting
failure, and every authenticated run also probed unauthenticated because
ctx.auth was never read here at all -- an authenticated high/full run
found exactly the parameters an unauthenticated one would, silently
missing anything that only appears behind login.

Credential handling: arjun's `--headers` takes ONE literal string on the
command line (parsed by splitting on '\\n' -- see
arjun/core/utils.py:extract_headers/parse_headers in the installed 2.2.7
package, read directly rather than trusted from --help). Unlike katana's
`-H, -headers string[] ... (file)` (goflags' "(file)" suffix, meaning the
flag ALSO accepts a path), arjun's argparse `--headers` has no such
alternate form: its own source always treats the value as the header text
itself, never as a path to read. There is therefore no way to route
ctx.auth through a file the way katana.py does -- see
`_write_auth_header_file` there for the pattern this stage cannot use.

That means a live Authorization/Cookie value IS visible in this process's
argv for the lifetime of the arjun run -- to any local user via `ps`, even
though Task 3.5's runner-level redaction keeps it out of sweep.log and
run.json. This is a real, residual exposure, not an oversight; it is
recorded here and in the Task 7 report so the decision is visible rather
than silently accepted. Mitigating it further (e.g. a wrapper script that
reads the header block from a file arjun's own process reads via stdin/
env instead of argv) is out of scope for this task.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator
from urllib.parse import urlencode, urlsplit

from ..artifacts import Artifact, ArtifactKind
from ..scope import normalize as normalize_host


def dedupe_endpoints(urls: list[str]) -> list[str]:
    """One URL per (host, path). Order is deterministic.

    Now that arjun runs AFTER the crawler (see requires_facets) its input is
    every discovered endpoint, and the same endpoint arrives several times
    over: http and https, :80 and :443, are one page as far as a hidden
    query parameter is concerned. Measured against a lab crawl: 300
    probeable URLs, 121 distinct (host, path) pairs -- so 60% of the
    requests would have re-fuzzed a page already fuzzed, for no finding that
    the first pass could not produce.

    That matters beyond tidiness. arjun brute-forces parameter names, so
    every duplicate endpoint multiplies a wordlist's worth of requests
    against the client -- and unlike naabu or katana, arjun takes no rate
    flag at this level for that volume to be capped by.

    Sorted rather than first-seen: build_command must be deterministic or
    preflight validates a different argv than the runner executes.
    """
    seen: set[tuple[str, str]] = set()
    out: list[str] = []
    for url in sorted(urls):
        parts = urlsplit(url)
        key = (parts.hostname or "", parts.path or "/")
        if key in seen:
            continue
        seen.add(key)
        out.append(url)
    return out


def probeable(artifact) -> bool:
    """Is this service worth (and safe to) hand to arjun?

    TWO reasons, and the second one alone would justify it.

    Semantically: parameter discovery brute-forces query parameters against a
    page and compares the responses. A 400, 404 or 500 has no parameters to
    find and no stable baseline to compare against, so it was always pure
    cost -- requests spent against a client for a result that cannot exist.

    Operationally: arjun 2.2.7 CRASHES on a non-200 when run over a list of
    URLs. Measured against the lab --

        arjun/__main__.py, line 135, in initialize
          print('%s Target returned HTTP %i, ...' % (bad, request.status_code))
        AttributeError: 'dict' object has no attribute 'status_code'

    -- an upstream bug (in multi-URL mode `request` is a dict, not a response
    object) that fires while arjun is warning about the non-200. So the FIRST
    such target kills the process: it died on target 1 of 27 in 0.1s and the
    stage was recorded `partial -- 0 artifacts, 0 findings`. Non-200s are
    ordinary on any real estate, so as wired this stage would have
    contributed nothing on most engagements while reporting only that it ran
    short.

    A service with NO recorded status is kept. Not every HTTP_SERVICE comes
    from httpx -- katana, vhost and jsrecon contribute artifacts that may
    carry no status_code -- and dropping those would quietly shrink arjun's
    scope to whatever httpx alone confirmed, which is the same class of
    silent coverage loss this filter exists to prevent.
    """
    raw = (getattr(artifact, "meta", None) or {}).get("status_code")
    if raw is None or raw == "":
        return True
    try:
        status = int(raw)
    except (TypeError, ValueError):
        return True
    return 200 <= status < 400


class ArjunStage:
    name = "arjun"
    enabled_levels = frozenset({"high", "full"})
    #: arjun has no resolver option at all; it resolves through Python's
    #: system resolver.
    honors_resolver = False
    resolver_note = "arjun has no resolver option at all; it resolves through Python's system resolver."
    requires = ["arjun"]
    consumes = ArtifactKind.HTTP_SERVICE
    produces = {ArtifactKind.HTTP_SERVICE}
    # Without this arjun was an ordinary HTTP_SERVICE enricher, i.e. a PEER of
    # katana, tie-broken alphabetically (a-r-j < k-a-t) -- so it ran BEFORE
    # the crawler and its input was whatever httpx had produced: bare origins
    # with no path.
    #
    # Parameter discovery against a bare origin tests parameters on `/`, and
    # every hidden parameter worth finding lives somewhere else --
    # /account?debug=1, /api/status?admin=1, /api/orders?user_id=<n>.
    # Measured against a lab: arjun got 28 origins, ran 59 seconds, reported
    # "complete -- 0 artifacts, 0 findings", and katana then discovered 625
    # endpoints it never saw. The stage could not have found anything on any
    # target, and nothing in the run said so.
    #
    # This is precisely the case registry.order's docstring already sets out
    # for jsrecon -- a stage that READS what an artifact points at, rather
    # than discovering more artifacts from a bare origin -- and `url_path` is
    # the same facet katana already provides and jsrecon already requires. It
    # was simply never declared here.
    requires_facets = frozenset({"url_path"})
    optional = True
    raw_suffix = "json"       # arjun -oJ, not the runner's default jsonl
    writes_own_raw = True     # arjun writes this file itself, via -oJ
    levels = {
        "low":  [],
        "mid":  [],
        "high": ["-t", "10", "--stable"],
        "full": ["-t", "20", "--stable"],
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        from ..rate import replace_value_flag
        infile = ctx.run_dir / "raw" / "arjun-input.txt"
        infile.parent.mkdir(parents=True, exist_ok=True)
        pool = [a for a in ctx.store.get(ArtifactKind.HTTP_SERVICE)
                if a.value.startswith("http")]
        services = [a for a in pool if probeable(a)]
        permitted, _ = ctx.scope.filter([a.value for a in services])
        permitted = dedupe_endpoints(permitted)
        if pool and not permitted:
            # There WERE services and every one of them is unprobeable, so
            # this stage has nothing it can legitimately do: the runner
            # records an empty argv as NO_INPUT. Handing arjun a list of
            # non-200s is precisely what killed it -- see probeable().
            #
            # Conditioned on `pool` being non-empty, NOT on `permitted`
            # alone: preflight calls build_command before httpx has produced
            # any HTTP_SERVICE at all, and that probe is the only place this
            # stage's flags are validated against the real binary. An empty
            # POOL is preflight; an empty FILTER is a genuine refusal.
            return []
        infile.write_text("\n".join(permitted) + "\n", encoding="utf-8")
        # The SAME path the runner will hand to parse() -- computed from
        # this stage's own declared name/raw_suffix, not a literal that
        # could silently drift from them.
        outfile = ctx.raw_path(self.name, self.raw_suffix)
        # arjun takes --headers as ONE newline-joined block, not repeated
        # -H (unlike katana/nuclei/vhost), and has no file-based form (see
        # module docstring). ctx.auth is threaded in here so an
        # authenticated run actually probes authenticated; each header and
        # the composed Cookie line is appended to the same block. This goes
        # through Task 3.5's runner-level redaction the same way any other
        # stage's argv does -- _redact_command matches by VALUE, not by
        # argument shape, so a live value inside this block gets redacted
        # from sweep.log/run.json with no arjun-specific code. It is still
        # visible in argv via `ps` for the life of the process -- see the
        # module docstring's residual-exposure note.
        headers = [f"User-Agent: {ctx.user_agent}"]
        if getattr(ctx, "auth", None) and not ctx.auth.is_empty():
            for key, value in ctx.auth.headers.items():
                headers.append(f"{key}: {value}")
            if ctx.auth.cookies:
                headers.append(f"Cookie: {ctx.auth.cookie_header()}")
        flags = replace_value_flag(
            self.levels[ctx.config.level], ("--rate-limit",),
            "--rate-limit", ctx.config.rate_override,
        )
        cmd = [str(binaries.resolve("arjun")), "-i", str(infile),
               "-oJ", str(outfile), *flags,
               "--headers", "\n".join(headers)]
        if ctx.config.proxy:
            cmd += ["--proxy", ctx.config.proxy]
        return cmd

    def parse(self, raw_path: Path) -> Iterator[Artifact]:
        path = Path(raw_path)
        if not path.exists() or not path.read_text(encoding="utf-8").strip():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return
        for url, entry in (data or {}).items():
            # arjun -oJ maps each URL to an object: {"method", "headers",
            # "params"}. Iterating that object directly would treat its keys
            # as discovered parameter names -- "headers"/"method"/"params"
            # themselves become bogus "discovered" parameter names. Verified
            # against the real arjun 2.2.7 binary (arjun/core/exporter.py's
            # json_export dumps the result dict verbatim). A bare list is
            # tolerated in case the format changes back.
            if isinstance(entry, dict):
                params = entry.get("params") or []
            elif isinstance(entry, list):
                params = entry
            else:
                continue
            if not params:
                continue
            query = urlencode({p: "1" for p in params})
            joiner = "&" if "?" in url else "?"
            yield Artifact(
                ArtifactKind.HTTP_SERVICE, f"{url}{joiner}{query}",
                meta={"src": "arjun", "params": list(params), "has_params": True,
                      # The choke point in runner.py (_meta_host_or_value)
                      # scope-checks THIS field for every HTTP_SERVICE
                      # artifact -- see katana.py's identical comment.
                      # Without it an out-of-scope discovery here would be
                      # judged on whatever normalize() makes of the whole
                      # parameterised URL string instead of failing closed
                      # onto the same host the un-parameterised URL judged.
                      #
                      # scope.normalize(), not a bare urlsplit().hostname --
                      # the SAME function katana.py and jsrecon.py use and
                      # the same one the choke point normalizes with, so the
                      # three cannot drift. normalize() already wraps
                      # urlsplit in `except ValueError` for a malformed
                      # authority ("http://[::1/broken" raises "Invalid IPv6
                      # URL"). Letting that escape would be far worse than
                      # one bad row: parse() is a generator consumed inside
                      # runner.py's broad try/except, so the exception
                      # terminates the WHOLE generator and every artifact
                      # from every later key is lost, surfacing only as a
                      # generic PARSE_ERROR. Normalizing to "" instead makes
                      # admission control refuse just this row and record
                      # it, while the rest of the discovery still lands.
                      #
                      # build_command() happens to filter its input through
                      # ctx.scope.filter() and arjun echoes the input line
                      # back as the -oJ key, but that protection is
                      # INCIDENTAL, not contractual: parse() takes a bare
                      # path with no ctx or scope coupling, so a stale or
                      # resumed raw file, a future arjun that changes its
                      # echo behaviour, or any direct .parse(path) call
                      # bypasses it entirely.
                      "host": normalize_host(url)},
            )
