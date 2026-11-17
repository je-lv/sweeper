"""Lazily-loaded JavaScript chunks, recovered without running a browser.

WHY THIS EXISTS. A code-split front end ships one entry bundle in its HTML
and loads everything else at runtime. A crawler that follows `<script src>`
therefore sees a single file and misses the rest of the application -- and
the rest of the application is where the endpoints, the parameter names and
the secrets are. The bundle's own routing table is usually the most complete
map of the API that exists anywhere.

MEASURED, not assumed. Against a real Vite build shipped with a tool on this
machine (Starkiller, 66 JS files in dist/assets):

    files on disk                     66
    referenced by index.html           1   <- what a crawler sees
    recovered from the entry bundle   65   <- everything but the entry itself

That is the whole gap in one number: 1 of 66 without this, 66 of 66 with it.

The Vite shapes below (`import("./Name-hash.js")`, and the `assets/...`
literals in __vitePreload dependency arrays) were read off that build --
32 and 441 occurrences respectively. The webpack and Next.js shapes are
pattern-based rather than measured here: no bundle on this machine used a
runtime chunk map, so those are written from the documented output shapes
and are marked as such on each pattern. They fail closed -- a pattern that
matches nothing costs nothing and yields no URL.

WHAT THIS DELIBERATELY DOES NOT DO. It does not execute anything. The
browser-extension tools in this space work by letting the page load its own
chunks, which means running the target's JavaScript; that is a different
risk posture from a scanner and not one to adopt silently. Everything here
is a regex over bytes already downloaded.

Scope is NOT this module's job and must not be: it returns candidate URLs
and the caller checks every one against ctx.scope before fetching, so the
refusal is recorded in the one place that records refusals. See
stages/jsrecon.fetch_js.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

#: A hashed asset filename. The content hash is what distinguishes a BUILD
#: ARTIFACT from an arbitrary `.js` string, and requiring one is what stops
#: this returning every quoted filename in the bundle.
#:
#: Checked against real names from builds on this machine and the standard
#: bundler layouts:
#:
#:   matches   About-840a70b6.js  main.4d816da9.chunk.js  2.705bef74.chunk.js
#:             index-53847554.js  vendors~main.abc12345.chunk.js
#:   rejects   helpers.js  index.js  app.js  jquery.min.js  some.filename.js
#:
#: The hash must follow a `-` or `.`, run at least six characters, and
#: contain a digit -- `some.filename.js` is otherwise indistinguishable from
#: `main.4d816da9.js` on shape alone. `~` is webpack's splitChunks separator.
_HASHED = (r"[A-Za-z0-9_\-.~]*?[-.](?=[A-Za-z0-9]*[0-9])[A-Za-z0-9]{6,}"
           r"(?:\.[A-Za-z0-9]+)*\.js")

#: MEASURED against the Starkiller Vite build (32 occurrences): a dynamic
#: import with a literal relative path. This is the canonical code-splitting
#: shape for every ESM bundler, so it is also the highest-yield pattern here.
_DYNAMIC_IMPORT = re.compile(
    r"""import\(\s*["'](?P<path>[^"'\s]+\.js)["']\s*\)"""
)

#: MEASURED against the same build (441 occurrences): bare asset paths, which
#: is how Vite lists a chunk's own dependencies in its __vitePreload calls.
#: Anchored on a directory segment so it cannot match an arbitrary word.
_ASSET_PATH = re.compile(
    r"""["'](?P<path>(?:\.{0,2}/)?(?:[A-Za-z0-9_\-.]+/)*"""
    r"""(?:assets|static|chunks|_next|js|dist|build)/[^"'\s]*?"""
    + _HASHED + r""")["']"""
)

#: PATTERN-BASED (webpack 4/5 runtime), not measured here. The runtime builds
#: a chunk URL by concatenating a literal prefix, the chunk id, a literal
#: separator, a hash looked up in an object, and a literal suffix:
#:
#:   "static/js/" + e + "." + {147:"a1b2c3d4",512:"deadbeef"}[e] + ".chunk.js"
#:
#: The middle is left deliberately loose because real runtimes put a
#: chunk-NAME lookup there too (`({12:"vendors"}[e]||e)`).
_WEBPACK_TEMPLATE = re.compile(
    r"""["'](?P<prefix>[^"']*?)["']\s*\+[^"']{0,200}?\+\s*["'](?P<sep>[^"']{0,4})["']"""
    r"""\s*\+\s*\{(?P<map>[^{}]{4,4000})\}\[[^\]]{1,40}\]\s*\+\s*["'](?P<suffix>[^"']*?\.js)["']"""
)

#: The `id:"hash"` pairs inside that object. Keys may be bare numbers or
#: quoted strings; values are the content hashes.
_MAP_ENTRY = re.compile(r"""["']?(?P<id>[A-Za-z0-9_\-]+)["']?\s*:\s*["'](?P<hash>[A-Za-z0-9_\-]+)["']""")

#: PATTERN-BASED (webpack): the public path the runtime prefixes to every
#: chunk it builds. Without it a reconstructed "static/js/..." resolves
#: against the BUNDLE's directory rather than the site root.
_PUBLIC_PATH = re.compile(
    r"""(?:__webpack_require__|\b[a-zA-Z_$][\w$]{0,3})\.p\s*=\s*["'](?P<path>[^"']*)["']"""
)

#: PATTERN-BASED (Next.js): the build manifests list every route's chunks and
#: are themselves fetchable, so naming them is enough -- the caller fetches
#: them and this module runs again over the result.
_NEXT_MANIFEST = re.compile(
    r"""["'](?P<path>/_next/static/[^"'\s]+/_(?:build|ssg)Manifest\.js)["']"""
)

#: Cap on how many candidates one bundle may contribute. A 3 MB vendor
#: bundle with an unlucky pattern must not turn into thousands of requests
#: against a client; the caller's own cap applies on top of this.
MAX_PER_BUNDLE = 200


def _resolve(base_url: str, path: str) -> str:
    """Resolve `path` the way the RUNTIME would, not the way a link would.

    A bundler's dependency list holds paths relative to the app's BASE, not
    to the directory the bundle happens to sit in. Vite emits `assets/X.js`
    from inside `/assets/index.js`, and plain urljoin turns that into
    `/assets/assets/X.js` -- caught by validating against a real build, where
    it mis-resolved 65 of 91 candidates into a directory that does not exist.

    The rule: if the path's first segment repeats the directory the bundle is
    already in, it is base-relative, so resolve it one level up. That is
    correct both for a site at the root (`/assets/index.js` + `assets/X.js`
    -> `/assets/X.js`) and for one served under a prefix
    (`/app/assets/index.js` + `assets/X.js` -> `/app/assets/X.js`), without
    assuming either.
    """
    if path.startswith(("/", "http://", "https://")):
        return urljoin(base_url, path)
    first = path.split("/", 1)[0]
    base_dir = base_url.rsplit("/", 1)[0]
    if first and base_dir.endswith("/" + first):
        return urljoin(base_dir[: -len(first)], path)
    return urljoin(base_url, path)


def _is_javascript(path: str) -> bool:
    """Reject a path whose query/fragment hides a non-JS target."""
    clean = path.split("?", 1)[0].split("#", 1)[0]
    return clean.endswith(".js") or clean.endswith(".mjs")


def _webpack_urls(text: str, public_path: str) -> list[str]:
    """Reconstruct `prefix + id + sep + hash + suffix` for each mapped chunk."""
    out: list[str] = []
    for m in _WEBPACK_TEMPLATE.finditer(text):
        prefix, sep, suffix = m.group("prefix"), m.group("sep"), m.group("suffix")
        for entry in _MAP_ENTRY.finditer(m.group("map")):
            built = f"{prefix}{entry.group('id')}{sep}{entry.group('hash')}{suffix}"
            # public_path is joined here rather than by the caller: it is a
            # property of the RUNTIME that emitted this template, so it
            # belongs to the same reconstruction.
            out.append(urljoin(public_path, built) if public_path else built)
    return out


def candidates(text: str, base_url: str) -> list[str]:
    """Absolute URLs of chunks referenced by `text`, in a stable order.

    `base_url` is the URL the bundle was SERVED from, so a relative path
    resolves the way the browser would have resolved it. Returns [] rather
    than raising on anything malformed: a bundle that cannot be parsed must
    degrade to "no extra chunks", never to a failed stage.
    """
    if not text or not base_url:
        return []

    found: list[str] = []
    public_path = ""
    m = _PUBLIC_PATH.search(text)
    if m and m.group("path"):
        public_path = m.group("path")

    for pattern in (_DYNAMIC_IMPORT, _ASSET_PATH, _NEXT_MANIFEST):
        for match in pattern.finditer(text):
            found.append(match.group("path"))
    found.extend(_webpack_urls(text, public_path))

    seen: set[str] = set()
    out: list[str] = []
    for path in found:
        if not _is_javascript(path):
            continue
        try:
            url = _resolve(base_url, path)
        except ValueError:
            # A malformed authority ("https://[::1/x") -- same handling as
            # jsrecon._safe_urljoin: skip the candidate, keep the bundle.
            continue
        if not urlsplit(url).scheme.startswith("http"):
            continue
        # The bundle must not propose ITSELF as a new chunk: that is an
        # infinite fetch loop dressed as a discovery.
        if url == base_url or url in seen:
            continue
        seen.add(url)
        out.append(url)
        if len(out) >= MAX_PER_BUNDLE:
            break
    return out
