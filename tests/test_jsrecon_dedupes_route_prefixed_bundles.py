"""One bundle served under twenty route paths must cost one request.

The 2026-08-05 live run against the same three SPA origins reproduced the
2026-08-04 numbers EXACTLY, after prioritise_candidates had landed:

    9 read + 111 not-javascript = 120 = MAX_JS_FILES
    9 + 111 + 380 over-cap      = 500 = MAX_JS_CANDIDATES

Ordering could not help, because on this scope the dead references are not
vendored libraries -- they carry the SAME content-hashed filenames as the
real bundles, one copy per crawled route:

    https://shop.acc.example/main.b6eecf01882a734d.js          <- the file
    https://shop.acc.example/trade-in/main.b6eecf01882a734d.js <- catch-all
    https://shop.acc.example/tenants/countries/main.b6ee....js <- catch-all

A relative `<script src="main.<hash>.js">` on an SPA route resolves against
that route, so every crawled path yields a full set of copies. They are
tier 0 to prioritise_candidates -- correctly, the NAME is a build artifact's
name -- so the budget is spent on them in exactly the same proportion.

A build hash IS a content identity: the same fingerprinted filename on the
same origin is the same bytes, whatever route prefix it appears under. So
the second copy is not worth a request, and skipping it is a coverage gain
rather than a loss.
"""

import urllib.error

import pytest

import sweeper.stages.jsrecon as m

BASE = "https://shop.acc.example"
HASHED = "main.b6eecf01882a734d.js"


class _FakeResp:
    def __init__(self, body, content_type="application/javascript"):
        self._body = body.encode()
        self.headers = {"Content-Type": content_type}
        self.url = None

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeScope:
    def allows(self, url):
        return True


class _FakeCtx:
    scope = _FakeScope()
    user_agent = "test"


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch):
    monkeypatch.setattr(m.time, "sleep", lambda *_: None)


def _fetch(tmp_path, monkeypatch, urls, responder):
    """Run fetch_js against `responder`, returning (issued, records)."""
    issued = []

    def fake_urlopen(opener, req, timeout=None):
        issued.append(req.full_url)
        return responder(req.full_url)

    monkeypatch.setattr(m, "_urlopen", fake_urlopen)
    records = m.fetch_js(_FakeCtx(), urls, tmp_path / "js")
    return issued, records


def _js(_url):
    return _FakeResp("var a=1;")


def test_the_same_hashed_bundle_under_many_routes_costs_one_request(
        tmp_path, monkeypatch):
    """The live-run defect. Twenty copies of one file, one request."""
    routes = ["", "/trade-in", "/tenants/countries", "/static/dashboard/js",
              "/checkout", "/account", "/products", "/search"]
    urls = [f"{BASE}{r}/{HASHED}" for r in routes]

    issued, _ = _fetch(tmp_path, monkeypatch, urls, _js)

    assert issued == [f"{BASE}/{HASHED}"], (
        f"one bundle, one request expected; issued {len(issued)}: {issued}")


def test_the_copy_at_the_shallowest_path_is_the_one_requested(
        tmp_path, monkeypatch):
    """A catch-all copy is the real path with a route prefix in front of
    it, so it is always deeper. Discovery order must not decide this --
    a crawl reaches routes in whatever order it reaches them."""
    urls = [
        f"{BASE}/tenants/countries/{HASHED}",   # discovered first
        f"{BASE}/trade-in/{HASHED}",
        f"{BASE}/{HASHED}",                     # the real file
    ]

    issued, _ = _fetch(tmp_path, monkeypatch, urls, _js)

    assert issued == [f"{BASE}/{HASHED}"]


def test_a_skipped_copy_is_recorded_naming_the_url_that_was_read(
        tmp_path, monkeypatch):
    """The rule this whole stage is built on: a bundle that went unread is
    never invisible. A duplicate must not be silently dropped, and must not
    masquerade as skipped-over-cap -- its bytes WERE read, from elsewhere."""
    urls = [f"{BASE}/{HASHED}", f"{BASE}/trade-in/{HASHED}"]

    _, records = _fetch(tmp_path, monkeypatch, urls, _js)

    dup = [r for r in records if r["url"] == f"{BASE}/trade-in/{HASHED}"]
    assert dup, f"the skipped copy has no record at all: {records}"
    assert dup[0]["status"] == m._STATUS_DUPLICATE
    assert dup[0]["detail"] == f"{BASE}/{HASHED}"


def test_an_unfingerprinted_filename_is_never_deduped(tmp_path, monkeypatch):
    """`/admin/app.js` and `/shop/app.js` are two different files that
    happen to share a name. Only a content hash licenses the assumption
    that two paths hold the same bytes."""
    urls = [f"{BASE}/admin/app.js", f"{BASE}/shop/app.js"]

    issued, _ = _fetch(tmp_path, monkeypatch, urls, _js)

    assert sorted(issued) == sorted(urls)


def test_a_copy_is_skipped_only_after_one_has_actually_been_read(
        tmp_path, monkeypatch):
    """Claimed on a successful read, never on a mere attempt.

    An Angular app with a <base href> emits `<script src="main.<hash>.js">`
    on every route, so the SHALLOWEST path can be the dead one while the
    real file sits under /static/. Claiming on the attempt would skip the
    only readable copy and report the bundle as read.
    """
    dead = f"{BASE}/{HASHED}"
    real = f"{BASE}/static/js/{HASHED}"

    def responder(url):
        if url == dead:
            return _FakeResp("<!doctype html>", content_type="text/html")
        return _FakeResp("var a=1;")

    issued, records = _fetch(tmp_path, monkeypatch, [real, dead], responder)

    assert issued == [dead, real], (
        "the catch-all's html answer must not claim the bundle")
    assert [r["status"] for r in records if r["url"] == real] == [m._STATUS_OK]


def test_a_copy_is_not_skipped_when_the_first_attempt_errored(
        tmp_path, monkeypatch):
    """A transport error is evidence of nothing -- the same rule the dnssec
    stage learned. The other copy is still worth its request."""
    first = f"{BASE}/{HASHED}"
    second = f"{BASE}/trade-in/{HASHED}"

    def responder(url):
        if url == first:
            raise urllib.error.URLError("connection reset")
        return _FakeResp("var a=1;")

    issued, _ = _fetch(tmp_path, monkeypatch, [first, second], responder)

    assert issued == [first, second]


def test_two_hosts_serving_the_same_bundle_are_both_read(
        tmp_path, monkeypatch):
    """Identity is per-origin. Endpoints extracted from a bundle resolve
    against the URL it was served from, so reading one host's copy and
    skipping another's would attribute the second host's attack surface to
    the first -- a reporting defect, not a saving."""
    urls = [f"{BASE}/{HASHED}", f"https://other.acc.example/{HASHED}"]

    issued, _ = _fetch(tmp_path, monkeypatch, urls, _js)

    assert sorted(issued) == sorted(urls)


def test_a_discovered_chunk_that_duplicates_a_read_bundle_costs_nothing(
        tmp_path, monkeypatch):
    """Chunks are appended to the same worklist mid-walk (see
    sweeper/chunks.py), and a code-split app references its siblings from
    every chunk. They must obey the same identity rule as crawled
    candidates, or the budget leaks back out through the queue."""
    entry = f"{BASE}/entry.aaaaaaaa1111.js"
    chunk = f"{BASE}/{HASHED}"

    def responder(url):
        if url == entry:
            # references the chunk under a route prefix, as a relative
            # import resolved from a route page would
            return _FakeResp(f'import("/trade-in/{HASHED}");')
        return _FakeResp("var a=1;")

    issued, _ = _fetch(tmp_path, monkeypatch, [entry, chunk], responder)

    assert issued == [entry, chunk], f"issued {issued}"


def test_a_duplicate_is_not_logged_as_an_unread_bundle(tmp_path):
    """sweep.log is where an operator learns what was NOT covered.

    On the live scope 380 candidates were copies of nine bundles. Logging
    each as "JS NOT READ" would describe a 380-bundle coverage gap that
    does not exist, and would bury the handful of genuinely unread ones --
    the exact failure this stage's logging was built to prevent.
    """
    stage = m.JsreconStage()
    stage.fetch_records = [
        {"url": f"{BASE}/{HASHED}", "status": m._STATUS_OK, "detail": ""},
        {"url": f"{BASE}/trade-in/{HASHED}", "status": m._STATUS_DUPLICATE,
         "detail": f"{BASE}/{HASHED}"},
        {"url": f"{BASE}/gone.js", "status": "http-404", "detail": ""},
    ]
    lines = []

    class LogCtx:
        def log(self, msg):
            lines.append(msg)

    stage._log_fetch_records(LogCtx())

    not_read = [ln for ln in lines if "JS NOT READ" in ln]
    assert len(not_read) == 1, f"duplicates logged as unread: {not_read}"
    assert "/gone.js" in not_read[0]
    assert any("1 unread" in ln for ln in lines), (
        f"the summary counts a duplicate as unread: {lines}")
    assert any("duplicate" in ln.lower() for ln in lines), (
        "a deduplicated copy must still be visible somewhere in the log")


def test_every_distinct_bundle_on_a_real_sized_scope_gets_read(
        tmp_path, monkeypatch):
    """The shape the live scope actually presented, at its real size.

    500 candidates that dedupe to 212 distinct bundles. Deduplication got
    the wasted requests back -- 66 read where 9 were before -- but the
    request budget then became the binding limit in its own right: 120
    requests spent, 92 distinct bundles left `skipped-over-cap`.

    A cap that stops short of the distinct set is now stopping short of
    real files rather than of copies, which is a different bargain from the
    one 120 was chosen for. The budget must reach every distinct bundle a
    scope of this size presents.
    """
    distinct = [f"{BASE}/chunk{i:04d}.{i:08x}.js" for i in range(212)]
    # 288 copies spread over the first bundles, as a crawl of many routes
    # produces: the same file under one route prefix after another.
    copies = [f"{BASE}/route{j}/chunk{i:04d}.{i:08x}.js"
              for i in range(96) for j in range(3)]
    assert len(distinct) + len(copies) == 500

    issued, records = _fetch(tmp_path, monkeypatch, distinct + copies, _js)

    read = [r["url"] for r in records if r["status"] == m._STATUS_OK]
    assert len(read) == 212, (
        f"{212 - len(read)} distinct bundles went unread; "
        f"{len(issued)} requests issued against a cap of {m.MAX_JS_FILES}")
    assert not [r for r in records if r["status"] == m._STATUS_CAPPED], (
        "no distinct bundle should be lost to the cap at this scope size")
