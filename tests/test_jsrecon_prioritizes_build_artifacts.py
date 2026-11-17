"""jsrecon must read application code before vendored and dead candidates.

The 2026-08-04 live run against three SPA origins read 9 of 500 candidate
bundles. Not because the cap was too low -- because of the ORDER the cap
was spent in:

    9 read + 111 not-javascript = 120 = MAX_JS_FILES   (request budget gone)
    9 + 111 + 380 over-cap      = 500 = MAX_JS_CANDIDATES

111 of the 120 requests (92.5%) went to URLs that answered `text/html`.
Those origins catch-all-route every unknown path to index.html, so each
dead `/static/dashboard/js/jquery-ui.js` reference katana harvested cost a
slot from the request budget, and the content-hashed build chunks -- where
endpoints and secrets actually live -- were never reached.

`fetch_js` drains its worklist FIFO in discovery order, so this is purely
an ordering defect. Raising the cap does not fix it: the dead references
scale with the crawl, so a larger budget is spent the same way.
"""

from sweeper.stages.jsrecon import prioritise_candidates


def test_hashed_build_chunks_are_read_before_vendored_libraries():
    """A fingerprinted filename is the strongest signal of application code.

    Vendored libraries are public, unmodified, and hold no endpoints or
    secrets worth the request. Real candidates from the live run.
    """
    base = "https://shop.acc.example:443"
    urls = [
        f"{base}/static/dashboard/js/jquery-ui.js",
        f"{base}/static/dashboard/js/bootstrap.bundle.min.js",
        f"{base}/runtime.2b676e486f3abf28.js",
        f"{base}/static/dashboard/js/dataTables.bootstrap4.js",
        f"{base}/_nuxt/DE3bru81.js",
    ]

    ordered = prioritise_candidates(urls)

    assert ordered[:2] == [
        f"{base}/runtime.2b676e486f3abf28.js",
        f"{base}/_nuxt/DE3bru81.js",
    ], "content-hashed build artifacts must come first"


def test_every_candidate_is_kept():
    """Prioritising REORDERS; it must never drop a candidate.

    Dropping here would be a silent coverage loss -- the opposite of the
    skipped-over-cap record, which exists so an unread bundle is always
    visible to the operator.
    """
    urls = [
        "https://x.test/vendor/jquery.js",
        "https://x.test/app.9f8e7d6c.js",
        "https://x.test/main.js",
    ]

    ordered = prioritise_candidates(urls)

    assert sorted(ordered) == sorted(urls)
    assert len(ordered) == len(urls)


def test_discovery_order_is_preserved_within_a_tier():
    """Stable within a tier: with no signal to separate two candidates,
    the crawler's order is the best available evidence and must survive."""
    urls = [
        "https://x.test/alpha.js",
        "https://x.test/beta.js",
        "https://x.test/gamma.js",
    ]

    assert prioritise_candidates(urls) == urls


def test_vendored_libraries_sort_last():
    """Below ordinary unknown files: a known third-party library is the
    one candidate we can say in advance is not worth a request."""
    urls = [
        "https://x.test/js/jquery.min.js",
        "https://x.test/js/application-logic.js",
    ]

    ordered = prioritise_candidates(urls)

    assert ordered == [
        "https://x.test/js/application-logic.js",
        "https://x.test/js/jquery.min.js",
    ]


def test_fetch_js_spends_its_request_budget_on_build_artifacts_first(
        tmp_path, monkeypatch):
    """The live-run failure, reproduced at the cap.

    A crawl of an SPA whose catch-all answers every dead reference yields
    far more vendored/dead candidates than real bundles. With the budget
    smaller than the candidate list, the build artifacts must still be the
    ones that get requested -- that is the whole point of ordering.
    """
    import urllib.error

    import sweeper.stages.jsrecon as jsrecon_mod

    issued = []

    def fake_urlopen(opener, req, timeout=None):
        issued.append(req.full_url)
        raise urllib.error.URLError("no network in this test")

    monkeypatch.setattr(jsrecon_mod, "_urlopen", fake_urlopen)
    monkeypatch.setattr(jsrecon_mod.time, "sleep", lambda *_: None)
    monkeypatch.setattr(jsrecon_mod, "MAX_JS_FILES", 3)

    class FakeScope:
        def allows(self, url):
            return True

    class FakeCtx:
        scope = FakeScope()
        user_agent = "test"

    base = "https://acc.example"
    dead = [f"{base}/static/js/vendor/jquery-{i}.js" for i in range(20)]
    real = [
        f"{base}/runtime.2b676e486f3abf28.js",
        f"{base}/_nuxt/DE3bru81.js",
        f"{base}/main.9f8e7d6c.js",
    ]
    # Discovery order puts every dead reference first, as a crawl does.
    jsrecon_mod.fetch_js(FakeCtx(), dead + real, tmp_path / "js")

    assert sorted(issued) == sorted(real), (
        f"budget spent on the wrong candidates: {issued}")
