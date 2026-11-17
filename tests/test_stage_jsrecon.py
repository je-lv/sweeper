import http.server
import threading
import urllib.error
from pathlib import Path

from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.jsrecon import JsreconStage, extract_endpoints

JS = """
const API_BASE = "/api/v2/orders";
fetch("/api/v2/customers/" + id);
const k = "sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopQ";
const pub = "pk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopQ";
axios.get('https://acc.example/internal/report');
"""


def test_contract():
    assert registry.validate(JsreconStage()) == []


def test_produces_both_services_and_findings():
    s = JsreconStage()
    assert s.produces == {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING}


def test_runs_from_mid_through_full():
    s = JsreconStage()
    assert s.levels["low"] == []
    for lvl in ("mid", "high", "full"):
        assert s.levels[lvl] != []


def test_extract_endpoints_finds_api_paths():
    eps = extract_endpoints(JS)
    assert "/api/v2/orders" in eps
    assert "/api/v2/customers/" in eps


def test_extract_endpoints_ignores_short_noise():
    assert "/" not in extract_endpoints('const a="/";')


def test_secret_scan_separates_secret_from_publishable(tmp_path):
    from sweeper.secrets_rules import scan_text
    found = {f.template_id: f.severity
             for f in scan_text(JS, source="https://acc.example/app.js")}
    assert found["secret-stripe-secret"] == "critical"
    assert found["secret-stripe-publishable"] == "info"


def test_analyse_file_emits_endpoints_and_findings(tmp_path):
    from sweeper.stages.jsrecon import analyse_js
    out = list(analyse_js(JS, "https://acc.example/app.js"))
    assert any(isinstance(x, Finding) and x.severity == "critical" for x in out)
    assert any(getattr(x, "kind", None) is ArtifactKind.HTTP_SERVICE for x in out)


def test_endpoint_artifacts_are_absolute_urls():
    from sweeper.stages.jsrecon import analyse_js
    urls = [x.value for x in analyse_js(JS, "https://acc.example/static/app.js")
            if getattr(x, "kind", None) is ArtifactKind.HTTP_SERVICE]
    assert "https://acc.example/api/v2/orders" in urls


def test_verification_disabled_by_default(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    cmd = JsreconStage().trufflehog_command(ctx, tmp_path)
    assert "--no-verification" in cmd


# --- Task 6 additions beyond the brief -------------------------------------

def test_finding_never_carries_the_raw_secret():
    """secrets_rules.scan_text redacts at construction (Finding.evidence is
    already truncated) -- this is a re-check from the jsrecon call path,
    the actual caller in a real run, not just against scan_text directly.
    """
    from sweeper.stages.jsrecon import analyse_js
    findings = [x for x in analyse_js(JS, "https://acc.example/app.js")
                if isinstance(x, Finding)]
    secret = "sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopQ"
    for f in findings:
        assert secret not in f.evidence
        assert secret not in f.matcher
        assert secret not in f.description
        assert secret not in f.title


def test_endpoint_artifacts_carry_host_meta_for_admission_control():
    """runner.py's admission choke point scope-checks meta["host"], not the
    URL string. The relative-path branch resolves onto the source host
    (in-scope, ordinarily), but the absolute-URL branch can name a
    completely different host (acc.example/internal/report is same-host
    here, but nothing stops a future JS bundle naming an offsite one) --
    meta["host"] has to reflect whichever host the URL ACTUALLY names.
    """
    from sweeper.stages.jsrecon import analyse_js
    arts = [x for x in analyse_js(JS, "https://acc.example/static/app.js")
            if isinstance(x, Artifact)]
    by_value = {a.value: a for a in arts}
    assert by_value["https://acc.example/api/v2/orders"].meta["host"] == "acc.example"
    assert (by_value["https://acc.example/internal/report"].meta["host"]
            == "acc.example")


def test_looks_like_js_matches_content_type_or_extension():
    from sweeper.stages.jsrecon import _looks_like_js
    assert _looks_like_js(Artifact(ArtifactKind.HTTP_SERVICE,
                                    "https://acc.example/x",
                                    meta={"content_type": "application/javascript"}))
    assert _looks_like_js(Artifact(ArtifactKind.HTTP_SERVICE,
                                    "https://acc.example/app.bundle.js", meta={}))
    assert not _looks_like_js(Artifact(ArtifactKind.HTTP_SERVICE,
                                        "https://acc.example/index.html",
                                        meta={"content_type": "text/html"}))


def test_build_command_is_a_noop_and_touches_no_network_with_empty_store(tmp_path):
    """Matches preflight's real calling shape: preflight.run_preflight()
    calls build_command() for every stage before run_stages() runs ANY of
    them, so ctx.store has no HTTP_SERVICE artifacts yet at that point (see
    the module docstring). This must return instantly and issue nothing.
    """
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      level="full"))
    cmd = JsreconStage().build_command(ctx)
    assert cmd == ["/bin/true"]


def test_build_command_does_nothing_at_low(tmp_path, monkeypatch):
    """levels["low"] == [] gates the stage off entirely, even if the store
    somehow already had a javascript-flagged HTTP_SERVICE artifact.
    """
    import sweeper.stages.jsrecon as jsrecon_mod
    calls = []
    monkeypatch.setattr(jsrecon_mod, "fetch_js",
                        lambda *a, **kw: calls.append(a) or 0)
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      level="low"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/app.js",
                           meta={"content_type": "application/javascript"}))
    JsreconStage().build_command(ctx)
    assert calls == []


def test_build_command_fetches_only_js_flagged_services(tmp_path, monkeypatch):
    import sweeper.stages.jsrecon as jsrecon_mod
    seen = {}
    monkeypatch.setattr(
        jsrecon_mod, "fetch_js",
        lambda ctx, urls, js_dir, timeout=20: [seen.setdefault("urls", urls)] and []
    )
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      level="mid"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/app.js",
                           meta={"content_type": "application/javascript"}))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/",
                           meta={"content_type": "text/html"}))
    JsreconStage().build_command(ctx)
    assert seen["urls"] == ["https://acc.example/app.js"]


def test_fetch_js_caps_the_candidates_it_will_consider(tmp_path):
    """The absolute bound: MAX_JS_CANDIDATES.

    This assertion used to read `len(attempts) == MAX_JS_FILES` with a scope
    that refused everything, i.e. it measured candidates CONSIDERED. That was
    the same number back when the worklist was fixed at entry. It no longer
    is -- every bundle read can contribute more chunk URLs (see
    sweeper/chunks.py) -- and the two limits have come apart:

      MAX_JS_FILES      requests actually ISSUED. A URL refused by scope
                        sends no packet, so it must not consume the budget
                        that in-scope bundles need.
      MAX_JS_CANDIDATES how many candidates the loop will look at AT ALL,
                        which is what keeps a large bundle graph from
                        becoming an unbounded queue.

    Both are asserted -- here and in the test below -- because dropping
    either one is how this loop becomes unbounded again.
    """
    import sweeper.stages.jsrecon as jsrecon_mod
    attempts = []

    class FakeScope:
        def allows(self, url):
            attempts.append(url)
            return False   # never actually fetch; just count what was seen

    class FakeCtx:
        scope = FakeScope()
        user_agent = "test"

    urls = [f"https://acc.example/b{i}.js"
            for i in range(jsrecon_mod.MAX_JS_CANDIDATES + 25)]
    jsrecon_mod.fetch_js(FakeCtx(), urls, tmp_path / "js")
    assert len(attempts) == jsrecon_mod.MAX_JS_CANDIDATES


def test_fetch_js_caps_the_requests_it_will_issue(tmp_path, monkeypatch):
    """MAX_JS_FILES bounds this stage's own sequential fetch loop.

    There is no external, rate-limited binary here to bound it otherwise, so
    this is jsrecon's equivalent of naabu's -rate. Counted at the point a
    request is actually made, with scope allowing everything.
    """
    import sweeper.stages.jsrecon as jsrecon_mod
    issued = []

    def fake_urlopen(opener, req, timeout=None):
        issued.append(req.full_url)
        raise urllib.error.URLError("no network in this test")

    monkeypatch.setattr(jsrecon_mod, "_urlopen", fake_urlopen)
    monkeypatch.setattr(jsrecon_mod.time, "sleep", lambda *_: None)

    class FakeScope:
        def allows(self, url):
            return True

    class FakeCtx:
        scope = FakeScope()
        user_agent = "test"

    urls = [f"https://acc.example/b{i}.js"
            for i in range(jsrecon_mod.MAX_JS_FILES + 25)]
    jsrecon_mod.fetch_js(FakeCtx(), urls, tmp_path / "js")
    assert len(issued) == jsrecon_mod.MAX_JS_FILES


def test_parse_reads_populated_js_dir(tmp_path):
    raw_path = tmp_path / "raw" / "jsrecon.jsonl"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_text("", encoding="utf-8")
    js_dir = raw_path.parent / "js"
    js_dir.mkdir()
    (js_dir / "bundle0000.js").write_text(JS, encoding="utf-8")
    (js_dir / "bundle0000.url").write_text("https://acc.example/app.js",
                                            encoding="utf-8")
    out = list(JsreconStage().parse(raw_path))
    urls = [x.value for x in out if isinstance(x, Artifact)]
    assert "https://acc.example/api/v2/orders" in urls
    assert any(isinstance(x, Finding) for x in out)


def test_parse_with_no_js_dir_yields_nothing(tmp_path):
    raw_path = tmp_path / "raw" / "jsrecon.jsonl"
    raw_path.parent.mkdir(parents=True)
    raw_path.write_text("", encoding="utf-8")
    assert list(JsreconStage().parse(raw_path)) == []


# --- authenticated fetch + observability (review round 1) -------------------

class _FakeResp:
    def __init__(self, body, content_type="application/javascript"):
        self._body = body.encode()
        self.headers = {"Content-Type": content_type}

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _ctx(tmp_path, **kw):
    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")
    return RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)
    )


def test_fetch_js_sends_ctx_auth_headers(tmp_path, monkeypatch):
    """THE authenticated-run defect: katana crawls behind a login wall and
    hands jsrecon a bundle URL, which jsrecon then fetched ANONYMOUSLY --
    getting a 401 or a login page, and finding nothing in exactly the files
    authentication existed to reach.
    """
    import sweeper.stages.jsrecon as m
    from sweeper.auth import SecretBundle
    seen = {}

    def fake_urlopen(opener, req, timeout=20):
        seen["headers"] = dict(req.headers)
        return _FakeResp("var a=1;")

    monkeypatch.setattr(m, "_urlopen", fake_urlopen)
    ctx = _ctx(tmp_path, auth_mode="auth")
    ctx.auth = SecretBundle(headers={"Authorization": "Bearer tok123"},
                            cookies={"session": "abc"})
    m.fetch_js(ctx, ["https://acc.example/app.js"], tmp_path / "js")

    # urllib title-cases header names.
    lowered = {k.lower(): v for k, v in seen["headers"].items()}
    assert lowered["authorization"] == "Bearer tok123"
    assert lowered["cookie"] == "session=abc"


def test_fetch_js_sends_no_auth_headers_when_unauthenticated(tmp_path, monkeypatch):
    import sweeper.stages.jsrecon as m
    seen = {}

    def fake_urlopen(opener, req, timeout=20):
        seen["headers"] = dict(req.headers)
        return _FakeResp("var a=1;")

    monkeypatch.setattr(m, "_urlopen", fake_urlopen)
    ctx = _ctx(tmp_path)
    m.fetch_js(ctx, ["https://acc.example/app.js"], tmp_path / "js")
    lowered = {k.lower() for k in seen["headers"]}
    assert "authorization" not in lowered and "cookie" not in lowered


def test_http_error_is_recorded_not_silently_skipped(tmp_path, monkeypatch):
    """"No secrets found" must not be reachable by never having read the
    file. A 401 is a COVERAGE gap and has to be visible.
    """
    import sweeper.stages.jsrecon as m

    def fake_urlopen(opener, req, timeout=20):
        raise m.urllib.error.HTTPError(req.full_url, 401, "Unauthorized",
                                       {}, None)

    monkeypatch.setattr(m, "_urlopen", fake_urlopen)
    ctx = _ctx(tmp_path)
    records = m.fetch_js(ctx, ["https://acc.example/app.js"], tmp_path / "js")
    assert records == [{"url": "https://acc.example/app.js",
                        "status": "http-401", "detail": ""}]


def test_html_login_page_returned_with_200_is_recorded_as_not_javascript(
        tmp_path, monkeypatch):
    """The nastier half: a login wall that answers 200 with an HTML page.
    Parsing it as JS finds nothing and looks identical to a clean bundle.
    """
    import sweeper.stages.jsrecon as m
    monkeypatch.setattr(m, "_urlopen",
                        lambda opener, req, timeout=20: _FakeResp(
                            "<html>login</html>", "text/html; charset=utf-8"))
    ctx = _ctx(tmp_path)
    records = m.fetch_js(ctx, ["https://acc.example/app.js"], tmp_path / "js")
    assert records[0]["status"] == "not-javascript"
    assert "text/html" in records[0]["detail"]
    # And it must NOT have been written for analysis.
    assert not list((tmp_path / "js").glob("*.js"))


def test_transport_error_is_recorded_with_type_but_no_content(tmp_path, monkeypatch):
    import sweeper.stages.jsrecon as m
    monkeypatch.setattr(
        m, "_urlopen",
        lambda opener, req, timeout=20: (_ for _ in ()).throw(
            m.urllib.error.URLError("boom")))
    ctx = _ctx(tmp_path)
    records = m.fetch_js(ctx, ["https://acc.example/app.js"], tmp_path / "js")
    assert records[0]["status"] == "error"
    assert records[0]["detail"] == "URLError"


def test_over_cap_urls_are_recorded_rather_than_silently_truncated(
        tmp_path, monkeypatch):
    import sweeper.stages.jsrecon as m
    monkeypatch.setattr(m, "_urlopen",
                        lambda opener, req, timeout=20: _FakeResp("var a=1;"))
    # REQUEST_PAUSE_S is real politeness against a real host and nonsense in
    # a test: this issues MAX_JS_FILES requests, so an unpatched sleep makes
    # the test cost cap x 0.2s and grow every time the cap is raised.
    monkeypatch.setattr(m.time, "sleep", lambda *_: None)
    ctx = _ctx(tmp_path)
    urls = [f"https://acc.example/b{i}.js" for i in range(m.MAX_JS_FILES + 3)]
    records = m.fetch_js(ctx, urls, tmp_path / "js")
    capped = [r for r in records if r["status"] == "skipped-over-cap"]
    assert len(capped) == 3
    assert len(records) == len(urls), "every candidate URL must be accounted for"


def test_unread_bundles_are_named_in_sweep_log(tmp_path, monkeypatch):
    """The operator-facing half: sweep.log must name the URL and status of
    every bundle that was not read.
    """
    import sweeper.stages.jsrecon as m

    def fake_urlopen(opener, req, timeout=20):
        raise m.urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)

    monkeypatch.setattr(m, "_urlopen", fake_urlopen)
    ctx = _ctx(tmp_path, level="mid")
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                           "https://acc.example/secret.bundle.js",
                           meta={"content_type": "application/javascript"}))
    stage = JsreconStage()
    stage.build_command(ctx)

    log = (ctx.run_dir / "sweep.log").read_text()
    assert "https://acc.example/secret.bundle.js" in log
    assert "http-403" in log
    assert "read 0 of 1 candidate JS bundle(s)" in log
    assert "session may not have been accepted" in log


def test_sweep_log_never_contains_response_content(tmp_path, monkeypatch):
    """An authenticated bundle's BODY is exactly where the secrets are.
    sweep.log lives for the life of the run directory -- it must never
    become a second place a secret is written in plaintext.
    """
    import sweeper.stages.jsrecon as m
    secret = "sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopQ"
    monkeypatch.setattr(
        m, "_urlopen",
        lambda opener, req, timeout=20: _FakeResp(
            f"<html>{secret}</html>", "text/html"))
    ctx = _ctx(tmp_path, level="mid")
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                           "https://acc.example/app.js",
                           meta={"content_type": "application/javascript"}))
    JsreconStage().build_command(ctx)
    assert secret not in (ctx.run_dir / "sweep.log").read_text()


def test_successful_fetch_is_recorded_as_ok(tmp_path, monkeypatch):
    import sweeper.stages.jsrecon as m
    monkeypatch.setattr(m, "_urlopen",
                        lambda opener, req, timeout=20: _FakeResp("var a=1;"))
    ctx = _ctx(tmp_path)
    records = m.fetch_js(ctx, ["https://acc.example/app.js"], tmp_path / "js")
    assert records[0]["status"] == "ok"
    assert (tmp_path / "js" / "bundle0000.js").read_text() == "var a=1;"


def test_out_of_scope_url_is_recorded_as_refused(tmp_path, monkeypatch):
    import sweeper.stages.jsrecon as m
    monkeypatch.setattr(m, "_urlopen",
                        lambda opener, req, timeout=20: _FakeResp("var a=1;"))
    ctx = _ctx(tmp_path)
    records = m.fetch_js(ctx, ["https://evil.test/app.js"], tmp_path / "js")
    assert records[0]["status"] == "refused-by-scope"


# --- malformed-URL robustness (review round 1) ------------------------------

def test_malformed_url_does_not_discard_the_rest_of_the_analysis():
    """analyse_js is a generator consumed inside runner.py's broad
    try/except: an escaping ValueError terminates it and discards every
    endpoint AND finding that would have followed -- including the secrets.
    """
    from sweeper.stages.jsrecon import analyse_js
    js = 'a("//[::1/x");\nb("/api/v2/orders");\nvar k="%s";' % (
        "sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopQ")
    out = list(analyse_js(js, "https://acc.example/app.js"))
    urls = [x.value for x in out if isinstance(x, Artifact)]
    assert "https://acc.example/api/v2/orders" in urls
    assert any(isinstance(x, Finding) and x.severity == "critical" for x in out)


def test_malformed_source_url_does_not_raise():
    from sweeper.stages.jsrecon import analyse_js
    out = list(analyse_js('a("/api/v2/orders");', "https://[::1/x"))
    # Must not raise; endpoints that cannot be resolved are skipped, and
    # the secret scan still runs.
    assert all(isinstance(x, (Artifact, Finding)) for x in out)


def test_protocol_relative_url_is_attributed_to_the_other_host():
    """urljoin("https://acc.example/app.js", "//evil.test/track") resolves
    to https://evil.test/track -- meta["host"] must say evil.test, or the
    choke point would scope-check the SOURCE host and admit it.
    """
    from sweeper.stages.jsrecon import analyse_js
    out = list(analyse_js('fetch("//evil.test/track/beacon");',
                          "https://acc.example/app.js"))
    art = next(x for x in out if isinstance(x, Artifact))
    assert art.value == "https://evil.test/track/beacon"
    assert art.meta["host"] == "evil.test"


def test_looks_like_js_survives_a_malformed_url():
    from sweeper.stages.jsrecon import _looks_like_js
    assert _looks_like_js(Artifact(ArtifactKind.HTTP_SERVICE,
                                    "https://[::1/x", meta={})) is False


# --- redirect scope + credential containment (review round 2, B2) -----------
#
# fetch_js scope-checked the candidate URL and then handed the request to
# urllib, whose default HTTPRedirectHandler copies the whole header dict --
# Authorization and Cookie included -- onto a request to whatever host a 302
# names. `requests` drops them across a host change; urllib does not. An
# in-scope bundle 302ing to a CDN or an object store is the ordinary case on
# a web application, so this could send a live bearer token and session cookie
# to a third party that was never in the allowlist, record no refusal, and
# filed the off-host body under the in-scope URL.
#
# The leak happens INSIDE the opener, between the scope check and the socket.
# A test that stubs _urlopen cannot see it, and one that only inspects the
# Request object redirect_request hands back cannot prove urllib never opened
# the refused URL. These tests therefore drive the real handler chain over
# real loopback sockets and assert on what a server was actually sent.
# "localhost" and "127.0.0.1" are two hostnames for the same socket, which is
# what makes an out-of-scope host testable without a packet leaving the host.

class _RecordingServer:
    """Loopback HTTP server that records every request it receives.

    `routes(path, port) -> ("redirect", location) | ("ok", body)`.
    """

    def __init__(self, routes):
        self.requests: list[dict] = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def do_GET(self):
                outer.requests.append({
                    "path": self.path,
                    "host": self.headers.get("Host", ""),
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                })
                action, value = outer.routes(self.path, outer.port)
                if action == "redirect":
                    self.send_response(302)
                    self.send_header("Location", value)
                    self.end_headers()
                    return
                if action == "code":
                    self.send_error(value)
                    return
                body = value.encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.routes = routes
        self._srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._srv.server_address[1]

    def __enter__(self):
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self._srv.shutdown()
        self._srv.server_close()
        return False

    def credentialed(self) -> list[dict]:
        """Requests that carried a credential-bearing header."""
        return [r for r in self.requests
                if {"authorization", "cookie"} & set(r["headers"])]


def _scoped_ctx(tmp_path, *hosts, **kw):
    """A RunContext whose allowlist is exactly `hosts`."""
    t = tmp_path / "t.txt"
    t.write_text("".join(f"{h}\n" for h in hosts))
    return RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)
    )


def _authed(ctx):
    from sweeper.auth import SecretBundle
    ctx.auth = SecretBundle(headers={"Authorization": "Bearer tok123"},
                            cookies={"session": "abc"})
    return ctx


def test_off_scope_redirect_sends_nothing_to_the_off_scope_host(tmp_path):
    """THE finding: an in-scope .js that 302s to a host outside the
    allowlist. Nothing at all may be sent there -- not the credentials, not
    a credential-free request either.
    """
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        if path == "/app.js":
            return "redirect", f"http://127.0.0.1:{port}/cdn.js"
        return "ok", "var served_off_scope=1;"

    with _RecordingServer(routes) as srv:
        ctx = _authed(_scoped_ctx(tmp_path, "localhost", auth_mode="auth"))
        url = f"http://localhost:{srv.port}/app.js"
        records = m.fetch_js(ctx, [url], tmp_path / "js")

    assert [r["path"] for r in srv.requests] == ["/app.js"], (
        "the off-scope redirect target must never have been requested")
    assert all(r["host"].split(":")[0] == "localhost"
               for r in srv.credentialed()), (
        "no credential-bearing request may reach a host outside the allowlist")
    assert not list((tmp_path / "js").glob("*.js")), (
        "no off-host body may be filed as evidence for the in-scope URL")
    assert records[0]["status"] == "refused-by-scope"
    assert "127.0.0.1" in records[0]["detail"]


def test_off_scope_redirect_is_visible_to_the_operator(tmp_path):
    """A silently dropped fetch is the defect class this project keeps
    producing. The refusal has to reach sweep.log AND the run manifest's
    scope refusals, not just the return value.
    """
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        return "redirect", f"http://127.0.0.1:{port}/cdn.js"

    with _RecordingServer(routes) as srv:
        ctx = _authed(_scoped_ctx(tmp_path, "localhost", auth_mode="auth"))
        url = f"http://localhost:{srv.port}/app.js"
        stage = JsreconStage()
        stage.fetch_records = m.fetch_js(ctx, [url], tmp_path / "js")
        stage._log_fetch_records(ctx)

    log = (ctx.run_dir / "sweep.log").read_text()
    assert url in log and "refused-by-scope" in log and "127.0.0.1" in log
    assert "read 0 of 1 candidate JS bundle(s)" in log
    assert any(r["normalized"] == "127.0.0.1" for r in ctx.scope.refusals), (
        "the attempted excursion must appear in the run manifest too")


def test_in_scope_cross_host_redirect_drops_the_credentials(tmp_path):
    """Second rule, asked separately from scope: "in scope" is not "the
    origin these credentials were issued for". A "*.acc.example" allowlist
    puts a hundred hosts in scope; the session belongs to one of them.
    """
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        if path == "/app.js":
            return "redirect", f"http://127.0.0.1:{port}/cdn.js"
        return "ok", "var a=1;"

    with _RecordingServer(routes) as srv:
        ctx = _authed(_scoped_ctx(tmp_path, "localhost", "127.0.0.1",
                                  auth_mode="auth"))
        url = f"http://localhost:{srv.port}/app.js"
        records = m.fetch_js(ctx, [url], tmp_path / "js")
        final = f"http://127.0.0.1:{srv.port}/cdn.js"

    by_path = {r["path"]: r for r in srv.requests}
    assert set(by_path) == {"/app.js", "/cdn.js"}
    assert by_path["/app.js"]["headers"]["authorization"] == "Bearer tok123"
    assert not {"authorization", "cookie"} & set(by_path["/cdn.js"]["headers"]), (
        "credentials must not follow a host change even inside scope")
    assert records[0]["status"] == "ok"
    assert "credentials withheld" in records[0]["detail"]
    assert "127.0.0.1" in records[0]["detail"]
    # And the evidence is attributed to where the bytes actually came from.
    assert (tmp_path / "js" / "bundle0000.url").read_text() == final


def test_same_origin_redirect_keeps_the_credentials(tmp_path):
    """The guard against over-correcting: stripping on every redirect would
    quietly undo the authenticated-fetch fix this stage exists to carry.
    """
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        if path == "/app.js":
            return "redirect", f"http://localhost:{port}/real.js"
        return "ok", "var a=1;"

    with _RecordingServer(routes) as srv:
        ctx = _authed(_scoped_ctx(tmp_path, "localhost", auth_mode="auth"))
        records = m.fetch_js(ctx, [f"http://localhost:{srv.port}/app.js"],
                             tmp_path / "js")

    by_path = {r["path"]: r for r in srv.requests}
    assert by_path["/real.js"]["headers"]["authorization"] == "Bearer tok123"
    assert by_path["/real.js"]["headers"]["cookie"] == "session=abc"
    assert records[0]["status"] == "ok" and records[0]["detail"] == ""


def test_redirect_chain_is_bounded(tmp_path):
    """An unbounded chain is a hang. Every hop is in scope and same-origin
    here, so nothing but the bound can stop it.
    """
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        n = int(path.rsplit("/r", 1)[1])
        return "redirect", f"http://localhost:{port}/r{n + 1}"

    with _RecordingServer(routes) as srv:
        ctx = _scoped_ctx(tmp_path, "localhost")
        records = m.fetch_js(ctx, [f"http://localhost:{srv.port}/r0"],
                             tmp_path / "js")

    assert len(srv.requests) <= m.MAX_REDIRECTS + 1, (
        f"chain ran to {len(srv.requests)} requests")
    assert records[0]["status"].startswith("http-3")
    assert records[0]["detail"] == "redirect not followed"


def test_https_to_http_downgrade_on_one_host_drops_the_credentials(tmp_path):
    """Same host, so a host-only comparison would let the session cookie go
    out in cleartext. Scheme and port are part of the origin.
    """
    import sweeper.stages.jsrecon as m
    ctx = _scoped_ctx(tmp_path, "acc.example")
    handler = m._ScopedRedirectHandler(ctx, ())
    req = m.urllib.request.Request(
        "https://acc.example/app.js",
        headers={"Authorization": "Bearer t", "Cookie": "s=1"})
    new = handler.redirect_request(req, None, 302, "Found", {},
                                   "http://acc.example/app.js")
    assert new is not None
    assert not {k.lower() for k in new.headers} & {"authorization", "cookie"}


def test_a_bespoke_credential_header_is_stripped_too(tmp_path):
    """A property, not an enumeration: the handler is told which headers
    ctx.auth actually produced for THIS run, so an operator whose session
    lives in "X-Api-Key" is covered without editing a hard-coded list.
    """
    import sweeper.stages.jsrecon as m
    from sweeper.auth import SecretBundle
    ctx = _scoped_ctx(tmp_path, "*.acc.example", auth_mode="auth")
    ctx.auth = SecretBundle(headers={"X-Api-Key": "k"})
    handler = m._ScopedRedirectHandler(ctx, m._auth_headers(ctx))
    req = m.urllib.request.Request("https://a.acc.example/app.js",
                                   headers={"X-Api-Key": "k"})
    new = handler.redirect_request(req, None, 302, "Found", {},
                                   "https://b.acc.example/app.js")
    assert new is not None, "b.acc.example is in scope; the hop is allowed"
    assert "x-api-key" not in {k.lower() for k in new.headers}


def test_redirect_to_a_non_http_scheme_is_refused(tmp_path):
    import sweeper.stages.jsrecon as m
    ctx = _scoped_ctx(tmp_path, "acc.example")
    handler = m._ScopedRedirectHandler(ctx, ())
    req = m.urllib.request.Request("https://acc.example/app.js")
    assert handler.redirect_request(req, None, 302, "Found", {},
                                    "ftp://acc.example/app.js") is None
    assert handler.refusal


def test_a_refusal_is_not_reported_against_the_next_candidate(tmp_path):
    """One handler serves the whole candidate list, so its per-URL state has
    to be cleared between candidates. Otherwise the SECOND URL's ordinary
    404 is filed as a scope refusal -- a fabricated scope event, and a real
    coverage gap relabelled as something the operator would not chase.

    127.0.0.2 is loopback but is not the address the server bound, so if the
    refusal ever stopped working this would fail to connect rather than
    reach anything.
    """
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        if path == "/a.js":
            return "redirect", f"http://127.0.0.2:{port}/off.js"
        return "code", 404

    with _RecordingServer(routes) as srv:
        ctx = _scoped_ctx(tmp_path, "localhost")
        records = m.fetch_js(ctx, [f"http://localhost:{srv.port}/a.js",
                                   f"http://localhost:{srv.port}/b.js"],
                             tmp_path / "js")

    assert [r["status"] for r in records] == ["refused-by-scope", "http-404"]
    assert records[1]["detail"] == ""


def test_a_credential_strip_is_not_reported_against_the_next_candidate(tmp_path):
    """The same staleness the other way round: a bundle fetched WITH the
    session must not be annotated as having been fetched without it, or the
    operator discounts a clean result that was never degraded.
    """
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        if path == "/a.js":
            return "redirect", f"http://127.0.0.1:{port}/cdn.js"
        return "ok", "var a=1;"

    with _RecordingServer(routes) as srv:
        ctx = _authed(_scoped_ctx(tmp_path, "localhost", "127.0.0.1",
                                  auth_mode="auth"))
        records = m.fetch_js(ctx, [f"http://localhost:{srv.port}/a.js",
                                   f"http://localhost:{srv.port}/b.js"],
                             tmp_path / "js")

    assert [r["status"] for r in records] == ["ok", "ok"]
    assert "credentials withheld" in records[0]["detail"]
    assert records[1]["detail"] == "", (
        "the second bundle was fetched with the session; its record must "
        "not carry the first bundle's strip")


# --- chunk discovery: the code a crawler never sees -------------------------
# A code-split front end ships ONE entry bundle in its HTML and loads the rest
# at runtime, so katana hands this stage a single URL. These drive the real
# fetch loop against a real server, because the whole point is that the extra
# requests actually happen -- a unit test on chunks.candidates() alone would
# pass just as well if nothing ever fetched what it returned.


def test_a_chunk_reachable_only_from_the_bundle_is_fetched(tmp_path):
    """The capability, end to end.

    /app.js is the only URL the crawler knows. The secret lives in a chunk
    whose name appears nowhere but inside /app.js.
    """
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        if path == "/app.js":
            return "ok", 'const r=[()=>import("./Admin-a1b2c3d4.js")];'
        return "ok", 'const k="sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopQ";'

    with _RecordingServer(routes) as srv:
        ctx = _scoped_ctx(tmp_path, "localhost")
        m.fetch_js(ctx, [f"http://localhost:{srv.port}/app.js"], tmp_path / "js")

    assert "/Admin-a1b2c3d4.js" in [r["path"] for r in srv.requests], (
        "the chunk was named only inside the bundle and was never fetched")
    bodies = "".join(p.read_text() for p in (tmp_path / "js").glob("*.js"))
    assert "sk_live_" in bodies, "the chunk's contents never reached evidence"


def test_a_chunk_outside_the_allowlist_is_refused(tmp_path):
    """A bundle can name any host it likes; scope still decides.

    This is why chunks.candidates() returns candidates instead of fetching:
    every one goes through the same ctx.scope.allows() that records refusals.
    """
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        if path == "/app.js":
            return "ok", 'import("https://evil.example/assets/x-a1b2c3d4.js")'
        return "ok", "var x=1;"

    with _RecordingServer(routes) as srv:
        ctx = _scoped_ctx(tmp_path, "localhost")
        records = m.fetch_js(ctx, [f"http://localhost:{srv.port}/app.js"],
                             tmp_path / "js")

    assert not any("evil.example" in r["path"] for r in srv.requests)
    refused = [r for r in records if r["status"] == "refused-by-scope"]
    assert any("evil.example" in r["url"] for r in refused), (
        "an out-of-scope chunk must be RECORDED as refused, not just dropped")


def test_chunk_discovery_does_not_loop_on_a_self_referencing_bundle(tmp_path):
    """A bundle that names itself must not be fetched twice."""
    import sweeper.stages.jsrecon as m

    def routes(path, port):
        return "ok", 'import("./app-11111111.js")'

    with _RecordingServer(routes) as srv:
        ctx = _scoped_ctx(tmp_path, "localhost")
        m.fetch_js(ctx, [f"http://localhost:{srv.port}/app-11111111.js"],
                   tmp_path / "js")

    paths = [r["path"] for r in srv.requests]
    assert len(paths) == len(set(paths)), f"refetched: {paths}"
