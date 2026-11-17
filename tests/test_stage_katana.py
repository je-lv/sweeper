from pathlib import Path
from urllib.parse import urlsplit

import pytest

from sweeper import binaries, preflight
from sweeper.artifacts import ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.katana import KatanaStage

FIX = Path(__file__).parent / "fixtures" / "katana.jsonl"


def ctx_for(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)
    )


def test_contract():
    assert registry.validate(KatanaStage()) == []


def test_form_submission_only_at_full():
    s = KatanaStage()
    assert "-aff" not in s.levels["mid"]
    assert "-aff" not in s.levels["high"]
    assert "-aff" in s.levels["full"]


def test_js_parsing_enabled_from_mid():
    s = KatanaStage()
    assert "-jc" in s.levels["mid"] and "-jsl" in s.levels["mid"]
    assert s.levels["low"] == []


def test_mid_is_shallow_and_high_is_deeper():
    s = KatanaStage()
    assert "1" in s.levels["mid"]
    assert "3" in s.levels["high"]


def test_endpoints_parsed():
    vals = [a.value for a in KatanaStage().parse(FIX)]
    assert "https://acc.example/search?q=shoes&cat=3" in vals


def test_content_type_recorded():
    a = next(a for a in KatanaStage().parse(FIX) if a.value.endswith("app.bundle.js"))
    assert "javascript" in a.meta["content_type"]


def test_parameterised_urls_flagged_for_dast():
    a = next(a for a in KatanaStage().parse(FIX) if "?" in a.value)
    assert a.meta["has_params"] is True


def test_auth_configured_uses_a_header_file_not_literal_argv(tmp_path):
    # katana's -H accepts a FILE of "header: value" lines (verified against
    # `katana -h`). Redaction (Task 3.5) protects sweep.log/run.json, but
    # only a header FILE keeps the live value out of argv entirely, which
    # is what `ps` shows to any local user.
    from sweeper.auth import SecretBundle
    from sweeper.context import RunConfig, RunContext
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    # auth_mode="auth": ctx.auth carries credentials only on an
    # authenticated run (see context.AuthModeViolation).
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      auth_mode="auth"))
    ctx.auth = SecretBundle(headers={"Authorization": "Bearer testtoken123"})

    cmd = KatanaStage().build_command(ctx)

    assert "testtoken123" not in " ".join(cmd), \
        "live credential value leaked into argv"
    h_indexes = [i for i, a in enumerate(cmd) if a == "-H"]
    header_file = Path(cmd[h_indexes[-1] + 1])
    assert header_file.is_file()
    assert "Authorization: Bearer testtoken123" in header_file.read_text()
    assert (header_file.stat().st_mode & 0o777) == 0o600


def test_no_auth_configured_no_header_file(tmp_path):
    from sweeper.context import RunConfig, RunContext
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    cmd = KatanaStage().build_command(ctx)
    assert cmd.count("-H") == 1   # only the User-Agent header


# --- Task 6 additions beyond the brief -------------------------------------

def test_host_meta_set_for_admission_control():
    """runner.py's admission choke point (_meta_host_or_value) scope-checks
    meta["host"], not the URL string, for every HTTP_SERVICE artifact.
    Without this, a discovered off-host URL (cdn.other.example in the
    fixture) would still normalize correctly via the value fallback, but
    every producer in this codebase sets meta["host"] explicitly (httpx,
    vhost) and this stage must not be the exception.
    """
    arts = list(KatanaStage().parse(FIX))
    by_value = {a.value: a for a in arts}
    assert by_value["https://acc.example/"].meta["host"] == "acc.example"
    assert (by_value["https://cdn.other.example/lib.js"].meta["host"]
            == "cdn.other.example")


def test_produces_declaration_matches_what_parse_actually_yields():
    stage = KatanaStage()
    emitted = {a.kind for a in stage.parse(FIX)}
    assert emitted == stage.produces


def test_every_running_level_caps_concurrency_and_rate():
    """katana's own default rate-limit (150/s) is not unbounded the way
    ffuf's -rate-0-default is, but every level that adds crawl behaviour
    beyond the bare defaults must still carry an explicit, bounded cap --
    same convention as naabu's -rate and vhost's -t/-rate, for the same
    no-DoS rules-of-engagement term.
    """
    stage = KatanaStage()
    for level in LEVELS:
        args = stage.levels[level]
        if not args:
            continue   # "low" -- bare katana defaults, see module docstring
        assert "-c" in args and "-rl" in args, f"{level}: no concurrency/rate cap"
        concurrency = int(args[args.index("-c") + 1])
        rate = int(args[args.index("-rl") + 1])
        assert 0 < concurrency <= 20, f"{level}: -c {concurrency} unbounded"
        assert 0 < rate <= 50, f"{level}: -rl {rate} unbounded"


def test_full_throttles_harder_than_high_because_form_submission_mutates_state():
    """`full` submits forms (-aff): every request there can place an order
    or apply a coupon, a real-world side effect, not just network load --
    so its rate is deliberately LOWER than high's, the opposite of naabu's/
    vhost's escalation.
    """
    stage = KatanaStage()
    high_rate = int(stage.levels["high"][stage.levels["high"].index("-rl") + 1])
    full_rate = int(stage.levels["full"][stage.levels["full"].index("-rl") + 1])
    assert full_rate < high_rate


def test_no_mutation_flags_below_full():
    """Only `full` may mutate request parameters. -aff is katana's only
    state-mutating flag; nothing at low/mid/high may enable it.
    """
    stage = KatanaStage()
    for level in ("low", "mid", "high"):
        assert "-aff" not in stage.levels[level]


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("katana") is None,
                    reason="katana not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    """Ask katana itself whether each level's flag set parses.

    Matches preflight's real calling shape: it validates every stage's
    build_command() before httpx has produced any HTTP_SERVICE artifacts,
    so an empty -list input file is exactly what a real preflight run
    probes here.
    """
    ctx = ctx_for(tmp_path, level=level)
    err = preflight.validate_arguments(KatanaStage(), ctx)
    assert err == "", f"katana rejected the {level!r} flag set: {err}"


def test_no_real_target_survives_preflight_substitution(tmp_path):
    """Re-check of the preflight target-leak guard against katana's REAL
    build_command. The -list file path is substituted by shape (it ends in
    .txt); this confirms the substituted probe argv is actually clean of
    "acc.example" by CONTENT, not just by assumption.
    """
    ctx = ctx_for(tmp_path)
    cmd = KatanaStage().build_command(ctx)
    probe = []
    for arg in cmd:
        if arg.startswith(("http://", "https://")):
            probe.append("http://" + preflight.DEAD_ENDPOINT)
        elif arg.endswith(".txt"):
            probe.append("SUBSTITUTED.txt")
        else:
            probe.append(arg)
    leak = preflight._find_leak(
        probe,
        safe_values={"http://" + preflight.DEAD_ENDPOINT, "SUBSTITUTED.txt"},
        targets=preflight._real_targets(ctx),
    )
    assert leak is None, f"real target leaked into probe argv: {leak}"


# --- discovered URLs and the admission choke point --------------------------
# Drives the REAL runner rather than re-implementing its admission logic in
# the test: mirroring runner.py's per-kind host extraction here is exactly
# how a test keeps passing after the thing it checks has drifted.

class _StubbedKatana(KatanaStage):
    """KatanaStage with the real crawl replaced by canned JSONL output.

    Everything downstream -- stdout capture, parse(), admission control,
    discovery-refusal accounting -- is the real code path.
    """

    def build_command(self, ctx):
        return ["/bin/cat", str(FIX)]


def _run_with(tmp_path, allow: str):
    from sweeper.runner import run_stages
    from sweeper.artifacts import Artifact
    t = tmp_path / "targets.txt"
    t.write_text(allow + "\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/",
                           meta={"host": "acc.example"}))
    [result] = run_stages(ctx, [_StubbedKatana()])
    return ctx, result


def test_out_of_scope_crawl_discovery_is_refused_by_the_choke_point(tmp_path):
    """A crawl following an offsite <script src> must not silently start
    scanning that host: cdn.other.example (in the fixture) is not in the
    allowlist, so it is surfaced and counted but never admitted to the pool.
    """
    ctx, result = _run_with(tmp_path, allow="acc.example")

    assert "https://cdn.other.example/lib.js" not in ctx.store.values(
        ArtifactKind.HTTP_SERVICE
    )
    assert any(d["host"] == "cdn.other.example" and d["stage"] == "katana"
               for d in ctx.scope.discoveries_refused)
    assert ctx.scope.refusals == []


def test_in_scope_crawl_discovery_is_admitted_with_correct_host(tmp_path):
    ctx, result = _run_with(tmp_path, allow="acc.example")

    admitted = ctx.store.values(ArtifactKind.HTTP_SERVICE)
    assert "https://acc.example/search?q=shoes&cat=3" in admitted
    art = next(a for a in ctx.store.get(ArtifactKind.HTTP_SERVICE)
               if a.value == "https://acc.example/search?q=shoes&cat=3")
    assert art.meta["host"] == "acc.example"
    # Three fixture rows are in scope, but the seed service is the same root
    # URL as one of them. StageResult counts newly stored inventory records,
    # not duplicate emissions that ArtifactStore correctly deduplicates.
    assert result.artifacts == 2


# --- malformed-URL robustness (review round 1) ------------------------------

MALFORMED_JSONL = (
    '{"request":{"method":"GET","endpoint":"https://acc.example/first"},'
    '"response":{"status_code":200,"headers":{"Content-Type":"text/html"}}}\n'
    # Malformed authority: urlsplit(...).hostname raises "Invalid IPv6 URL".
    '{"request":{"method":"GET","endpoint":"https://[::1/x"},'
    '"response":{"status_code":200,"headers":{"Content-Type":"text/html"}}}\n'
    '{"request":{"method":"GET","endpoint":"https://acc.example/last"},'
    '"response":{"status_code":200,"headers":{"Content-Type":"text/html"}}}\n'
)


def test_malformed_url_does_not_discard_the_rest_of_the_crawl(tmp_path):
    """A bare urlsplit().hostname raises ValueError on "https://[::1/x".
    parse() is a generator consumed inside runner.py's broad try/except, so
    an escaping exception does NOT skip one row the way the adjacent
    `except json.JSONDecodeError: continue` does -- it terminates the whole
    generator and every artifact from every LATER line is lost, surfacing
    only as a generic PARSE_ERROR. The row after the bad one is what proves
    this.
    """
    raw = tmp_path / "katana.jsonl"
    raw.write_text(MALFORMED_JSONL, encoding="utf-8")
    vals = [a.value for a in KatanaStage().parse(raw)]
    assert "https://acc.example/first" in vals
    assert "https://acc.example/last" in vals, \
        "rows after a malformed URL were discarded"


def test_malformed_url_fails_closed_and_is_recorded_not_silently_dropped(tmp_path):
    """It must not be admitted (no scope bypass), and it must not vanish:
    the runner's admission control records it in discoveries_refused naming
    the offending value, and logs it.
    """
    from sweeper.runner import run_stages
    from sweeper.artifacts import Artifact

    raw_fixture = tmp_path / "canned.jsonl"
    raw_fixture.write_text(MALFORMED_JSONL, encoding="utf-8")

    class _Stubbed(KatanaStage):
        def build_command(self, ctx):
            return ["/bin/cat", str(raw_fixture)]

    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/",
                           meta={"host": "acc.example"}))
    [result] = run_stages(ctx, [_Stubbed()])

    # Fails closed: never admitted.
    assert "https://[::1/x" not in ctx.store.values(ArtifactKind.HTTP_SERVICE)
    # Recorded, naming the offending value.
    assert any(d["value"] == "https://[::1/x"
               for d in ctx.scope.discoveries_refused)
    # And the run is NOT a generic parse failure -- the good rows landed.
    assert result.status == "complete"
    assert result.artifacts == 2


def test_host_meta_uses_scope_normalize_so_a_masquerade_cannot_bypass():
    """meta["host"] must be what scope.normalize() says, not a hand-parsed
    authority: "acc.example:80@evil.test" addresses evil.test. Reusing
    normalize() is what keeps this stage and the choke point from drifting.
    """
    raw = "https://acc.example:80@evil.test/x"
    from sweeper.scope import normalize
    import json as _json
    from pathlib import Path as _Path
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = _Path(d) / "k.jsonl"
        p.write_text(_json.dumps(
            {"request": {"method": "GET", "endpoint": raw},
             "response": {"status_code": 200, "headers": {}}}) + "\n",
            encoding="utf-8")
        [art] = list(KatanaStage().parse(p))
    assert art.meta["host"] == normalize(raw) == "evil.test"


# --- crawl scope: katana's default -field-scope rdn is broader than the
# --- ScopeGuard, and the choke point only discards RESULTS (finding B1) -----

import re as _re
import socket as _socket
import socketserver as _socketserver
import struct as _struct
import subprocess as _subprocess
import threading as _threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from sweeper.scope import ScopeGuard, normalize
from sweeper.stages.katana import NEVER_MATCHES, crawl_scope_regexes


def _scope_arg(cmd):
    """The -cs value in a built command, or None."""
    return cmd[cmd.index("-cs") + 1] if "-cs" in cmd else None


def _matches(allowed, url):
    return any(_re.search(rx, url) for rx in crawl_scope_regexes(allowed))


@pytest.mark.parametrize("level", LEVELS)
def test_crawl_scope_is_constrained_at_every_level(tmp_path, level):
    """Not in self.levels, on purpose: `low` carries no level flags at all,
    so a scope restriction expressed there would be missing from exactly the
    level most likely to be pointed at an unfamiliar estate.
    """
    ctx = ctx_for(tmp_path, level=level)
    cmd = KatanaStage().build_command(ctx)
    scope_file = _scope_arg(cmd)
    assert scope_file is not None, f"{level}: no -cs crawl-scope constraint"
    assert Path(scope_file).read_text().strip(), f"{level}: empty scope file"


def test_scope_file_is_derived_from_the_allowlist_not_the_seed(tmp_path):
    """The whole point of B1: the crawl boundary must come from
    ctx.scope.allowed, the same source the seed list is filtered against --
    not from katana's own idea of the seed's registrable domain.
    """
    ctx = ctx_for(tmp_path)
    ctx.scope.allowed = {"shop.acc.example", "*.other.example"}
    written = Path(_scope_arg(KatanaStage().build_command(ctx))).read_text()
    assert written.splitlines() == crawl_scope_regexes(ctx.scope.allowed)


def test_crawl_scope_agrees_with_the_scope_guard_host_for_host():
    """Property, not an enumeration of flags: for every allowlist and every
    hostname, a URL is inside the crawl scope iff ScopeGuard permits the
    host it addresses. Any disagreement is either unauthorized traffic (the
    regex is broader) or lost coverage (narrower).
    """
    allowlists = [
        {"acc.example"},
        {"*.acc.example"},
        {"shop.acc.example"},
        {"acc.example", "*.b.example"},
        {"*.dev.acc.example"},
    ]
    hosts = [
        "acc.example", "shop.acc.example", "internal-admin.acc.example",
        "a.b.acc.example", "dev.acc.example", "x.dev.acc.example",
        "notacc.example", "acc.example.evil.test", "ACC.EXAMPLE",
        "acc.example.", "b.example", "x.b.example", "evil.test",
    ]
    for allow in allowlists:
        guard = ScopeGuard(set(allow))
        for host in hosts:
            for url in (f"http://{host}/", f"https://{host}:8443/a/b?c=1",
                        f"http://{host}:80/x#frag"):
                assert _matches(guard.allowed, url) is \
                    guard.permits_discovery(normalize(url)), \
                    f"{allow} vs {url}"


@pytest.mark.parametrize("url", [
    # -cs matches against the whole URL string, so every one of these puts an
    # in-scope hostname somewhere in a URL that ADDRESSES a different host.
    # scope.normalize() reads each of them as evil.test; so must the crawl.
    "http://acc.example@evil.test/",
    "http://acc.example:80@evil.test/",
    "http://user.acc.example@evil.test/",
    "http://evil.test/?next=http://acc.example/",
    "http://evil.test/acc.example",
    "http://evil.test/#http://acc.example",
    # These three matter most, and are the ones a lazier host pattern gets
    # wrong: the in-scope name sits after a DOT, so a subdomain wildcard
    # written with "." or "[^/]" instead of a label character class matches
    # right across the "/" or "?" and out of the authority. Each of these
    # addresses evil.test and each was confirmed to slip through a
    # dot-permissive class.
    "http://evil.test/a.acc.example",
    "http://evil.test/?x=y.acc.example",
    "http://evil.test/#z.acc.example",
    # ...and the target used as an attacker-chosen SUBDOMAIN label, which
    # does address a host containing the target text but is not the target.
    "http://acc.example.evil.test/",
])
def test_a_hostname_outside_the_authority_does_not_widen_the_crawl(url):
    guard = ScopeGuard({"acc.example", "*.acc.example"})
    assert normalize(url).endswith("evil.test")
    assert not guard.permits_discovery(normalize(url))
    assert not _matches(guard.allowed, url), f"crawl-scope bypass via {url}"


def test_wildcard_entry_widens_the_crawl_and_a_bare_entry_does_not():
    bare = crawl_scope_regexes(ScopeGuard({"acc.example"}).allowed)
    wild = crawl_scope_regexes(ScopeGuard({"*.acc.example"}).allowed)
    sub = "https://shop.acc.example/cart"
    assert not any(_re.search(r, sub) for r in bare)
    assert any(_re.search(r, sub) for r in wild)
    # ...and the wildcard still stops at its own base.
    assert not any(_re.search(r, "https://acc.example.evil.test/") for r in wild)


def test_ipv6_target_is_bracketed_so_it_is_not_silently_out_of_scope():
    """scope.normalize() stores "::1" unbracketed; the URL katana matches
    renders it "http://[::1]:8080/". Without reconciling the two, every IPv6
    target falls out of the crawl scope and only the seed is ever fetched.
    """
    allowed = ScopeGuard({"[::1]:8080"}).allowed
    assert allowed == {"::1"}
    assert _matches(allowed, "http://[::1]:8080/app")
    assert not _matches(allowed, "http://[::2]:8080/app")


def test_empty_allowlist_fails_closed_rather_than_writing_an_empty_file(tmp_path):
    """Measured on katana v1.6.1: an EMPTY -cs file supplies no in-scope
    constraint at all and the crawl falls back to the rdn default -- the
    fail-open direction. A never-matching regex is what keeps an empty
    allowlist from widening the crawl instead of closing it.
    """
    assert crawl_scope_regexes(set()) == [NEVER_MATCHES]
    assert not _matches(set(), "http://acc.example/")
    # and it is a regex the engine accepts, not a parse error
    assert _re.compile(NEVER_MATCHES).search("anything") is None


def test_no_generated_regex_contains_a_comma():
    """-cs is a comma-separated goflags slice: a comma inside a regex splits
    it into two fragments, each invalid. An invalid -cs regex does not make
    katana exit non-zero -- it makes katana crawl NOTHING, silently, with
    status 0, which preflight cannot detect. So the generated form must not
    contain one.
    """
    allowed = ScopeGuard({"acc.example", "*.b.example", "[::1]:8080"}).allowed
    for rx in crawl_scope_regexes(allowed) + [NEVER_MATCHES]:
        assert "," not in rx, rx


def test_scope_regexes_reach_katana_through_a_file_not_argv(tmp_path):
    """They are built from the allowlist, so inline they would put every
    target hostname in argv, where `ps` shows it to any local user and where
    preflight's substitution does not reach.

    Note that preflight.TargetLeakInProbe would NOT have caught that: it
    searches for the target as a literal, and a regex-escaped hostname
    ("acc\\.example") does not contain it. The guard failing to object is
    precisely why the file form is the one to use rather than relying on it.
    """
    ctx = ctx_for(tmp_path)
    cmd = KatanaStage().build_command(ctx)
    scope_file = _scope_arg(cmd)
    assert scope_file.endswith(".txt")
    assert _re.escape("acc.example") in Path(scope_file).read_text()
    leak = preflight._find_leak(
        [a for a in cmd if not a.endswith(".txt")],
        safe_values=set(), targets=preflight._real_targets(ctx),
    )
    assert leak is None, f"target reached katana argv outside a file: {leak}"


# --- real binary, two local vhosts -----------------------------------------
# A flag-string assertion cannot tell you katana honours the flag. These drive
# the real katana v1.6.1 against two hostnames that share a registrable domain
# and resolve to one local server, and watch what the server is actually
# asked for.

_SEED_HOST = "shop.acc.example"
_SIBLING_HOST = "internal-admin.acc.example"


class _Recorder(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        self.server.hits.append(host)
        port = self.server.server_address[1]
        body = (f'<html><body>'
                f'<a href="http://{_SIBLING_HOST}:{port}/admin">x</a>'
                f'<a href="http://{_SEED_HOST}:{port}/page2">y</a>'
                f'</body></html>').encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _WildcardDNS(_socketserver.BaseRequestHandler):
    """Answers every A query with 127.0.0.1 so the two vhost names resolve
    without touching /etc/hosts or the network. NOERROR/no-answer for
    anything else (AAAA), which is what makes the client fall back to A.
    """

    def handle(self):
        data, sock = self.request
        try:
            off = 12
            while data[off]:
                off += data[off] + 1
            off += 1
            qtype = _struct.unpack("!H", data[off:off + 2])[0]
            off += 4
            answer = (b"\xc0\x0c" + _struct.pack("!HHIH", 1, 1, 60, 4)
                      + _socket.inet_aton("127.0.0.1")) if qtype == 1 else b""
            sock.sendto(
                data[:2] + _struct.pack("!HHHHH", 0x8180, 1, 1 if answer else 0,
                                        0, 0) + data[12:off] + answer,
                self.client_address)
        except Exception:       # a malformed query must not kill the fixture
            pass


_OFFDOMAIN_HOST = "evil.test"


class _RedirectRecorder(BaseHTTPRequestHandler):
    """Seed page links to three redirectors: one 302 to a sibling under the
    same registrable domain, one to an unrelated registrable domain, and one
    back to the seed host itself. The third is the control for the COST of
    -dr -- it is the ordinary, wanted redirect that must not be lost.
    """
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        self.server.hits.append(host)
        port = self.server.server_address[1]
        routes = {
            "/to-sibling": f"http://{_SIBLING_HOST}:{port}/PWNED",
            "/to-offdomain": f"http://{_OFFDOMAIN_HOST}:{port}/PWNED2",
            "/to-samehost": f"http://{_SEED_HOST}:{port}/landed-samehost",
        }
        if self.path in routes:
            self._redirect(routes[self.path])
            return
        body = ("<html><body>" + "".join(
            f'<a href="http://{_SEED_HOST}:{port}{p}">x</a>' for p in routes
        ) + "</body></html>").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _VhostLab:
    handler = _Recorder

    def __enter__(self):
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.http.hits = []
        self.dns = _socketserver.ThreadingUDPServer(("127.0.0.1", 0), _WildcardDNS)
        for srv in (self.http, self.dns):
            t = _threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
        self.http_port = self.http.server_address[1]
        self.dns_port = self.dns.server_address[1]
        return self

    def __exit__(self, *exc):
        for srv in (self.http, self.dns):
            srv.shutdown()
            srv.server_close()

    def crawl(self, cmd):
        """Run a katana argv against this lab; return the hosts it asked for."""
        self.http.hits.clear()
        _subprocess.run(cmd + ["-r", f"127.0.0.1:{self.dns_port}", "-duc"],
                        capture_output=True, text=True, timeout=180)
        return sorted(set(self.http.hits))


class _RedirectLab(_VhostLab):
    """Same wildcard-DNS lab, but the pages 302 instead of linking."""
    handler = _RedirectRecorder


def _sequential(cmd):
    """The same argv with katana's concurrency pinned to one worker.

    NOT a workaround for a flaky test -- a fix for one that could pass
    without proving anything. The redirect fixture serves THREE redirector
    pages, and at the real `-c 8` katana races them: measured over six
    control runs, one crossing or the other was missing from two of them.
    That intermittency ran both ways. The control half went red ~65% of the
    time, which is how it was noticed; the SAFETY half was quietly weakened
    by exactly the same race, because "the off-domain host was not
    contacted" proves nothing in a run where katana never got round to
    fetching the page that redirects there. A green safety assertion was
    therefore worth about 80% of a green safety assertion.

    At `-c 1` the crawl is sequential and visits every link every time: 4/4
    control runs reached all three hosts, and the fixture stops being able
    to hide a regression by accident.

    Concurrency is not the property under test -- `-dr` is, and the
    assertion that the REAL command carries it is made against the
    unmodified argv before this is applied.
    """
    out = list(cmd)
    if "-c" in out:
        out[out.index("-c") + 1] = "1"
    return out


def _lab_ctx(tmp_path, lab, allow):
    from sweeper.artifacts import Artifact
    t = tmp_path / "targets.txt"
    t.write_text(allow + "\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      level="high"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                           f"http://{_SEED_HOST}:{lab.http_port}/",
                           meta={"host": _SEED_HOST}))
    return ctx


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("katana") is None,
                    reason="katana not installed; cannot drive the real binary")
def test_real_crawl_does_not_touch_a_sibling_host_under_the_same_domain(tmp_path):
    """B1, end to end against katana v1.6.1.

    internal-admin.acc.example shares a registrable domain with the seed, so
    katana's own -field-scope rdn default crawls it. The runner's admission
    choke point discards that discovery -- but only after the GET has been
    sent, which is the unauthorized traffic the rules of engagement forbid.

    The second half is the control, and it is what stops this test from
    being one that cannot fail: with the -cs argument stripped from the very
    same command, against the very same fixture, the sibling IS contacted.
    If the fixture ever stopped exercising the crossing, that half goes red.
    """
    with _VhostLab() as lab:
        cmd = KatanaStage().build_command(_lab_ctx(tmp_path, lab, "shop.acc.example"))
        assert "-cs" in cmd

        scoped = lab.crawl(cmd)
        assert _SEED_HOST in scoped, \
            "the seed itself was never crawled -- the scope regex was rejected"
        assert _SIBLING_HOST not in scoped, \
            f"live request to an unauthorized sibling host: {scoped}"

        i = cmd.index("-cs")
        unscoped = lab.crawl(cmd[:i] + cmd[i + 2:])
        assert _SIBLING_HOST in unscoped, \
            ("control failed: without -cs the fixture did not reach the "
             f"sibling either, so it proves nothing. hosts={unscoped}")


# --- N1(a): redirects are outside every scope flag katana has ---------------
# Measured against v1.6.1: with -cs pinned to the seed host, a 302 was still
# followed to a sibling AND to an unrelated registrable domain, so the hop
# escapes katana's own rdn default too. -cos, -fs and -e are not consulted on
# it either. -dr is the only control that closes it, so it is on at every
# level and parse() re-derives the destination from the recorded Location.

from sweeper.stages.katana import _redirect_target


@pytest.mark.parametrize("level", LEVELS)
def test_redirects_are_disabled_at_every_level(tmp_path, level):
    """Not in self.levels for the same reason -cs is not: `low` carries no
    level flags at all, and a redirect is a scope escape at every level.
    """
    ctx = ctx_for(tmp_path, level=level)
    assert "-dr" in KatanaStage().build_command(ctx), \
        f"{level}: redirects not disabled — a 302 escapes the allowlist"


def _redirect_row(endpoint, status, location, extra_headers=None):
    import json as _json
    headers = dict(extra_headers or {})
    if location is not None:
        headers["Location"] = location
    return _json.dumps({"request": {"method": "GET", "endpoint": endpoint},
                        "response": {"status_code": status,
                                     "headers": headers}}) + "\n"


def _parse_text(tmp_path, text, name="k.jsonl"):
    raw = tmp_path / name
    raw.write_text(text, encoding="utf-8")
    return list(KatanaStage().parse(raw))


def test_recorded_redirect_destination_is_yielded_as_a_discovery(tmp_path):
    """-dr stops katana walking the hop; this is what stops that costing
    coverage. The destination becomes an ordinary discovery so the admission
    choke point -- which, unlike katana, fails closed -- decides on it.
    """
    arts = _parse_text(tmp_path, _redirect_row(
        "https://acc.example/login", 302, "https://acc.example/dashboard"))
    vals = [a.value for a in arts]
    assert "https://acc.example/dashboard" in vals
    dest = next(a for a in arts if a.value.endswith("/dashboard"))
    assert dest.meta["host"] == "acc.example"
    assert dest.meta["discovered_via"] == "redirect"
    assert dest.meta["redirect_from"] == "https://acc.example/login"
    # Never fetched, so no response facts may be claimed for it.
    assert dest.meta["status_code"] == 0
    assert dest.meta["content_type"] == ""


def test_relative_location_is_resolved_against_the_request_url(tmp_path):
    """`Location: /dashboard` is the common form. Yielding it unresolved
    would produce a hostless value the choke point cannot scope-check.
    """
    arts = _parse_text(tmp_path, _redirect_row(
        "https://acc.example/a/b/login", 302, "/dashboard"))
    assert "https://acc.example/dashboard" in [a.value for a in arts]


@pytest.mark.parametrize("location,why", [
    ("mailto:ops@acc.example", "mailto is not an HTTP service"),
    ("javascript:alert(1)", "javascript is not an HTTP service"),
    ("tel:+15551234", "tel is not an HTTP service"),
])
def test_a_non_http_location_is_not_typed_as_an_http_service(tmp_path, location, why):
    arts = _parse_text(tmp_path, _redirect_row(
        "https://acc.example/x", 302, location))
    assert [a.value for a in arts] == ["https://acc.example/x"], why


def test_a_location_on_a_non_redirect_status_invents_no_traffic(tmp_path):
    """A `Location` on a 200 is not a hop any client would have taken;
    treating it as one puts a URL in the evidence trail the crawl never
    implied.
    """
    arts = _parse_text(tmp_path, _redirect_row(
        "https://acc.example/x", 200, "https://acc.example/elsewhere"))
    assert [a.value for a in arts] == ["https://acc.example/x"]


def test_a_self_redirect_does_not_duplicate_the_row(tmp_path):
    arts = _parse_text(tmp_path, _redirect_row(
        "https://acc.example/x", 302, "https://acc.example/x"))
    assert [a.value for a in arts] == ["https://acc.example/x"]


def test_location_header_is_read_case_insensitively(tmp_path):
    import json as _json
    text = _json.dumps({"request": {"method": "GET",
                                    "endpoint": "https://acc.example/x"},
                        "response": {"status_code": 301,
                                     "headers": {"location":
                                                 "https://acc.example/y"}}}) + "\n"
    assert "https://acc.example/y" in [a.value for a in _parse_text(tmp_path, text)]


def test_content_type_is_also_read_case_insensitively(tmp_path):
    import json as _json
    text = _json.dumps({"request": {"method": "GET",
                                    "endpoint": "https://acc.example/a.js"},
                        "response": {"status_code": 200,
                                     "headers": {"cOnTeNt-TyPe":
                                                 "application/javascript"}}}) + "\n"
    [art] = _parse_text(tmp_path, text)
    assert art.meta["content_type"] == "application/javascript"


def test_a_malformed_location_does_not_discard_the_rest_of_the_crawl(tmp_path):
    """urljoin raises ValueError on a malformed authority exactly as urlsplit
    does, and parse() is a generator: an escaping exception loses every LATER
    row, not just this one.
    """
    text = (_redirect_row("https://acc.example/first", 302, "//[::1/x")
            + _redirect_row("https://acc.example/last", 200, None))
    vals = [a.value for a in _parse_text(tmp_path, text)]
    assert "https://acc.example/first" in vals
    assert "https://acc.example/last" in vals, \
        "a malformed Location discarded the rest of the crawl"


def test_offscope_redirect_destination_is_refused_by_the_choke_point(tmp_path):
    """The whole point of N1(a), through the REAL runner: katana would have
    fetched this host outright. Now it is refused, counted and named instead.
    """
    from sweeper.runner import run_stages
    from sweeper.artifacts import Artifact

    raw_fixture = tmp_path / "canned.jsonl"
    raw_fixture.write_text(
        _redirect_row("https://acc.example/go", 302, "https://evil.test/PWNED")
        + _redirect_row("https://acc.example/in", 302, "https://acc.example/ok"),
        encoding="utf-8")

    class _Stubbed(KatanaStage):
        def build_command(self, ctx):
            return ["/bin/cat", str(raw_fixture)]

    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/",
                           meta={"host": "acc.example"}))
    [result] = run_stages(ctx, [_Stubbed()])

    admitted = ctx.store.values(ArtifactKind.HTTP_SERVICE)
    assert "https://evil.test/PWNED" not in admitted
    assert any(d["host"] == "evil.test" and d["stage"] == "katana"
               for d in ctx.scope.discoveries_refused)
    # ...and the in-scope destination is not lost to the same rule.
    assert "https://acc.example/ok" in admitted
    assert result.status == "complete"


def test_redirect_target_helper_rejects_every_non_followable_shape():
    """Property over enumeration: whatever comes back is either "" or an
    absolute http(s) URL that differs from the request.
    """
    endpoint = "https://acc.example/x"
    cases = [
        (200, "https://acc.example/y"), (204, "/y"), (404, "/y"),
        (302, ""), (302, None), (301, "mailto:a@b.c"), (302, "ftp://acc.example/"),
        (302, "https://acc.example/x"), (399, "/y"), (300, "/y"),
    ]
    for status, location in cases:
        out = _redirect_target(endpoint, {
            "status_code": status,
            "headers": {} if location is None else {"Location": location}})
        assert out == "" or (
            urlsplit(out).scheme in ("http", "https") and out != endpoint), \
            f"{status} {location!r} -> {out!r}"


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("katana") is None,
                    reason="katana not installed; cannot drive the real binary")
def test_real_crawl_does_not_follow_a_redirect_off_the_allowlist(tmp_path):
    """N1(a) end to end against katana v1.6.1.

    The lab 302s to a sibling under the same registrable domain AND to an
    unrelated one. -cs bounds which URLs katana CRAWLS but is not consulted
    on a redirect hop, so both were being fetched -- the second is outside
    even katana's own rdn default.

    The control half is what stops this being a test that cannot fail: with
    -dr stripped from the very same command against the very same fixture,
    both hosts ARE contacted.
    """
    with _RedirectLab() as lab:
        cmd = KatanaStage().build_command(_lab_ctx(tmp_path, lab, "shop.acc.example"))
        assert "-dr" in cmd
        cmd = _sequential(cmd)

        scoped = lab.crawl(cmd)
        assert _SEED_HOST in scoped, \
            "the seed itself was never crawled -- the flag set was rejected"
        assert _SIBLING_HOST not in scoped, \
            f"302 followed to an unauthorized sibling host: {scoped}"
        assert _OFFDOMAIN_HOST not in scoped, \
            f"302 followed to an unrelated registrable domain: {scoped}"

        i = cmd.index("-dr")
        unscoped = lab.crawl(cmd[:i] + cmd[i + 1:])
        assert _SIBLING_HOST in unscoped and _OFFDOMAIN_HOST in unscoped, \
            ("control failed: without -dr the fixture did not cross either, "
             f"so it proves nothing. hosts={unscoped}")


@pytest.mark.parametrize("level", LEVELS)
def test_duplicate_content_filter_is_disabled_at_every_level(tmp_path, level):
    """-duf is what makes -dr's readback work. katana's dedupe drops the
    `response` object -- and with it the Location -- from every page whose
    body matches one already seen, and redirect bodies are empty, so without
    this only the first 302 of a crawl yields a destination.
    """
    assert "-duf" in KatanaStage().build_command(ctx_for(tmp_path, level=level))


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("katana") is None,
                    reason="katana not installed; cannot drive the real binary")
def test_real_duf_is_what_makes_redirect_readback_reliable(tmp_path):
    """The measurement -duf rests on, kept as a test because it is entirely
    non-obvious and a future flag tidy-up would otherwise silently drop it.

    Three endpoints 302 with identical (empty) bodies. With katana's default
    dedupe, all but one arrive with no response and therefore no Location.
    Both halves drive the real binary, so if katana ever changes this
    behaviour the test says so instead of quietly over-reporting.
    """
    with _RedirectLab() as lab:
        ctx = _lab_ctx(tmp_path, lab, "*.acc.example")
        cmd = KatanaStage().build_command(ctx)
        assert "-duf" in cmd

        with_duf = tmp_path / "with.jsonl"
        lab.crawl(cmd + ["-o", str(with_duf)])
        got = {a.value for a in KatanaStage().parse(with_duf)
               if a.meta.get("discovered_via") == "redirect"}

        i = cmd.index("-duf")
        without = tmp_path / "without.jsonl"
        lab.crawl(cmd[:i] + cmd[i + 1:] + ["-o", str(without)])
        fewer = {a.value for a in KatanaStage().parse(without)
                 if a.meta.get("discovered_via") == "redirect"}

        assert len(got) == 3, f"-duf did not recover every destination: {got}"
        assert len(fewer) < len(got), (
            "control failed: the default dedupe did not suppress any "
            f"redirect response, so -duf is unmotivated. got={fewer}")


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("katana") is None,
                    reason="katana not installed; cannot drive the real binary")
def test_real_same_host_redirect_destination_survives_dr_as_a_discovery(tmp_path):
    """The stated cost of -dr, paid back. katana no longer walks the
    same-host hop, so if parse() did not read the Location back out of the
    recorded 302 the destination would be lost entirely. This drives the real
    binary and then the real parse() over its real output.
    """
    with _RedirectLab() as lab:
        ctx = _lab_ctx(tmp_path, lab, "shop.acc.example")
        out = tmp_path / "katana.jsonl"
        lab.crawl(KatanaStage().build_command(ctx) + ["-o", str(out)])

        vals = [a.value for a in KatanaStage().parse(out)]
        landed = f"http://{_SEED_HOST}:{lab.http_port}/landed-samehost"
        assert landed in vals, \
            f"same-host redirect destination lost to -dr: {vals}"
        # ...and the off-scope destinations are still surfaced for the choke
        # point to refuse, rather than quietly dropped by the parser.
        assert any(v.startswith(f"http://{_SIBLING_HOST}:") for v in vals)


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("katana") is None,
                    reason="katana not installed; cannot drive the real binary")
def test_real_output_omits_credentials_but_keeps_what_parse_reads(tmp_path):
    """N1(b) against the real binary, as an A/B on one crawl.

    raw/katana.jsonl is the evidence trail operators archive; katana echoes
    every request's raw wire bytes into it, so the Authorization and Cookie
    values that -H deliberately keeps out of argv were written back in
    cleartext. The control half runs the identical command with -or removed
    and asserts the secrets ARE present, so this cannot pass vacuously.
    """
    from sweeper.auth import SecretBundle

    with _RedirectLab() as lab:
        t = tmp_path / "targets.txt"
        t.write_text("shop.acc.example\n")
        ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                          level="high", auth_mode="auth"))
        from sweeper.artifacts import Artifact
        ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                               f"http://{_SEED_HOST}:{lab.http_port}/",
                               meta={"host": _SEED_HOST}))
        ctx.auth = SecretBundle(headers={"Authorization": "Bearer LIVETOKEN123"},
                                cookies={"session": "SECRETSESS"})
        cmd = KatanaStage().build_command(ctx)
        assert "-or" in cmd

        redacted = tmp_path / "redacted.jsonl"
        lab.crawl(cmd + ["-o", str(redacted)])
        text = redacted.read_text()
        assert "LIVETOKEN123" not in text, "bearer token in the evidence trail"
        assert "SECRETSESS" not in text, "session cookie in the evidence trail"

        # What parse() depends on must survive the redaction.
        arts = {a.value: a for a in KatanaStage().parse(redacted)}
        seed = arts[f"http://{_SEED_HOST}:{lab.http_port}/"]
        assert seed.meta["status_code"] == 200, "-or destroyed status_code"
        assert "text/html" in seed.meta["content_type"], \
            "-or destroyed response.headers"

        # Control: the same command WITHOUT -or leaks both, and yields the
        # same endpoints with the same statuses -- so -or costs nothing else.
        i = cmd.index("-or")
        leaky = tmp_path / "leaky.jsonl"
        lab.crawl(cmd[:i] + cmd[i + 1:] + ["-o", str(leaky)])
        leaked = leaky.read_text()
        assert "LIVETOKEN123" in leaked and "SECRETSESS" in leaked, \
            ("control failed: the credentials were absent even without -or, "
             "so this test proves nothing")
        control = {a.value: a for a in KatanaStage().parse(leaky)}
        assert set(control) == set(arts), "-or changed which endpoints appear"
        assert ({v: a.meta["status_code"] for v, a in control.items()}
                == {v: a.meta["status_code"] for v, a in arts.items()}), \
            "-or changed a recorded status_code"


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("katana") is None,
                    reason="katana not installed; cannot drive the real binary")
def test_real_crawl_follows_a_sibling_host_when_a_wildcard_authorizes_it(tmp_path):
    """The mirror of the test above: a "*." allowlist entry must WIDEN the
    crawl, not merely be accepted. Without this, the safe implementation is
    "never leave the seed host", which would silently under-crawl every
    engagement scoped to a whole domain.
    """
    with _VhostLab() as lab:
        cmd = KatanaStage().build_command(_lab_ctx(tmp_path, lab, "*.acc.example"))
        hosts = lab.crawl(cmd)
        assert _SEED_HOST in hosts
        assert _SIBLING_HOST in hosts, \
            f"a *. entry did not widen the crawl to a sibling host: {hosts}"
