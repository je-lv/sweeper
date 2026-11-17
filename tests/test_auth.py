import http.server
import os
import re
import stat
import subprocess
import threading
from pathlib import Path

import pytest
import yaml
from sweeper import binaries
from sweeper.auth import (DROP_HEADERS, NO_AUTHORITY_REGEX, LoginFlow,
                          SecretBundle, authority_regexes, from_burp_request,
                          to_nuclei_secret_file)

RAW = """POST /api/login HTTP/1.1
Host: acc.example
User-Agent: Mozilla/5.0
Cookie: session=abc123; csrf=zzz
Authorization: Bearer eyJhbGciOi.PAYLOAD.SIG
X-CSRF-Token: tok-42
Content-Type: application/json

{"user":"tester"}
"""


def test_burp_import_extracts_cookies(tmp_path):
    p = tmp_path / "req.txt"; p.write_text(RAW)
    b = from_burp_request(p)
    assert b.cookies["session"] == "abc123"
    assert b.cookies["csrf"] == "zzz"


def test_burp_import_extracts_authorization_and_csrf(tmp_path):
    p = tmp_path / "req.txt"; p.write_text(RAW)
    b = from_burp_request(p)
    assert b.headers["Authorization"].startswith("Bearer ")
    assert b.headers["X-CSRF-Token"] == "tok-42"


def test_burp_import_drops_hop_by_hop_and_noise_headers(tmp_path):
    p = tmp_path / "req.txt"; p.write_text(RAW)
    b = from_burp_request(p)
    for junk in ("Host", "Content-Type", "User-Agent", "Cookie"):
        assert junk not in b.headers


def test_header_args_render_for_cli():
    b = SecretBundle(headers={"Authorization": "Bearer x"},
                     cookies={"session": "abc"})
    args = b.header_args()
    assert "-H" in args
    joined = " ".join(args)
    assert "Authorization: Bearer x" in joined
    assert "Cookie: session=abc" in joined


def test_empty_bundle_yields_no_args():
    assert SecretBundle().header_args() == []


# --- the credential must actually reach the wire ---------------------------
# The previous test here asserted only that the YAML had a `headers` key, so
# it stayed green while the file matched nothing: nuclei's `domains:` list is
# literal and is matched against the request AUTHORITY, meaning the emitted
# `domains: ["*"]` never fired and every authenticated engagement scanned the
# anonymous surface while report.md printed `Auth: auth`. Only an observation
# on the wire can distinguish "a well-formed secret file" from "a secret file
# nuclei acts on", so that is what is asserted below.

PROBE_TEMPLATE = """id: sweeper-auth-probe
info:
  name: sweeper auth probe
  author: sweeper
  severity: info
  description: asserts credentials reach the request
http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: status
        status:
          - 200
"""


class _RecordingListener:
    """Captures the headers of every request nuclei actually sends.

    `address` exists so two listeners can be two different HOSTS, not two
    ports of one host. In-scope-ness is a property of the host here --
    scope.normalize() strips the port and ScopeGuard stores hostnames -- so
    a second port on 127.0.0.1 is not an out-of-scope authority and cannot
    demonstrate anything about scoping. 127.0.0.2 is loopback like 127.0.0.1
    (the whole 127/8 block is), needs no DNS and reaches no network.
    """

    def __init__(self, address: str = "127.0.0.1"):
        self.address = address
        self.requests: list[dict[str, str]] = []
        received = self.requests

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                received.append(dict(self.headers))
                body = b"sweeper probe\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._srv = http.server.ThreadingHTTPServer((address, 0), Handler)
        self.url = "http://%s:%d" % (address, self._srv.server_address[1])

    def __enter__(self):
        self._thread = threading.Thread(target=self._srv.serve_forever,
                                        daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()
        self._thread.join(timeout=5)


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("nuclei") is None,
                    reason="nuclei not installed; cannot probe the real binary")
def test_secret_file_credential_reaches_the_request(tmp_path):
    """End-to-end against the pinned nuclei binary and a local listener.

    Asserts on the header the server RECEIVED, not on the shape of the file
    that was written. A secret file that nuclei parses happily and then
    ignores fails this test, which is exactly the defect that shipped.
    """
    run_dir = tmp_path / "run"; run_dir.mkdir()
    template = tmp_path / "probe.yaml"; template.write_text(PROBE_TEMPLATE)
    bundle = SecretBundle(
        headers={"Authorization": "Bearer SWEEPER-CANARY-9f3a"},
        cookies={"session": "abc123", "csrf": "zzz"},
    )

    with _RecordingListener() as listener:
        secret_file = to_nuclei_secret_file(bundle, run_dir / "secrets.yaml",
                                            run_dir=run_dir,
                                            authorities=[listener.url])
        proc = subprocess.run(
            [str(binaries.resolve("nuclei")), "-u", listener.url,
             "-t", str(template), "-secret-file", str(secret_file),
             "-duc", "-silent", "-nc"],
            capture_output=True, text=True, timeout=180,
        )

    # Without this the test would pass vacuously if nuclei never ran the
    # template at all -- no request means no header to find missing.
    assert listener.requests, (
        "nuclei sent no request to the listener, so nothing was proven; "
        f"exit={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    received = listener.requests[0]
    assert received.get("Authorization") == "Bearer SWEEPER-CANARY-9f3a", (
        "the credential did not reach the request: nuclei scanned "
        f"anonymously. Headers received: {sorted(received)}"
    )
    assert received.get("Cookie") == "session=abc123; csrf=zzz", (
        f"cookies did not reach the request. Headers received: {sorted(received)}"
    )


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("nuclei") is None,
                    reason="nuclei not installed; cannot probe the real binary")
def test_credential_reaches_the_scoped_authority_and_no_other(tmp_path):
    """The scoping property, observed on the wire, not asserted about YAML.

    nuclei is driven with `-list`, so one run contacts many authorities from
    one secret file. Two listeners on two different loopback HOSTS are
    scanned in the SAME nuclei process and only one of them is named in
    `authorities`. A shape assertion cannot tell the difference between this
    file and the `domains-regex: [".*"]` that shipped -- both are well-formed
    YAML with a `headers` key, and both send the credential to the in-scope
    host. Only the out-of-scope listener's request separates them, so that is
    what is asserted.
    """
    run_dir = tmp_path / "run"; run_dir.mkdir()
    template = tmp_path / "probe.yaml"; template.write_text(PROBE_TEMPLATE)
    bundle = SecretBundle(
        headers={"Authorization": "Bearer SWEEPER-CANARY-9f3a"},
        cookies={"session": "abc123"},
    )

    with _RecordingListener("127.0.0.2") as in_scope, \
            _RecordingListener("127.0.0.1") as off_scope:
        secret_file = to_nuclei_secret_file(
            bundle, run_dir / "secrets.yaml", run_dir=run_dir,
            authorities=[in_scope.url],
        )
        targets = tmp_path / "list.txt"
        targets.write_text(f"{in_scope.url}\n{off_scope.url}\n")
        proc = subprocess.run(
            [str(binaries.resolve("nuclei")), "-list", str(targets),
             "-t", str(template), "-secret-file", str(secret_file),
             "-duc", "-silent", "-nc"],
            capture_output=True, text=True, timeout=180,
        )

    # Both halves have to have been exercised, or the test proves nothing:
    # no request to the in-scope listener means no credential to find, and
    # no request to the off-scope one means no chance to leak.
    assert in_scope.requests and off_scope.requests, (
        "nuclei did not scan both listeners, so nothing was proven; "
        f"exit={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    assert all(r.get("Authorization") == "Bearer SWEEPER-CANARY-9f3a"
               for r in in_scope.requests), (
        "the credential did not reach the authority it was scoped to: "
        f"{[sorted(r) for r in in_scope.requests]}"
    )
    for received in off_scope.requests:
        assert "Authorization" not in received and "Cookie" not in received, (
            "the credential was offered to an authority it was NOT scoped "
            f"to: {sorted(received)}"
        )


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("nuclei") is None,
                    reason="nuclei not installed; cannot probe the real binary")
def test_a_secret_file_with_no_authorities_sends_nothing_and_still_runs(
    tmp_path
):
    """The fail-closed default, and the reason it is a pattern not an omission.

    app.execute() writes the secret file before any HTTP_SERVICE artifact
    exists, so it takes the default. Two things must both hold, and only the
    real binary can show either: the credential goes nowhere, AND nuclei
    still starts. `domains-regex: []` and `static: []` also send nothing --
    by aborting the whole run with "domains or domains-regex cannot be
    empty" / "no secrets in given provider", which would turn every
    authenticated run into no run at all.
    """
    run_dir = tmp_path / "run"; run_dir.mkdir()
    template = tmp_path / "probe.yaml"; template.write_text(PROBE_TEMPLATE)
    bundle = SecretBundle(headers={"Authorization": "Bearer SWEEPER-CANARY"},
                          cookies={"session": "abc123"})
    secret_file = to_nuclei_secret_file(bundle, run_dir / "secrets.yaml",
                                        run_dir=run_dir)

    with _RecordingListener() as listener:
        proc = subprocess.run(
            [str(binaries.resolve("nuclei")), "-u", listener.url,
             "-t", str(template), "-secret-file", str(secret_file),
             "-duc", "-silent", "-nc"],
            capture_output=True, text=True, timeout=180,
        )

    assert listener.requests, (
        "nuclei never scanned: a never-matching authority pattern must leave "
        "the run working, not abort it. "
        f"exit={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
    )
    for received in listener.requests:
        assert "Authorization" not in received and "Cookie" not in received, (
            f"an unscoped secret file sent the credential: {sorted(received)}"
        )


def test_secret_file_uses_neither_dead_constant(tmp_path):
    """Fast regression guard for the two constants that have shipped.

    A shape check, and not proof of anything on its own -- the wire tests
    above are the proof. It exists so both specific regressions are caught in
    the default run even where the real binary is unavailable.
    """
    b = SecretBundle(headers={"Authorization": "Bearer x"}, cookies={"s": "1"})
    p = to_nuclei_secret_file(b, tmp_path / "secrets.yaml", run_dir=tmp_path,
                              authorities=["https://acc.example:8443"])
    entry = yaml.safe_load(p.read_text())["static"][0]
    assert "*" not in entry.get("domains", []), (
        "nuclei matches `domains` literally against the request authority, "
        "so '*' matches nothing and the credential is never sent"
    )
    assert ".*" not in entry["domains-regex"], (
        "'.*' matches every authority, so `-list` offers the credential to "
        "every host in the run rather than the ones it was issued for"
    )
    assert entry["domains-regex"] == [r"^acc\.example(?::\d+)?$"]
    assert {h["key"] for h in entry["headers"]} == {"Authorization", "Cookie"}


# --- the authority patterns themselves --------------------------------------
# Properties, not an enumeration of today's output. The authority is the
# request's host:port, and every one of these was confirmed against the real
# nuclei v3.11.0 rather than reasoned about -- the two defects that shipped
# here were both a guess about what the pattern is matched against.

def _matches(pattern: str, authority: str) -> bool:
    return re.search(pattern, authority) is not None


def test_authority_pattern_covers_the_host_with_and_without_a_port():
    """Both forms occur. httpx emits `https://acc.example` for a default port
    and `https://acc.example:8443` otherwise, and nuclei matches the URL's
    authority VERBATIM -- portless for the first, host:port for the second.
    A pattern that pins one form silently sends nothing for the other, which
    is the defect that made every authenticated run anonymous.
    """
    pattern, = authority_regexes(["https://acc.example"])
    assert _matches(pattern, "acc.example")
    assert _matches(pattern, "acc.example:443")
    assert _matches(pattern, "acc.example:8443")


def test_authority_pattern_is_anchored_at_both_ends():
    """Unanchored, a hostname matches every authority that merely contains
    it -- including an attacker-chosen subdomain of a domain they own.
    """
    pattern, = authority_regexes(["https://acc.example"])
    assert not _matches(pattern, "acc.example.evil.test")
    assert not _matches(pattern, "acc.example.evil.test:443")
    assert not _matches(pattern, "notacc.example")
    assert not _matches(pattern, "evil.test/?next=acc.example")


def test_authority_pattern_escapes_the_hostname():
    """An unescaped '.' is a wildcard, so `acc.example` would also cover
    `accXexample` -- a host someone else can register.
    """
    pattern, = authority_regexes(["https://acc.example"])
    assert not _matches(pattern, "accXexample")
    assert not _matches(pattern, "acc-example")


def test_authority_patterns_cover_every_admitted_host_and_nothing_else():
    patterns = authority_regexes([
        "https://a.acc.example", "https://a.acc.example:8443/deep/path",
        "http://b.acc.example:8080",
    ])
    # One per distinct HOST -- the two a.acc.example targets are one host.
    assert len(patterns) == 2
    for authority in ("a.acc.example", "a.acc.example:8443",
                      "b.acc.example:8080"):
        assert any(_matches(p, authority) for p in patterns), authority
    for authority in ("c.acc.example", "acc.example", "evil.test"):
        assert not any(_matches(p, authority) for p in patterns), authority


def test_an_ipv6_host_is_rebracketed():
    """scope.normalize() hands back urlsplit's .hostname, which drops the
    brackets ("::1"), but the request authority carries them ("[::1]:8080").
    The bare form matches nothing, which is the credential silently not being
    sent all over again.
    """
    pattern, = authority_regexes(["http://[::1]:8080/"])
    assert _matches(pattern, "[::1]:8080")
    assert _matches(pattern, "[::1]")


def test_no_authorities_yields_a_never_matching_pattern_not_an_empty_list():
    """Empty must fail closed AND stay runnable. nuclei treats both
    `domains-regex: []` and `static: []` as fatal, so expressing "goes
    nowhere" by omission refuses the run instead of scanning anonymously.
    """
    for empty in ([], (), None, ["", "   "]):
        assert authority_regexes(empty) == [NO_AUTHORITY_REGEX]
    for authority in ("acc.example", "acc.example:443", "", "[::1]", "*"):
        assert not _matches(NO_AUTHORITY_REGEX, authority)


def test_malformed_request_raises_clear_error(tmp_path):
    p = tmp_path / "req.txt"; p.write_text("this is not an http request")
    with pytest.raises(ValueError, match="request line"):
        from_burp_request(p)


# --- the secret file must not be readable by other local accounts ----------
# A plain write_text() takes whatever the umask allows: 0o664 under this
# environment's umask 002, 0o644 under the common 022. Either hands the
# client's live session and bearer tokens to every account on a shared
# engagement box. The mode must not depend on the umask.

def test_nuclei_secret_file_is_owner_only(tmp_path):
    b = SecretBundle(headers={"Authorization": "Bearer x"}, cookies={"s": "1"})
    p = to_nuclei_secret_file(b, tmp_path / "secrets.yaml", run_dir=tmp_path)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_nuclei_secret_file_mode_survives_a_permissive_umask(tmp_path):
    """os.open()'s mode argument is still masked by the umask, so the
    restrictive mode has to be applied to the descriptor, not merely
    requested at create time."""
    old = os.umask(0o022)
    try:
        b = SecretBundle(headers={"Authorization": "Bearer x"})
        p = to_nuclei_secret_file(b, tmp_path / "secrets.yaml", run_dir=tmp_path)
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    finally:
        os.umask(old)


def test_nuclei_secret_file_tightens_an_existing_loose_file(tmp_path):
    """O_CREAT's mode does not apply to a file that already exists."""
    p = tmp_path / "secrets.yaml"
    p.write_text("stale")
    os.chmod(p, 0o666)
    to_nuclei_secret_file(SecretBundle(headers={"Authorization": "Bearer x"}), p,
                          run_dir=tmp_path)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_secret_file_is_confined_to_the_run_dir(tmp_path):
    run_dir = tmp_path / "run"; run_dir.mkdir()
    b = SecretBundle(headers={"Authorization": "Bearer x"})
    assert to_nuclei_secret_file(b, run_dir / "secrets.yaml", run_dir=run_dir)
    with pytest.raises(ValueError, match="outside the run directory"):
        to_nuclei_secret_file(b, tmp_path / "escaped.yaml", run_dir=run_dir)


def test_dot_dot_escape_is_rejected(tmp_path):
    run_dir = tmp_path / "run"; run_dir.mkdir()
    b = SecretBundle(headers={"Authorization": "Bearer x"})
    with pytest.raises(ValueError, match="outside the run directory"):
        to_nuclei_secret_file(b, run_dir / ".." / "escaped.yaml", run_dir=run_dir)
    assert not (tmp_path / "escaped.yaml").exists()


def test_symlinked_parent_escape_is_rejected(tmp_path):
    """A textual prefix check passes here; only comparing resolved paths
    catches it."""
    run_dir = tmp_path / "run"; run_dir.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    (run_dir / "link").symlink_to(outside, target_is_directory=True)
    b = SecretBundle(headers={"Authorization": "Bearer x"})
    with pytest.raises(ValueError, match="outside the run directory"):
        to_nuclei_secret_file(b, run_dir / "link" / "secrets.yaml", run_dir=run_dir)
    assert not (outside / "secrets.yaml").exists()


def test_run_dir_is_required():
    """An optional security parameter fails open. Keyword-only, so `path`
    and `run_dir` cannot be silently transposed at a call site."""
    b = SecretBundle(headers={"Authorization": "Bearer x"})
    with pytest.raises(TypeError):
        to_nuclei_secret_file(b, "secrets.yaml")


def test_path_that_is_a_symlink_pointing_outside_is_rejected(tmp_path):
    """The final component itself being a symlink, rather than a parent."""
    run_dir = tmp_path / "run"; run_dir.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    target = outside / "stolen.yaml"
    (run_dir / "secrets.yaml").symlink_to(target)
    b = SecretBundle(headers={"Authorization": "Bearer x"})
    with pytest.raises(ValueError, match="outside the run directory"):
        to_nuclei_secret_file(b, run_dir / "secrets.yaml", run_dir=run_dir)
    assert not target.exists()


def test_dot_dot_that_resolves_back_inside_is_allowed(tmp_path):
    """Resolving is the point: a detour out and back in is legitimate."""
    run_dir = tmp_path / "run"; run_dir.mkdir()
    (run_dir / "sub").mkdir()
    b = SecretBundle(headers={"Authorization": "Bearer x"})
    p = to_nuclei_secret_file(b, run_dir / "sub" / ".." / "secrets.yaml",
                              run_dir=run_dir)
    assert p == (run_dir / "secrets.yaml").resolve()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_symlinked_run_dir_is_allowed(tmp_path):
    """run_dir itself may be a symlink; both sides are resolved."""
    real = tmp_path / "real_run"; real.mkdir()
    link = tmp_path / "run_link"; link.symlink_to(real, target_is_directory=True)
    b = SecretBundle(headers={"Authorization": "Bearer x"})
    p = to_nuclei_secret_file(b, link / "secrets.yaml", run_dir=link)
    assert (real / "secrets.yaml").exists()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_secret_file_open_refuses_to_follow_symlinks(tmp_path, monkeypatch):
    """O_NOFOLLOW is what closes the gap between the containment check and the
    open: the leaf does not exist at check time, so a writable directory would
    let it be swapped for a symlink out before open() ran."""
    seen = {}
    real_open = os.open

    def spy(p, flags, mode=0o777, **kw):
        seen["flags"] = flags
        return real_open(p, flags, mode, **kw)

    monkeypatch.setattr(os, "open", spy)
    run_dir = tmp_path / "run"; run_dir.mkdir()
    to_nuclei_secret_file(SecretBundle(headers={"Authorization": "Bearer x"}),
                          run_dir / "secrets.yaml", run_dir=run_dir)
    assert seen["flags"] & os.O_NOFOLLOW


def test_symlink_planted_after_the_check_cannot_redirect_the_write(
        tmp_path, monkeypatch):
    """The race, made deterministic: plant the attacker's symlink inside the
    exact window by hooking the last call made before the open.

    Without O_NOFOLLOW the credential lands in the attacker's file outside the
    run directory; with it, the open fails and nothing is written.
    """
    run_dir = tmp_path / "run"; run_dir.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    target = outside / "stolen.yaml"
    leaf = run_dir / "secrets.yaml"
    real_resolve = Path.resolve
    resolved_leaf = real_resolve(leaf)

    def resolve_then_plant(self, *a, **kw):
        resolved = real_resolve(self, *a, **kw)
        if resolved == resolved_leaf and not leaf.is_symlink():
            leaf.symlink_to(target)          # attacker wins the race
        return resolved

    monkeypatch.setattr(Path, "resolve", resolve_then_plant)
    b = SecretBundle(headers={"Authorization": "Bearer eyJ.PAYLOAD.SIG"})
    with pytest.raises(OSError):
        to_nuclei_secret_file(b, leaf, run_dir=run_dir)
    assert not target.exists()


def test_rejection_message_does_not_leak_credentials(tmp_path):
    run_dir = tmp_path / "run"; run_dir.mkdir()
    b = SecretBundle(headers={"Authorization": "Bearer eyJ.PAYLOAD.SIG"},
                     cookies={"session": "abc123"})
    with pytest.raises(ValueError) as exc:
        to_nuclei_secret_file(b, tmp_path / "escaped.yaml", run_dir=run_dir)
    text = str(exc.value)
    for secret in ("eyJ.PAYLOAD.SIG", "abc123", "Bearer "):
        assert secret not in text


# --- repr must not render credential values -------------------------------
# The only prior guard was a comment. Auth is wired into stages in Tasks 7-8,
# where ctx.log(f"{ctx.auth}"), a traceback holding a local `bundle`, or a
# debug print(vars(ctx)) would each dump every token in full.

def test_repr_does_not_leak_secret_values():
    b = SecretBundle(headers={"Authorization": "Bearer eyJhbGciOi.PAYLOAD.SIG"},
                     cookies={"session": "abc123"})
    text = repr(b)
    for secret in ("eyJhbGciOi.PAYLOAD.SIG", "Bearer ", "abc123"):
        assert secret not in text
    # Shape is still legible enough to debug with.
    assert "Authorization" in text and "session" in text


def test_str_does_not_leak_secret_values():
    b = SecretBundle(headers={"Authorization": "Bearer tok-42"},
                     cookies={"session": "abc123"})
    assert "tok-42" not in str(b)
    assert "abc123" not in str(b)


def test_login_flow_repr_does_not_leak_body_or_url():
    f = LoginFlow(url="https://acc.example/login?t=urltoken",
                  body='{"user":"tester","pass":"pw-secret"}',
                  success_marker="Welcome tester")
    text = repr(f)
    for secret in ("pw-secret", "tester", "urltoken"):
        assert secret not in text


def test_bundle_repr_does_not_leak_through_nested_login():
    b = SecretBundle(login=LoginFlow(body='{"pass":"pw-secret"}'))
    assert "pw-secret" not in repr(b)


def test_drop_headers_has_no_dead_cookie_entry():
    """Cookie is intercepted into .cookies before DROP_HEADERS is consulted,
    so an entry here could never match and would overstate the filter."""
    assert "cookie" not in DROP_HEADERS
