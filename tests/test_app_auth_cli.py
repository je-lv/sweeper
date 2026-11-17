"""Supplying credentials without the interactive menu.

Authenticated scanning was reachable ONLY through menu option 7. On the
command line, `--auth auth --no-menu` set auth_mode but attached no bundle,
so preflight refused the run with "no credentials configured -- import a
Burp request or enter headers via menu option 7". That refusal is correct
and fails closed -- the deliverable never claims an authenticated scan that
did not happen -- but it left every automated run unauthenticated, and the
authenticated surface of an application is usually the half worth testing.

Credentials arrive as a FILE PATH, never as argv. A --header/--cookie flag
would put the live session token in the process table for anything on the
box to read; that is the exposure katana's header-file and nuclei's
-secret-file already exist to avoid, and the entry point has to keep the
same property.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from sweeper import app

REQUEST = (
    "GET /account HTTP/1.1\r\n"
    "Host: acc.example\r\n"
    "Cookie: session=s3cr3tvalue\r\n"
    "Authorization: Bearer tok3nvalue\r\n"
    "\r\n"
)


def write_request(tmp_path, text=REQUEST):
    p = tmp_path / "req.txt"
    p.write_text(text)
    return p


def base_args(tmp_path, *extra):
    t = tmp_path / "t.txt"
    t.write_text("acc.example\n")
    return ["--targets", str(t), "--outdir", str(tmp_path / "out"),
            "--no-menu", "--stages", "dnsx", *extra]


def run_capturing(monkeypatch, argv):
    captured = {}

    def fake_execute(config, *a, **kw):
        captured["config"] = config
        captured["auth_bundle"] = kw.get("auth_bundle")
        return SimpleNamespace(run_dir=Path("/dev/null")), []

    monkeypatch.setattr(app, "execute", fake_execute)
    app.main(argv)
    return captured


def test_credentials_from_a_request_file_reach_the_run(tmp_path, monkeypatch):
    got = run_capturing(monkeypatch, base_args(
        tmp_path, "--auth-request", str(write_request(tmp_path))))
    bundle = got["auth_bundle"]
    assert bundle is not None and not bundle.is_empty()
    assert bundle.cookies["session"] == "s3cr3tvalue"
    assert bundle.headers["Authorization"] == "Bearer tok3nvalue"


def test_supplying_credentials_implies_auth_mode(tmp_path, monkeypatch):
    """Otherwise execute()'s auth invariant drops them and warns.

    Credentials attached while auth_mode is 'unauth' are deliberately NOT
    sent -- so without this the flag would appear to work and change nothing.
    """
    got = run_capturing(monkeypatch, base_args(
        tmp_path, "--auth-request", str(write_request(tmp_path))))
    assert got["config"].auth_mode == "auth"


def test_an_explicit_unauth_alongside_credentials_is_refused(tmp_path):
    """Contradictory, and the wrong thing to guess at.

    Guessing unauthenticated silently omits the authenticated surface;
    guessing authenticated silently sends credentials the operator may have
    meant to withhold. Neither is a default worth having.
    """
    with pytest.raises(SystemExit):
        app.main(base_args(tmp_path, "--auth-request",
                           str(write_request(tmp_path)), "--auth", "unauth"))


def test_not_passing_auth_at_all_is_not_treated_as_a_conflict(tmp_path, monkeypatch):
    """The ordinary case. --auth defaults to unauth, so the conflict check
    has to distinguish 'not given' from 'given as unauth'."""
    got = run_capturing(monkeypatch, base_args(
        tmp_path, "--auth-request", str(write_request(tmp_path))))
    assert got["config"].auth_mode == "auth"


def test_a_request_file_with_no_credentials_names_the_right_problem(tmp_path):
    """It must not fall through to preflight's 'no credentials configured'.

    The operator DID supply a file; being told they configured nothing sends
    them looking in the wrong place.
    """
    p = write_request(tmp_path, "GET / HTTP/1.1\r\nHost: acc.example\r\n\r\n")
    with pytest.raises(SystemExit):
        app.main(base_args(tmp_path, "--auth-request", str(p)))


def test_a_missing_file_is_an_argument_error(tmp_path):
    with pytest.raises(SystemExit):
        app.main(base_args(tmp_path, "--auth-request",
                           str(tmp_path / "nope.txt")))


def test_a_malformed_request_is_an_argument_error(tmp_path):
    p = write_request(tmp_path, "this is not an http request at all\r\n")
    with pytest.raises(SystemExit):
        app.main(base_args(tmp_path, "--auth-request", str(p)))


def test_no_credential_value_appears_in_argv(tmp_path, monkeypatch):
    """The property the file interface exists for.

    Anything on the box can read /proc/<pid>/cmdline; a session token in
    there outlives the scan in shell history and process accounting.
    """
    argv = base_args(tmp_path, "--auth-request", str(write_request(tmp_path)))
    run_capturing(monkeypatch, argv)
    joined = " ".join(argv)
    assert "s3cr3tvalue" not in joined
    assert "tok3nvalue" not in joined


def test_unauthenticated_runs_are_unaffected(tmp_path, monkeypatch):
    got = run_capturing(monkeypatch, base_args(tmp_path))
    assert got["auth_bundle"] is None
    assert got["config"].auth_mode == "unauth"
