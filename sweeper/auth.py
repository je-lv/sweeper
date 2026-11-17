"""Authenticated scanning.

Credentials arrive either from interactive prompts or by importing a raw
HTTP request saved from Burp — the same format race.py and coupon_probe.py
already consume, so it fits existing muscle memory.

Secret material is written inside the run directory, owner-only, and is in
scope for redaction before any export. Both of those are enforced in code by
to_nuclei_secret_file() rather than left to the caller: a docstring is not an
access control.

Neither SecretBundle nor LoginFlow renders its values in repr(). Live
credentials reach a log, a traceback frame or a debug print through the
default dataclass repr long before anyone reviews the call site.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Iterable

import yaml

from .scope import normalize

# Headers that identify the captured request rather than the session.
# No "cookie" entry: the Cookie header is intercepted into .cookies before
# this set is consulted, so an entry here would be dead and would overstate
# what the filter does.
DROP_HEADERS = {
    "host", "content-length", "content-type", "user-agent", "accept",
    "accept-encoding", "accept-language", "connection",
    "referer", "origin", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-dest",
    "upgrade-insecure-requests", "cache-control", "pragma",
}

# Owner read/write only. Asserted in the tests against the mode actually on
# disk, because os.open()'s mode argument is still masked by the umask.
SECRET_FILE_MODE = 0o600

# nuclei's secret-file `domains:` list is matched LITERALLY -- there is no glob
# expansion -- and BOTH `domains` and `domains-regex` are matched against the
# request AUTHORITY, not the bare hostname. Every line below was confirmed on
# the wire against the pinned nuclei v3.11.0 by pointing it at recording
# listeners on 127.0.0.1, never assumed:
#
#   domains: ["*"]                -> header NOT sent   (matches no authority)
#   domains: ["127.0.0.1"]        -> header NOT sent   (port is part of it)
#   domains: ["127.0.0.1:18814"]  -> header sent
#   domains-regex: ["^127\\.0\\.0\\.1$"]       -> NOT sent to 127.0.0.1:18814
#                                              -> IS sent to a portless
#                                                 "http://127.0.0.1" target
#   domains-regex: ["^127\\.0\\.0\\.1:18814$"] -> header sent
#   domains-regex: [".*"]         -> header sent TO EVERY HOST IN THE RUN
#
# Two defects have now been fixed here in a row, and they are opposite errors
# with the same root cause -- guessing at what the pattern is matched against:
#
#   1. `["*"]` matched nothing, so every "authenticated" run scanned the
#      anonymous surface while report.md printed `Auth: auth`.
#   2. `domains-regex: [".*"]` matches EVERY authority. nuclei is driven with
#      `-list` (see stages/nuclei.py), so the client's session token was
#      offered to every host in the run rather than the ones it was issued
#      for. Not an off-scope leak while nuclei's redirects are off by
#      default, but a credential must be scoped to the authorities it
#      belongs to, not to whatever the scanner happens to be pointed at.
#
# So the pattern set is built from the run's own admitted targets --
# authority_regexes() below -- and never from a constant.
#
# The authority is the URL's host:port VERBATIM: present when the target URL
# carries a port, absent when it does not (both confirmed on the wire, see
# the two `^127\.0\.0\.1$` lines above). `(?::\d+)?` covers both forms, which
# is what a host-granular allowlist means anyway -- scope.normalize() strips
# the port and ScopeGuard stores hostnames, so "in scope" is a property of
# the host and of nothing else. Pinning the exact port instead would invent a
# scope distinction the allowlist does not make, and would silently send
# nothing the moment httpx and nuclei rendered one service's URL differently
# -- defect 1 all over again.
_AUTHORITY_SUFFIX = r"(?::\d+)?"

# The authority pattern for "no host at all". nuclei's engine is Go's RE2,
# which has NO lookahead, so the usual never-matching `(?!)` is not available
# -- it is rejected outright ([FTL] "invalid domain regex", confirmed on the
# wire, and a rejected regex is FATAL: nuclei exits 1 and scans nothing).
# `[^\s\S]` is the complement of "any character", which RE2 accepts and which
# can never match.
#
# It must be a never-matching PATTERN and not an empty list: both
# `domains-regex: []` and `static: []` are fatal to nuclei ("domains or
# domains-regex cannot be empty" / "no secrets in given provider"), so
# expressing "this credential goes nowhere" by omission would refuse the
# whole run instead of scanning anonymously.
NO_AUTHORITY_REGEX = r"[^\s\S]"


def authority_regexes(targets: Iterable[str]) -> list[str]:
    """Anchored authority patterns for exactly the hosts `targets` name.

    `targets` is the run's ADMITTED target list -- in practice the
    scope-filtered HTTP_SERVICE values nuclei is about to be handed via
    `-list` (see stages/nuclei.py). One pattern per distinct host, so a
    credential is offered to a host if and only if that host is being
    scanned under the operator's allowlist.

    Anchored at both ends and escaped, which is the whole point:

    * unanchored, `acc.example` matches the authority `acc.example.evil.test`
      -- an attacker-chosen subdomain of a domain they control -- and
      `evil.test/?x=acc.example` besides;
    * unescaped, the `.` in `acc.example` is a wildcard, so `accXexample`
      matches.

    An IPv6 host is re-bracketed. scope.normalize() returns urlsplit's
    .hostname, which strips the brackets ("::1"), but the authority in the
    request carries them ("[::1]:8080"), so the bare form would match
    nothing.

    An EMPTY result is not an empty list -- see NO_AUTHORITY_REGEX. Empty is
    the ordinary state during preflight (no HTTP_SERVICE artifact exists
    until httpx has run) and it must fail closed: the file stays valid,
    nuclei still starts, and the credential is attached to nothing.
    """
    hosts: dict[str, None] = {}
    for target in targets or ():
        host = normalize(target)
        if not host:
            continue
        if ":" in host:          # IPv6 literal; the authority is bracketed
            host = f"[{host}]"
        hosts.setdefault(host, None)
    if not hosts:
        return [NO_AUTHORITY_REGEX]
    # re.escape's output is RE2-compatible -- confirmed on the wire for the
    # characters a hostname can carry ("\-", "\.", "\[", "\]"); nuclei
    # accepted them and matched correctly.
    return [f"^{re.escape(host)}{_AUTHORITY_SUFFIX}$" for host in sorted(hosts)]


@dataclass(repr=False)
class LoginFlow:
    url: str = ""
    method: str = "POST"
    body: str = ""
    success_marker: str = ""

    def __repr__(self) -> str:
        """Shape only. body carries the username and password, and a login
        URL can carry a token in its query string, so neither is rendered.
        """
        return (
            f"LoginFlow(method={self.method!r}, url=<{len(self.url)} chars>, "
            f"body=<{len(self.body)} chars>, "
            f"success_marker=<{len(self.success_marker)} chars>)"
        )


@dataclass(repr=False)
class SecretBundle:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    login: LoginFlow | None = None

    def __repr__(self) -> str:
        """Header and cookie NAMES are rendered; their values never are.

        Written out rather than using field(repr=False) so that the default
        is closed: a field added to this class later is invisible here until
        someone deliberately renders it, where field(repr=False) would expose
        it the moment it was added without the flag.
        """
        return (
            f"SecretBundle(headers={sorted(self.headers)!r}, "
            f"cookies={sorted(self.cookies)!r}, "
            f"login={'set' if self.login else None})"
        )

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def header_args(self) -> list[str]:
        """Render as repeated -H arguments, the form every PD tool accepts."""
        args: list[str] = []
        for key, value in self.headers.items():
            args += ["-H", f"{key}: {value}"]
        if self.cookies:
            args += ["-H", f"Cookie: {self.cookie_header()}"]
        return args

    def is_empty(self) -> bool:
        return not self.headers and not self.cookies


def from_burp_request(path: Path) -> SecretBundle:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    head = text.replace("\r\n", "\n").split("\n\n", 1)[0]
    lines = [l for l in head.split("\n") if l.strip()]
    # A request line is exactly "METHOD path HTTP/version". Checking only
    # that the line has >=2 tokens accepts free-text noise ("this is not
    # an http request" is 6 tokens) as a request line, so an operator who
    # points this at the wrong file gets a header-parsing traceback deep
    # inside the loop below instead of a clear error at the boundary.
    request_line = lines[0].split() if lines else []
    if len(request_line) != 3 or not request_line[2].upper().startswith("HTTP/"):
        raise ValueError(
            "malformed request: could not parse request line "
            "(expected 'METHOD /path HTTP/1.1')"
        )

    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key, value = key.strip(), value.strip()
        if key.lower() == "cookie":
            jar = SimpleCookie()
            jar.load(value)
            for name, morsel in jar.items():
                cookies[name] = morsel.value
            continue
        if key.lower() in DROP_HEADERS:
            continue
        headers[key] = value
    return SecretBundle(headers=headers, cookies=cookies)


def to_nuclei_secret_file(bundle: SecretBundle, path: Path, *,
                          run_dir: Path,
                          authorities: Iterable[str] = ()) -> Path:
    """Emit a nuclei -secret-file. Static credentials only.

    Dynamic re-login is configured separately via LoginFlow; nuclei's
    dynamic auth requires a template, which is generated in Task 10.

    `authorities` is the run's admitted target list; the credential is
    offered to those hosts and to no others (see authority_regexes). It
    defaults to NOTHING rather than to everything, and that direction is the
    point: a caller who does not know yet which hosts will be scanned writes
    a file that sends the credential nowhere, which is a run that finds less
    than it should. The opposite default sends the client's session token to
    every host the scanner is pointed at, which is a finding in someone
    else's report. app.execute() writes the file before any stage has run --
    no HTTP_SERVICE artifact exists that early -- so it takes this default,
    and stages/nuclei.py rewrites the file from its own scope-filtered
    `-list` contents in build_command(), which is the last moment the set of
    scanned authorities can still change.

    This is the one place a live credential is written to disk, which nuclei's
    -secret-file mechanism requires. Two properties are therefore enforced
    here and not left to the caller:

    Mode 0o600, applied to the descriptor before any content is written. A
    plain write_text() takes whatever the umask allows -- 0o664 here, 0o644
    under the common umask 022 -- which on a shared engagement box hands the
    client's session and bearer tokens to every local account. Writing first
    and chmod'ing after would still leave a window where the full file is
    world-readable, so the mode is set on the fd between truncation and the
    write.

    Containment in run_dir. Required and keyword-only: an optional security
    parameter fails open, and the caller who forgets it is exactly the caller
    it protects against. Keyword-only because `path` and `run_dir` are both
    paths, and a silent transposition should not be expressible.
    """
    # Both sides fully resolved, then the resolved path is what gets opened --
    # validating one path and opening another is how a check gets bypassed.
    # resolve() collapses ".." (a path that detours out and back in is fine,
    # that is the point of resolving) and follows symlinked components on the
    # path and on run_dir alike, none of which a textual prefix check catches.
    root = Path(run_dir).resolve()
    path = Path(path).resolve()
    if path != root and root not in path.parents:
        # Names what was refused and why. Never interpolates the bundle or any
        # file content: this message is operator-facing and gets logged.
        raise ValueError(
            f"refusing to write secret material outside the run directory: "
            f"{path} is not under {root}"
        )

    headers = dict(bundle.headers)
    if bundle.cookies:
        headers["Cookie"] = bundle.cookie_header()
    data = {
        "static": [{
            "type": "header",
            # NOT `domains: ["*"]` (matches no authority -- the credential is
            # never sent) and NOT `domains-regex: [".*"]` (matches EVERY
            # authority -- the credential is sent to every host in the run).
            # Both have shipped; see the comment block above authority_regexes.
            "domains-regex": authority_regexes(authorities),
            "headers": [{"key": k, "value": v} for k, v in headers.items()],
        }]
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_NOFOLLOW closes the window between the resolve() above and this open.
    # The leaf does not exist yet at check time, so anyone able to write in the
    # directory can swap in a symlink pointing outside; open() would follow it
    # and write the credential there, and fchmod would then merely tighten the
    # attacker's own inode. A legitimate target is never a symlink, so refusing
    # to follow one costs nothing. This covers the final component only --
    # intermediate components are covered by new_run_dir() creating the run
    # directory 0o700, so no other account can write inside it at all.
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
        SECRET_FILE_MODE,
    )
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        # O_CREAT's mode is masked by the umask, and it does not apply at all
        # to a file that already existed -- an existing secrets.yaml keeps its
        # old, possibly loose, mode. fchmod fixes both, on the fd, while the
        # file is still empty.
        os.fchmod(fd, SECRET_FILE_MODE)
        fh.write(yaml.safe_dump(data, sort_keys=False))
    return path
