# sweeper/binaries.py
"""Absolute-path resolution and identity verification for external tools.

NEVER use PATH lookup. On Kali:
  /usr/bin/httpx   is the Python HTTP client, not ProjectDiscovery's httpx
  /usr/bin/nuclei  is v3.8.0, not the pinned v3.11.0 in ~/.pdtm/go/bin
Resolving by PATH silently runs the wrong program.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

PDTM = Path.home() / ".pdtm" / "go" / "bin"
USR = Path("/usr/bin")
#: pipx and `pip install --user` both land console scripts here, which is
#: where the one Python-packaged tool in this set lives. Kept distinct from
#: USR because a distro package and a user install of the same name are
#: different versions, and run.json records which one actually ran.
LOCAL = Path.home() / ".local" / "bin"

# A version worth recording sits on a line that also says "version". True of
# all ten tools here that report one, across three unrelated output formats
# ("[INF] Current Version: v1.2.3", "Nmap version 7.98", "ffuf version:
# 2.1.0-dev").
#
# Searching the whole output instead took the first number-shaped thing
# anywhere in it, which is not the same question. nmap's own version never
# matched (two components, not three), so the match landed on its
# "Compiled with: liblua-5.4.8" line and nmap was recorded as running
# liblua's version; arjun matched "127.0.0" out of the 127.0.0.1:8080
# default in its --help. Both passed the identity check, so the wrong string
# reached the manifest — which is the evidence trail saying which tool
# version produced which finding. A confidently wrong version there is worse
# than no version, so match per-line and accept None.
VERSION_LINE_RE = re.compile(r"version", re.I)
# Two or more components, not exactly three: nmap prints "Nmap version 7.98".
VERSION_RE = re.compile(r"v?(\d+(?:\.\d+)+)")
# A line that is a version and NOTHING else, for specs that set
# bare_version. fullmatch against the stripped line is the whole safeguard:
# "Compiled with: liblua-5.4.8" and "127.0.0.1:8080" both carry a
# version-shaped number and neither is one, so neither can match here.
BARE_VERSION_RE = re.compile(r"v?(\d+(?:\.\d+)+)")

# Identity pattern for ProjectDiscovery tools. It matches the vendor string
# rather than the tool's own name because pdtm binaries render their name as
# ASCII art on `-version`; the only literal text in the banner is
# "projectdiscovery.io" and "Current Version: X". This still rejects impostors
# like /usr/bin/httpx (the Python HTTP client), which never prints it.
#
# WARNING: this is correct only for ProjectDiscovery tools. Non-PD tools added
# later (nmap, ffuf, arjun, trufflehog) print their own names normally and need
# tool-specific identity patterns — do not reuse PD_IDENTITY for them.
PD_IDENTITY = r"projectdiscovery"


@dataclass(frozen=True)
class BinarySpec:
    name: str
    candidates: list[Path]
    version_flag: str
    identity_pattern: str
    install_hint: str
    #: This tool prints its version and nothing else, so the "line must say
    #: version" rule cannot see it. Opt-in, never a global fallback — see
    #: extract_version. Not set for delv, whose "delv 9.20.18-1-Debian" is
    #: not a bare version line and would still (correctly) record None.
    bare_version: bool = False


@dataclass
class BinaryStatus:
    name: str
    path: Path | None = None
    # None means the tool reports no version, which is a real answer:
    # trufflehog prints "trufflehog dev" and arjun has no version flag at all.
    version: str | None = None
    ok: bool = False
    reason: str = ""


KNOWN_BINARIES: dict[str, BinarySpec] = {
    "dnsx": BinarySpec(
        "dnsx", [PDTM / "dnsx"], "-version", PD_IDENTITY,
        "pdtm -install dnsx",
    ),
    "naabu": BinarySpec(
        "naabu", [PDTM / "naabu"], "-version", PD_IDENTITY,
        "pdtm -install naabu",
    ),
    # PDTM FIRST. /usr/bin/httpx is the Python client and must never win.
    "httpx": BinarySpec(
        "httpx", [PDTM / "httpx", USR / "httpx-toolkit"], "-version", PD_IDENTITY,
        "pdtm -install httpx   (or: apt install httpx-toolkit)",
    ),
    "cdncheck": BinarySpec(
        "cdncheck", [PDTM / "cdncheck"], "-version", PD_IDENTITY,
        "pdtm -install cdncheck",
    ),
    "tlsx": BinarySpec(
        "tlsx", [PDTM / "tlsx"], "-version", PD_IDENTITY,
        "pdtm -install tlsx",
    ),
    "katana": BinarySpec(
        "katana", [PDTM / "katana"], "-version", PD_IDENTITY,
        "pdtm -install katana",
    ),
    # subfinder and nuclei print no ASCII-art banner on -version -- just
    # "[INF] Current Version:" -- so PD_IDENTITY never matches and verify()
    # would disable both. They do print their own name elsewhere in the
    # output ("Subfinder Config Directory", "Nuclei Engine Version"), so a
    # per-tool name pattern is used instead.
    "subfinder": BinarySpec(
        "subfinder", [PDTM / "subfinder"], "-version", r"subfinder",
        "pdtm -install subfinder",
    ),
    "nuclei": BinarySpec(
        "nuclei", [PDTM / "nuclei"], "-version", r"nuclei",
        "pdtm -install nuclei",
    ),
    "nmap": BinarySpec(
        "nmap", [USR / "nmap"], "--version", r"nmap",
        "apt install nmap",
    ),
    # BIND's validating resolver-and-lookup tool, used by the dnssec stage.
    # `-v` prints "delv 9.20.18-1-Debian" -- one line, no "version" in it,
    # so the identity pattern is the name itself as with nmap and ffuf.
    "delv": BinarySpec(
        "delv", [USR / "delv"], "-v", r"delv",
        "apt install bind9-dnsutils",
    ),
    "ffuf": BinarySpec(
        "ffuf", [USR / "ffuf"], "-V", r"ffuf",
        "apt install ffuf",
    ),
    # SPF/DMARC/MTA-STS record validation, used by the maildns stage.
    # `--version` prints the bare number ("5.17.4") with no tool name and no
    # "version" in it, so the identity pattern is the version shape itself --
    # the only spec here that cannot match on a name. USR first so a distro
    # package wins over a user install if both exist.
    "checkdmarc": BinarySpec(
        "checkdmarc", [USR / "checkdmarc", LOCAL / "checkdmarc"],
        "--version", r"^\d+\.\d+",
        "pipx install checkdmarc",
        bare_version=True,
    ),
    "trufflehog": BinarySpec(
        "trufflehog", [USR / "trufflehog"], "--version", r"trufflehog",
        "apt install trufflehog",
    ),
    # arjun has no version flag at all; --help is the only flag that prints
    # its own name without doing any work.
    "arjun": BinarySpec(
        "arjun", [USR / "arjun"], "--help", r"arjun",
        "apt install arjun",
    ),
}


def extract_version(blob: str, bare: bool = False) -> str | None:
    """The version a tool reports, or None if it does not report one.

    None is not a failure to parse — it is the honest record for a tool that
    genuinely has no version to give, and it must not be replaced with a
    fabricated string. See VERSION_LINE_RE.

    `bare` is for the tools that print the number and NOTHING else
    (`checkdmarc --version` -> "5.17.4"). The keyword rule is right for
    every tool that names its version, and those tools would otherwise
    record None forever — a gap in the manifest that says which tool version
    produced which finding. It stays opt-in per spec rather than becoming a
    fallback, because a fallback is how "any number anywhere" comes back:
    the line must be a version and nothing else, so liblua-5.4.8 and
    127.0.0.1:8080 are still refused.
    """
    for line in blob.splitlines():
        if VERSION_LINE_RE.search(line):
            m = VERSION_RE.search(line)
            if m:
                return m.group(1)
    if bare:
        for line in blob.splitlines():
            m = BARE_VERSION_RE.fullmatch(line.strip())
            if m:
                return m.group(1)
    return None


def resolve(name: str) -> Path | None:
    spec = KNOWN_BINARIES.get(name)
    if spec is None:
        return None
    for cand in spec.candidates:
        if cand.is_file():
            return cand
    return None


def verify(name: str) -> BinaryStatus:
    # A stage may declare requires=["typo"]. That is a configuration error
    # worth reporting clearly, not a KeyError that kills the run.
    spec = KNOWN_BINARIES.get(name)
    if spec is None:
        return BinaryStatus(
            name,
            reason=(f"unknown binary {name!r}: no entry in KNOWN_BINARIES. "
                    "Add a BinarySpec for it before a stage requires it."),
        )
    path = resolve(name)
    if path is None:
        tried = ", ".join(str(c) for c in spec.candidates)
        return BinaryStatus(
            name, reason=f"not found (tried: {tried}) — install with: {spec.install_hint}"
        )
    try:
        proc = subprocess.run(
            [str(path), spec.version_flag],
            capture_output=True, text=True,
            # Every child sweeper spawns gets DEVNULL, not an inherited
            # stdin -- see runner.py's Popen. A version probe that blocked on
            # a pipe would fail binary verification and abort the run before
            # a single target was touched.
            stdin=subprocess.DEVNULL, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return BinaryStatus(name, path=path, reason=f"could not execute: {exc}")

    blob = f"{proc.stdout}\n{proc.stderr}"
    if not re.search(spec.identity_pattern, blob, re.I):
        snippet = " ".join(blob.split())[:120]
        return BinaryStatus(
            name, path=path,
            reason=(
                f"identity check failed: output of "
                f"{path} {spec.version_flag} did not match "
                f"{spec.identity_pattern!r}. A different program may be "
                f"shadowing it. Got: {snippet!r}"
            ),
        )
    return BinaryStatus(name, path=path,
                        version=extract_version(blob, bare=spec.bare_version),
                        ok=True)
