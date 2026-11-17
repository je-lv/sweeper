"""nmap stage — service and version detection on discovered ports.

naabu says "443 open"; nmap says "nginx 1.24.0". That difference is what
makes an infrastructure section actionable rather than a port list.

Timing is deliberately left at nmap's default (T3); nothing here raises it.
`-sC` is `--script=default`, a curated set that excludes scripts tagged
intrusive/dos — `--script vuln` (or any other intrusive category) is never
requested, in line with the engagement's no-DoS/no-ReDoS constraint.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator

from ..artifacts import Artifact, ArtifactKind, Finding

# Versions with well-known public advisories worth surfacing for triage.
OUTDATED = (
    (re.compile(r"OpenSSH\s+([0-6]\.|7\.[0-8])"), "medium",
     "Outdated OpenSSH version"),
    (re.compile(r"Apache(?:/| )2\.[0-2]\."), "medium",
     "Outdated Apache httpd version"),
    (re.compile(r"nginx(?:/| )1\.(?:[0-9]|1[0-7])\."), "low",
     "Outdated nginx version"),
    (re.compile(r"vsftpd\s+2\.3\.4"), "critical",
     "vsftpd 2.3.4 — backdoored release"),
)

_HOST_CLOSE = "</host>"


def host_port(artifact) -> tuple[str, str]:
    """The (host, port) an artifact describes, preferring its meta.

    The fallback is computed lazily and with rpartition, which never raises.
    `a.meta.get("port", a.value.rsplit(":", 1)[1])` evaluated its default
    EAGERLY, so a PORT artifact whose value carried no colon raised
    IndexError even when meta["port"] was present and the fallback was never
    going to be used.
    """
    host = artifact.meta.get("host") or ""
    port = artifact.meta.get("port") or ""
    if host and port:
        return host, port
    head, sep, tail = artifact.value.rpartition(":")
    if not sep:
        return (host or artifact.value), port
    return (host or head), (port or tail)


def complete_host_blocks(text: str) -> Iterator[str]:
    """Yield each complete <host>...</host> substring of a partial document.

    Index scanning, deliberately NOT a regex: `<host.*?</host>` over a large
    truncated document is exactly the catastrophic-backtracking construct the
    engagement's no-ReDoS constraint rules out. str.find is linear and cannot
    backtrack.

    "<host" also prefixes "<hostnames" and "<hostname", so the character
    after it must end the tag name for the match to count. The closing search
    is for the exact "</host>" including its ">", which "</hostnames>" does
    not contain.
    """
    pos = 0
    while True:
        start = text.find("<host", pos)
        if start == -1:
            return
        after = start + len("<host")
        if after < len(text) and text[after] not in " \t\r\n>/":
            pos = after                      # <hostnames> / <hostname ...>
            continue
        end = text.find(_HOST_CLOSE, start)
        if end == -1:
            return                           # truncated mid-host: unusable
        yield text[start:end + len(_HOST_CLOSE)]
        pos = end + len(_HOST_CLOSE)


class NmapStage:
    name = "nmap"
    artifact_kind = ArtifactKind.PORT
    protocols = None
    accepted_states = {"open"}
    #: nmap's --dns-servers takes addresses only and always queries port
    #: 53, so it cannot express a resolver on another port; targets are
    #: forward-resolved through the system resolver.
    honors_resolver = False
    resolver_note = "nmap's --dns-servers takes addresses only and always queries port 53, so it cannot express a resolver on another port; targets are forward-resolved through the system resolver."
    requires = ["nmap"]
    consumes = ArtifactKind.PORT
    produces = {ArtifactKind.PORT, ArtifactKind.FINDING}
    optional = True
    levels = {
        "low":  [],
        "mid":  ["-sV", "--version-intensity", "2"],
        # -sC REMOVED. Two independent reasons, either sufficient.
        #
        # It crashes nmap 7.98 outright. Reproduced against the lab:
        #   nmap: nse_nsock.cc:381: void callback(nsock_pool, nsock_event,
        #   void*): Assertion `lua_status(L) == LUA_YIELD' failed.
        # an NSE assertion failure that aborts with SIGABRT, so the stage
        # produced NOTHING at high and full -- service detection lost for the
        # whole run. The identical command without -sC completes cleanly (57
        # port elements, well-formed close). Upstream bug, but the cost lands
        # here.
        #
        # And parse() never read its output anyway: this module parses
        # <host>, <address>, <hostname>, <port>, <state> and <service>, and
        # has no handling for <script> elements at all. So -sC was spending
        # scan time against the client to produce a section nothing reads --
        # the same objection stages/dnsx.py records for not requesting flags
        # its parser ignores.
        #
        # Re-adding it needs BOTH: script parsing in parse(), and a check
        # that the installed nmap does not abort.
        "high": ["-sV", "--version-intensity", "5"],
        "full": ["-sV", "--version-intensity", "5"],
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        ports = ctx.store.get(ArtifactKind.PORT)
        pairs = [host_port(a) for a in ports]
        hosts = sorted({h for h, _ in pairs if h})
        permitted, _ = ctx.scope.filter(hosts)

        # Targets go through a -iL file, same idiom as naabu/dnsx/httpx —
        # NOT as bare positional args. preflight.validate_arguments swaps
        # any argument ending in ".txt" for a throwaway dead-endpoint file
        # before probing; a bare hostname positional argument is invisible
        # to that substitution, so the real targets would be the ones
        # preflight's dry-run argument probe actually contacts. Routing
        # through a file keeps preflight's "only 127.0.0.1:1 is ever
        # contacted" guarantee intact for this stage too.
        hosts_file = ctx.run_dir / "raw" / "nmap-input.txt"
        hosts_file.parent.mkdir(parents=True, exist_ok=True)
        hosts_file.write_text("\n".join(permitted) + "\n", encoding="utf-8")

        cmd = [str(binaries.resolve("nmap")), "-Pn", "-n", "--resolve-all",
               "-iL", str(hosts_file)]

        # -p is only added when there is a real port list. preflight calls
        # every stage's build_command before ANY stage has run — naabu
        # (which produces the PORT artifacts this stage consumes) has not
        # executed yet, so ctx.store.get(PORT) is genuinely empty at
        # preflight time even in a real run. `-p ""` is not a syntax error
        # nmap reports the way preflight expects (it exits with "Error #485:
        # Your port specifications are illegal", which matches none of
        # ARG_ERROR_MARKERS), so it would silently pass preflight while
        # never actually exercising whether -sV/-sC/--version-intensity are
        # accepted — the exact class of defect preflight exists to catch.
        # Omitting -p when there is nothing to scan sidesteps that: nmap
        # accepts the rest of the command normally and falls through to
        # "no targets" against the substituted dead endpoint. At real
        # run-time this stage is skipped by the NO_INPUT path before ever
        # reaching here if PORT is still empty, so -p is always present
        # once nmap actually executes against a target.
        port_values = {p for _, p in pairs if p.isdigit()}
        if port_values:
            cmd += ["-p", ",".join(sorted(port_values, key=int))]

        cmd += self.levels[ctx.config.level]
        if ctx.config.rate_override:
            # Applies to both this TCP enrichment stage and NmapUdpStage,
            # which inherits this command shape.  --rate is an engagement-
            # wide ceiling, not merely Naabu's packet setting.
            cmd += ["--max-rate", str(ctx.config.rate_override)]
        # XML to stdout, not to a side file: the runner captures stdout into
        # raw/nmap.jsonl (ctx.raw_path(stage.name) always uses the default
        # "jsonl" extension, regardless of the tool's real format) and hands
        # THAT path to parse() — a file written via a separate "-oX <path>"
        # would never be read by parse() at all.
        cmd += ["-oX", "-"]
        return cmd

    def parse(self, raw_path: Path) -> Iterator[Artifact | Finding]:
        path = Path(raw_path)
        if not path.exists():
            return
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            return

        # Salvage, do not raise. nmap emits ONE XML document, so unlike the
        # JSONL tools (where a bad line is skippable and costs one record)
        # truncation costs 100% of the scan. And truncation is routine, not
        # exotic: runner.py's per-stage timeout kills the subprocess and
        # explicitly keeps the partial stdout, marking the stage PARTIAL —
        # then still calls parse() on it. Raising there took the whole run
        # down over a document that was 80% complete and 80% usable.
        try:
            host_els = list(ET.fromstring(text).iter("host"))
        except ET.ParseError:
            host_els = []
            for block in complete_host_blocks(text):
                try:
                    host_els.append(ET.fromstring(block))
                except ET.ParseError:
                    continue     # incomplete inner markup; skip just this one

        for host_el in host_els:
            name_el = host_el.find("./hostnames/hostname")
            addr_el = host_el.find("./address")
            host = (name_el.get("name") if name_el is not None
                    else (addr_el.get("addr") if addr_el is not None else ""))
            if not host:
                continue
            for port_el in host_el.iter("port"):
                state = port_el.find("state")
                port_state = state.get("state", "") if state is not None else ""
                if port_state not in self.accepted_states:
                    continue
                portid = port_el.get("portid", "")
                # tcp and udp are enumerated separately by nmap and can
                # legitimately share a portid (53/tcp DNS and 53/udp DNS,
                # say) -- see the matcher below for why this is captured.
                protocol = port_el.get("protocol", "")
                if self.protocols is not None and protocol not in self.protocols:
                    continue
                svc = port_el.find("service")
                service = svc.get("name", "") if svc is not None else ""
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                banner = f"{product} {version}".strip()

                yield Artifact(
                    self.artifact_kind, f"{host}:{portid}",
                    meta={"host": host, "port": portid, "service": service,
                          "product": product, "version": version,
                          "protocol": protocol,
                          "state": port_state,
                          "ip": addr_el.get("addr", "") if addr_el is not None else "",
                          "ips": ([addr_el.get("addr", "")]
                                  if addr_el is not None and addr_el.get("addr") else [])},
                )

                for pattern, severity, title in OUTDATED:
                    if banner and pattern.search(banner):
                        yield Finding(
                            stage=self.name, severity=severity, title=title,
                            target=(f"{host}:{portid}/udp"
                                    if self.artifact_kind is ArtifactKind.UDP_PORT
                                    else f"{host}:{portid}"),
                            template_id=f"nmap-outdated-{service or 'service'}",
                            # matcher=f"{protocol}:{banner}": target carries
                            # only host:portid, with no protocol -- tcp and
                            # udp entries sharing a port number (routine:
                            # nmap commonly labels 53/tcp and 53/udp both
                            # "domain") collide on target, and when the
                            # service name also matches, on template_id too.
                            # Without a matcher two GENUINELY DIFFERENT
                            # banners on the two protocols hash to one
                            # finding_id and only the first-submitted
                            # survives store.add_finding. protocol+banner is
                            # intrinsic to this scan result and identical on
                            # a rerun against an unchanged service, so this
                            # keeps finding_id stable across runs (see
                            # artifacts.finding_id's docstring) while
                            # distinguishing tcp from udp and any differing
                            # banner on either.
                            matcher=f"{protocol}:{banner}",
                            evidence=f"{host}:{portid}/{protocol} — {banner}",
                            raw_ref=f"raw/{self.name}.jsonl",
                            description="The reported version has known public "
                                        "advisories. Confirm the exact build before "
                                        "reporting; banners can be misleading.",
                            remediation="Upgrade to a currently supported release.",
                        )
                        break
