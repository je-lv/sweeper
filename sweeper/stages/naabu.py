"""naabu stage — TCP port discovery.

Connect scan by default so no root privilege is required. naabu emits
duplicate rows for the same host:port, so the parser dedupes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..artifacts import Artifact, ArtifactKind


def _without(flags: list[str], names) -> list[str]:
    """`flags` minus each named flag AND the value that follows it.

    Shared by the -rate and port replacements below. Written once because
    both need the same off-by-one-free skip: dropping a flag but keeping its
    value leaves a bare number in argv, which naabu reads as a positional
    and preflight classifies as ARG_ERROR — aborting the run instead of
    narrowing it.
    """
    out, skip = [], False
    for flag in flags:
        if skip:
            skip = False
            continue
        if flag in names:
            skip = True          # drop the flag and its value
            continue
        out.append(flag)
    return out


class NaabuStage:
    name = "naabu"
    #: This tool takes an operator-supplied resolver; see
    #: sweeper.resolvers and run.json's "resolver" block.
    honors_resolver = True
    requires = ["naabu"]
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    optional = False
    levels = {
        "low":  ["-top-ports", "100", "-rate", "150"],
        "mid":  ["-top-ports", "1000", "-rate", "500"],
        "high": ["-p", "1-65535", "-rate", "800"],
        "full": ["-p", "1-65535", "-rate", "1000"],
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        binary = binaries.resolve("naabu")
        hosts_file = ctx.run_dir / "raw" / "naabu-input.txt"
        hosts_file.parent.mkdir(parents=True, exist_ok=True)
        permitted, _ = ctx.scope.filter(ctx.store.values(ArtifactKind.HOST))
        hosts_file.write_text("\n".join(permitted) + "\n", encoding="utf-8")
        flags = list(self.levels[ctx.config.level])
        if ctx.config.rate_override:
            # REPLACE the level's -rate, don't append a second one. Go's flag
            # package happens to take the last occurrence, so appending works
            # here by luck of the parser rather than by construction — and
            # clap-based tools reject duplicate args outright, which preflight
            # would classify as ARG_ERROR and abort the whole run. Build the
            # command correctly instead of depending on parser semantics.
            flags = _without(flags, ("-rate",)) + ["-rate", str(ctx.config.rate_override)]
        # A plain attribute, not getattr-with-a-default, for the reason
        # RunConfig.triage_file states: if this field is ever renamed away,
        # a getattr fallback would silently scan the level's full range
        # while the operator believed they had narrowed it. Raising loudly
        # is the safe failure here.
        if ctx.config.ports:
            # Same replacement rule as the rate above, and for a sharper
            # reason: a command carrying BOTH the level's `-p 1-65535` and
            # the operator's `-p 80,443` has not been narrowed at all, and
            # which one wins is a property of the parser rather than of
            # anything the operator can see. Strip whichever port form the
            # level used — low/mid use -top-ports, high/full use -p — so the
            # command can only ever name one selection.
            #
            # This control narrows a live `high` run: scope is per-HOST but
            # services are host:PORT, so an
            # all-ports scan of an authorised name reaches every service on
            # its IP, with no off-scope hostname for the scope guard to
            # refuse.
            from .. import ports as portspec
            flags = (_without(flags, portspec.PORT_FLAGS)
                     + portspec.flag_args(ctx.config.ports))
        from .. import resolvers
        return [str(binary), "-list", str(hosts_file), "-json", "-silent",
                "-duc", "-scan-all-ips",
                *flags, *resolvers.flag_args(ctx)]

    def parse(self, raw_path: Path) -> Iterator[Artifact]:
        found: dict[str, dict] = {}
        for line in Path(raw_path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = row.get("host") or row.get("ip") or ""
            port = row.get("port")
            if not host or port is None:
                continue
            value = f"{host}:{port}"
            ip = row.get("ip", "")
            if value not in found:
                found[value] = {
                    "host": host, "port": str(port), "ip": ip,
                    "ips": [ip] if ip else [],
                    "tls": bool(row.get("tls", False)),
                }
            else:
                if ip and ip not in found[value]["ips"]:
                    found[value]["ips"].append(ip)
                found[value]["tls"] = (
                    found[value]["tls"] or bool(row.get("tls", False))
                )
        for value, meta in found.items():
            yield Artifact(
                ArtifactKind.PORT, value, meta=meta,
            )
