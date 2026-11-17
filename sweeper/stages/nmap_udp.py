"""Bounded UDP discovery and service detection with nmap.

UDP is kept in its own artifact kind so tcp/53 and udp/53 are both preserved
instead of one silently overwriting the other in the artifact store. The
default depth is deliberately smaller than TCP because an unanswered UDP
probe is ambiguous and retries are expensive: low top-20, mid top-100, and
high/full top-1000. ``--udp-ports`` replaces those defaults.
"""
from __future__ import annotations

from pathlib import Path

from ..artifacts import ArtifactKind
from .nmap import NmapStage


class NmapUdpStage(NmapStage):
    name = "nmap_udp"
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.UDP_PORT, ArtifactKind.FINDING}
    artifact_kind = ArtifactKind.UDP_PORT
    protocols = {"udp"}
    accepted_states = {"open", "open|filtered"}
    optional = True
    levels = {
        "low": ["-sV", "--version-intensity", "1"],
        "mid": ["-sV", "--version-intensity", "2"],
        "high": ["-sV", "--version-intensity", "5"],
        "full": ["-sV", "--version-intensity", "5"],
    }
    default_top = {"low": "20", "mid": "100", "high": "1000", "full": "1000"}

    def build_command(self, ctx) -> list[str]:
        from .. import binaries, ports

        permitted, _ = ctx.scope.filter(ctx.store.values(ArtifactKind.HOST))
        hosts_file = ctx.run_dir / "raw" / "nmap_udp-input.txt"
        hosts_file.parent.mkdir(parents=True, exist_ok=True)
        hosts_file.write_text("\n".join(permitted) + "\n", encoding="utf-8")

        selection = (ports.nmap_flag_args(ctx.config.udp_ports)
                     if ctx.config.udp_ports
                     else ["--top-ports", self.default_top[ctx.config.level]])
        cmd = [
            str(binaries.resolve("nmap")), "-Pn", "-n", "--resolve-all",
            "-sU", "-iL", str(hosts_file), *selection,
            *self.levels[ctx.config.level], "-oX", "-",
        ]
        if ctx.config.rate_override:
            cmd += ["--max-rate", str(ctx.config.rate_override)]
        return cmd
