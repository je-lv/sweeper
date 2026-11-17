"""cdncheck stage — CDN/WAF/cloud fronting detection.

Runs before port scanning so downstream results can be read correctly: a
port list for a CDN edge describes the CDN, not the target. The inverse is
a finding — a host not behind the CDN/WAF its siblings use may be the
origin, reachable directly and bypassing edge protections. "Is behind a
CDN" is normal and not itself a finding; only an unfronted outlier among
fronted siblings is.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..artifacts import Artifact, ArtifactKind, Finding

# Filename for the query-list sidecar build_command writes next to the raw
# output, following the same "-input.txt beside raw/<stage>.jsonl" idiom
# naabu/dnsx/httpx already use for their own input files.
INPUT_SIDECAR = "cdncheck-input.txt"


class CdncheckStage:
    name = "cdncheck"
    #: This tool takes an operator-supplied resolver; see
    #: sweeper.resolvers and run.json's "resolver" block.
    honors_resolver = True
    requires = ["cdncheck"]
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.HOST, ArtifactKind.FINDING}
    optional = True
    # cdncheck's own work is DNS-only lookups against public provider IP
    # ranges, not per-target probing, so there is nothing to escalate across
    # levels the way port count or script intrusiveness escalates elsewhere.
    levels = {"low": [], "mid": [], "high": [], "full": []}

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        infile = ctx.run_dir / "raw" / INPUT_SIDECAR
        infile.parent.mkdir(parents=True, exist_ok=True)
        permitted, _ = ctx.scope.filter(ctx.store.values(ArtifactKind.HOST))
        infile.write_text("\n".join(permitted) + "\n", encoding="utf-8")
        # Flags verified against cdncheck v1.2.46 on this machine:
        #   input is -i/-input (NOT -l); goflags accepts a file path here.
        #   json output is -jsonl/-j (NOT -json — that flag does not exist).
        # Both wrong forms are hard argument errors that abort the whole run.
        # -resp is deliberately absent: verified against v1.2.46 that the
        # -jsonl output is byte-identical with and without it, because -resp
        # only affects the human-readable CLI format that -jsonl replaces.
        from .. import resolvers
        return [str(binaries.resolve("cdncheck")), "-i", str(infile),
                "-jsonl", "-silent", "-duc",
                *resolvers.flag_args(ctx)]

    def parse(self, raw_path: Path) -> Iterator[Artifact | Finding]:
        raw_path = Path(raw_path)
        matched: dict[str, dict] = {}

        for line in raw_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            host = row.get("input", "")
            if not host:
                continue
            meta = {
                "ip": row.get("ip", ""),
                "cdn": bool(row.get("cdn", False)),
                "cdn_name": row.get("cdn_name", ""),
                "waf": bool(row.get("waf", False)),
                "waf_name": row.get("waf_name", ""),
                "cloud": bool(row.get("cloud", False)),
                "cloud_name": row.get("cloud_name", ""),
            }
            matched[host] = meta
            yield Artifact(ArtifactKind.HOST, host, meta=meta)

        # cdncheck emits a JSON line ONLY for a host it recognises as CDN or
        # WAF fronted — verified against the real v1.2.46 binary: a host with
        # no match produces NO output line at all ("[INF] No results found."
        # on stderr when every queried host misses), never a {"cdn": false}
        # row. So "not fronted" can only be read by diffing the query list
        # against what came back, not by a field on a row that will never
        # exist. The query list is the sidecar file build_command writes
        # next to the raw output (see INPUT_SIDECAR).
        sidecar = raw_path.parent / INPUT_SIDECAR
        if not sidecar.exists():
            return
        queried = [h.strip() for h in
                   sidecar.read_text(encoding="utf-8").splitlines() if h.strip()]

        # `cloud` is deliberately NOT part of `fronted`, and must not be
        # added. cdncheck's `cloud` means "this IP belongs to AWS/Azure/GCP
        # etc." — a hosting fact, not an edge-protection fact. A bare EC2 box
        # with a public IP is cloud:true and has no CDN or WAF in front of
        # it, so counting cloud as fronted would suppress exactly the origin
        # exposures this finding exists to catch: most exposed origins ARE
        # cloud-hosted. Pinned by
        # test_cloud_only_sibling_still_counts_as_exposed.
        fronted = {h for h, m in matched.items() if m["cdn"] or m["waf"]}
        if not fronted:
            # Nothing in this batch is CDN/WAF-fronted, so there is no
            # baseline to call any single host an outlier against. A site
            # with no CDN/WAF anywhere is the normal case, not a finding —
            # flagging every host here would just be noise. See the module
            # docstring.
            return

        for host in queried:
            if host in fronted:
                continue
            yield Finding(
                stage="cdncheck", severity="low",
                title="Host not behind CDN or WAF while siblings are",
                target=host, template_id="cdn-origin-exposed",
                evidence=f"{host}: no CDN/WAF match, unlike {sorted(fronted)}",
                raw_ref="raw/cdncheck.jsonl",
                description="Sibling hosts in this engagement are CDN- or "
                            "WAF-fronted but this one is not. It may be the "
                            "origin, reachable directly and bypassing edge "
                            "protections.",
                remediation="Place the host behind the CDN/WAF, or restrict "
                            "origin access to the CDN's published egress "
                            "ranges.",
            )
