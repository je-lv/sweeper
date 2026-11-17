"""httpx stage — probe discovered ports for live HTTP services.

Binary is resolved by absolute path. /usr/bin/httpx on Kali is the Python
HTTP client; running it here would fail in a confusing way.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .. import useragents
from ..artifacts import Artifact, ArtifactKind


class HttpxStage:
    name = "httpx"
    #: This tool takes an operator-supplied resolver; see
    #: sweeper.resolvers and run.json's "resolver" block.
    honors_resolver = True
    requires = ["httpx"]
    consumes = ArtifactKind.PORT
    produces = {ArtifactKind.HTTP_SERVICE}
    optional = False
    # -nf (no-fallback) is at EVERY level, `low` included, and is not
    # optional. Without it httpx probes one scheme per port and stops at the
    # first response -- and nginx answers a plain-HTTP request to a TLS port
    # with "400 The plain HTTP request was sent to HTTPS port", which IS a
    # response. So `host:8443` was recorded as http://host:8443 (400) and the
    # real https://host:8443 (200) behind it was never probed at all.
    #
    # Measured against a lab: eighteen such entries in the store, every one a
    # protocol mismatch, and not one of the HTTPS services behind them. nginx
    # is most of the web, so this silently erased any HTTPS service on a
    # non-443 port. The bogus half is still recorded -- it is genuinely what
    # the port returns to an HTTP request -- and consumers that need a
    # working origin filter on status (stages/arjun.probeable,
    # stages/vhost.select_origin).
    #
    # It costs at most one extra probe per port, which is the cheapest
    # request this tool makes, against never seeing a service at all.
    levels = {
        "low":  ["-status-code", "-title", "-tech-detect", "-tls-grab", "-nf"],
        "mid":  ["-status-code", "-title", "-tech-detect", "-tls-grab", "-nf",
                 "-favicon", "-jarm", "-cdn", "-web-server"],
        "high": ["-status-code", "-title", "-tech-detect", "-tls-grab", "-nf",
                 "-favicon", "-jarm", "-cdn", "-web-server", "-include-response"],
        "full": ["-status-code", "-title", "-tech-detect", "-tls-grab", "-nf",
                 "-favicon", "-jarm", "-cdn", "-web-server", "-include-response"],
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        from ..rate import replace_value_flag
        binary = binaries.resolve("httpx")
        infile = ctx.run_dir / "raw" / "httpx-input.txt"
        infile.parent.mkdir(parents=True, exist_ok=True)
        permitted, _ = ctx.scope.filter(ctx.store.values(ArtifactKind.PORT))
        infile.write_text("\n".join(permitted) + "\n", encoding="utf-8")
        cmd = [str(binary), "-list", str(infile), "-json", "-silent", "-duc"]
        # httpx's -probe-all-ips is incompatible with -proxy: in v1.7.2 it
        # rewrites the proxy destination to each resolved target IP while
        # retaining the proxy's port. A proxy at 127.0.0.1:8080 therefore
        # becomes target-ip:8080, bypassing the proxy and the operator's port
        # selection. Let the proxy resolve the hostname instead.
        if not ctx.config.proxy:
            cmd.append("-probe-all-ips")
        cmd += replace_value_flag(
            self.levels[ctx.config.level], ("-rl", "-rate-limit"),
            "-rl", ctx.config.rate_override,
        )
        # ctx.user_agent, not a fresh draw: build_command must be
        # deterministic or preflight validates a different argv than we run.
        cmd += useragents.header_args_for(ctx.user_agent)
        if ctx.config.proxy:
            cmd += ["-proxy", ctx.config.proxy]
        from .. import resolvers
        cmd += resolvers.flag_args(ctx)
        return cmd

    def parse(self, raw_path: Path) -> Iterator[Artifact]:
        for line in Path(raw_path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("failed"):
                continue
            # Burp returns its own branded HTML error page when it cannot
            # establish the requested upstream connection. httpx sees that
            # proxy-generated response as a successful 200 and would record
            # non-HTTP ports (53 in the live validation) as web services.
            # ProjectDiscovery also fingerprints the page as an error, so
            # require both signals rather than dropping a real application
            # merely because somebody gave it the title "Burp Suite".
            knowledge = row.get("knowledgebase") or {}
            if (row.get("title") == "Burp Suite"
                    and knowledge.get("PageType") == "error"):
                continue
            url = row.get("url", "")
            if not url:
                continue
            addresses = row.get("a") or []
            if isinstance(addresses, str):
                addresses = [addresses]
            observed_ip = row.get("ip")
            if observed_ip and observed_ip not in addresses:
                addresses = [*addresses, observed_ip]
            yield Artifact(
                ArtifactKind.HTTP_SERVICE, url,
                meta={
                    "host": row.get("host", ""),
                    "port": str(row.get("port", "")),
                    "scheme": row.get("scheme", ""),
                    "status_code": row.get("status_code", 0),
                    "title": row.get("title", ""),
                    "webserver": row.get("webserver", ""),
                    "tech": row.get("tech", []),
                    "content_length": row.get("content_length", 0),
                    "cdn_name": row.get("cdn_name", ""),
                    # httpx may emit the DNS set as ``a`` and some versions
                    # also identify the backend used as ``ip``. Preserve the
                    # union so URL-level deduplication does not erase which
                    # addresses were actually in play during the probe.
                    "ips": addresses,
                },
            )

    def empty_result_error(self, ctx) -> str:
        """Explain an empty result when the configured proxy has disappeared.

        ProjectDiscovery httpx exits 0 and emits nothing when an HTTP proxy
        refuses connections. Without this post-run check, a Burp restart in
        the middle of a long infrastructure scan becomes a false clean HTTP
        result even if the proxy was healthy during preflight.
        """
        if not ctx.config.proxy:
            return ""
        from ..preflight import proxy_reachable
        try:
            reachable = proxy_reachable(ctx.config.proxy)
        except ValueError as exc:
            return f"invalid proxy configuration: {exc}"
        if not reachable:
            return ("configured proxy became unreachable and httpx returned "
                    "no output")
        return ""
