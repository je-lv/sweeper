"""vhost stage — Host-header fuzzing for hidden virtual hosts.

Only meaningful results are those whose response differs from the baseline
that every non-existent vhost returns; identical responses are the wildcard
default and are suppressed.

A discovered vhost is emitted as an HTTP_SERVICE artifact as well as a
Finding. Reporting it without producing the artifact is the weaker half of
the feature: every downstream HTTP_SERVICE consumer (nuclei, katana,
jsrecon, arjun) reads the artifact pool, so a vhost that never enters the
store is found and then never probed, with nothing in the manifest saying
so. See parse() for how scope is handled -- the artifact is emitted, not
pre-filtered, precisely so the runner's admission choke point decides.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

from .. import useragents
from ..artifacts import Artifact, ArtifactKind, Finding

WORDLIST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"

#: ffuf's placeholder. Kept as a name because it appears in three places
#: that must agree: the Host header pattern, the row's input dict, and the
#: pattern echoed back in ffuf's own config block (which parse() reads to
#: re-qualify a bare label -- see _pattern_from_config).
FUZZ = "FUZZ"


def fuzz_host_pattern(target_host: str, allowed) -> str:
    """The Host header to fuzz, e.g. "FUZZ.vulnshop.test". "" if impossible.

    THE BUG THIS FIXES. The stage sent `Host: FUZZ` against a wordlist of
    bare DNS labels, so every request carried `Host: admin` instead of
    `Host: admin.vulnshop.test`. No virtual host matches a bare label, so
    every guess hit the server's default vhost and returned one identical
    wildcard response -- which the baseline filter below then correctly
    discarded as noise. The stage therefore could not discover a vhost
    against ANY target, while reporting "complete -- 0 findings".

    The suffix comes from the TARGET, not from a registrable-domain list:
    a subdomain fuzzes beside itself (git.acc.example -> FUZZ.acc.example),
    and an apex keeps its whole name (acc.example -> FUZZ.acc.example)
    because dropping a label there would leave a bare TLD and fuzz a
    namespace nobody authorized.

    An IP target has no domain to append, so the allowlist supplies one --
    that is where the engagement's authorized domains are. With no usable
    suffix this returns "" and the caller sends NO REQUESTS, rather than
    thousands that cannot route.
    """
    host = (target_host or "").strip().strip(".").lower()
    labels = host.split(".")
    is_ip = host and all(part.isdigit() for part in labels) and len(labels) == 4
    if host and not is_ip and ":" not in host:
        # 3+ labels: drop the leftmost and fuzz beside the target. 2 labels:
        # an apex, keep it whole.
        base = ".".join(labels[1:]) if len(labels) >= 3 else host
        if base.count(".") >= 1:
            return f"{FUZZ}.{base}"
    for entry in sorted(allowed or []):
        candidate = str(entry).strip().lower().lstrip("*").lstrip(".")
        if not candidate or ":" in candidate or candidate.count(".") < 1:
            continue
        if all(part.isdigit() for part in candidate.split(".")):
            continue      # an allowlisted IP is no better a suffix than the target
        return f"{FUZZ}.{candidate}"
    return ""


def select_origin(artifacts, permitted: list[str]) -> str:
    """The ONE origin to fuzz, chosen rather than taken.

    This stage fuzzes a single origin -- correctly, since every virtual host
    on a server shares its address, so one origin discovers all of them. That
    makes WHICH origin the whole game, and it used to be `permitted[0]`: an
    arbitrary pick out of an unordered pool.

    Observed against a lab: httpx records nginx's "plain HTTP request was
    sent to HTTPS port" 400 as a live HTTP service, so the pool contained
    `http://api.acc.example:8443` -- a protocol mismatch that answers 400 to
    everything. That sorted first, so the stage fuzzed it: 5000 requests,
    5000 identical errors, zero results, reported as a clean empty stage.

    Ranked, in order:

      * a WORKING origin first (2xx/3xx). A 400/500 origin cannot show a
        vhost difference because it never gets as far as routing on Host.
      * port 80, then 443, then anything else. On an https origin the TLS
        SNI comes from the URL while the vhost under test comes from the
        Host header, so the two disagree by construction and a server that
        routes on SNI never reveals the vhost. Plain HTTP has no such
        ambiguity.
      * URL, purely to make the choice deterministic -- preflight and the
        runner each call build_command, and a pick that varied between them
        would mean preflight validated a command that was never run.

    A pool with no working origin still yields one: 4xx everywhere can just
    mean the default vhost rejects unknown names, which is the condition
    this stage exists for.
    """
    allowed = set(permitted)
    best, best_key = "", None
    for art in artifacts:
        url = getattr(art, "value", "")
        if url not in allowed:
            continue
        meta = getattr(art, "meta", None) or {}
        try:
            status = int(meta.get("status_code") or 0)
        except (TypeError, ValueError):
            status = 0
        port = str(meta.get("port") or urlsplit(url).port or "")
        key = (
            0 if 200 <= status < 400 else 1,
            {"80": 0, "443": 1}.get(port, 2),
            url,
        )
        if best_key is None or key < best_key:
            best, best_key = url, key
    return best


def _pattern_from_config(doc: dict) -> str:
    """The Host pattern ffuf was run with, read back out of its own output.

    Returns "" when the file predates this stage sending a qualified Host
    header (or came from a hand-rolled ffuf run), in which case parse()
    falls back to the bare label -- the old behaviour, which is wrong but is
    still better than dropping an archived result on the floor.
    """
    headers = ((doc.get("config") or {}).get("headers") or {})
    for key, value in headers.items():
        if str(key).lower() == "host" and FUZZ in str(value):
            return str(value)
    return ""


class VhostStage:
    name = "vhost"
    enabled_levels = frozenset({"high", "full"})
    #: ffuf has no resolver option; it resolves through the system
    #: resolver.
    honors_resolver = False
    resolver_note = 'ffuf has no resolver option; it resolves through the system resolver.'
    requires = ["ffuf"]
    consumes = ArtifactKind.HTTP_SERVICE
    produces = {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING}
    optional = True
    # ffuf writes its own result file (-o) rather than emitting JSON on
    # stdout -- `-s` (silent) suppresses stdout entirely. Declaring this
    # (see the Stage protocol in stages/base.py, Task 3.5) tells the runner
    # to compute the SAME path build_command tells ffuf to write to, and to
    # never overwrite it with captured stdout. Getting this wrong is exactly
    # the defect that shipped before: parse() silently reading an empty
    # file on every run. See test_output_file_is_the_same_path_the_runner_
    # will_hand_to_parse and test_raw_suffix_and_writes_own_raw_are_declared.
    raw_suffix = "json"
    writes_own_raw = True
    # -t bounds CONCURRENCY (threads in flight); -rate bounds THROUGHPUT
    # (requests per second). They are not substitutes: 25 threads with no
    # rate cap is 25 threads going as fast as the target answers, which on a
    # fast origin is hundreds of requests per second at one host. ffuf's
    # own default is `-rate 0`, i.e. unbounded, so the cap has to be set
    # explicitly -- same reasoning as naabu's per-level -rate, and the same
    # client no-DoS rules-of-engagement term.
    #
    # The numbers are deliberately far below naabu's (150-1000): naabu's
    # rate counts SYN packets spread across a whole host list, while every
    # request here is a full HTTP request/response against ONE host, which
    # costs the target orders of magnitude more (TLS, app framework, DB).
    # One request per second per thread is the pacing rule, which keeps the
    # ~5000-entry wordlist to roughly 3.5 minutes at `high` and 2 minutes at
    # `full` -- fast enough to be useful, slow enough to sit under ordinary
    # WAF/rate-limit thresholds rather than tripping them (a scan that trips
    # rate limiting measures the rate limiter, not the application).
    levels = {
        "low":  [],
        "mid":  [],
        "high": ["-t", "25", "-rate", "25"],
        "full": ["-t", "40", "-rate", "40"],
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        from ..rate import replace_value_flag
        # .get(), not .values(): the CHOICE of origin needs each artifact's
        # meta (status_code, port) -- see select_origin for why taking the
        # first one is not good enough.
        artifacts = ctx.store.get(ArtifactKind.HTTP_SERVICE)
        permitted, _ = ctx.scope.filter([a.value for a in artifacts])
        target = select_origin(artifacts, permitted)
        # The Host header must carry a FULLY QUALIFIED name or it cannot match
        # a virtual host -- see fuzz_host_pattern. No usable suffix means no
        # command at all: the runner reads an empty argv as NO_INPUT and
        # records the stage as skipped, which is honest, where firing 5000
        # unroutable requests and reporting 0 findings is not.
        #
        # A missing PATTERN is the refusal, NOT an empty `target`. preflight
        # calls build_command before httpx has produced any HTTP_SERVICE, and
        # that probe (`-u ""`) is the only place this stage's flags get
        # validated against the real binary. At RUN time the runner has
        # already skipped the stage if its consume pool is empty, so an empty
        # target here only ever means "preflight".
        pattern = fuzz_host_pattern(urlsplit(target).hostname or target,
                                    getattr(ctx.scope, "allowed", set()))
        if not pattern:
            return []
        # Same path the runner will compute for parse() -- see raw_suffix /
        # writes_own_raw above. Deriving it from self.name/self.raw_suffix
        # (rather than hardcoding "vhost"/"json" separately here) is what
        # keeps build_command's -o and the runner's raw_path from ever being
        # able to drift apart.
        outfile = ctx.raw_path(self.name, self.raw_suffix)
        outfile.parent.mkdir(parents=True, exist_ok=True)
        flags = replace_value_flag(
            self.levels[ctx.config.level], ("-rate",), "-rate",
            ctx.config.rate_override,
        )
        cmd = [str(binaries.resolve("ffuf")), "-u", target,
                "-H", f"Host: {pattern}",
                *useragents.header_args_for(ctx.user_agent),
                "-w", WORDLIST,
                "-o", str(outfile), "-of", "json", "-s",
                *flags]
        if ctx.config.proxy:
            cmd += ["-x", ctx.config.proxy]
        return cmd

    def parse(self, raw_path: Path) -> Iterator[Artifact | Finding]:
        # ffuf -of json emits a single object: {"results": [...], "config": {...}}.
        # It is NOT jsonl. Reading it line-by-line silently yields nothing.
        path = Path(raw_path)
        if not path.exists() or not path.read_text(encoding="utf-8").strip():
            return
        try:
            doc = json.loads(path.read_text(encoding="utf-8")) or {}
        except json.JSONDecodeError:
            return
        rows = doc.get("results") or []
        if not rows:
            return
        # ffuf echoes the headers it was given into its own config block, so
        # the Host PATTERN this run used is recoverable from the evidence
        # file alone. parse() takes only a path (no ctx), and re-deriving the
        # pattern here rather than passing it in keeps the raw file
        # self-describing: an operator re-parsing an archived vhost.json gets
        # the same fully-qualified names the live run did.
        pattern = _pattern_from_config(doc)

        # The response shape returned by the majority of guesses is the
        # wildcard baseline; anything matching it is not a real vhost.
        shapes = Counter((r.get("length"), r.get("words")) for r in rows)
        baseline, _count = shapes.most_common(1)[0]

        raw_ref = f"raw/{self.name}.{self.raw_suffix}"
        for row in rows:
            if (row.get("length"), row.get("words")) == baseline:
                continue
            # The Host header actually sent. Real ffuf echoes it back as the
            # row's "host" field (verified against ffuf 2.1.0-dev), but FUZZ
            # is the value this stage itself substituted, so it is the
            # authority; "host" is only a fallback.
            label = (row.get("input") or {}).get(FUZZ, "") or row.get("host", "")
            if not label:
                continue
            # The FULLY QUALIFIED vhost, not the bare wordlist label. A
            # finding that says "admin" is not actionable, and worse, the
            # runner's admission check matches meta["host"] against the
            # allowlist -- a bare label matches nothing, so the artifact this
            # stage just discovered would be refused as out of scope.
            name = pattern.replace(FUZZ, label) if pattern else label

            url = row.get("url", "")
            scheme = urlsplit(url).scheme or "https"

            # meta["host"] is the DISCOVERED VHOST NAME, never the IP or the
            # original target, and that choice is the whole scope story here.
            # runner.py's admission choke point reads meta["host"] for an
            # HTTP_SERVICE and refuses the artifact unless that hostname is
            # in the allowlist, recording it as a discovery refusal instead.
            #
            # That is the intended outcome. A hidden vhost served from an
            # in-scope IP may belong to an entirely different tenant or
            # customer: the TCP connection being to an authorized address
            # does not make the VIRTUAL HOST authorized. So a discovered
            # vhost gets exactly the treatment subfinder's discovered
            # subdomains get -- surfaced and counted, but not scanned until
            # an operator widens scope. There is deliberately no
            # special-casing here; emitting the artifact with the right
            # meta["host"] is all it takes for the existing machinery to do
            # the right thing.
            yield Artifact(
                ArtifactKind.HTTP_SERVICE, f"{scheme}://{name}",
                meta={"host": name, "vhost": name, "src": self.name,
                      "status_code": row.get("status"),
                      "content_length": row.get("length"),
                      "origin_url": url},
            )

            yield Finding(
                stage="vhost", severity="medium",
                title="Hidden virtual host responds differently",
                target=row.get("url", ""), template_id="vhost-discovered",
                # matcher=name: target is the ORIGIN url and template_id is
                # a constant, so every vhost discovered under one origin
                # shares (stage, target, template_id) -- with no matcher
                # they all hash to the SAME finding_id and
                # store.add_finding() kept only the first, discarding every
                # other hidden vhost this stage exists to find. `name` (the
                # Host header actually sent, see above) is intrinsic to the
                # discovery itself and identical on a rerun against the same
                # origin and wordlist, so this keeps finding_id stable
                # across runs (see artifacts.finding_id's docstring) while
                # making two distinct vhosts hash differently.
                matcher=name,
                evidence=f"Host: {name} -> status={row.get('status')} "
                         f"length={row.get('length')}",
                raw_ref=raw_ref,
                description="This Host header returns a response distinct from the "
                            "wildcard baseline, indicating a virtual host not linked "
                            "from the main site.",
                remediation="Confirm the vhost is intended to be reachable; restrict "
                            "internal hosts at the edge.",
            )
