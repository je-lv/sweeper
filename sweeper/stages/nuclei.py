"""nuclei stage — template scanning.

Two hard rules enforced here, both with tests, both non-negotiable per the
client's rules of engagement:
  1. -exclude-tags dos is passed at EVERY level, unconditionally. DoS and
     ReDoS payloads are excluded by policy, not by default setting.
  2. -dast is passed ONLY at full. dast mutates request parameters, and
     `full` is the only level permitted to do that.

The binary is the pinned pdtm build (v3.11.0, ~/.pdtm/go/bin/nuclei).
/usr/bin/nuclei (v3.8.0) must never be used, or findings become
irreproducible -- binaries.py's KNOWN_BINARIES entry for "nuclei" only
lists the pdtm candidate, so binaries.resolve("nuclei") already refuses to
fall back to /usr/bin; this stage must not duplicate or second-guess that
list.

Credentials: nuclei takes them via `-secret-file <path>` (see auth.py's
to_nuclei_secret_file), so only a filesystem path ever appears in this
stage's argv -- no residual `ps` exposure the way arjun.py has.

build_command REWRITES that file rather than passing it through. nuclei is
driven with `-list`, so a credential whose `domains-regex` is a constant is
offered to every host in the run; it has to be anchored to the authorities
this run actually contacts, and this stage is the only place that set is
known -- app.execute() writes the file before httpx has produced a single
HTTP_SERVICE artifact. ctx.auth is therefore read here (nowhere else in
this module), and only to re-emit the same file with the scope-filtered
`-list` contents as its authority set. See auth.authority_regexes.

Finding-id collisions: nuclei is the highest-risk stage for this. One
template can match the same host more than once (a directory-listing
template hitting several exposed paths, a secrets-detection style
extractor pulling more than one value off one page). nuclei's own
"matcher-name" field is frequently ABSENT -- verified against the real
v3.11.0 binary: it is only emitted when a template declares MORE THAN ONE
named matcher; the common case of a single matcher (or an extractor with
no named matcher at all) omits the key entirely. Relying on matcher-name
alone therefore collapses distinct matches of the same template onto one
`matcher` value, and Finding.id hashes (stage, target, template_id,
matcher) with no `matched_at` or evidence in the mix (see
artifacts.finding_id's docstring) -- so an empty, constant matcher lets a
genuinely different finding silently overwrite an earlier one in
ArtifactStore.add_finding(), exactly the defect its docstring warns about
and that has already hit dnsx/tlsx/vhost/nmap. `matched-at` (the specific
URL/path a match landed on) and `extracted-results` (what an extractor
pulled out) are both intrinsic to the match itself and repeat identically
on a rerun, so parse() folds them into `matcher` alongside matcher-name
rather than using matcher-name verbatim.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .. import useragents
from ..artifacts import SEVERITIES, ArtifactKind, Finding

# Never negotiable, at any level. Passed unconditionally in build_command,
# not merely defaulted, so no future flag-set edit can drop it by accident.
ALWAYS_EXCLUDE_TAGS = "dos"

TAGS = {
    "low":  ["tech", "exposure", "misconfiguration"],
    "mid":  ["tech", "exposure", "misconfiguration", "cve", "takeover",
             "default-login", "exposed-panels", "ssl", "dns", "network"],
    "high": [],   # empty = all templates
    "full": [],
}

SEVERITY_FLAGS = {
    "low":  ["-severity", "info,low"],
    "mid":  [],
    "high": [],
    "full": [],
}


#: nginx's answer to a plain-HTTP request on a TLS port. httpx runs with -nf
#: and records it deliberately (see stages/httpx.py: without -nf the real
#: HTTPS service behind it is never probed at all), so the store legitimately
#: holds both halves. arjun and vhost already filter this out; nuclei spent
#: three of its live-run targets on it and hit its time limit having produced
#: nothing.
PROTOCOL_MISMATCH = "plain http request was sent to https port"


def scannable(artifact) -> bool:
    """False for a service that is only a protocol mismatch.

    Deliberately narrow: an ORDINARY 400 is a real response from a real
    service and plenty of templates fire on one. Only the specific
    plain-HTTP-to-TLS-port answer is dropped, and only when the title says
    so -- a service with no recorded title or status is kept, because katana
    and jsrecon contribute URLs that never went through httpx.
    """
    meta = getattr(artifact, "meta", None) or {}
    title = str(meta.get("title") or "").lower()
    return PROTOCOL_MISMATCH not in title



class NucleiStage:
    name = "nuclei"
    #: This tool takes an operator-supplied resolver; see
    #: sweeper.resolvers and run.json's "resolver" block.
    honors_resolver = True
    requires = ["nuclei"]
    # HTTP_SERVICE is what ORDERS this stage (it must follow httpx), but the
    # command also reads PORT artifacts -- see build_command. Declared here so
    # the registry cannot schedule nuclei before naabu has produced them.
    consumes = ArtifactKind.HTTP_SERVICE
    consumes_any = {
        ArtifactKind.HTTP_SERVICE, ArtifactKind.PORT, ArtifactKind.UDP_PORT,
    }
    produces = {ArtifactKind.FINDING}
    optional = False
    levels = {
        "low":  ["-rate-limit", "50", "-c", "10"],
        "mid":  ["-rate-limit", "150", "-c", "25"],
        "high": ["-rate-limit", "250", "-c", "40", "-headless"],
        # -dast ONLY here: it mutates request parameters (SQLi/XSS-style
        # fuzzing of discovered params), which is exactly the class of
        # state-changing behaviour low/mid/high are defined not to do. See
        # test_dast_only_at_full.
        "full": ["-rate-limit", "300", "-c", "50", "-headless", "-dast"],
    }

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        from ..rate import replace_value_flag
        level = ctx.config.level
        infile = ctx.run_dir / "raw" / "nuclei-input.txt"
        infile.parent.mkdir(parents=True, exist_ok=True)
        services = [a for a in ctx.store.get(ArtifactKind.HTTP_SERVICE)
                    if scannable(a)]
        permitted, _ = ctx.scope.filter([a.value for a in services])
        # The NON-HTTP services as well, as bare host:port. Without them every
        # network-protocol template in the library is unreachable no matter
        # what the scan discovers -- on a stock install that is the SNMP, SSH,
        # SMTP, FTP, database and network-level TLS checks. naabu finds those
        # ports and tlsx probes their certificates, so they were discovered,
        # inventoried, and then never assessed: the stage reported `complete`
        # having skipped a whole class of infrastructure finding.
        #
        # Web ports keep their scheme and are NOT repeated here. nuclei needs
        # the scheme to select HTTP templates, and sending the same endpoint
        # twice doubles the traffic to a client for no extra coverage.
        covered = set()
        for url in permitted:
            rest = url.split("://", 1)[-1].split("/", 1)[0]
            covered.add(rest)
            host, _, port = rest.rpartition(":")
            if host and port:
                covered.add(rest)
        ports_permitted, _ = ctx.scope.filter(ctx.store.values(ArtifactKind.PORT))
        network = [p for p in ports_permitted if p not in covered]
        udp_permitted, _ = ctx.scope.filter(
            ctx.store.values(ArtifactKind.UDP_PORT)
        )
        # Nuclei's network templates select TCP or UDP themselves. The
        # endpoint syntax remains host:port; transport provenance stays in
        # udp_ports.jsonl and the report inventory. Deduplicate where the
        # same numeric endpoint is open on both transports.
        lines = list(permitted) + network + [
            p for p in udp_permitted if p not in network
        ]
        infile.write_text("\n".join(lines) + "\n", encoding="utf-8")

        cmd = [str(binaries.resolve("nuclei")), "-list", str(infile),
               "-jsonl", "-silent",
               "-scan-all-ips",
               # -dr, unconditional at every level. A redirect is a second,
               # independent way out of scope that the allowlist cannot see:
               # ctx.scope only ever vets the URL we HAND the tool, never
               # where that URL sends it next.
               #
               # MEASURED against a lab, not reasoned about. An in-scope
               # /assets/js/legacy-tracker.js answers 302 with
               # Location: http://offscope.example.test/leaked.js -- a
               # different registrable domain, in no allowlist. Without this
               # flag nuclei followed it:
               #     "matched-at": "http://offscope.example.test/leaked.js"
               # and the target's off-scope tripwire logged the request. With
               # it, the scan is clean AND the 302 is still reported, matched
               # at the in-scope URL -- the finding survives, only the hop is
               # refused.
               #
               # It is not nuclei's CLI default that causes this: `redirects:
               # true` is set inside individual template YAML, which 1575
               # shipped templates do, including ones tagged
               # `misconfiguration` -- a tag this stage selects at every
               # level. A per-template setting cannot be bounded by an
               # allowlist, so the control has to be global.
               #
               # Same defect and same fix as katana's -dr; see that module.
               # -fhr (same-host redirects only) also closed the escape when
               # measured and would in principle keep same-host hops, but no
               # test could show it actually following one, so the proven
               # fail-closed option is used instead.
               "-dr",
               # Unconditional, at every level -- see ALWAYS_EXCLUDE_TAGS
               # and test_dos_excluded_at_every_level.
               "-exclude-tags", ALWAYS_EXCLUDE_TAGS,
               # -disable-update-check, also unconditional. CONFIRMED
               # empirically against the pinned v3.11.0, not assumed: with
               # the flag absent, a scan rewrites
               # ~/.config/nuclei/.templates-config.json and refreshes its
               # "nuclei-latest-version" / "nuclei-templates-latest-version"
               # fields -- values that can only come from a remote source.
               # With -duc the file is not touched at all. (nuclei's own
               # config documents `disable-update-check: false` as the
               # default, i.e. the check is ON unless asked otherwise.)
               #
               # Two reasons this is not optional on an engagement. It is an
               # outbound connection to a THIRD PARTY (ProjectDiscovery)
               # made mid-engagement, which is disclosable and is not
               # covered by the client's scope allowlist -- ctx.scope guards
               # where we send SCAN traffic, and nothing else would have
               # caught this. And on a network-isolated or egress-filtered
               # box that check blocks rather than fails fast, silently
               # burning the stage's whole timeout budget before any
               # template runs; the run then reports as degraded with no
               # indication that a phone-home, not the target, caused it.
               "-duc"]

        if TAGS[level]:
            cmd += ["-tags", ",".join(TAGS[level])]
        cmd += SEVERITY_FLAGS[level]
        cmd += replace_value_flag(
            self.levels[level], ("-rate-limit", "-rl"),
            "-rate-limit", ctx.config.rate_override,
        )

        cmd += useragents.header_args_for(ctx.user_agent)
        if level == "low":
            cmd.append("-no-interactsh")     # OAST off at low only
        if ctx.config.time_limit:
            cmd += ["-timeout", "10"]
        if ctx.config.proxy:
            cmd += ["-proxy", ctx.config.proxy]
        secret_file = getattr(ctx, "secret_file", None)
        if secret_file:
            bundle = getattr(ctx, "auth", None)
            if bundle is not None and not bundle.is_empty():
                # Rewritten HERE, not left as app.execute() wrote it. The
                # credential is scoped to the authorities it is offered to,
                # and `permitted` above -- the scope-filtered HTTP_SERVICE
                # values that are about to become this stage's `-list` -- is
                # the exact set of authorities this run will contact. It does
                # not exist any earlier: app.execute() writes the file before
                # httpx has produced a single HTTP_SERVICE artifact, so the
                # file it writes deliberately matches nothing, and this is the
                # last point at which the real set is known.
                #
                # A constant is what shipped twice: `domains: ["*"]` matched
                # no authority (every "authenticated" run scanned anonymously)
                # and `domains-regex: [".*"]` matched every authority, handing
                # the client's session token to every host in the run instead
                # of the ones it was issued for. See auth.authority_regexes.
                #
                # Only when a bundle is actually present. A secret_file with
                # no ctx.auth cannot be rescoped -- there is nothing to
                # rewrite it from -- and overwriting it with an empty bundle
                # would be worse than leaving it: the file already on disk is
                # the fail-closed one.
                from ..auth import to_nuclei_secret_file
                secret_file = to_nuclei_secret_file(
                    bundle, Path(secret_file), run_dir=ctx.run_dir,
                    authorities=permitted,
                )
            # A PATH only -- the live credential values never touch this
            # argv. See auth.to_nuclei_secret_file and the module docstring.
            cmd += ["-secret-file", str(secret_file)]
        if getattr(ctx.config, "custom_templates", ""):
            cmd += ["-t", str(ctx.config.custom_templates)]
        # file_args, not flag_args: nuclei's -r is the one resolver option
        # here that takes a FILE PATH rather than a comma-separated list
        # (verified against v3.8.0's own help text). Passing the list form
        # would make nuclei try to open "1.1.1.1:53" as a filename.
        from .. import resolvers
        cmd += resolvers.file_args(ctx)
        return cmd

    def parse(self, raw_path: Path) -> Iterator[Finding]:
        for lineno, line in enumerate(
            Path(raw_path).read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = row.get("info") or {}
            severity = (info.get("severity") or "info").lower()
            if severity not in SEVERITIES:
                severity = "info"
            extracted = list(row.get("extracted-results") or [])
            evidence = ", ".join(extracted)
            matched_at = row.get("matched-at", "")
            # See the module docstring: matcher-name alone is frequently
            # empty/absent, so matched-at and any extracted result are
            # folded in too -- both are intrinsic to THIS match and stable
            # across a rerun of the same scan, so finding_id() stays stable
            # (Plan 3's diffing depends on that) while two genuinely
            # different matches of one template on one host no longer
            # collapse onto the same id. Never a counter or index: that
            # would not survive a rerun. See
            # test_two_matches_of_one_template_on_one_target_produce_two_findings
            # and test_finding_ids_are_stable_across_a_rerun_of_the_same_scan.
            matcher = "|".join(
                part for part in (row.get("matcher-name", ""), matched_at, evidence)
                if part
            )
            yield Finding(
                stage="nuclei", severity=severity,
                title=info.get("name", row.get("template-id", "nuclei finding")),
                target=row.get("host", ""),
                template_id=row.get("template-id", ""),
                matcher=matcher,
                matched_at=matched_at,
                description=info.get("description", ""),
                remediation=info.get("remediation", ""),
                references=list(info.get("reference") or []),
                evidence=evidence,
                raw_ref=f"raw/nuclei.jsonl#L{lineno}",
            )
