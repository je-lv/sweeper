"""Markdown report.

Includes an explicit coverage section naming every stage that did not run
(or ran to only partial completion) and why. A report that silently omits a
skipped, failed, or partial stage reads as complete coverage when it is
not — that has been this project's most common defect, so the coverage
section and the DEGRADED banner are treated as the report's primary
function, not its footer.
"""
from __future__ import annotations

from pathlib import Path

from ..artifacts import ArtifactKind
from ..stages.base import summarize_coverage

ORDER = ("critical", "high", "medium", "low", "info")

# The asset inventory, in the order a reader wants it and under the labels
# both reports use. One definition: the HTML report imports this, so the two
# deliverables cannot end up listing different inventories for one run.
ASSET_KINDS = (
    (ArtifactKind.HOST, "Hosts"),
    (ArtifactKind.DNS_RECORD, "DNS records"),
    (ArtifactKind.PORT, "Ports"),
    (ArtifactKind.UDP_PORT, "UDP endpoints (open or open|filtered)"),
    (ArtifactKind.HTTP_SERVICE, "HTTP services"),
)

# A `full`-level scan can turn up thousands of ports. Printing every one as
# a bullet makes the report unreadable and the file huge, and buries the
# findings and coverage sections that matter more; cap the inline listing
# and point the reader at the full artifact file on disk instead.
INVENTORY_CAP = 200


def _inline(text: str) -> str:
    """Make arbitrary text safe inside an inline code span.

    RULE: every value interpolated into a `...` span goes through this.
    Findings, targets, template ids, inventory values and refused targets all
    originate outside this program — scanner templates, HTTP responses,
    crawled URLs — and a single backtick unbalances the span so the rest of
    the line escapes as prose. Escaping some of them and not others is worse
    than escaping none, because it reads as handled.

    Newlines break the bullet structure, so they are folded too. Replace
    rather than escape: inside a code span a backslash is literal, so there
    is nothing to escape with. This is a deliberate asymmetry with _cell(),
    which escapes the pipe because \\| does render literally in a table;
    each is correct for its context.

    test_every_line_has_balanced_backticks is the general guard: it walks the
    whole rendered report and catches the next span added without _inline.
    """
    return (str(text)
            .replace("`", "'")
            .replace("\r", " ")
            .replace("\n", " ")
            .strip())


def _prose(text: str) -> str:
    """Collapse newlines in free text so a bullet stays one bullet.

    Also neutralises backticks, because prose can share a line with a code
    span: the Stage/Template bullet renders `_prose(stage)` and an
    `_inline(template_id)` span on one line, and a stray backtick in the
    prose half pairs with the span's OPENING delimiter, capturing it and
    letting template_id escape as prose. Balanced backticks per line is the
    invariant; prose has to hold up its end of it.
    """
    return " ".join(str(text).replace("`", "'").split())


def _cell(text: str) -> str:
    """Make arbitrary text safe to place in a Markdown table cell.

    Finding titles, evidence and stage failure reasons are
    attacker-influenced — they come from scanner templates and HTTP
    responses. An unescaped pipe breaks the row into spurious columns and a
    newline splits it across lines, which matters most in the coverage
    table: its reason column carries raw tool output and it is what a
    reader relies on to know what was not scanned.

    Backticks are neutralised here too: a table row is one line, so two
    cells each carrying a stray backtick would pair across the cell
    boundary and render the text between them as a code span. The coverage
    table is the section a reader relies on most, so it does not get to be
    the one that renders wrong.
    """
    return (str(text)
            .replace("\\", "\\\\")
            .replace("`", "'")
            .replace("|", "\\|")
            .replace("\r", " ")
            .replace("\n", " ")
            .strip())


def render_markdown(ctx, results) -> str:
    store = ctx.store
    findings = store.findings
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ORDER}
    aborted = getattr(ctx, "aborted_reason", "")
    # One definition, shared with the HTML report and (via is_degraded) the
    # manifest. See summarize_coverage().
    summary = summarize_coverage(results, ctx.coverage, aborted)
    degraded = summary.degraded

    out: list[str] = []
    add = out.append

    add(f"# sweeper report — {ctx.run_dir.name}\n")
    if aborted:
        add("> **RUN ABORTED** — the scan stopped before completing. "
            "Nothing below represents full coverage.\n>\n"
            f"> Reason: {_prose(aborted)}\n")
    elif degraded:
        add("> **DEGRADED RUN** — one or more stages did not complete fully. "
            "See *Coverage* below before treating this as full coverage.\n")

    # A finding-id collision means some stage's matcher failed to
    # distinguish two genuinely different findings -- the first was kept,
    # the second was not, and every severity/asset count below is drawn from
    # what the store actually holds, so it may UNDERCOUNT what was really
    # found. Led with, next to DEGRADED/ABORTED, because a report that
    # quietly rounds down is worse than one that admits the gap. See
    # *Finding ID collisions* below for identity.
    if store.finding_collisions:
        add(f"> **{len(store.finding_collisions)} FINDING ID COLLISION"
            f"{'S' if len(store.finding_collisions) != 1 else ''} DETECTED** "
            "— one or more stages found two different issues that hashed to "
            "the same id. Only the first was kept per collision; the finding "
            "counts in this report may be an UNDERCOUNT. See *Finding ID "
            "collisions* below.\n")

    # Decide-and-inform notices raised at run start (see RunContext.warnings):
    # things the run proceeded despite, which the operator was told about and
    # which belong in the human-readable deliverable, not only in run.json.
    # The arjun `ps` credential exposure is the current case -- a reader of
    # this report needs to know credentials were visible in the process list
    # on the scanning host, and a reader is far more likely to open this file
    # than the manifest.
    warnings = list(getattr(ctx, "warnings", []))
    if warnings:
        add(f"> **{len(warnings)} RUN WARNING"
            f"{'S' if len(warnings) != 1 else ''}** — the run continued, and "
            "the operator was informed at run start:\n>")
        for w in warnings:
            add(f"> - {_prose(w)}")
        add("")

    add("## Summary\n")
    add(f"- **Level:** {ctx.config.level} · **Auth:** {ctx.config.auth_mode}")
    add(f"- **Started:** {ctx.started}")
    add(f"- **Hosts:** {len(store.get(ArtifactKind.HOST))} · "
        f"**TCP ports:** {len(store.get(ArtifactKind.PORT))} · "
        f"**UDP endpoints:** {len(store.get(ArtifactKind.UDP_PORT))} · "
        f"**Services:** {len(store.get(ArtifactKind.HTTP_SERVICE))} · "
        f"**DNS records:** {len(store.get(ArtifactKind.DNS_RECORD))}\n")

    add("| Severity | Count |")
    add("|---|---|")
    for sev in ORDER:
        add(f"| {sev} | {counts[sev]} |")
    add("")

    add("## Findings\n")
    if not findings:
        add("No findings.\n")
    else:
        for sev in ORDER:
            group = [f for f in findings if f.severity == sev]
            if not group:
                continue
            add(f"### {sev.upper()} ({len(group)})\n")
            for f in sorted(group, key=lambda x: (x.target, x.template_id)):
                # A title is a heading, not a table cell, but it is just as
                # attacker-influenced: an embedded newline would inject what
                # reads as a further heading or section. _cell collapses it.
                add(f"#### {_cell(f.title)}\n")
                add(f"- **Target:** `{_inline(f.target)}`")
                add(f"- **Stage:** {_prose(f.stage)} · "
                    f"**Template:** `{_inline(f.template_id)}`")
                if f.evidence:
                    add(f"- **Evidence:** `{_inline(f.evidence)}`")
                if f.description:
                    add(f"- {_prose(f.description)}")
                if f.remediation:
                    add(f"- **Remediation:** {_prose(f.remediation)}")
                if f.raw_ref:
                    add(f"- **Raw:** `{_inline(f.raw_ref)}`")
                add("")

    if store.finding_collisions:
        add(f"## Finding ID collisions ({len(store.finding_collisions)})\n")
        add("Two DIFFERENT findings that hashed to the same id — a bug in "
            "the emitting stage's `matcher`, not a duplicate. "
            "`store.add_finding()` kept the first-submitted finding "
            "(deterministic, and real evidence) and discarded the rest; "
            "each row below is one discarded finding. Identity only — "
            "never evidence or matcher, which can carry scan-derived or "
            "secret material — see `sweep.log` and "
            "`artifacts/findings.jsonl` in this run directory for detail.\n")
        add("| Stage | Target | Template | Differing fields |")
        add("|---|---|---|---|")
        for c in store.finding_collisions:
            add(f"| {_cell(c['stage'])} | {_cell(c['target'])} | "
                f"{_cell(c['template_id'])} | "
                f"{_cell(', '.join(c['differing_fields']))} |")
        add("")

    add("## Asset inventory\n")
    for kind, label in ASSET_KINDS:
        values = sorted(store.values(kind))
        if not values:
            continue
        add(f"### {label} ({len(values)})\n")
        shown, remaining = values[:INVENTORY_CAP], values[INVENTORY_CAP:]
        for v in shown:
            add(f"- `{_inline(v)}`")
        if remaining:
            add(f"- *... and {len(remaining)} more {label.lower()} "
                f"(truncated; see `artifacts/` in the run directory for the full list)*")
        add("")

    add("## Coverage — what was scanned and what wasn't\n")

    if summary.targets_requested:
        line = (f"**Targets:** {summary.targets_requested} requested, "
                f"{summary.targets_permitted} in scope")
        if summary.targets_refused:
            line += f", {summary.targets_refused} refused"
        add(line + ".\n")

    # A narrowed port range, stated plainly, on the same principle as a
    # stage reporting "stopped at the 20m time limit": the reader must be
    # able to tell a scan that found nothing on a port from one that never
    # looked at it. Only rendered when set -- an absent line means the
    # level's own range, which the Run details section already names.
    if ctx.config.ports:
        add(f"**Ports:** restricted by the operator to "
            f"`{_inline(ctx.config.ports)}`. Services outside that selection "
            f"were not scanned, at any stage: every later stage consumes the "
            f"ports this one discovered.\n")
    if ctx.config.udp_ports:
        add(f"**UDP ports:** restricted by the operator to "
            f"`{_inline(ctx.config.udp_ports)}`. UDP services outside that "
            "selection were not scanned.\n")
    if ctx.config.proxy:
        add("**HTTP proxy:** every HTTP stage was configured to use "
            f"`{_inline(ctx.config.proxy)}`. Raw DNS, TCP, UDP, and TLS "
            "probes do not traverse an HTTP proxy and ran directly.\n")

    add(f"Stages completed: {', '.join(summary.completed) or 'none'}\n")
    # summary.gaps holds both stages that ran short and stages requested for
    # which no StageResult exists at all -- see summarize_coverage(). The
    # HTML report renders the same list, so the two deliverables cannot name
    # different gaps for one run.
    if summary.gaps:
        add("The following stages **were not scanned, or did not complete "
            "in full**:\n")
        add("| Stage | Outcome | Class | Reason |")
        add("|---|---|---|---|")
        for g in summary.gaps:
            add(f"| {_cell(g.stage)} | {_cell(g.status)} | "
                f"{_cell(g.failure)} | {_cell(g.reason)} |")
        add("")
    elif summary.completed:
        add("All selected stages completed.\n")
    else:
        # "All selected stages completed" for a zero-stage run reads
        # reassuring and means nothing. Say what actually happened.
        add("**No stages ran.** Nothing was scanned.\n")

    if ctx.scope.refusals:
        add("### Out-of-scope targets refused\n")
        add("Targets the operator supplied that are outside scope — "
            "worth checking against the rules of engagement.\n")
        for ref in ctx.scope.refusals:
            add(f"- `{_inline(ref['target'])}`")
        add("")

    # Deliberately a SEPARATE section from the one above, reading its own
    # separately-accounted list. ctx.scope.refusals means "the operator gave
    # us an out-of-scope target" (possibly an RoE problem, worth flagging
    # loudly); this means "a stage discovered something outside scope and
    # admission control correctly did not scan it" (expected, routine, and
    # on some runs hundreds of entries). A discovery-heavy run finding many
    # out-of-scope hosts is a *successful* run, not a degraded one — see
    # is_degraded(), which this section's contents never feed into.
    if ctx.scope.discoveries_refused:
        add(f"### Discovered, not scanned (out of scope) "
            f"({len(ctx.scope.discoveries_refused)})\n")
        add("Hosts a stage discovered during this run that are outside "
            "scope. Not sent to any scanning stage. This is expected, "
            "routine output and does not, by itself, mean this run is "
            "incomplete.\n")
        for d in ctx.scope.discoveries_refused:
            add(f"- `{_inline(d['host'])}` (via {_inline(d['stage'])})")
        add("")

    return "\n".join(out) + "\n"


def write_markdown(ctx, results) -> Path:
    path = ctx.run_dir / "report.md"
    path.write_text(render_markdown(ctx, results), encoding="utf-8")
    return path
