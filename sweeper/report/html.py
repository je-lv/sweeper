"""HTML report — the renderer half of `templates/report.html.j2`.

This module builds the template's context and nothing else. Everything the
page *presents* (severity ordering, filter options, bar widths) is derived
inside the template, so the contract between the two stays small enough to
assert: see `build_context` and
`tests/test_report_html.py::test_renderer_supplies_every_name_the_template_reads`.

Two properties are load-bearing here rather than in the template:

**Coverage comes from `summarize_coverage`, never recomputed.** An earlier
revision of this renderer worked out `degraded` inline and got it wrong in
three separate ways (it ignored `partial`, ignored refused targets, and
ignored stages requested that never produced a result), so the HTML
deliverable read clean for runs whose Markdown twin said DEGRADED. Rendering
a second view of a run must never be a second opinion about it.

**Escaping is not left to `select_autoescape()`.** That helper matches on
the last extension and returns False for `report.html.j2`, so the idiomatic
environment renders this template unescaped — and findings carry scanner
output, response snippets and crawled URLs. The template defends itself with
its own `{% autoescape %}` block; this module sets `autoescape=True` as well.
Belt and braces, deliberately: the failure mode is stored XSS in a document
we hand to a client.
"""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from ..artifacts import ArtifactKind
from ..stages.base import summarize_coverage
from .markdown import ASSET_KINDS, INVENTORY_CAP, ORDER

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
TEMPLATE_NAME = "report.html.j2"

# A tool that reports no version records None (see RunContext.tool_versions):
# "checked, reports no version", which is different from never having been
# verified. Rendering that as the literal "None" in a client deliverable
# reads as a bug; say what it means.
NO_VERSION = "version not reported"

_env = None


def _environment():
    """Built once, lazily.

    Lazily because Jinja is only needed to produce this one artefact and
    this repo ships no dependency metadata: importing it at module scope
    would make `sweeper` itself unimportable on a host without Jinja, taking
    the scan and the Markdown report down with it.
    """
    global _env
    if _env is None:
        import jinja2
        _env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
            undefined=jinja2.StrictUndefined,
            trim_blocks=True,
            lstrip_blocks=True,
        )
    return _env


def _assets(store) -> dict[str, dict]:
    """Inventory, capped, under the same labels the Markdown report uses.

    The cap is the Markdown report's, imported rather than restated. A
    `full` scan can turn up thousands of ports; inlining all of them makes
    the file huge and buries the sections that matter more. Truncation is
    stated in the section itself, because a silently short inventory is the
    same defect this project keeps producing in a smaller box.

    Three separate values, deliberately. An earlier revision appended the
    truncation notice as an extra element of the value list — the same list
    the template counts for its heading — so a run with 500 ports rendered
    "Ports (201)" in HTML and "Ports (500)" in Markdown. The count of a
    thing and the lines used to show it are not the same number and no
    longer share a variable: `total` is how many exist, `shown` is what is
    inlined, `truncated` is the difference, and the notice is rendered from
    `truncated` rather than smuggled into `shown`.
    """
    out: dict[str, dict] = {}
    for kind, label in ASSET_KINDS:
        values = sorted(store.values(kind))
        if not values:
            continue
        out[label] = {
            "total": len(values),
            "shown": values[:INVENTORY_CAP],
            "truncated": max(0, len(values) - INVENTORY_CAP),
        }
    return out


def build_context(ctx, results, triage=None) -> dict:
    """The template's context. Exactly the names it reads, and no others.

    `triage`, when given, annotates findings via `TriageState.apply()`,
    which returns NEW `Finding` objects. The store's own instances are left
    untouched: producing a report is a read of run state, not a write of it.

    `counts` is derived from the very list passed as `findings`, so the
    distribution and the table can only disagree if something upstream is
    genuinely inconsistent — which the template then says out loud rather
    than letting one number stand in for the other.

    `aborted_reason`, `warnings` and `finding_collisions` are the three
    signals the Markdown report LEADS with, and for a while this context
    carried none of them: an interrupted run rendered as an unexplained
    DEGRADED banner, a run that exposed live credentials via `ps` (the
    arjun warning) said nothing at all, and a run with a known finding
    undercount printed the rounded-down count as fact. This file is the one
    that gets redacted and handed to the client, so a caveat that exists
    only in the Markdown twin is a caveat the client never sees.
    `tests/test_report_html.py::test_html_leads_with_every_signal_the_markdown_leads_with`
    is the guard for those three, and it compares the two reports' banner
    labels as sets rather than checking three known names.

    That guard is narrower than it once claimed to be, and `discoveries_refused`
    is what proved it: it reads only the LEAD banners (the Markdown
    blockquotes above the first `##`, the HTML `.banner` elements), and it
    drives them from a fixed set of three run-state signals, so a section
    that renders in the Markdown *body* and nowhere in the HTML was invisible
    to it twice over. The body-level property is
    `test_every_scope_record_list_reaches_both_reports_or_neither`, which
    reflects over `ScopeGuard`'s record lists instead of naming them: a
    fourth list surfaced in one report and not the other fails it without
    anyone remembering to extend a fixture.
    """
    findings = ctx.store.findings
    if triage is not None:
        findings = triage.apply(findings)

    aborted_reason = getattr(ctx, "aborted_reason", "")
    summary = summarize_coverage(results, ctx.coverage, aborted_reason)

    return {
        "run_name": ctx.run_dir.name,
        "level": ctx.config.level,
        # The operator's port restriction, if any. Empty means the level's
        # own range and the template renders nothing. See RunConfig.ports.
        "ports": ctx.config.ports,
        "udp_ports": ctx.config.udp_ports,
        "proxy": ctx.config.proxy,
        "auth_mode": ctx.config.auth_mode,
        "started": ctx.started,
        "degraded": summary.degraded,
        # Why the run stopped early, not merely that it did. `degraded` is
        # already True whenever this is set (summarize_coverage folds it
        # in), so without the string the page shows the banner and no cause.
        "aborted_reason": aborted_reason,
        # Decide-and-inform notices raised at run start (RunContext.warnings)
        # — things the run proceeded despite and the operator was told about.
        "warnings": list(getattr(ctx, "warnings", [])),
        # Identity only, never `evidence` or `matcher`: a matcher derived
        # from an offending secret CAN equal that secret, which is why
        # store.add_finding keeps them out of its own log line too. These
        # four fields are the same ones the Markdown report's collision
        # table prints, and `id` is dropped because nothing on the page
        # reads it.
        "finding_collisions": [
            {
                "stage": c["stage"],
                "target": c["target"],
                "template_id": c["template_id"],
                "differing_fields": list(c["differing_fields"]),
            }
            for c in ctx.store.finding_collisions
        ],
        "counts": {s: sum(1 for f in findings if f.severity == s) for s in ORDER},
        # asdict() copies; the store's Finding instances never reach the
        # template. Findings are redacted at construction
        # (sweeper/secrets_rules.py), so no field here can hold a raw
        # secret, and nothing in this path reconstructs one.
        "findings": [asdict(f) for f in findings],
        "assets": _assets(ctx.store),
        "coverage": [asdict(g) for g in summary.gaps],
        "refusals": [{"target": r["target"]} for r in ctx.scope.refusals],
        # A SEPARATE list from `refusals`, and separately accounted all the
        # way down (ScopeGuard keeps two lists so that a subfinder run
        # turning up 200 out-of-scope subdomains cannot read as 200 RoE
        # problems). These reached report.md and run.json but not this file
        # — and this file is the one the design spec designates for handing
        # to the client and the one the menu's `o` key opens, so the hosts
        # that a scope-extension conversation is *about* were missing from
        # the only document that conversation happens over. `host` and
        # `stage` only: the Markdown twin prints exactly those two, and a
        # field shown in one deliverable and not the other is the same
        # defect in a smaller box.
        "discoveries_refused": [
            {"host": d["host"], "stage": d["stage"]}
            for d in ctx.scope.discoveries_refused
        ],
        "tool_versions": {
            name: (version if version else NO_VERSION)
            for name, version in ctx.tool_versions.items()
        },
        "targets_requested": summary.targets_requested,
        "targets_permitted": summary.targets_permitted,
    }


def render_html(ctx, results, triage=None) -> str:
    return _environment().get_template(TEMPLATE_NAME).render(
        build_context(ctx, results, triage)
    )


def write_html(ctx, results, triage=None) -> Path:
    path = ctx.run_dir / "report.html"
    path.write_text(render_html(ctx, results, triage), encoding="utf-8")
    return path
