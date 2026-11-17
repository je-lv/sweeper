"""Tests for the HTML *renderer* (Task 5).

Task 4 tested the template against hand-written context dicts. This file
tests the code that builds those dicts from a real `RunContext`, and — the
reason the coverage summary was extracted into one function — that the
Markdown and HTML reports **cannot disagree** about the same run.

The parity sweep is the centrepiece. Every previous instance of this
project's recurring defect (partial work presenting as complete) was a
second copy of a rule drifting from the first. `render_html` recomputing
`degraded` inline would have been the third. So rather than assert that
`render_html` happens to call `is_degraded`, these tests render *both*
reports over a product of stage outcomes and coverage denominators and
require them to agree — a property that fails for any divergence, including
ones nobody thought to enumerate.
"""
from __future__ import annotations

import itertools
import json
import re
from html.parser import HTMLParser

import pytest

from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.report.html import (build_context, render_html, write_html)
from sweeper.report.markdown import (ASSET_KINDS, INVENTORY_CAP,
                                     render_markdown)
from sweeper.stages.base import (Coverage, FailureClass, StageResult,
                                 is_degraded, summarize_coverage)
from sweeper.triage import TriageState

# Kept in step with tests/test_report_html_template.py's CONTEXT_KEYS, but
# derived from the template itself below rather than copied, so the two can
# never drift.
XSS = "<script>alert('pwn')</script>"


def ctx_for(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))


def seeded(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    ctx.store.add(Artifact(ArtifactKind.PORT, "acc.example:443"))
    ctx.store.add_finding(Finding(stage="dnsx", severity="high",
                                  title="AXFR permitted",
                                  target="ns1.acc.example",
                                  template_id="dns-axfr"))
    ctx.store.add_finding(Finding(stage="dnsx", severity="info",
                                  title="No CAA record", target="acc.example",
                                  template_id="dns-caa-missing"))
    return ctx


# ==========================================================================
# 1. the context contract, derived from the template rather than restated
# ==========================================================================

def template_names() -> set[str]:
    import jinja2
    import jinja2.meta
    from sweeper.report import html as html_mod
    source = (html_mod.TEMPLATE_DIR / html_mod.TEMPLATE_NAME).read_text(
        encoding="utf-8")
    return jinja2.meta.find_undeclared_variables(jinja2.Environment().parse(source))


def test_renderer_supplies_every_name_the_template_reads(tmp_path):
    """The property, not an enumeration of thirteen names.

    Adding a `{% if aborted %}` block to the template without teaching the
    renderer to pass `aborted` fails here — under StrictUndefined that
    combination raises mid-render in front of an operator, which is how a
    report goes missing at exactly the moment it matters.
    """
    supplied = set(build_context(seeded(tmp_path), []))
    missing = template_names() - supplied
    assert not missing, f"template reads names the renderer never passes: {sorted(missing)}"


def test_renderer_passes_nothing_the_template_does_not_read(tmp_path):
    """The other direction: a key the template ignores is a key whose value
    silently does not appear in the deliverable."""
    supplied = set(build_context(seeded(tmp_path), []))
    extra = supplied - template_names()
    assert not extra, f"renderer passes unused names: {sorted(extra)}"


def test_renders_under_strict_undefined(tmp_path):
    """The renderer's own environment, not a test-local one."""
    out = render_html(seeded(tmp_path), [])
    assert out.lstrip().startswith("<!doctype html>")
    assert "AXFR permitted" in out
    assert "{{" not in out and "{%" not in out


# ==========================================================================
# 2. degraded comes from the one definition
# ==========================================================================

# Each of these is a run the *old* inline recomputation got wrong: it only
# looked for status == "failed", so a partial stage, a refused target and a
# stage that never produced a result all rendered as a clean run.
DEGRADING_RUNS = {
    "partial stage": (
        [StageResult(stage="nuclei", status="partial",
                     failure=FailureClass.PARTIAL, reason="timed out")],
        Coverage(targets_requested=1, targets_permitted=1,
                 stages_requested=["nuclei"]),
    ),
    "refused target": (
        [StageResult(stage="dnsx", status="complete")],
        Coverage(targets_requested=3, targets_permitted=1,
                 stages_requested=["dnsx"]),
    ),
    "stage never recorded": (
        [StageResult(stage="dnsx", status="complete")],
        Coverage(targets_requested=1, targets_permitted=1,
                 stages_requested=["dnsx", "naabu"]),
    ),
    "parse error": (
        [StageResult(stage="katana", status="failed",
                     failure=FailureClass.PARSE_ERROR, reason="bad json")],
        Coverage(targets_requested=1, targets_permitted=1,
                 stages_requested=["katana"]),
    ),
}


@pytest.mark.parametrize("name", sorted(DEGRADING_RUNS))
def test_html_reports_degraded_for_every_kind_of_coverage_gap(tmp_path, name):
    results, coverage = DEGRADING_RUNS[name]
    ctx = seeded(tmp_path)
    ctx.coverage = coverage
    assert "DEGRADED RUN" in render_html(ctx, results), name


def test_clean_run_is_not_marked_degraded(tmp_path):
    ctx = seeded(tmp_path)
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["dnsx"])
    out = render_html(ctx, [StageResult(stage="dnsx", status="complete")])
    assert "DEGRADED RUN" not in out


def test_no_input_skip_alone_does_not_degrade(tmp_path):
    """`is_degraded` treats NO_INPUT as a correct outcome. The HTML report
    must not invent a stricter or looser rule of its own."""
    ctx = seeded(tmp_path)
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["naabu"])
    out = render_html(ctx, [StageResult(stage="naabu", status="skipped",
                                        failure=FailureClass.NO_INPUT,
                                        reason="no ports")])
    assert "DEGRADED RUN" not in out
    # ...but it is still named in coverage: not degrading is not the same as
    # not worth reporting.
    assert "naabu" in out


def test_aborted_run_is_never_presented_as_clean(tmp_path):
    """An aborted run whose recorded stages all completed is the worst case:
    every per-result check passes and the scan still stopped early. The
    Markdown report and run.json both say so; the HTML report must too --
    and it must say WHY, which for a long time it did not."""
    ctx = seeded(tmp_path)
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["dnsx"])
    ctx.aborted_reason = "KeyboardInterrupt"
    out = render_html(ctx, [StageResult(stage="dnsx", status="complete")])
    assert "RUN ABORTED" in out
    assert "KeyboardInterrupt" in out
    # ...and it must not, in the same breath, reassure the reader.
    assert "All selected stages completed." not in out


# ==========================================================================
# 3. PARITY — the two reports cannot disagree about the same run
# ==========================================================================

def html_coverage_stages(out: str) -> set[str]:
    """Stage names in the rendered HTML coverage table."""
    class P(HTMLParser):
        def __init__(self):
            super().__init__()
            self.in_cov = self.in_body = False
            self.cell = None
            self.rows = []
            self.row = None

        def handle_starttag(self, tag, attrs):
            a = dict(attrs)
            if tag == "table" and "cov" in (a.get("class") or "").split():
                self.in_cov = True
            elif tag == "tbody" and self.in_cov:
                self.in_body = True
            elif tag == "tr" and self.in_body:
                self.row = []
            elif tag == "td" and self.row is not None:
                self.cell = []

        def handle_endtag(self, tag):
            if tag == "td" and self.cell is not None:
                self.row.append("".join(self.cell).strip())
                self.cell = None
            elif tag == "tr" and self.row is not None:
                self.rows.append(self.row)
                self.row = None
            elif tag == "tbody" and self.in_body:
                self.in_body = False
            elif tag == "table" and self.in_cov:
                self.in_cov = False

        def handle_data(self, data):
            if self.cell is not None:
                self.cell.append(data)

    p = P()
    p.feed(out)
    # The empty-state row is a single colspan cell, not a stage.
    return {r[0] for r in p.rows if len(r) == 4}


def md_coverage_stages(md: str) -> set[str]:
    """Stage names in the Markdown 'not scanned, or did not complete' table."""
    lines = md.splitlines()
    try:
        start = lines.index("| Stage | Outcome | Class | Reason |")
    except ValueError:
        return set()
    out = set()
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        out.add(line.split("|")[1].strip())
    return out


def md_warns(md: str) -> bool:
    return "DEGRADED RUN" in md or "RUN ABORTED" in md


def html_warns(out: str) -> bool:
    # Both spellings, exactly as md_warns above: the HTML report leads an
    # aborted run with RUN ABORTED *instead of* DEGRADED RUN, the same
    # if/elif the Markdown report uses. Checking only one spelling here
    # would make this parity sweep read an aborted run as unflagged.
    return "DEGRADED RUN" in out or "RUN ABORTED" in out


# A product, not a list of cases somebody thought of: every stage outcome
# against every failure class, against a coverage denominator that is either
# satisfied or short in each of its two independent ways.
STATUSES = ("complete", "failed", "skipped", "partial")
DENOMINATORS = (
    Coverage(targets_requested=2, targets_permitted=2, stages_requested=["s0"]),
    Coverage(targets_requested=2, targets_permitted=1, stages_requested=["s0"]),
    Coverage(targets_requested=2, targets_permitted=2,
             stages_requested=["s0", "never-ran"]),
    Coverage(),
)
SCENARIOS = [
    ([StageResult(stage="s0", status=st, failure=fc, reason="r")], cov, abort)
    for st, fc, cov, abort in itertools.product(
        STATUSES, FailureClass, DENOMINATORS, ("", "operator interrupt"))
]


@pytest.mark.parametrize("results,coverage,aborted", SCENARIOS,
                         ids=lambda v: str(v)[:40])
def test_markdown_and_html_agree_on_degraded(tmp_path, results, coverage, aborted):
    ctx = seeded(tmp_path)
    ctx.coverage = coverage
    ctx.aborted_reason = aborted
    md, html = render_markdown(ctx, results), render_html(ctx, results)
    assert md_warns(md) == html_warns(html), (
        f"reports disagree: markdown={md_warns(md)} html={html_warns(html)} "
        f"for {results[0].status}/{results[0].failure.name}/{coverage}/{aborted!r}")


@pytest.mark.parametrize("results,coverage,aborted", SCENARIOS,
                         ids=lambda v: str(v)[:40])
def test_markdown_and_html_name_the_same_coverage_gaps(tmp_path, results,
                                                       coverage, aborted):
    ctx = seeded(tmp_path)
    ctx.coverage = coverage
    ctx.aborted_reason = aborted
    md, html = render_markdown(ctx, results), render_html(ctx, results)
    assert md_coverage_stages(md) == html_coverage_stages(html)


@pytest.mark.parametrize("results,coverage,aborted", SCENARIOS,
                         ids=lambda v: str(v)[:40])
def test_manifest_and_html_agree_on_degraded(tmp_path, results, coverage, aborted):
    """The third consumer. run.json computes `degraded` in context.py; if
    that copy ever drifts from summarize_coverage, the deliverable and the
    machine-readable record start telling different stories."""
    ctx = seeded(tmp_path)
    ctx.coverage = coverage
    ctx.aborted_reason = aborted
    ctx.write_manifest(results)
    manifest = json.loads((ctx.run_dir / "run.json").read_text(encoding="utf-8"))
    assert manifest["degraded"] == html_warns(render_html(ctx, results))


# --------------------------------------------------------------------------
# 3b. LEAD-SIGNAL PARITY — whatever the Markdown leads with, the HTML leads
#     with. Asserted as set equality over labels extracted from each format,
#     NOT as a check for three known field names: `report.html` is the file
#     that gets redacted and handed to the client, and a caveat that lives
#     only in its Markdown twin is a caveat the client never reads. A fourth
#     signal added to either report and not the other fails this.
# --------------------------------------------------------------------------

BOLD = re.compile(r"\*\*(.+?)\*\*")


def md_lead_signals(md: str) -> set[str]:
    """The labels the Markdown report leads with.

    Every blockquote line above the first `##` section contributes its first
    bold span — that is how markdown.py labels each of these notices, and
    reading the label rather than the prose is what keeps this test from
    being a copy of either report's wording.
    """
    out = set()
    for line in md.splitlines():
        if line.startswith("## "):
            break
        if line.startswith(">"):
            m = BOLD.search(line)
            if m:
                out.add(" ".join(m.group(1).split()))
    return out


def html_lead_signals(out: str) -> set[str]:
    """The same labels from the HTML: the <strong> opening each .banner."""
    class P(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.depth = 0          # >0 while inside a .banner element
            self.in_strong = False
            self.have_label = False  # only the FIRST <strong> per banner
            self.buf: list[str] = []
            self.labels: set[str] = set()

        def handle_starttag(self, tag, attrs):
            if self.depth:
                self.depth += 1
                if tag == "strong" and not self.have_label:
                    self.in_strong, self.buf = True, []
            elif "banner" in (dict(attrs).get("class") or "").split():
                self.depth, self.have_label = 1, False

        def handle_endtag(self, tag):
            if self.in_strong and tag == "strong":
                self.labels.add(" ".join("".join(self.buf).split()))
                self.in_strong, self.have_label = False, True
            if self.depth:
                self.depth -= 1

        def handle_data(self, data):
            if self.in_strong:
                self.buf.append(data)

    p = P()
    p.feed(out)
    return p.labels


def seed_collision(ctx):
    """Two DIFFERENT findings that hash to the same id — a stage whose
    matcher cannot tell them apart. The store keeps the first and records
    the collision, so the reported counts are a known undercount."""
    same = dict(stage="nuclei", target="acc.example",
                template_id="git-config", matcher="fixed")
    ctx.store.add_finding(Finding(severity="high", title="one", **same))
    ctx.store.add_finding(Finding(severity="high", title="two", **same))
    assert ctx.store.finding_collisions, "fixture produced no collision"


SIGNALS = {
    "aborted": lambda ctx: setattr(ctx, "aborted_reason",
                                   "interrupted by operator (SIGINT)"),
    "collisions": seed_collision,
    "warnings": lambda ctx: ctx.warnings.extend([
        "arjun exposes live credentials via `ps` on this host",
        "a second decide-and-inform notice",
    ]),
}

# The power set: every signal alone, in every combination, and none at all.
SIGNAL_SETS = [frozenset(c)
               for n in range(len(SIGNALS) + 1)
               for c in itertools.combinations(sorted(SIGNALS), n)]


def run_with_signals(tmp_path, on, degrading):
    ctx = seeded(tmp_path)
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["dnsx"])
    for name in sorted(on):
        SIGNALS[name](ctx)
    if degrading:
        return ctx, [StageResult(stage="dnsx", status="failed",
                                 failure=FailureClass.TRANSPORT,
                                 reason="connection refused")]
    return ctx, [StageResult(stage="dnsx", status="complete")]


@pytest.mark.parametrize("degrading", [False, True])
@pytest.mark.parametrize("on", SIGNAL_SETS,
                         ids=lambda s: "+".join(sorted(s)) or "none")
def test_html_leads_with_every_signal_the_markdown_leads_with(tmp_path, on,
                                                              degrading):
    ctx, results = run_with_signals(tmp_path, on, degrading)
    md, html = render_markdown(ctx, results), render_html(ctx, results)
    assert html_lead_signals(html) == md_lead_signals(md)


def test_lead_signal_sweep_is_not_vacuous(tmp_path):
    """A parity test over labels neither report emits passes trivially.
    Prove the sweep sees every signal, sees them together, and sees none."""
    seen, sizes = set(), set()
    for i, on in enumerate(SIGNAL_SETS):
        for degrading in (False, True):
            d = tmp_path / f"r{i}-{degrading}"
            d.mkdir()
            ctx, results = run_with_signals(d, on, degrading)
            labels = md_lead_signals(render_markdown(ctx, results))
            assert labels == html_lead_signals(render_html(ctx, results))
            seen |= labels
            sizes.add(len(labels))
    assert 0 in sizes, "no scenario renders a clean run"
    assert max(sizes) >= 3, "no scenario renders several signals at once"
    assert {"RUN ABORTED", "DEGRADED RUN"} <= seen
    assert any(s.endswith("DETECTED") for s in seen), "no collision label seen"
    assert any("RUN WARNING" in s for s in seen), "no warning label seen"


# --------------------------------------------------------------------------
# body parity: what the two reports SAY, not only what they lead with
# --------------------------------------------------------------------------
# The sweep above is a genuine property over LEAD signals -- it compares
# label sets, not three known names -- but it is narrower than its docstring
# once claimed, and `discoveries_refused` (O2) is what proved it. That list
# renders as a `###` section in the Markdown BODY, so `md_lead_signals`
# stops at the first `##` and never reaches it; and it is not one of the
# three entries in `SIGNALS`, so no scenario in the sweep even populates it.
# It was invisible twice over, and the HTML omitted it entirely.
#
# So: a property over the run-state record lists themselves, reflected off
# `ScopeGuard` rather than named here. A fourth list added to the guard and
# surfaced in one report only fails this without anyone editing a fixture.


class AnyKey(dict):
    """A record whose every field reads as the sentinel, whatever the field
    happens to be called.

    Lets one seeding rule cover record shapes that differ (`refusals` holds
    target/normalized, `discoveries_refused` holds stage/kind/value/host,
    `extensions` holds host/reason) -- including a shape invented after this
    test was written, which is the whole point. Jinja resolves `d.host` by
    trying getattr first and falling back to `d['host']`, so both reports'
    access styles land on __missing__.
    """

    def __init__(self, value: str):
        super().__init__()
        self.value = value

    def __missing__(self, key):
        return self.value


def scope_record_lists(scope) -> list[str]:
    """Every list-of-records the scope guard keeps, discovered not listed."""
    return sorted(n for n, v in vars(scope).items()
                  if not n.startswith("_") and isinstance(v, list))


def test_scope_record_list_reflection_is_not_vacuous(tmp_path):
    """The reflection below is only a property if it actually finds the
    lists. If ScopeGuard is refactored to keep them somewhere `vars()` does
    not see, the parity test would pass over an empty set of names."""
    names = scope_record_lists(ctx_for(tmp_path).scope)
    assert len(names) >= 3, f"reflection found only {names}"
    assert "discoveries_refused" in names and "refusals" in names


def test_every_scope_record_list_reaches_both_reports_or_neither(tmp_path):
    """O2's property. Not "the HTML renders discoveries_refused" -- that is
    an enumeration, and enumerating is how three signals got surfaced and a
    fourth did not.

    A scope record the Markdown deliverable names and the HTML one does not
    is a fact the client never sees, because the HTML is the file the client
    is handed. The converse is a fact the operator's own archive never sees.
    Both directions are asserted.
    """
    names = scope_record_lists(ctx_for(tmp_path).scope)
    seen: dict[str, tuple[bool, bool]] = {}
    for name in names:
        d = tmp_path / f"scope-{name}"
        d.mkdir()
        ctx = seeded(d)
        sentinel = f"sentinel-{name.replace('_', '-')}.out-of-scope.test"
        getattr(ctx.scope, name).append(AnyKey(sentinel))
        seen[name] = (sentinel in render_markdown(ctx, []),
                      sentinel in render_html(ctx, []))

    asymmetric = {n: v for n, v in seen.items() if v[0] != v[1]}
    assert not asymmetric, (
        "scope records reach one deliverable and not the other "
        f"(markdown, html): {asymmetric}")
    # Non-vacuity: if every list silently stopped rendering in BOTH reports
    # the equality above would hold and say nothing.
    assert sum(1 for v in seen.values() if v == (True, True)) >= 2, (
        f"fewer than two scope lists reach either report: {seen}")


def test_markdown_and_html_report_the_same_discovered_host_count(tmp_path):
    """Both deliverables state how many hosts were found out of scope. They
    may not state different numbers for one run."""
    ctx = seeded(tmp_path)
    for i in range(250):
        host = f"h{i:03d}.thirdparty.example"
        ctx.scope.record_discovery_refusal(stage="subfinder", kind="HOST",
                                           value=host, host=host)
    md, html = render_markdown(ctx, []), render_html(ctx, [])
    label = "Discovered, not scanned (out of scope)"
    md_n = re.search(r"### %s \((\d+)\)" % re.escape(label), md)
    html_n = re.search(r"%s \((\d+)\)" % re.escape(label), html)
    assert md_n and html_n, f"section missing (md={bool(md_n)}, html={bool(html_n)})"
    assert md_n.group(1) == html_n.group(1) == "250"
    # and the hosts themselves, not only the count: this list is uncapped in
    # both deliverables because it is what a scope extension would cover.
    assert "h249.thirdparty.example" in html


def test_hostile_discovered_hostname_renders_inert(tmp_path):
    """Discovered hostnames come from crawl output and DNS -- putting a name
    in a crawled page is all it takes to get it rendered in the operator's
    browser. This goes through the RENDERER's own environment, where
    `select_autoescape()` would have returned False for `.html.j2`."""
    ctx = seeded(tmp_path)
    ctx.scope.record_discovery_refusal(stage=XSS, kind="HOST", value=XSS,
                                       host=f"{XSS}.thirdparty.example")
    assert ctx.scope.discoveries_refused, "test is vacuous: nothing recorded"
    out = render_html(ctx, [])
    assert "thirdparty.example" in out, "discovery never reached the report"
    assert XSS not in out
    assert "&lt;script&gt;" in out or "alert(&#39;pwn&#39;)" in out


def test_parity_sweep_actually_exercises_both_outcomes(tmp_path):
    """A parity test where every scenario degrades would pass against a
    renderer that hard-codes DEGRADED. Prove the sweep straddles the line."""
    seen = set()
    for results, coverage, aborted in SCENARIOS:
        seen.add(is_degraded(results, coverage) or bool(aborted))
    assert seen == {True, False}


# ==========================================================================
# 4. rendering a report must not mutate run state
# ==========================================================================

def test_render_does_not_mutate_stored_findings(tmp_path):
    ctx = seeded(tmp_path)
    state = TriageState(tmp_path / "triage.json")
    target = ctx.store.findings[0]
    state.set(target.id, "false-positive", note="known, accepted")
    before = [(f.id, f.triage, f.triage_note) for f in ctx.store.findings]

    out = render_html(ctx, [], triage=state)

    assert [(f.id, f.triage, f.triage_note) for f in ctx.store.findings] == before
    assert all(f.triage == "new" for f in ctx.store.findings)
    assert "false-positive" in out


def test_triage_state_reaches_the_rendered_report(tmp_path):
    ctx = seeded(tmp_path)
    state = TriageState(tmp_path / "triage.json")
    state.set(ctx.store.findings[0].id, "confirmed", note="verified by hand")
    out = render_html(ctx, [], triage=state)
    assert "verified by hand" in out


# ==========================================================================
# 5. reconciliation: no number may exceed what the store holds
# ==========================================================================

def test_severity_counts_sum_to_the_findings_rendered(tmp_path):
    ctx = seeded(tmp_path)
    context = build_context(ctx, [])
    assert sum(context["counts"].values()) == len(context["findings"])


def test_counts_never_exceed_the_store(tmp_path):
    ctx = seeded(tmp_path)
    ctx.store.add_finding(Finding(stage="x", severity="critical", title="k",
                                  target="acc.example", template_id="t"))
    context = build_context(ctx, [])
    assert sum(context["counts"].values()) <= len(ctx.store.findings)
    assert len(context["findings"]) <= len(ctx.store.findings)


def test_asset_inventory_is_capped_and_says_so(tmp_path):
    ctx = ctx_for(tmp_path)
    for i in range(INVENTORY_CAP + 25):
        ctx.store.add(Artifact(ArtifactKind.HOST, f"h{i:04d}.acc.example"))
    hosts = build_context(ctx, [])["assets"]["Hosts"]
    assert hosts["total"] == INVENTORY_CAP + 25
    assert len(hosts["shown"]) == INVENTORY_CAP
    assert hosts["truncated"] == 25
    # The notice is rendered FROM `truncated`; it is not an element of the
    # list the template counts. That is the whole defect.
    assert not any("more hosts" in v for v in hosts["shown"])
    out = render_html(ctx, [])
    assert f"Hosts ({INVENTORY_CAP + 25})" in out
    assert "25 more hosts" in out


def test_markdown_and_html_report_the_same_inventory_counts(tmp_path):
    """The `_assets` half of B9. The truncation notice was appended to the
    value list the template counts, so a run with 500 ports rendered
    "Ports (201)" in HTML and "Ports (500)" in Markdown — the HTML heading
    silently became the number of lines printed, cap included."""
    ctx = ctx_for(tmp_path)
    for i in range(INVENTORY_CAP + 300):
        ctx.store.add(Artifact(ArtifactKind.PORT, f"acc.example:{i}"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    md, html = render_markdown(ctx, []), render_html(ctx, [])

    html_counts = {m.group(1): int(m.group(2)) for m in
                   re.finditer(r"<summary>(.+?) \((\d+)\)</summary>", html)}
    md_counts = {}
    for _, label in ASSET_KINDS:
        m = re.search(r"^### %s \((\d+)\)$" % re.escape(label), md, re.M)
        if m:
            md_counts[label] = int(m.group(1))

    assert md_counts, "fixture recorded no inventory at all"
    assert html_counts == md_counts


# ==========================================================================
# 6. escaping survives the renderer's own environment
# ==========================================================================

def test_hostile_finding_text_renders_inert(tmp_path):
    """Task 4 proved the template escapes. This proves the *renderer's*
    environment does not undo it -- `select_autoescape()` returns False for
    a `.html.j2` filename, so this is a live failure mode, not a hypothetical.
    """
    ctx = ctx_for(tmp_path)
    ctx.store.add_finding(Finding(stage="nuclei", severity="high", title=XSS,
                                  target="acc.example", template_id=XSS,
                                  evidence=XSS, description=XSS,
                                  remediation=XSS, matched_at=XSS))
    out = render_html(ctx, [])
    assert XSS not in out
    assert "&lt;script&gt;" in out


def test_hostile_stage_reason_renders_inert(tmp_path):
    """Tool failure reasons carry raw tool output straight into the coverage
    table -- the section a reader relies on most."""
    ctx = seeded(tmp_path)
    out = render_html(ctx, [StageResult(stage="naabu", status="failed",
                                        failure=FailureClass.TRANSPORT,
                                        reason=XSS)])
    assert XSS not in out


def test_hostile_abort_reason_renders_inert(tmp_path):
    """`aborted_reason` is `f"{type(exc).__name__}: {exc}"` (app.py) — an
    exception message can carry a response body straight off the target."""
    ctx = seeded(tmp_path)
    ctx.aborted_reason = XSS
    out = render_html(ctx, [])
    assert "RUN ABORTED" in out, "abort reason never reached the report"
    assert XSS not in out
    assert "&lt;script&gt;" in out


def test_hostile_run_warning_renders_inert(tmp_path):
    ctx = seeded(tmp_path)
    ctx.warnings.append(XSS)
    out = render_html(ctx, [])
    assert "1 RUN WARNING" in out, "warning never reached the report"
    assert XSS not in out
    assert "&lt;script&gt;" in out


def test_hostile_collision_identity_renders_inert(tmp_path):
    """A collision row carries a stage's own target and template id, which
    come from scanner output."""
    ctx = seeded(tmp_path)
    same = dict(stage="nuclei", target=XSS, template_id=XSS, matcher="fixed")
    ctx.store.add_finding(Finding(severity="high", title="a", **same))
    ctx.store.add_finding(Finding(severity="high", title="b", **same))
    assert ctx.store.finding_collisions, "fixture produced no collision"
    out = render_html(ctx, [])
    assert "FINDING ID COLLISION" in out, "collision never reached the report"
    assert XSS not in out
    assert "&lt;script&gt;" in out


def test_refused_target_renders_inert(tmp_path):
    """An out-of-scope target is operator-supplied text that reaches the
    coverage section verbatim. The page has its own legitimate <script>
    block, so assert on the payload rather than on the tag."""
    ctx = seeded(tmp_path)
    ctx.scope.filter([f"{XSS}.evil.test"])
    assert ctx.scope.refusals, "test is vacuous: nothing was refused"
    out = render_html(ctx, [])
    assert "evil.test" in out, "refusal never reached the report"
    assert XSS not in out
    assert "alert(&#39;pwn&#39;)" in out or "&lt;script&gt;" in out


# ==========================================================================
# 7. summarize_coverage itself
# ==========================================================================

def test_summarize_names_missing_stages_that_have_no_result():
    s = summarize_coverage([StageResult(stage="dnsx", status="complete")],
                           Coverage(stages_requested=["dnsx", "naabu"]))
    assert s.completed == ["dnsx"]
    assert [g.stage for g in s.gaps] == ["naabu"]
    assert s.gaps[0].status == "missing"
    assert s.degraded is True


def test_summarize_reports_refused_targets():
    s = summarize_coverage([], Coverage(targets_requested=5, targets_permitted=2))
    assert s.targets_refused == 3
    assert s.degraded is True


def test_summarize_degrades_on_abort_with_no_failed_result():
    clean = [StageResult(stage="dnsx", status="complete")]
    cov = Coverage(targets_requested=1, targets_permitted=1,
                   stages_requested=["dnsx"])
    assert summarize_coverage(clean, cov).degraded is False
    assert summarize_coverage(clean, cov, "interrupted").degraded is True


def test_summarize_lists_non_degrading_skips_as_gaps_anyway():
    s = summarize_coverage([StageResult(stage="naabu", status="skipped",
                                        failure=FailureClass.NO_INPUT)],
                           Coverage(stages_requested=["naabu"]))
    assert [g.stage for g in s.gaps] == ["naabu"]
    assert s.degraded is False


# ==========================================================================
# 8. write_html
# ==========================================================================

def test_write_html_lands_next_to_the_markdown_report(tmp_path):
    ctx = seeded(tmp_path)
    path = write_html(ctx, [])
    assert path == ctx.run_dir / "report.html"
    assert path.read_text(encoding="utf-8").lstrip().startswith("<!doctype html>")


def test_report_makes_no_external_request(tmp_path):
    """The no-network property, re-checked on real renderer output: a
    deliverable opened from file:// must not tell a third party which
    engagement is being read, and when."""
    out = render_html(seeded(tmp_path), [])
    assert not re.search(r"""(?:src|href)\s*=\s*["']\s*(?:https?:)?//""", out)
    assert "url(http" not in out.replace(" ", "")
