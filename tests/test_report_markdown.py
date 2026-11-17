import json

from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.report.markdown import INVENTORY_CAP, render_markdown
from sweeper.stages.base import Coverage, FailureClass, StageResult


def ctx_for(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))


def seeded(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    ctx.store.add(Artifact(ArtifactKind.PORT, "acc.example:443"))
    ctx.store.add_finding(Finding(stage="dnsx", severity="high", title="AXFR permitted",
                                  target="ns1.acc.example", template_id="dns-axfr"))
    ctx.store.add_finding(Finding(stage="dnsx", severity="info", title="No CAA record",
                                  target="acc.example", template_id="dns-caa-missing"))
    return ctx


def test_severity_counts_rendered(tmp_path):
    md = render_markdown(seeded(tmp_path), [])
    assert "| high | 1 |" in md
    assert "| info | 1 |" in md


def test_findings_ordered_critical_first(tmp_path):
    ctx = seeded(tmp_path)
    ctx.store.add_finding(Finding(stage="x", severity="critical", title="Key leak",
                                  target="acc.example", template_id="t-crit"))
    md = render_markdown(ctx, [])
    assert md.index("Key leak") < md.index("AXFR permitted")


def test_skipped_stages_named_with_reason(tmp_path):
    md = render_markdown(seeded(tmp_path), [
        StageResult(stage="naabu", status="skipped",
                    failure=FailureClass.MISSING_BINARY, reason="binary not found"),
    ])
    assert "naabu" in md
    assert "binary not found" in md
    assert "was not scanned" in md.lower() or "not scanned" in md.lower()


def test_scope_refusals_surface_in_report(tmp_path):
    ctx = seeded(tmp_path)
    ctx.scope.filter(["evil.test"])
    md = render_markdown(ctx, [])
    assert "evil.test" in md


# --- Discoveries refused: a separate, clearly-labelled section -------------
# ctx.scope.refusals means "the operator supplied an out-of-scope target".
# ctx.scope.discoveries_refused means "a stage discovered something outside
# scope and correctly did not scan it" -- expected and routine, sometimes
# hundreds of entries. They must render in different sections so a reader
# does not read a big discovery count as an RoE problem, and a run with many
# discovery refusals must not present as degraded.


def test_discoveries_refused_render_in_their_own_labelled_section(tmp_path):
    ctx = seeded(tmp_path)
    ctx.scope.record_discovery_refusal(
        stage="subfinder", kind="HOST",
        value="found.evil.test", host="found.evil.test",
    )
    md = render_markdown(ctx, [])
    assert "found.evil.test" in md
    assert "Discovered, not scanned" in md
    # Not filed under the operator-target-refusal heading.
    section = md[md.index("### Discovered, not scanned"):]
    assert "found.evil.test" in section


def test_discoveries_refused_do_not_land_under_out_of_scope_targets_refused(tmp_path):
    ctx = seeded(tmp_path)
    ctx.scope.filter(["operator-supplied-evil.test"])
    ctx.scope.record_discovery_refusal(
        stage="subfinder", kind="HOST",
        value="found.evil.test", host="found.evil.test",
    )
    md = render_markdown(ctx, [])
    refused_section = md[md.index("### Out-of-scope targets refused"):
                         md.index("### Discovered, not scanned")]
    assert "operator-supplied-evil.test" in refused_section
    assert "found.evil.test" not in refused_section


def test_many_discoveries_refused_do_not_trigger_degraded_banner(tmp_path):
    ctx = seeded(tmp_path)
    for i in range(200):
        ctx.scope.record_discovery_refusal(
            stage="subfinder", kind="HOST",
            value=f"evil{i}.test", host=f"evil{i}.test",
        )
    md = render_markdown(ctx, [StageResult(stage="subfinder", status="complete")])
    assert "DEGRADED" not in md.upper()
    assert "Discovered, not scanned (out of scope) (200)" in md


def test_no_discoveries_refused_omits_the_section(tmp_path):
    md = render_markdown(seeded(tmp_path), [])
    assert "Discovered, not scanned" not in md


def test_backtick_in_discovery_refusal_host_stays_in_span(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.scope.record_discovery_refusal(
        stage="subfinder", kind="HOST",
        value="evil`test.example", host="evil`test.example",
    )
    md = render_markdown(ctx, [])
    line = [ln for ln in md.splitlines() if "evil" in ln and "test.example" in ln]
    assert len(line) == 1
    assert line[0].count("`") == 2


def test_asset_inventory_present(tmp_path):
    md = render_markdown(seeded(tmp_path), [])
    assert "acc.example:443" in md


def test_no_findings_renders_cleanly(tmp_path):
    md = render_markdown(ctx_for(tmp_path), [])
    assert "No findings" in md


def test_report_states_degraded_when_stage_skipped(tmp_path):
    md = render_markdown(seeded(tmp_path), [
        StageResult(stage="naabu", status="skipped",
                    failure=FailureClass.MISSING_BINARY, reason="missing"),
    ])
    assert "DEGRADED" in md.upper()


def test_no_input_skip_is_not_degraded(tmp_path):
    """A stage skipped because it had nothing to consume is a correct
    outcome, not a degradation — mirrors the definition in
    RunContext.write_manifest."""
    md = render_markdown(seeded(tmp_path), [
        StageResult(stage="katana", status="skipped",
                    failure=FailureClass.NO_INPUT, reason="no http services"),
    ])
    assert "DEGRADED" not in md.upper()


def test_partial_stage_appears_in_coverage_and_sets_degraded(tmp_path):
    """A stage that exited non-zero but produced usable output is degraded
    coverage, not a completion: it must appear in the 'was not scanned'
    table and trip the DEGRADED banner, exactly like skipped/failed."""
    md = render_markdown(seeded(tmp_path), [
        StageResult(stage="httpx", status="partial",
                    failure=FailureClass.PARTIAL, reason="exited 1 with output"),
    ])
    assert "DEGRADED" in md.upper()
    assert "httpx" in md
    assert "exited 1 with output" in md
    lowered = md.lower()
    coverage_section = lowered[lowered.index("coverage"):]
    assert "httpx" in coverage_section


def _coverage_rows(md):
    """The data rows of the coverage table, excluding header and separator."""
    section = md[md.index("## Coverage"):]
    return [ln for ln in section.splitlines()
            if ln.startswith("|") and "---" not in ln
            and not ln.startswith("| Stage |")]


def test_pipe_and_newline_in_reason_stay_one_intact_row(tmp_path):
    """A stage reason carries raw tool output. An unescaped pipe would split
    the row into spurious columns and a newline would break it across lines,
    corrupting the one section a reader relies on to know what was missed."""
    md = render_markdown(seeded(tmp_path), [
        StageResult(stage="naabu", status="partial", failure=FailureClass.PARTIAL,
                    reason="rate limited | lost 40%\nsecond line"),
    ])
    rows = _coverage_rows(md)
    assert len(rows) == 1, f"reason broke the table into {len(rows)} rows: {rows}"
    row = rows[0]
    assert "\\|" in row, "pipe was not escaped"
    # Exactly the 4 declared columns: split on unescaped pipes only.
    assert len(row.replace("\\|", "\x00").split("|")) - 2 == 4
    assert "second line" in row


def test_pipe_and_newline_in_finding_title_do_not_inject(tmp_path):
    """Titles come from scanner templates and are equally untrusted. An
    embedded newline must not inject what reads as a further heading."""
    ctx = ctx_for(tmp_path)
    ctx.store.add_finding(Finding(stage="httpx", severity="high",
                                  title="Reflected XSS | param\n## Injected heading",
                                  target="acc.example", template_id="t-inj"))
    md = render_markdown(ctx, [])
    title_lines = [ln for ln in md.splitlines() if ln.startswith("#### ")]
    assert len(title_lines) == 1
    assert "\\|" in title_lines[0], "pipe was not escaped"
    # The injected heading was folded into the title line, not left to
    # start a line of its own where it would render as a real section.
    assert not any(ln.lstrip().startswith("## Injected") for ln in md.splitlines())
    assert "Injected heading" in title_lines[0]


def test_manifest_and_report_agree_on_degraded(tmp_path):
    """Regression guard for the drift this task found: the report once
    exempted a failed stage carrying NO_INPUT while write_manifest did not,
    so the report printed clean while run.json said degraded. Both now call
    the single is_degraded()."""
    ctx = seeded(tmp_path)
    results = [StageResult(stage="dnsx", status="failed",
                           failure=FailureClass.NO_INPUT, reason="died late")]
    ctx.write_manifest(results)
    manifest = json.loads((ctx.run_dir / "run.json").read_text())
    md = render_markdown(ctx, results)
    assert manifest["degraded"] is True
    assert ("DEGRADED" in md.upper()) is manifest["degraded"]


# --- The coverage section states the denominator plainly --------------------


def test_coverage_section_states_the_denominator_with_a_refusal(tmp_path):
    ctx = seeded(tmp_path)
    ctx.coverage = Coverage(targets_requested=2, targets_permitted=1,
                            stages_requested=["dnsx"])
    md = render_markdown(ctx, [StageResult(stage="dnsx", status="complete")])
    coverage_section = md[md.index("## Coverage"):]
    assert "2 requested" in coverage_section
    assert "1 in scope" in coverage_section
    assert "1 refused" in coverage_section
    assert "DEGRADED" in md.upper()


def test_coverage_section_omits_refused_count_when_nothing_was_refused(tmp_path):
    ctx = seeded(tmp_path)
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["dnsx"])
    md = render_markdown(ctx, [StageResult(stage="dnsx", status="complete")])
    coverage_section = md[md.index("## Coverage"):]
    assert "1 requested" in coverage_section
    assert "refused" not in coverage_section


def test_coverage_table_lists_a_requested_stage_with_no_result_at_all(tmp_path):
    """The other half of the mechanism finding: a stage requested but never
    reached (e.g. one after an abort) has no StageResult, so it cannot
    appear via the ordinary skipped/failed/partial rows -- it needs its
    own."""
    ctx = seeded(tmp_path)
    ctx.coverage = Coverage(targets_requested=1, targets_permitted=1,
                            stages_requested=["dnsx", "naabu"])
    md = render_markdown(ctx, [StageResult(stage="dnsx", status="complete")])
    coverage_section = md[md.index("## Coverage"):]
    assert "naabu" in coverage_section
    assert "DEGRADED" in md.upper()


def test_zero_stage_run_says_nothing_ran(tmp_path):
    md = render_markdown(ctx_for(tmp_path), [])
    assert "No stages ran" in md
    assert "All selected stages completed" not in md


def test_inventory_caps_long_lists(tmp_path):
    ctx = ctx_for(tmp_path)
    for i in range(INVENTORY_CAP + 50):
        ctx.store.add(Artifact(ArtifactKind.PORT, f"acc.example:{i:05d}"))
    md = render_markdown(ctx, [])
    ports = md[md.index("### Ports"):]
    listed = [ln for ln in ports.splitlines() if ln.startswith("- `acc.example:")]
    assert len(listed) == INVENTORY_CAP
    assert "and 50 more ports" in ports


def _finding_bullet(md, label):
    """The single bullet line carrying the given label."""
    lines = [ln for ln in md.splitlines() if ln.startswith(f"- **{label}:**")]
    assert len(lines) == 1, f"expected one {label} bullet, got {lines}"
    return lines[0]


def test_backtick_in_evidence_cannot_break_out_of_code_span(tmp_path):
    """Evidence comes straight from scanner output. A backtick would close
    the span early and the remainder would escape as prose."""
    ctx = ctx_for(tmp_path)
    ctx.store.add_finding(Finding(stage="httpx", severity="high", title="Reflected",
                                  target="acc.example", template_id="t-ev",
                                  evidence="payload ` then **bold**\nsecond line"))
    md = render_markdown(ctx, [])
    bullet = _finding_bullet(md, "Evidence")
    # The only backticks on the line are the two span delimiters.
    assert bullet.count("`") == 2
    assert bullet.startswith("- **Evidence:** `") and bullet.endswith("`")
    # Content survives, folded onto the one bullet, inert inside the span.
    assert "second line" in bullet
    assert "**bold**" in bullet


def test_backtick_in_raw_ref_cannot_break_out_of_code_span(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.store.add_finding(Finding(stage="httpx", severity="high", title="Reflected",
                                  target="acc.example", template_id="t-raw",
                                  raw_ref="raw/httpx.jsonl ` line 3\nmore"))
    md = render_markdown(ctx, [])
    bullet = _finding_bullet(md, "Raw")
    assert bullet.count("`") == 2
    assert bullet.startswith("- **Raw:** `") and bullet.endswith("`")
    assert "more" in bullet


def test_newline_in_description_stays_one_bullet(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.store.add_finding(Finding(stage="httpx", severity="high", title="Reflected",
                                  target="acc.example", template_id="t-desc",
                                  description="first line\nsecond line",
                                  remediation="do this\nthen that"))
    md = render_markdown(ctx, [])
    desc = [ln for ln in md.splitlines() if ln.startswith("- first line")]
    assert len(desc) == 1
    assert desc[0] == "- first line second line"
    rem = _finding_bullet(md, "Remediation")
    assert rem == "- **Remediation:** do this then that"


def test_backtick_in_target_stays_in_span(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.store.add_finding(Finding(stage="httpx", severity="high", title="T",
                                  target="https://acc.example/x`y",
                                  template_id="t-tgt"))
    md = render_markdown(ctx, [])
    bullet = _finding_bullet(md, "Target")
    assert bullet.count("`") == 2
    assert bullet.endswith("`")


def test_backtick_in_template_id_stays_in_span(tmp_path):
    """The Stage/Template bullet puts prose and a code span on one line, so
    a stray backtick in either half can capture the span's delimiter."""
    ctx = ctx_for(tmp_path)
    ctx.store.add_finding(Finding(stage="ht`px", severity="high", title="T",
                                  target="acc.example", template_id="tpl`z"))
    md = render_markdown(ctx, [])
    bullet = _finding_bullet(md, "Stage")
    assert bullet.count("`") == 2
    assert bullet.endswith("`")


def test_backtick_in_inventory_value_stays_in_span(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/a`b"))
    md = render_markdown(ctx, [])
    line = [ln for ln in md.splitlines()
            if "acc.example" in ln and ln.startswith("- `")]
    assert len(line) == 1
    assert line[0].count("`") == 2


def test_backtick_in_refused_target_stays_in_span(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.scope.filter(["https://evil.test/p`q"])
    md = render_markdown(ctx, [])
    line = [ln for ln in md.splitlines() if "evil.test" in ln]
    assert len(line) == 1
    assert line[0].count("`") == 2


def _seed_every_external_field(tmp_path, marker="x`y"):
    """A run whose every externally-derived value carries a backtick."""
    ctx = ctx_for(tmp_path)
    for kind in (ArtifactKind.HOST, ArtifactKind.DNS_RECORD,
                 ArtifactKind.PORT, ArtifactKind.HTTP_SERVICE):
        ctx.store.add(Artifact(kind, f"{kind.name.lower()}-{marker}"))
    ctx.store.add_finding(Finding(
        stage=f"stage{marker}", severity="high", title=f"title{marker}",
        target=f"target{marker}", template_id=f"tpl{marker}",
        evidence=f"ev{marker}", description=f"desc{marker}",
        remediation=f"rem{marker}", raw_ref=f"raw{marker}"))
    ctx.scope.filter([f"https://evil.test/{marker}"])
    ctx.scope.record_discovery_refusal(
        stage=f"stage{marker}", kind="HOST",
        value=f"discovered{marker}.example", host=f"discovered{marker}.example",
    )
    results = [StageResult(stage=f"st{marker}", status="failed",
                           failure=FailureClass.TRANSPORT, reason=f"reason{marker}")]
    return ctx, results


# --- finding-id collisions surface honestly in the report ------------------


def test_finding_collision_renders_a_banner_and_table(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.store.add_finding(Finding(stage="dnsx", severity="high", title="First",
                                  target="acc.example", template_id="t-a",
                                  evidence="first-secret-evidence"))
    ctx.store.add_finding(Finding(stage="dnsx", severity="high", title="Second",
                                  target="acc.example", template_id="t-a",
                                  evidence="second-secret-evidence"))
    md = render_markdown(ctx, [])
    assert "FINDING ID COLLISION" in md.upper()
    assert "Finding ID collisions" in md
    assert "dnsx" in md
    assert "t-a" in md
    assert "evidence" in md  # the differing FIELD NAME, not its value
    # The discarded (second) finding was never stored, so its evidence must
    # never appear anywhere in the report.
    assert "second-secret-evidence" not in md
    # The collisions table itself carries identity only, never a value --
    # even for the finding that WAS kept and legitimately appears elsewhere,
    # in the ordinary Findings section.
    section = md[md.index("## Finding ID collisions"):]
    assert "first-secret-evidence" not in section


def test_no_collisions_omits_the_collision_section(tmp_path):
    md = render_markdown(seeded(tmp_path), [])
    assert "FINDING ID COLLISION" not in md.upper()
    assert "Finding ID collisions" not in md


def test_every_line_has_balanced_backticks(tmp_path):
    """The general guard.

    Three rounds of this task each found another unsanitised code span, so
    the per-field approach does not converge. This asserts the property over
    the whole rendered document: it catches the next span someone adds
    without _inline, and it catches prose or a table cell that lets a stray
    backtick pair with a neighbouring span's delimiter.
    """
    ctx, results = _seed_every_external_field(tmp_path)
    md = render_markdown(ctx, results)
    # Sanity: the seeded values really did reach the report.
    assert "target" in md and "evil.test" in md
    odd = [ln for ln in md.splitlines() if ln.count("`") % 2]
    assert not odd, f"unbalanced backticks on {len(odd)} line(s): {odd}"
