"""Shared report-writing entrypoint.

Every place that produces a StageResult list must write BOTH report.md and
report.html -- an aborted or crashed run is exactly the case where an
operator most needs to open a report and see why it stopped. write_reports
is the ONE place that does both, so no call site can wire up only one (the
gap this closes: an earlier version of app.py wired write_html into only
the success path, so an aborted or crashed run got report.md but no
report.html).

The HTML half is still wrapped in a try/except. This repo ships no
dependency metadata (see sweeper/report/html.py's `_environment()`
docstring), so Jinja2 is an optional, undeclared dependency: on a host
that lacks it, `write_html` raises ImportError. That must not take the
scan's own record down with it -- report.md depends on nothing outside the
standard library and is the primary deliverable, so it is written
unguarded; report.html is best-effort, and its absence is never silent
(logged to sweep.log and printed to the console), matching the resilience
`app._write_reports` had before this module replaced it.
"""
from __future__ import annotations

from pathlib import Path

from .html import write_html
from .markdown import write_markdown


def write_reports(ctx, results, triage=None) -> tuple[Path, Path | None]:
    md_path = write_markdown(ctx, results)
    try:
        html_path = write_html(ctx, results, triage=triage)
    except Exception as exc:            # noqa: BLE001 - see module docstring
        msg = f"HTML report not written ({type(exc).__name__}: {exc})"
        ctx.log(msg)
        try:
            from ..ui import theme
            theme.console.print(f"[yellow]report:[/yellow] {msg}")
        except Exception:               # noqa: BLE001 - console is best-effort
            pass
        html_path = None
    return md_path, html_path
