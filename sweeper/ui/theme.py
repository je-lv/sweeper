"""Shared console, colors and severity styling."""
from __future__ import annotations

import io
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim white",
}

ACCENT = "bold #c084fc"
OK = "bold #00d787"
WARN = "bold #ffb000"
BAD = "bold red"


def severity_text(sev: str) -> Text:
    return Text(sev.upper(), style=SEVERITY_STYLE.get(sev, "white"))


def banner(config, run_dir: Path) -> Panel:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim")
    t.add_column()
    t.add_row("Targets", f"{config.targets_file}")
    t.add_row("Level", Text(config.level, style=ACCENT))
    t.add_row("Auth", Text(config.auth_mode, style=ACCENT))
    t.add_row("Stages", ", ".join(config.stages) or "all eligible")
    t.add_row("Proxy", config.proxy or "off")
    t.add_row("Output", str(run_dir))
    return Panel(t, title="[bold]sweeper[/bold]", border_style=ACCENT)


def render_to_text(renderable) -> str:
    """Render to plain text — used by tests and for logging."""
    sink = io.StringIO()
    buf = Console(record=True, width=100, file=sink)
    buf.print(renderable)
    return buf.export_text()
