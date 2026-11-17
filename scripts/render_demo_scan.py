#!/usr/bin/env python3
"""Export the README's recorded sample progress view as an SVG."""
from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace

from rich.console import Console
from rich.terminal_theme import MONOKAI

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sweeper.stages.base import FailureClass, StageResult
from sweeper.ui.progress import ProgressReporter


OUTPUT = ROOT / "docs" / "sweeper-demo.svg"
STAGES = [
    "dnsx", "dnssec", "cdncheck", "naabu", "nmap", "tlsx", "httpx",
    "content", "katana", "jsrecon", "nuclei",
]


def main() -> None:
    console = Console(record=True, width=108, color_system="truecolor")
    console.print("[bold #00d787]$[/] sweeper -t targets.txt -l mid --no-menu --time-limit 20m")
    console.print()

    reporter = ProgressReporter(STAGES, console=console)
    results = [
        StageResult("dnsx", "complete", artifacts=18, findings=3),
        StageResult("dnssec", "complete", findings=1),
        StageResult("cdncheck", "complete", artifacts=4),
        StageResult("naabu", "complete", artifacts=11),
        StageResult("nmap", "complete", artifacts=9, findings=2),
        StageResult("tlsx", "complete", artifacts=6, findings=2),
        StageResult("httpx", "complete", artifacts=7, findings=1),
        StageResult("content", "complete", artifacts=5, findings=2),
        StageResult("katana", "complete", artifacts=42),
        StageResult("jsrecon", "complete", artifacts=17, findings=1),
        StageResult(
            "nuclei", "partial", failure=FailureClass.PARTIAL,
            reason="time limit reached; partial output retained", findings=4,
        ),
    ]
    ctx = SimpleNamespace(
        config=SimpleNamespace(level="mid", auth_mode="unauth"),
        scope=SimpleNamespace(refusals=[]),
    )
    reporter.bind(ctx=ctx, results=results, reading=(6 * 1024**3, 16 * 1024**3))
    reporter._run_started = 0.0
    reporter._run_ended = 94.2
    for index, name in enumerate(STAGES):
        row = reporter._rows[name]
        row.status = results[index].status
        row.started = index * 5.0
        row.finished = row.started + 4.2

    console.print(reporter._render())
    console.print("[bold #00d787]done[/]  [grey62]reports written to recon/sweeper/20261117-142530[/]")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    svg = console.export_svg(
        title="sweeper: recorded sample scan",
        theme=MONOKAI,
    )
    OUTPUT.write_text(
        "\n".join(line.rstrip() for line in svg.splitlines()) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
