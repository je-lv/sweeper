"""Live progress display for a run.

runner.run_stages() already calls an on_progress(stage_name, state) hook at
every state transition (see runner.py's _notify) — nothing on the CLI path
supplied one, so a real run printed nothing until it finished. This module
is the callback: app.py constructs a ProgressReporter and passes it as
on_progress.

States actually emitted, enumerated by reading every _notify() call site in
runner.py directly rather than guessing:

    "running"   — runner.py:184, a stage started
    "skipped"   — runner.py:181, NO_INPUT (nothing for the stage to consume)
    "failed"    — runner.py:210 (in-process TRANSPORT), :292 (subprocess
                  TRANSPORT with empty output), :387 (PARSE_ERROR)
    "complete"  — runner.py:396, result.status for a clean finish
    "partial"   — runner.py:396, result.status for a non-zero exit that
                  still produced usable output

A stage skipped outright because the operator hit Ctrl-C (INTERRUPTED,
appended directly to `results` at runner.py:169-172, never through
_notify) is never reported here at all — its row is simply left at
"pending", which is accurate: from this module's point of view it never
started.

Any state string not in the table above is still rendered, not dropped or
raised on: a future runner change that adds a state must degrade to
"show something changed" rather than crashing a live run. See
_STATE_STYLE.get(..., theme.WARN) below.

Never prints a command, argument, header or finding — only a stage NAME
(already public: it is the external tool's name, e.g. "naabu"), the STATE
STRING the runner hands back, COUNTS, and the stage's own reason string,
which the runner already writes verbatim to sweep.log and run.json.
sweep.log and run.json are the redacted record; this is a third channel and
must not carry anything they don't already carry in the clear.

WHAT IT SHOWS, AND WHY EACH ONE IS HERE. Every column below exists because
something was invisible during a live run:

    counts      a finished stage said only "done", so "did that find
                anything" meant waiting for the report
    reason      katana went `partial` and the table said only "partial".
                The reason -- killed by the kernel, not by sweeper -- was
                in run.json and the report, both read after the fact, and
                the person who could still act on it was watching the table
    memory      the machine filled up and nothing said so until the OOM
                killer fired (see ui/meminfo.py)
    refusals    a run refusing hundreds of out-of-scope discoveries looks
                identical to one refusing none, and that difference is the
                whole scope-safety story

BOUND, NOT PUSHED. The (name, state) callback contract is unchanged. The
extra data is read from a ctx and the results list the runner already
mutates in place, handed over once via bind(). That keeps every existing
caller working, and a reporter nobody binds renders exactly as it did
before rather than crashing on data it does not have.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass

from rich import box
from rich.console import Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import meminfo, theme

#: Fraction of RAM in use at which the gauge stops being informational and
#: starts being a warning. A number alone is not a warning -- nobody
#: watching a table does arithmetic -- so past this it has to LOOK
#: different. 0.85 leaves roughly 2 GB of headroom on a 16 GB machine,
#: which is about one katana away from the kill measured on 2026-08-05.
MEM_ALARM = 0.85

#: Sentinel: "no override supplied", distinct from an explicit None, which
#: means "this machine cannot report memory, render no gauge".
_UNSET = object()

_GB = 1024 ** 3

#: skipped is the EXPECTED downstream of an upstream miss, not a fault of its
#: own. A whole column of WARN-yellow skips -- nine of them, on the run that
#: prompted this redesign -- drowns the one red failure that actually needs
#: acting on. So it recedes to a muted grey, and stays visibly distinct from
#: partial (which IS a WARN: a stage that ran and only half-succeeded).
MUTED = "grey42"

#: The brand chip in the header. Decorative; rich approximates the truecolour
#: background down to the nearest 256-colour on terminals that lack it, and
#: drops it entirely on a no-colour console, leaving the plain word.
BRAND_STYLE = "bold white on #7c3aed"

_STATE_STYLE = {
    "pending": "grey30",
    "running": theme.ACCENT,
    "complete": theme.OK,
    "skipped": MUTED,
    "partial": theme.WARN,
    "failed": theme.BAD,
}

#: The word inside each status badge (a reverse-video chip). Empty for
#: pending: an unstarted stage gets a dim dot, no chip.
_STATE_LABEL = {
    "pending": "",
    "running": "run",
    "complete": "done",
    "skipped": "skip",
    "partial": "partial",
    "failed": "failed",
}

#: Glyph in the leftmost column. "running" is special-cased to a spinner
#: frame in _render; every other state is a fixed shape, so status survives a
#: screenshot, a pipe, or a colour-blind reader -- colour alone never carries
#: it.
_STATE_GLYPH = {
    "pending": "·",
    "complete": "✔",
    "skipped": "·",
    "partial": "◐",
    "failed": "✘",
}

#: Braille spinner: reads as smooth motion at the 4fps this redraws at, where
#: the old |/-\ strobed.
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

#: Strips ANSI SGR sequences a tool baked into its own text -- naabu's error
#: arrives as "\x1b[1;31mFTL\x1b[0m ...". Without this the escapes render as
#: literal "[1;31m" in the reason column and fight the row's own styling.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(s: str) -> str:
    return _ANSI_RE.sub("", s or "")


def _gauge(frac: float, width: int = 10) -> "Text":
    """A proportion bar, green below 0.7, amber to the alarm line, red past
    it. The colour is backed by a named "LOW" in _header for the same reason
    the glyphs exist: a bar's colour alone is lost to a pipe or a screenshot,
    so the warning has to survive as text too."""
    frac = max(0.0, min(1.0, frac))
    filled = round(frac * width)
    style = (theme.BAD if frac >= MEM_ALARM
             else theme.WARN if frac >= 0.7
             else theme.OK)
    bar = Text()
    bar.append("▰" * filled, style=style)
    bar.append("▱" * (width - filled), style="grey30")
    return bar


@dataclass
class _Row:
    name: str
    status: str = "pending"
    started: float | None = None
    finished: float | None = None

    def elapsed(self, now: float) -> float | None:
        if self.started is None:
            return None
        end = self.finished if self.finished is not None else now
        return end - self.started


class ProgressReporter:
    """Renders run_stages()'s on_progress(name, state) calls as they happen.

    Construct with the ordered list of stage names the run intends to run —
    known before the run starts (app.py works it out via build_stages() or,
    for --resume, resume.incomplete_stages()) so every stage shows from the
    first frame, not only the ones that happened to report in. A stage that
    reports in without being in that list (e.g. incomplete_stages()
    disagreeing with what actually got dispatched) is still shown; it is
    appended rather than dropped.

    Use as a context manager around whatever drives the run:

        with ProgressReporter(names) as report:
            execute(config, on_progress=report)

    On a real terminal (`console.is_terminal`) this drives a `rich.live.Live`
    table, redrawn at a capped rate — never per artifact, only on a state
    transition or the refresh timer. Off a terminal — piped, redirected,
    cron — no Live is created at all: each call prints exactly one plain
    line via `print()`, with no rich markup and therefore no ANSI escapes,
    and no redraw. That branch is decided once, at construction, from
    `console.is_terminal`; it is not re-derived per line.
    """

    def __init__(self, stage_names, console=None,
                 refresh_per_second: float = 4.0) -> None:
        self.console = console or theme.console
        self.tty = self.console.is_terminal
        self._rows: dict[str, _Row] = {name: _Row(name) for name in stage_names}
        self._order: list[str] = list(stage_names)
        self._run_started = time.time()
        self._run_ended: float | None = None
        self._refresh_per_second = refresh_per_second
        self._live: Live | None = None
        # Optional, supplied by bind(). Absent is a supported state, not a
        # degraded one: the table renders without them.
        self._ctx = None
        self._results = None
        self._reading_override = _UNSET

    def bind(self, ctx=None, results=None, reading=_UNSET) -> None:
        """Hand over the live run objects the extra columns read from.

        Called by app.execute() once the RunContext exists, which is after
        this reporter was constructed -- hence a second call rather than
        constructor arguments.

        `results` is the SAME list run_stages mutates in place (see its
        docstring), so no updates have to be pushed here; each render reads
        whatever it currently holds. `reading` exists for tests to pin the
        memory figure, and passing an explicit None means "no gauge" as
        distinct from "not supplied".
        """
        if ctx is not None:
            self._ctx = ctx
        if results is not None:
            self._results = results
        if reading is not _UNSET:
            self._reading_override = reading

    # -- optional data, every reader fails soft -----------------------------
    def _result_for(self, name):
        """This stage's StageResult, or None. Never raises: the display must
        not be able to kill the run it is describing."""
        try:
            for r in self._results or ():
                if getattr(r, "stage", None) == name:
                    return r
        except Exception:
            return None
        return None

    def _reading(self):
        if self._reading_override is not _UNSET:
            return self._reading_override
        try:
            return meminfo.read()
        except Exception:
            return None

    def _refusal_count(self):
        try:
            return len(self._ctx.scope.refusals)
        except Exception:
            return None

    # -- context manager --------------------------------------------------
    def __enter__(self) -> "ProgressReporter":
        self._run_started = time.time()
        self._run_ended = None
        if self.tty:
            self._live = Live(
                console=self.console,
                get_renderable=self._render,
                refresh_per_second=self._refresh_per_second,
                transient=False,
            )
            self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._run_ended = time.time()
        if self._live is not None:
            self._live.refresh()
            self._live.__exit__(exc_type, exc, tb)
            self._live = None

    # -- the on_progress callback -------------------------------------------
    def __call__(self, name: str, state: str) -> None:
        row = self._rows.get(name)
        if row is None:
            row = _Row(name)
            self._rows[name] = row
            self._order.append(name)

        now = time.time()
        if state == "running":
            row.started = now
            row.finished = None
        else:
            # Every non-"running" state freezes this row's clock, including
            # an unrecognised one: it is not "running", so its elapsed time
            # must stop ticking rather than look like a stuck live stage.
            if row.started is None:
                row.started = now
            row.finished = now
        row.status = state

        if self.tty:
            # Guarded: a notify can arrive before __enter__ or after
            # __exit__ (a late callback from a stage being torn down), and
            # this module's whole contract is that the display cannot kill
            # the run it describes. The state is already recorded above, so
            # the next render shows it either way.
            if self._live is not None:
                self._live.refresh()
        else:
            elapsed = row.elapsed(now)
            suffix = f" ({elapsed:.1f}s)" if elapsed is not None else ""
            # Through the injected console (never a bare print()) so this
            # is testable against a StringIO console and, in production,
            # goes through the same stdout theme.console already uses.
            # No markup, no highlighting: guarantees plain text even if a
            # future rich version changes its non-terminal auto-detection.
            self.console.print(f"{name}: {state}{suffix}",
                               markup=False, highlight=False)

    # -- rendering ----------------------------------------------------------
    def _header(self) -> "Text":
        """The brand chip, run identity, memory gauge and refusal badge, on
        one line. Every piece past the chip is independently optional: an
        unbound reporter shows only the chip, a machine with no /proc shows no
        gauge, a run that has refused nothing shows no badge -- each reads its
        source through a try/except so a missing one is absent, not a blank.
        """
        line = Text()
        line.append(" sweeper ", style=BRAND_STYLE)

        try:
            cfg = self._ctx.config
            line.append("  ")
            line.append(str(cfg.level), style=theme.ACCENT)
            line.append(" · ", style="grey30")
            line.append(str(cfg.auth_mode), style="grey62")
        except Exception:
            pass

        reading = self._reading()
        used = meminfo.pressure(reading)
        if reading is not None and used is not None:
            available, total = reading
            line.append("     ")
            line.append("mem ", style="grey62")
            line.append(_gauge(used))
            line.append(f" {(total - available) / _GB:.1f}/{total / _GB:.1f}G",
                        style="grey62")
            if used >= MEM_ALARM:
                # Named, not merely coloured: has to survive a piped console,
                # a colour-blind operator and a screenshot.
                line.append(" LOW", style=theme.BAD)

        refused = self._refusal_count()
        if refused:
            line.append("     ")
            line.append(f" refused {refused} ", style=f"{theme.WARN} reverse")

        return line

    def _render(self):
        now = time.time()
        # Name column sized to the longest stage NAME only -- never to the
        # reason, which lives in its own trailing column and so can no longer
        # stretch the rows to its left. Floor of 6 keeps a one-stage --resume
        # from collapsing to a sliver.
        namew = max(6, max((len(n) for n in self._order), default=6))

        # expand=True + a single ratio column is what keeps the FIXED columns
        # fixed. Without it, a long no-wrap reason blows the table's ideal
        # width past the panel and rich shrinks EVERY column to fit -- the
        # name collapses to "cd…", the badge to "do…". With it, the fixed
        # columns hold their widths and the reason (ratio=1) is the only
        # column that gives, ellipsising in whatever space is left.
        table = Table.grid(padding=(0, 1), expand=True)
        table.add_column(justify="center", width=1)          # glyph
        table.add_column(width=namew, no_wrap=True)          # name
        table.add_column(width=9, no_wrap=True)              # status badge
        table.add_column(justify="right", width=6)           # elapsed
        table.add_column(justify="right", width=5)           # artifacts (Na)
        table.add_column(justify="right", width=5)           # findings (Nf)
        # The reason is the ONLY flexible column and it is last, so it absorbs
        # the remaining width and ellipsises there. sweep.log and the report
        # carry it in full.
        table.add_column(ratio=1, overflow="ellipsis", no_wrap=True)  # reason

        tally = {"complete": 0, "running": 0, "partial": 0,
                 "failed": 0, "skipped": 0, "pending": 0}
        for name in self._order:
            row = self._rows[name]
            status = row.status
            tally[status] = tally.get(status, 0) + 1
            style = _STATE_STYLE.get(status, theme.WARN)
            ran = status in ("complete", "partial", "failed")

            if status == "running":
                glyph = _SPINNER_FRAMES[int(now * 4) % len(_SPINNER_FRAMES)]
            else:
                glyph = _STATE_GLYPH.get(status, "·")

            label = _STATE_LABEL.get(status, status)
            badge = (Text(f" {label} ", style=f"{style} reverse")
                     if label else Text(""))

            if ran:
                name_style = "bold"
            elif status == "pending":
                name_style = "grey42"
            else:
                name_style = "grey62"

            elapsed = row.elapsed(now)
            time_txt = (Text(f"{elapsed:.1f}s", style="grey62")
                        if elapsed is not None else Text("—", style="grey30"))

            # Counts are known only once a stage has finished parsing. Blank
            # (not "0") while it runs or if it was skipped: a lone 0 on ten
            # skipped rows was noise, and a 0 on a running stage would read as
            # "found nothing" before it had looked. Labelled inline with a/f
            # so each row is self-describing -- no header row to scroll back to.
            result = self._result_for(name)
            art_txt = find_txt = Text("")
            if result is not None and ran:
                a = getattr(result, "artifacts", 0) or 0
                f = getattr(result, "findings", 0) or 0
                if a:
                    art_txt = Text(f"{a}a", style="grey62")
                if f:
                    find_txt = Text(f"{f}f", style=theme.OK)

            reason = _plain(getattr(result, "reason", "")
                            if result is not None else "")
            reason_txt = Text("")
            if reason and status in ("partial", "failed", "skipped"):
                rstyle = (theme.BAD if status == "failed"
                          else theme.WARN if status == "partial"
                          else MUTED)
                reason_txt = Text(reason, style=rstyle)

            table.add_row(Text(glyph, style=style),
                          Text(name, style=name_style),
                          badge, time_txt, art_txt, find_txt, reason_txt)

        end = self._run_ended if self._run_ended is not None else now
        foot = Text()
        foot.append(f"{tally['complete']} done", style=theme.OK)
        for key, colour, word in (("running", theme.ACCENT, "running"),
                                  ("partial", theme.WARN, "partial"),
                                  ("failed", theme.BAD, "failed"),
                                  ("skipped", MUTED, "skipped")):
            if tally.get(key):
                foot.append("  ·  ", style="grey30")
                foot.append(f"{tally[key]} {word}", style=colour)
        foot.append("  ·  ", style="grey30")
        foot.append(f"{end - self._run_started:.1f}s", style="grey62")

        body = Group(self._header(), Text(""), table, Text(""), foot)
        return Panel(body, box=box.ROUNDED, border_style="grey35",
                     padding=(0, 1), title="[grey42]recon sweep[/]",
                     title_align="left")
