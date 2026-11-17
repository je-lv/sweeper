"""Menu REPL.

prompt_fn and runner_fn are injected so the whole menu is testable without
a pty. Nothing here reads stdin directly.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.markup import escape

from ..context import RunConfig
from ..profile import ProfileError, load_profile, save_profile
from ..stages.base import LEVELS
from . import theme

AUTH_MODES = ("unauth", "auth")

ACK_PHRASE = "I ACKNOWLEDGE"

MENU = """\
 1) Targets file
 2) Operation level      [{level}]
 3) Auth mode            [{auth}]
 4) Toggle stages
 5) Subdomain enum       [{enum}]
 6) Advanced (proxy, rate, time limit)
 7) Auth credentials     [{creds}]
 8) Triage a finding
 9) Diff two runs
 O) Open last report
 ──────────────────────────────
 R) Run          S) Save profile
 L) Load profile Q) Quit"""


@dataclass
class MenuState:
    config: RunConfig
    acknowledgements: list[dict] = field(default_factory=list)
    auth: object = None
    # The operator's persistent triage state (sweeper.triage.TriageState).
    # None means "no verdict can be recorded this session" -- option 8 says
    # so out loud rather than accepting a verdict and dropping it. Populated
    # on the real menu path by app.main(); see _open_triage there.
    triage: object = None

    @property
    def target_count(self) -> int:
        try:
            return sum(
                1 for l in self.config.targets_file.read_text().splitlines()
                if l.strip() and not l.strip().startswith("#")
            )
        except OSError:
            return 0


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def creds_label(state: MenuState) -> str:
    """What the credentials indicator says -- three states, not two.

    Stored credentials are RETAINED when the operator switches to `unauth`
    (an authenticated pass followed by an unauthenticated baseline pass is
    ordinary workflow, and discarding an imported Burp bundle on a mode
    toggle would be an expensive surprise). Retention is only honest if the
    indicator stops claiming they are in use: "configured" while auth_mode
    is `unauth` would state the one thing that is not true of the next run.
    See context.AuthModeViolation for the invariant that makes retaining
    them safe rather than merely convenient.
    """
    if not state.auth or state.auth.is_empty():
        return "none"
    if state.config.auth_mode != "auth":
        return "stored, NOT in use (auth mode: unauth)"
    return "configured"


def gate_level(state: MenuState, level: str, prompt_fn) -> bool:
    """Confirm a level before anything is allowed to select it.

    Shared by every path that can set a level: typing one at option 2, and
    loading a profile that specifies one. Keeping the gate in the option-2
    branch alone left the profile path ungated — pressing L then R ran
    dast fuzzing with acknowledgements empty. A control has to cover every
    route to the thing it guards, not the route the author had in mind.

    Returns True if the level may be selected.
    """
    if level == "high":
        # A full 65535-port sweep is arguably DoS-adjacent — but only when
        # that is what is about to happen. With --ports set it is not, and a
        # prompt that overstates the scan is not a safer prompt: it asks the
        # operator to confirm something other than the run they configured,
        # which teaches them to dismiss it.
        tcp = (f"scans TCP ports {state.config.ports}" if state.config.ports
               else "runs a full 65535-port TCP sweep")
        udp = state.config.udp_ports or "top-1000"
        scan = f"{tcp} and scans UDP {udp}"
        answer = (prompt_fn(f"`high` {scan}. Proceed? [y/N] ") or "").strip()
        if answer.lower() not in ("y", "yes"):
            return False
        # Spec 2.2/6.1/12.1(5): BOTH gates are recorded in the manifest with
        # a timestamp, not only `full`'s typed acknowledgement. Without this
        # the confirmation happened but left no trace that it had.
        state.acknowledgements.append(
            {"level": "high", "phrase": answer, "via": "menu", "at": _now()}
        )
        return True

    if level != "full":
        return True

    # dast fuzzing mutates application state.
    typed = (prompt_fn(
        "`full` enables dast parameter fuzzing, which MUTATES application "
        f"state (orders, coupons, carts).\nType {ACK_PHRASE!r} to continue: "
    ) or "").strip()
    if typed != ACK_PHRASE:
        return False
    if (prompt_fn("Confirm manual business-logic testing is complete or on a "
                  "separate account [y/N] ") or "").strip().lower() not in ("y", "yes"):
        return False
    state.acknowledgements.append(
        {"level": "full", "phrase": typed, "via": "menu", "at": _now()}
    )
    return True


# Exactly what context.new_run_dir produces: YYYYMMDD-HHMMSS, plus a -2,
# -3, ... suffix for runs that collided within the same second. Fixed
# repetition counts, so there is nothing here to backtrack over.
_RUN_DIR_RE = re.compile(r"^(\d{8}-\d{6})(?:-(\d+))?$")


def _run_dir_order(name: str):
    """Chronological sort key for a run directory name."""
    stamp, suffix = _RUN_DIR_RE.match(name).groups()
    # The unsuffixed directory is the FIRST run of that second, so it sorts
    # below -2. int(), not the string: "-10" is later than "-2" and sorts
    # earlier as text.
    return (stamp, int(suffix or 1))


def _latest_run_dir(outdir) -> "Path | None":
    """Most recent run directory under `outdir`, or None if there isn't one.

    Only directories matching the run-directory naming contract count, and
    they are ordered by (timestamp, collision suffix). A plain sort of every
    subdirectory name gets this wrong in two ways, and both hand the
    operator a DIFFERENT run's report while telling them it is the latest:

      - "20260101-000000-10" sorts before "20260101-000000-2" as text, so
        the tenth run of a busy second loses to the second one; and
      - anything else living under outdir -- a `notes/` directory, a copy of
        a previous engagement -- competes with real runs on name, and almost
        any word beats every timestamp this tool will ever generate.

    Showing the wrong report is worse than showing none: the path is printed
    and then acted on, and nothing downstream re-checks which run it came
    from.
    """
    from pathlib import Path
    outdir = Path(outdir)
    if not outdir.is_dir():
        return None
    runs = [d for d in outdir.iterdir()
            if d.is_dir() and _RUN_DIR_RE.match(d.name)]
    return max(runs, key=lambda d: _run_dir_order(d.name), default=None)


def apply_choice(state: MenuState, key: str, prompt_fn) -> str:
    """Returns 'continue', 'run', or 'quit'."""
    key = (key or "").strip().lower()
    cfg = state.config

    if key == "q":
        return "quit"
    if key == "r":
        return "run"

    if key == "1":
        from pathlib import Path
        value = prompt_fn("Targets file: ")
        if value and Path(value).is_file():
            cfg.targets_file = Path(value)
        return "continue"

    if key == "2":
        value = (prompt_fn(f"Level {LEVELS}: ") or "").strip().lower()
        if value not in LEVELS:
            return "continue"
        if not gate_level(state, value, prompt_fn):
            return "continue"
        cfg.level = value
        return "continue"

    if key == "3":
        value = (prompt_fn(f"Auth mode {AUTH_MODES}: ") or "").strip().lower()
        if value in AUTH_MODES:
            cfg.auth_mode = value
            # Switching to `unauth` with credentials stored must say
            # something. Silently retaining them and silently ignoring them
            # are both worse than telling the operator which it is: the
            # whole point of a baseline pass is knowing it was
            # unauthenticated, and the whole risk is believing it was when
            # it wasn't (or vice versa).
            if value == "unauth" and state.auth is not None \
                    and not state.auth.is_empty():
                theme.console.print(
                    "[bold yellow]note:[/bold yellow] your stored "
                    "credentials are RETAINED but will NOT be sent while "
                    "auth mode is 'unauth'. Switch back to 'auth' to use "
                    "them again, or press 7 and enter blanks to discard "
                    "them."
                )
        return "continue"

    if key == "4":
        value = prompt_fn("Stages (comma separated, blank = all): ")
        cfg.stages = [s.strip() for s in (value or "").split(",") if s.strip()]
        return "continue"

    if key == "5":
        value = (prompt_fn("Enable subdomain enumeration? [y/N] ") or "").strip().lower()
        cfg.subdomain_enum = value in ("y", "yes")
        return "continue"

    if key == "6":
        cfg.proxy = (prompt_fn(f"Proxy [{cfg.proxy or 'none'}]: ") or cfg.proxy).strip()
        rate = (prompt_fn(f"Rate override [{cfg.rate_override or 'default'}]: ") or "").strip()
        if rate.isdigit():
            cfg.rate_override = int(rate)
        current_ports = cfg.ports or "level's own range"
        ports = (prompt_fn(
            f"Ports, as top-100 / 80,443 / 1-1024 "
            f"[{current_ports}]: ") or "").strip()
        if ports:
            # Validated here rather than left to naabu. This is the one entry
            # point where the operator is present and can be told: a typo
            # that reaches the stage is an ARG_ERROR that aborts the whole
            # run, and preflight cannot say which prompt it came from.
            from ..ports import PortSpecError, parse as parse_ports
            try:
                parse_ports(ports)
            except PortSpecError as exc:
                print(f"  Not a usable port selection: {exc}")
            else:
                cfg.ports = ports
        current_udp = cfg.udp_ports or "level's own UDP range"
        udp_ports = (prompt_fn(
            f"UDP ports, as top-100 / 53,161 / 1-1024 "
            f"[{current_udp}]: ") or "").strip()
        if udp_ports:
            from ..ports import PortSpecError, parse as parse_ports
            try:
                parse_ports(udp_ports)
            except PortSpecError as exc:
                print(f"  Not a usable UDP port selection: {exc}")
            else:
                cfg.udp_ports = udp_ports
        cfg.time_limit = (prompt_fn(f"Time limit per stage e.g. 45m "
                                    f"[{cfg.time_limit or 'none'}]: ") or cfg.time_limit).strip()
        cfg.custom_templates = (prompt_fn(
            f"Custom nuclei templates dir "
            f"[{cfg.custom_templates or 'none'}]: ") or cfg.custom_templates).strip()
        return "continue"

    if key == "7":
        from pathlib import Path

        from ..auth import SecretBundle, from_burp_request

        mode = (prompt_fn("Credentials from [b]urp request or [m]anual? ") or "").strip().lower()
        if mode.startswith("b"):
            path = prompt_fn("Path to raw Burp request: ")
            if path and Path(path).is_file():
                try:
                    state.auth = from_burp_request(Path(path))
                except ValueError as exc:
                    theme.console.print(f"[bold red]import failed:[/bold red] {exc}")
        elif mode.startswith("m"):
            bundle = SecretBundle()
            cookie = (prompt_fn("Cookie header (blank to skip): ") or "").strip()
            if cookie:
                for part in cookie.split(";"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        bundle.cookies[k.strip()] = v.strip()
            bearer = (prompt_fn("Authorization header (blank to skip): ") or "").strip()
            if bearer:
                bundle.headers["Authorization"] = bearer
            state.auth = bundle
        if state.auth and not state.auth.is_empty():
            cfg.auth_mode = "auth"
        elif cfg.auth_mode == "auth":
            # Credentials were cleared (blanks entered) while auth mode was
            # "auth". Leaving the mode alone would strand the operator on a
            # run preflight refuses -- "auth mode selected but no
            # credentials configured" -- for something they just did
            # deliberately. Drop back to unauth and say so.
            cfg.auth_mode = "unauth"
            theme.console.print(
                "[bold yellow]note:[/bold yellow] credentials cleared; "
                "auth mode set back to 'unauth'."
            )
        return "continue"

    if key == "s":
        from pathlib import Path
        path = prompt_fn("Save profile to: ")
        if path:
            save_profile(cfg, Path(path))
        return "continue"

    if key == "l":
        from pathlib import Path
        path = prompt_fn("Load profile from: ")
        if not (path and Path(path).is_file()):
            return "continue"
        try:
            loaded = load_profile(Path(path))
        except ProfileError as exc:
            # ANY failure to load a profile is one kind of thing -- a bad
            # level, a missing key, a YAML syntax error, a scalar or
            # list-valued document, the file vanishing between the
            # is_file() check and the read. Enumerating exception types
            # here is exactly what let a YAML syntax error (ParserError)
            # slip past an earlier version of this catch and kill the
            # session. Must not kill the REPL or discard every setting the
            # operator has entered so far -- keep the existing config.
            theme.console.print(
                f"[bold red]profile not loaded[/bold red] — {exc}"
            )
            return "continue"
        # Refuse rather than silently downgrading: the operator must see that
        # their profile was not applied, not discover later that it ran at a
        # level they did not choose.
        if not gate_level(state, loaded.level, prompt_fn):
            theme.console.print(
                f"[bold red]profile not loaded[/bold red] — it specifies "
                f"level '{loaded.level}', which was not confirmed."
            )
            return "continue"
        state.config = loaded
        return "continue"

    if key == "8":
        from ..triage import STATUSES

        if state.triage is None:
            # Checked BEFORE prompting, and said out loud. Collecting a
            # finding id and a verdict and then discarding them is the worse
            # failure by far: the operator walks away believing the decision
            # is recorded, and the next report re-reports the finding they
            # think they dismissed.
            theme.console.print(
                "[bold yellow]triage state is unavailable[/bold yellow] — no "
                "verdict can be recorded this session (see the warning "
                "printed when the menu opened)."
            )
            return "continue"
        finding_id = (prompt_fn("Finding id: ") or "").strip()
        if not finding_id:
            return "continue"
        # Offered straight from STATUSES rather than retyped beside it: a
        # status this menu does not list is unreachable for the operator,
        # and one it lists that set() rejects is a guaranteed error.
        status = (prompt_fn(f"Status [{'|'.join(STATUSES)}]: ") or "").strip()
        note = (prompt_fn("Note (optional): ") or "").strip()
        try:
            state.triage.set(finding_id, status, note=note)
        except ValueError as exc:
            theme.console.print(f"[bold red]{escape(str(exc))}[/bold red]")
        except OSError as exc:
            # The write is what makes a verdict outlive the session. A
            # failure here that scrolls past as nothing is the same defect
            # as the None case above, one layer down.
            theme.console.print(
                f"[bold red]verdict NOT recorded[/bold red] — could not "
                f"write {escape(str(state.triage.path))}: {escape(str(exc))}"
            )
        return "continue"

    if key == "9":
        from pathlib import Path

        from ..diff import diff_runs, render_diff

        old = (prompt_fn("Earlier run directory: ") or "").strip()
        new = (prompt_fn("Later run directory: ") or "").strip()
        unreadable = [p for p in (old, new) if not (p and Path(p).is_dir())]
        if unreadable:
            # Printing nothing here is indistinguishable from a comparison
            # that found nothing to report — the exact inference diff.py
            # exists to stop an operator drawing from an absence.
            theme.console.print(
                "[bold red]diff not run[/bold red] — not a run directory: "
                + escape(", ".join(repr(p) for p in unreadable))
            )
            return "continue"
        # markup=False is load-bearing, not tidiness. render_diff emits
        # Markdown, and rich reads "[critical]" / "[low]" as style tags and
        # DELETES them, so every severity label silently disappears from a
        # comparison the operator is about to act on. Finding titles are
        # scanner output as well — attacker-influenced text that must never
        # be interpreted as console markup.
        theme.console.print(render_diff(diff_runs(Path(old), Path(new))),
                            markup=False, highlight=False)
        return "continue"

    if key == "o":
        run_dir = _latest_run_dir(cfg.outdir)
        if run_dir is None:
            theme.console.print(
                f"[bold yellow]no runs found[/bold yellow] in "
                f"{escape(str(cfg.outdir))}"
            )
            return "continue"
        report = run_dir / "report.html"
        if not report.exists():
            theme.console.print(
                f"[bold yellow]no report.html in the most recent run"
                f"[/bold yellow] ({escape(str(run_dir))})"
            )
            return "continue"
        # The path first, unconditionally: it is the useful output whether or
        # not anything can open it, and it is what the operator falls back to.
        theme.console.print(f"Most recent report: {escape(str(report.resolve()))}")
        if shutil.which("xdg-open") is None:
            theme.console.print(
                "[yellow]xdg-open not found[/yellow] — open the path above "
                "manually."
            )
            return "continue"
        # Never launched without an explicit yes. A report opens in whatever
        # the desktop has registered as a browser, which is a process the
        # operator did not ask for on a host that is mid-engagement.
        answer = (prompt_fn("Open it now with xdg-open? [y/N] ") or "").strip().lower()
        if answer in ("y", "yes"):
            subprocess.Popen(["xdg-open", str(report.resolve())],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return "continue"

    return "continue"


def run_menu(state: MenuState, prompt_fn, runner_fn) -> None:
    while True:
        theme.console.print(theme.banner(state.config, state.config.outdir))
        theme.console.print(MENU.format(
            level=state.config.level,
            auth=state.config.auth_mode,
            enum="on" if state.config.subdomain_enum else "off",
            creds=creds_label(state),
        ))
        try:
            action = apply_choice(state, prompt_fn("> "), prompt_fn)
        except Exception as exc:
            # Defence in depth. apply_choice already handles the failure
            # modes known about today (ProfileError, refused level gates,
            # ...) but a REPL that dies on a bad input and discards the
            # operator's configuration is a bug regardless of which
            # exception caused it -- the same lesson malformed-profile
            # handling just relearned, generalised to the whole loop rather
            # than enumerated one exception type at a time.
            theme.console.print(
                f"[bold red]error:[/bold red] {type(exc).__name__}: {exc} "
                "— settings kept, continuing."
            )
            continue
        if action == "quit":
            return
        if action == "run":
            runner_fn(state)
