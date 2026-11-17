"""Wiring: config -> stages -> preflight -> run -> report."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from . import preflight
from .artifacts import Artifact, ArtifactKind
from .context import RunConfig, RunContext, utcnow
from .report import write_reports
from .runner import AbortRun, run_stages
from .scope import normalize
from .stages import registry
from .stages.arjun import ArjunStage
from .stages.base import LEVELS, Coverage
from .stages.cdncheck import CdncheckStage
from .stages.content import ContentStage
from .stages.dnssec import DnssecStage
from .stages.dnsx import DnsxStage
from .stages.httpx import HttpxStage
from .stages.jsrecon import JsreconStage
from .stages.katana import KatanaStage
from .stages.maildns import MaildnsStage
from .stages.naabu import NaabuStage
from .stages.nmap import NmapStage
from .stages.nmap_udp import NmapUdpStage
from .stages.nuclei import NucleiStage
from .stages.subfinder import SubfinderStage
from .stages.tlsx import TlsxStage
from .stages.vhost import VhostStage
from .triage import TriageState, default_triage_path
from .ui import theme

ALL_STAGES = (
    SubfinderStage, DnsxStage, DnssecStage, MaildnsStage, CdncheckStage,
    NaabuStage, NmapStage, NmapUdpStage, TlsxStage, HttpxStage, VhostStage, ContentStage,
    KatanaStage, JsreconStage, ArjunStage, NucleiStage,
)


class StageContractViolation(RuntimeError):
    """A stage module violates its own declared contract (registry.validate).

    This is a programming error in a stage's own definition, not a mistake
    an operator can fix by retyping something. It must not be caught by the
    same `except ValueError` that turns an unknown --stages name into a
    friendly exit-2 message — that used to be exactly what happened: a bare
    `except ValueError` in main() swallowed a broken stage module and
    presented it as a configuration typo. Deliberately not a ValueError
    subclass, so it is not caught there by accident.
    """


def build_stages(config: RunConfig):
    all_instances = [cls() for cls in ALL_STAGES]
    stages = all_instances
    if config.stages:
        wanted = set(config.stages)
        valid_names = {s.name for s in all_instances}
        unknown = sorted(wanted - valid_names)
        if unknown:
            # A typo here used to silently delete the stage from the run —
            # "--stages dnsx,naabu,htpx" ran two stages and the report
            # printed "All selected stages completed." A stage name that
            # does not exist must fail loudly, not disappear.
            raise ValueError(
                f"unknown stage name(s): {', '.join(unknown)}. "
                f"Valid stages: {', '.join(sorted(valid_names))}"
            )
        stages = [s for s in all_instances if s.name in wanted]
    # Subdomain enumeration output is never scanned without explicit
    # operator confirmation (see Global Constraints and Task 3's
    # scope-extension gate) — dropped here, AFTER the typo check above, so
    # `--stages subfinder` without --subdomain-enum is a deliberate policy
    # exclusion, never mistaken for (or reported as) an unknown stage name.
    if not config.subdomain_enum:
        stages = [s for s in stages if s.name != "subfinder"]
    # An empty per-level argv means "no extra flags" for most tools; it
    # cannot also mean "this stage is disabled". Stages whose entire job is
    # level-gated declare enabled_levels explicitly and are removed from the
    # planned denominator before preflight, progress reporting, and resume.
    disabled_for_level = [
        s.name for s in stages
        if config.level not in getattr(s, "enabled_levels", LEVELS)
    ]
    if config.stages and disabled_for_level:
        raise ValueError(
            f"stage(s) {', '.join(sorted(disabled_for_level))} are not "
            f"enabled at level {config.level!r}; choose a compatible level "
            "or remove them from --stages"
        )
    stages = [
        s for s in stages
        if config.level in getattr(s, "enabled_levels", LEVELS)
    ]
    for s in stages:
        errs = registry.validate(s)
        if errs:
            # StageContractViolation, NOT ValueError — deliberately. See its
            # docstring: a broken stage MODULE is a bug, not an operator
            # typo, and must not be swallowed by the bare `except ValueError`
            # in main() that turns an unknown --stages name into a friendly
            # exit-2 message. Downgrading this raise to ValueError (as an
            # earlier draft of this task did) would let exactly that happen.
            raise StageContractViolation(
                f"stage {s.name!r} violates the contract: {errs}"
            )
    return registry.order(stages)


def prepare(config: RunConfig) -> RunContext:
    ctx = RunContext.create(config)
    permitted, refused = ctx.scope.filter(ctx.load_targets())
    for target in permitted:
        # NORMALISE before seeding. ScopeGuard.allows() normalises before
        # comparing, but filter() hands back the raw line, and a HOST
        # artifact is a hostname by definition -- every stage downstream is
        # entitled to assume that.
        #
        # A scope file of `https://shop.client.example/` -- the ordinary
        # shape of a scope pasted out of an engagement document -- otherwise
        # seeds URLs as hosts. It passes scope validation (correctly), the
        # manifest reports them in scope, dnsx and cdncheck report
        # `complete`, and every DNS-based stage then fails to resolve a
        # hostname that is really a URL. Found on the first live run:
        # `naabu: no valid ipv4 or ipv6 targets were found`, everything
        # downstream skipped for want of a single port.
        #
        # normalize() also folds case and strips a trailing dot, so
        # `Shop.Example`, `shop.example.` and `shop.example` seed ONE host
        # instead of three artifacts that are all the same machine.
        host = normalize(target)
        if not host:
            # Nothing usable in the line at all (a bare "://", say). Recorded
            # rather than dropped: a target the operator listed and the run
            # never scanned must not vanish silently.
            ctx.log(f"scope: UNUSABLE TARGET {target!r} — no hostname in it")
            ctx.warnings.append(
                f"targets file entry {target!r} contains no hostname and was "
                "not scanned"
            )
            continue
        ctx.store.add(Artifact(ArtifactKind.HOST, host, meta={"src": "targets-file"}))
    for host in refused:
        ctx.log(f"scope: REFUSED {host}")
    ctx.store.flush()
    return ctx


def _merge_stage_results(stages, disabled_results, run_results):
    """Combine preflight's pre-populated skips with run_stages' results, in
    the originally requested stage order.

    A stage preflight disabled for a failed binary identity check never
    reaches run_stages, so run_stages has nothing to say about it. Without
    this merge that stage simply would not appear in the final results list
    — invisible in run.json's stages{} and in the report's coverage table,
    which is indistinguishable from full coverage to anyone reading either
    afterwards.
    """
    disabled_by_name = {r.stage: r for r in disabled_results}
    run_by_name = {r.stage: r for r in run_results}
    merged = []
    for s in stages:
        r = disabled_by_name.get(s.name) or run_by_name.get(s.name)
        if r is not None:
            merged.append(r)
    return merged


def execute(config: RunConfig, on_progress=None, acknowledgements=None,
            auth_bundle=None):
    # Stage-name validation needs only `config`, not a run directory. Doing
    # it before prepare() means a typo in --stages never leaves an orphaned,
    # empty run directory behind — it fails before anything is created.
    stages = build_stages(config)

    ctx = prepare(config)
    # The acknowledgement for a full-level run is the operator's
    # recorded authorisation. Held on MenuState, it dies with the process;
    # the manifest is where it has to land to be worth anything.
    ctx.acknowledgements = list(acknowledgements or [])

    # config.triage_file, not getattr(config, "triage_file", None): a plain
    # attribute access fails loudly if the RunConfig field is ever dropped,
    # whereas getattr-with-default silently falls back to the default path
    # and the operator's --triage-file is ignored with no error. One
    # TriageState, used at every report call site below, so report.md and
    # report.html can never annotate findings against two different triage
    # files for the same run.
    triage = TriageState(config.triage_file or default_triage_path())

    # THE AUTH INVARIANT: credentials are attached if and only if this run
    # reports auth_mode "auth". config.auth_mode is what run.json and the
    # report's "**Auth:**" line render, so attaching a bundle without
    # checking it makes the deliverable misstate what was sent. That is
    # reachable through ordinary workflow, not a corner case: configure
    # credentials at menu option 7 (which flips auth_mode to "auth"), then
    # switch option 3 back to "unauth" for a baseline pass -- MenuState
    # still holds the bundle, and _runner passes it unconditionally.
    # RunContext.auth's setter refuses the inconsistent state outright (see
    # AuthModeViolation); this branch is what keeps a legitimate run from
    # ever reaching it.
    have_credentials = auth_bundle is not None and not auth_bundle.is_empty()
    if have_credentials and config.auth_mode == "auth":
        from .auth import to_nuclei_secret_file
        ctx.auth = auth_bundle
        ctx.secret_file = to_nuclei_secret_file(
            auth_bundle, ctx.run_dir / "auth" / "secrets.yaml",
            run_dir=ctx.run_dir,
        )
        ctx.log("auth: credentials configured; secret-file written")
    elif have_credentials:
        # Deliberately not used -- but silently ignoring them is its own
        # failure mode: the operator supplied credentials and is entitled to
        # know this run did not send them. No secret-file is written, so no
        # credential lands on disk for this run either.
        warning = (
            f"credentials are configured but auth_mode is "
            f"{config.auth_mode!r}: this run sends NO credentials. Switch "
            "auth mode to 'auth' if you intended an authenticated run."
        )
        theme.console.print(f"[bold yellow]warning:[/bold yellow] {warning}")
        ctx.warnings.append(warning)
        ctx.log(f"warning: {warning}")

    # arjun has no file-based auth option -- see stages/arjun.py's module
    # docstring, confirmed against the installed arjun 2.2.7 source: unlike
    # katana's `-H <file>`, arjun's `--headers` always treats its value as
    # the literal header text, never a path. So when both auth and arjun are
    # selected, live credentials sit in arjun's argv for the life of that
    # process, visible to any local user via `ps` -- a residual exposure the
    # runner's redaction of sweep.log/run.json cannot close, because `ps` is
    # neither of those. This is a decide-and-inform situation, not a block:
    # the run continues, but the operator must be told, at the point the run
    # actually starts, and it must be recorded so the report reflects that
    # they were told -- not left as a comment only a code reader would see.
    if ctx.auth is not None and not ctx.auth.is_empty() and \
            any(s.name == "arjun" for s in stages):
        warning = (
            "arjun is selected with credentials configured: arjun has no "
            "file-based auth option, so live credentials WILL be visible "
            "in this process's argument list (`ps`) on this host for the "
            "duration of the arjun stage. Continuing."
        )
        theme.console.print(f"[bold yellow]warning:[/bold yellow] {warning}")
        ctx.warnings.append(warning)
        ctx.log(f"warning: {warning}")

    # The coverage denominator, captured at intent time -- before preflight
    # can disable a stage and before run_stages can run one. targets_file
    # lines are deduplicated because the store dedupes identical lines to
    # one HOST artifact; counting raw lines would flag a legitimately clean
    # run as a coverage gap. targets_permitted comes from what prepare()
    # actually seeded into the store, i.e. exactly the unique lines the
    # scope guard let through.
    unique_targets = list(dict.fromkeys(ctx.load_targets()))
    ctx.coverage = Coverage(
        targets_requested=len(unique_targets),
        targets_permitted=len(ctx.store.values(ArtifactKind.HOST)),
        stages_requested=[s.name for s in stages],
    )
    # Which of THIS run's stages can actually honour --resolver, read off the
    # stage objects themselves so the manifest cannot disagree with the argv.
    # Recorded even when no resolver was given: the answer is a property of
    # the stage set, and a reader comparing two runs should not have to infer
    # it from whether the flag happened to be used. See RunConfig.resolver.
    ctx.resolver_support = {
        s.name: bool(getattr(s, "honors_resolver", False)) for s in stages
    }

    try:
        report = preflight.run_preflight(ctx, stages)
    except Exception as exc:
        # Same rule as AbortRun, a failed preflight and a stage crash: a run
        # that dies must leave a record. This call used to sit OUTSIDE every
        # try: in execute(), so anything raising here -- preflight's own
        # fail-closed backstops, a scope guard, a binaries probe -- left a run
        # directory with no run.json and no report, which reads afterwards as
        # a clean, empty scan rather than a refused run.
        #
        # Re-raised, not swallowed: an exception that reaches here is a bug
        # (the operator-reachable refusals are report.errors, handled below),
        # and it must surface as itself. This only guarantees the record.
        # KeyboardInterrupt and SystemExit are not Exception subclasses, so
        # they still propagate untouched.
        ctx.aborted_reason = f"{type(exc).__name__}: {exc}"
        ctx.log(f"ABORTED: {ctx.aborted_reason}")
        ctx.store.flush()
        ctx.write_manifest([])
        write_reports(ctx, [], triage=triage)
        raise
    ctx.log(f"preflight: {report.target_count} targets, "
            f"{len(report.disabled_stages)} stages disabled")
    if not report.ok:
        # Same rule as an abort: a run that dies must leave a record saying
        # why. Writing only a manifest, with the reason on the console, means
        # anyone reading the run directory later sees a clean-looking empty
        # scan. Record the reason and write BOTH artefacts.
        reasons = report.errors + report.arg_errors
        for err in reasons:
            theme.console.print(f"[bold red]preflight:[/bold red] {err}")
        ctx.aborted_reason = "preflight failed: " + "; ".join(reasons)
        ctx.log(f"ABORTED: {ctx.aborted_reason}")
        ctx.write_manifest([])
        write_reports(ctx, [], triage=triage)
        raise SystemExit(2)

    # Passed in and mutated in place by run_stages, so a stage that
    # completed before a LATER stage raised something other than AbortRun is
    # still here afterward even though the exception unwound the frame that
    # held run_stages' own local copy of this list. See run_stages'
    # docstring.
    run_results: list = []
    # The progress display reads per-stage counts, the reason a stage
    # stopped early, and the live scope-refusal count from these two
    # objects. Optional by design: on_progress may be None (automation), or
    # any other callable (tests), and neither has to know about this. See
    # ui/progress.ProgressReporter.bind for why it is a second call rather
    # than a constructor argument -- ctx does not exist when the reporter is
    # built. `run_results` is passed to run_stages below and mutated IN
    # PLACE, so the display needs no further updates.
    if hasattr(on_progress, "bind"):
        try:
            on_progress.bind(ctx=ctx, results=run_results)
        except Exception:
            # A display that cannot bind still shows stage states; one that
            # raises here would abort a scan over a cosmetic feature.
            pass
    try:
        # run_stages only ever sees the stages preflight verified the binary
        # identity of. It must never re-decide that on its own — see
        # runner.run_stages' docstring.
        run_stages(ctx, report.runnable, on_progress=on_progress,
                   results=run_results)
    except AbortRun as exc:
        # Keep the results gathered before the abort. Discarding them writes
        # an empty manifest over the one run_stages already wrote, so the
        # report reads "No stages ran" — indistinguishable from selecting no
        # stages, with no record of why the run died. An abort is exactly
        # when that record matters.
        theme.console.print(f"[bold red]ABORTED:[/bold red] {exc}")
        run_results = exc.results
        ctx.aborted_reason = str(exc)
        ctx.log(f"ABORTED: {exc}")
    except Exception as exc:
        # Same rule as AbortRun and a failed preflight: a run that dies must
        # leave a record. run_results was mutated in place by run_stages, so
        # it still holds whatever stages completed (or were mid-flight)
        # before this exception — preserve that instead of discarding it,
        # or a stage that finished cleanly vanishes from the manifest along
        # with the one that actually broke.
        ctx.aborted_reason = f"{type(exc).__name__}: {exc}"
        ctx.log(f"ABORTED: {ctx.aborted_reason}")
        ctx.store.flush()
        results = _merge_stage_results(stages, report.disabled_results, run_results)
        ctx.write_manifest(results)
        write_reports(ctx, results, triage=triage)
        raise

    results = _merge_stage_results(stages, report.disabled_results, run_results)
    ctx.store.flush()
    ctx.write_manifest(results)
    write_reports(ctx, results, triage=triage)
    return ctx, results


def _open_triage():
    """The operator's persistent triage state, or None with a reason said aloud.

    Built HERE, on the menu path, because MenuState.triage defaults to None
    and menu option 8 can only decline without it: an operator would select
    "Triage a finding", type a verdict, and have nothing recorded. A menu
    option wired to a working module is still dead if nothing ever hands it
    the module.

    Two failures are surfaced rather than swallowed:

      - construction failing at all (no home directory, an unreadable path)
        leaves triage unavailable for the session, and option 8 says so; and
      - TriageState.load_error, which means the file exists but could not be
        trusted. triage.py fails closed there and treats every finding as
        untriaged — correct, but only safe if the operator knows, or they
        will read findings they dismissed weeks ago as new ones. That
        attribute exists to be surfaced; this is the caller that surfaces it.
    """
    from rich.markup import escape
    try:
        state = TriageState(default_triage_path())
    except Exception as exc:            # noqa: BLE001 - see docstring
        theme.console.print(
            f"[bold yellow]triage state unavailable[/bold yellow] "
            f"({type(exc).__name__}: {escape(str(exc))}) — menu option 8 "
            "cannot record verdicts this session."
        )
        return None
    if state.load_error:
        theme.console.print(
            f"[bold yellow]triage:[/bold yellow] {escape(state.load_error)} "
            "— every finding will read as untriaged until this is resolved."
        )
    return state


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="sweeper")
    ap.add_argument("-t", "--targets", required=False, type=Path)
    ap.add_argument("-o", "--outdir", type=Path, default=Path("recon/sweeper"))
    ap.add_argument("-l", "--level", choices=LEVELS, default="mid")
    # default=None, not "unauth": --auth-request has to tell an explicit
    # `--auth unauth` (a contradiction worth refusing) apart from the flag
    # simply not being passed (the ordinary case). Resolved to "unauth"
    # immediately after parsing.
    ap.add_argument("--auth", choices=("unauth", "auth"), default=None)
    # Credentials as a FILE PATH, never as argv. A --header/--cookie flag
    # would put the live session token in the process table for anything on
    # the box to read, which is the exposure katana's header-file and
    # nuclei's -secret-file already exist to avoid; handing this one a path
    # keeps that property on the entry point too.
    #
    # Without this, authenticated scanning was reachable ONLY through the
    # interactive menu -- preflight refused --auth auth --no-menu with "no
    # credentials configured -- import a Burp request or enter headers via
    # menu option 7", which fails closed correctly but leaves every
    # automated run unauthenticated. The auth surface of an application is
    # usually the half worth testing.
    ap.add_argument("--auth-request", type=Path, default=None, metavar="FILE",
                    help="raw HTTP request file (Burp 'Copy to file') whose "
                         "Cookie/Authorization headers are used for the scan. "
                         "Implies --auth auth. Credentials are read from the "
                         "file and never appear in argv.")
    ap.add_argument("--stages", default="")
    ap.add_argument("--proxy", default="")
    ap.add_argument(
        "--user-agent", default="",
        help="fixed User-Agent for every HTTP stage; defaults to one "
             "browser UA chosen once per run",
    )
    # --time-limit and --rate exist on the menu path and, until now, nowhere
    # else. This file already states the rule they were breaking, a few dozen
    # lines down, about the level gates: a control reachable through only one
    # of two entry points is not a control. --rate is the client's no-DoS
    # rules-of-engagement term (see stages/naabu.py) and --time-limit is the
    # only bound on a stage's runtime -- there is no default. An operator
    # running --no-menu, which is the automation path, could set neither.
    ap.add_argument("--time-limit", default="",
                    help="per-stage time limit as 45s / 45m / 2h. No limit by "
                         "default: a stage runs until its tool finishes.")
    ap.add_argument("--rate", type=int, default=0,
                    help="override the level's request-rate cap (naabu -rate, "
                         "and the equivalent elsewhere). Use to honour a "
                         "client's no-DoS engagement term.")
    # default=None, not "": argparse cannot otherwise tell `--ports ""` from
    # the flag being absent, and those mean opposite things. An operator who
    # typed an empty value meant to restrict something; treating that as
    # "use the level's range" would scan all 65535 ports while they believed
    # they had narrowed it.
    ap.add_argument("--ports", default=None, metavar="SPEC",
                    help="restrict the ports naabu scans, as top-100 or "
                         "80,443,8443 or 1-1024. REPLACES the level's own "
                         "range. Scope is enforced per host but services are "
                         "host:PORT, so an all-ports scan of an authorised "
                         "name reaches every service on its IP -- use this "
                         "unless the client owns everything on those IPs.")
    ap.add_argument("--udp-ports", default=None, metavar="SPEC",
                    help="restrict UDP discovery, as top-100 or 53,161 or "
                         "1-1024. REPLACES the level's UDP range.")
    ap.add_argument("--content-wordlist", action="append", default=[],
                    metavar="FILE",
                    help="extra wordlist for content discovery; repeatable. "
                         "ADDS to the level's built-in lists. A bespoke path "
                         "is in no SecLists file, so your own list is the "
                         "only thing that will find it.")
    ap.add_argument("--content-wordlist-only", action="store_true",
                    help="use ONLY --content-wordlist, not the level's "
                         "built-in lists.")
    ap.add_argument("--resolver", default="",
                    help="comma-separated DNS resolvers as IP or IP:port "
                         "(e.g. 10.0.0.53 or 127.0.0.1:15353). Required for "
                         "split-horizon or internal DNS, where the scanning "
                         "box's own resolver returns NXDOMAIN for the whole "
                         "scope. ffuf/arjun/jsrecon cannot take one and stay "
                         "on system DNS; run.json records which stages did.")
    ap.add_argument("--no-resolver-fallback", action="store_true",
                    help="never fall back to a public resolver. By default, "
                         "if the system resolver cannot resolve ANY target "
                         "and you named no --resolver, sweeper retries "
                         "against public DNS and records that it did -- those "
                         "queries disclose the scope's hostnames to a third "
                         "party. Use this where that is unacceptable.")
    ap.add_argument("--custom-templates", default="",
                    help="path to a custom nuclei template directory; "
                         "validated at preflight via `nuclei -validate`")
    ap.add_argument("--no-menu", action="store_true",
                    help="run immediately instead of opening the menu")
    # The level gates live in the menu REPL. Without an equivalent here,
    # `-l full --no-menu` runs the most invasive level — dast fuzzing that
    # mutates application state — with no gate and an empty acknowledgement
    # list. A safety control reachable through only one of two entry points
    # is not a control.
    ap.add_argument("--yes", action="store_true",
                    help="confirm a `high` run non-interactively (a full "
                         "65535-port sweep unless --ports narrows it)")
    ap.add_argument("--ack", action="store_true",
                    help="confirm a `full` run, which enables dast parameter "
                         "fuzzing and MUTATES application state")
    ap.add_argument("--resume", type=Path,
                    help="resume an interrupted run directory")
    ap.add_argument("--diff", nargs=2, type=Path, metavar=("OLD", "NEW"),
                    help="compare two run directories and exit")
    ap.add_argument("--triage-file", type=Path,
                    default=None,
                    help="path to persistent triage state "
                         "(default: ~/.sweeper/triage.json)")
    args = ap.parse_args(argv)

    if args.diff:
        from .diff import diff_runs, render_diff
        theme.console.print(render_diff(diff_runs(args.diff[0], args.diff[1])))
        return 0

    if args.resume:
        from .resume import ResumeError, load_manifest, resume_run, stages_to_rerun
        from .ui.progress import ProgressReporter
        try:
            # stages_to_rerun, not incomplete_stages: a resume also re-runs
            # every stage downstream of an incomplete one, and a display
            # seeded from the incomplete list alone shows stages arriving
            # that it said were not part of this resume.
            stage_names = stages_to_rerun(load_manifest(args.resume))
        except Exception:
            # Same badness resume_run() itself is about to hit (missing
            # dir, corrupt run.json) -- it raises ResumeError for that and
            # is handled below. Losing the planned stage LIST here costs
            # only the up-front "pending" rows; ProgressReporter still
            # renders every stage that actually reports in.
            stage_names = []
        with ProgressReporter(stage_names) as progress:
            try:
                ctx, _results = resume_run(args.resume, on_progress=progress)
            except ResumeError as exc:
                theme.console.print(f"[bold red]resume failed:[/bold red] {exc}")
                return 2
            except SystemExit as exc:
                # resume_run refuses at preflight the same way execute()
                # does, and for the same reasons -- most commonly an
                # `auth_mode: "auth"` manifest, which cannot be resumed
                # because there is no way to hand --resume the credentials.
                # It already printed each reason and recorded them in
                # run.json; this only turns the refusal into an exit code
                # instead of a traceback.
                theme.console.print(
                    "[bold red]resume did not start[/bold red] "
                    f"(exit {exc.code}). The run directory is unchanged apart "
                    "from run.json recording why."
                )
                code = exc.code
                if code is None:
                    return 1
                return code if isinstance(code, int) else 1
        theme.console.print(f"[bold green]done[/bold green] → {ctx.run_dir}")
        return 0

    if not args.targets:
        ap.error("--targets is required unless --diff or --resume is used")

    # Same gates as the menu, enforced on the CLI path — and NOT conditioned
    # on --no-menu. The REPL's gate lives in apply_choice and fires only when
    # the operator CHANGES the level, never for one preset on the command
    # line: `-l full` without --no-menu opens the menu already at full, and
    # pressing R runs dast fuzzing with no acknowledgement at all. A gate that
    # depends on which door you came through is not a gate.
    cli_acks: list[dict] = []
    if args.level == "high" and not args.yes:
        # Describe the scan actually configured. With --ports set, "a full
        # 65535-port sweep" is false, and a gate that overstates what it
        # guards is one an operator learns to wave through.
        tcp = (f"scans TCP ports {args.ports}" if args.ports
               else "runs a full 65535-port TCP sweep")
        udp = (args.udp_ports or "top-1000")
        scan = f"{tcp} and scans UDP {udp}"
        ap.error(f"--level high {scan}. Re-run with --yes to confirm.")
    if args.level == "high":
        # Spec: acknowledgements for both the `high` and `full` confirmations
        # are recorded in the manifest with a timestamp.
        # Only `full` was — `high` confirmed and then left no trace it had
        # been confirmed at all.
        cli_acks.append({"level": "high", "phrase": "--yes",
                         "via": "cli", "at": utcnow()})
    if args.level == "full":
        if not args.ack:
            ap.error(
                "--level full enables dast parameter fuzzing, which MUTATES "
                "application state (orders, coupons, carts). Re-run with "
                "--ack to proceed."
            )
        cli_acks.append({"level": "full", "phrase": "--ack",
                         "via": "cli", "at": utcnow()})

    # Validate the resolver value HERE, before a RunContext (and therefore a
    # run directory) exists. A malformed entry must be an argument error, not
    # something discovered once a stage is already sending DNS queries to
    # whatever the string happened to parse as. Routed through ap.error for
    # the same exit-2-with-usage treatment the level gates above get, rather
    # than left to escape as a traceback: every other bad value on this line
    # is reported that way.
    from . import resolvers
    from .resolvers import ResolverError
    try:
        resolvers.parse(args.resolver)
    except ResolverError as exc:
        ap.error(f"--resolver: {exc}")

    # Validated here, not left to runner._timeout. That function deliberately
    # never raises -- it logs a malformed value and applies NO limit -- which
    # is right for a value arriving from an old profile mid-run, but wrong for
    # one an operator just typed: "--time-limit 45" would silently run with no
    # bound at all, which is the opposite of what was asked for.
    if args.time_limit and not re.fullmatch(r"\d+\s*[smh]", args.time_limit.strip().lower()):
        ap.error(f"--time-limit: {args.time_limit!r} must be of the form "
                 "45s, 45m or 2h (a bare number has no unit and would be "
                 "ignored, leaving the run unbounded)")
    if args.rate < 0:
        ap.error("--rate must be a positive number of requests per second")

    # Validated here, before a RunContext exists, for the same reason as
    # --resolver above: the dangerous --ports value is not the one naabu
    # rejects (a loud preflight ARG_ERROR) but the one it accepts under a
    # meaning the operator did not intend, which scans a range nobody
    # authorised and reports nothing unusual while doing it.
    if args.ports is not None:
        from .ports import PortSpecError, parse as parse_ports
        try:
            parse_ports(args.ports)
        except PortSpecError as exc:
            ap.error(f"--ports: {exc}")
    if args.udp_ports is not None:
        from .ports import PortSpecError, parse as parse_ports
        try:
            parse_ports(args.udp_ports)
        except PortSpecError as exc:
            ap.error(f"--udp-ports: {exc}")

    for wl in args.content_wordlist:
        if not Path(wl).is_file():
            # At argument time, not once the stage is already running: an
            # unreadable wordlist silently narrows what content discovery can
            # find, and a smaller result set looks exactly like a cleaner
            # target.
            ap.error(f"--content-wordlist: {wl} is not a readable file")
    if args.content_wordlist_only and not args.content_wordlist:
        ap.error("--content-wordlist-only needs at least one "
                 "--content-wordlist to use instead of the built-in lists")

    # Credentials for the non-interactive path. Loaded HERE, before a run
    # directory exists, so a bad file is an argument error rather than
    # something discovered after a run has started writing evidence.
    cli_auth = None
    auth_explicit = args.auth is not None
    if args.auth is None:
        args.auth = "unauth"
    if args.auth_request is not None:
        if auth_explicit and args.auth == "unauth":
            # Contradictory, and the wrong one to guess at: silently scanning
            # unauthenticated would omit the whole authenticated surface,
            # while silently scanning authenticated would send credentials the
            # operator may have meant to withhold. Refuse and let them say.
            ap.error(
                "--auth-request supplies credentials but --auth is 'unauth'. "
                "Drop --auth unauth to scan authenticated, or drop "
                "--auth-request for a baseline pass."
            )
        from .auth import from_burp_request
        try:
            cli_auth = from_burp_request(args.auth_request)
        except (OSError, ValueError) as exc:
            ap.error(f"--auth-request: {exc}")
        if cli_auth.is_empty():
            # A file that parsed but carried no Cookie and no Authorization
            # is not credentials. Letting it through would reach preflight's
            # "no credentials configured" refusal with the operator believing
            # they had supplied some -- the error would name the wrong
            # problem.
            ap.error(
                f"--auth-request: {args.auth_request} contains no Cookie or "
                "Authorization header, so there are no credentials to use."
            )
        args.auth = "auth"

    if "\r" in args.user_agent or "\n" in args.user_agent:
        ap.error("--user-agent must not contain CR or LF characters")

    config = RunConfig(
        targets_file=args.targets, outdir=args.outdir, level=args.level,
        auth_mode=args.auth, proxy=args.proxy, user_agent=args.user_agent,
        stages=[s.strip() for s in args.stages.split(",") if s.strip()],
        custom_templates=args.custom_templates,
        triage_file=args.triage_file,
        resolver=args.resolver,
        content_wordlists=",".join(args.content_wordlist),
        content_wordlists_only=args.content_wordlist_only,
        time_limit=args.time_limit,
        rate_override=args.rate,
        ports=args.ports or "",
        udp_ports=args.udp_ports or "",
        resolver_fallback=not args.no_resolver_fallback,
    )

    if not args.no_menu:
        from .ui.menu import MenuState, run_menu
        # Seed the acknowledgement given on the command line. Without this,
        # `-l full --ack` passes the gate and then
        # records nothing, so the authorisation the operator just gave is
        # absent from the manifest of the run it authorised.
        state = MenuState(config, acknowledgements=list(cli_acks),
                          triage=_open_triage())

        def _runner(st):
            # execute() raises SystemExit on preflight failure, and ValueError
            # on an unknown --stages/profile stage name (build_stages).
            # Letting either escape kills the REPL and discards every
            # setting the operator just entered, on two of the most common
            # recoverable errors there are. A StageContractViolation (a
            # broken stage MODULE, not an operator typo) is deliberately
            # NOT a ValueError and is deliberately NOT caught here — it is a
            # bug, not a configuration mistake, and must surface as itself.
            #
            # The stage list is recomputed per run rather than once outside
            # this closure: the operator can change level, --stages or
            # subdomain enumeration between runs in the same REPL session,
            # and a display seeded from a stale list would show stages that
            # are not going to run. build_stages() is pure, so this is free.
            from .ui.progress import ProgressReporter
            try:
                stage_names = [s.name for s in build_stages(st.config)]
            except ValueError as exc:
                theme.console.print(
                    f"[bold red]run did not start[/bold red]: {exc} "
                    "Settings kept — fix the problem and run again."
                )
                return
            try:
                with ProgressReporter(stage_names) as progress:
                    ctx, results = execute(
                        st.config, on_progress=progress,
                        acknowledgements=st.acknowledgements,
                        auth_bundle=st.auth,
                    )
            except SystemExit as exc:
                theme.console.print(
                    f"[bold red]run did not start[/bold red] (exit {exc.code}). "
                    "Settings kept — fix the problem and run again."
                )
                return
            except ValueError as exc:
                theme.console.print(
                    f"[bold red]run did not start[/bold red]: {exc} "
                    "Settings kept — fix the problem and run again."
                )
                return
            theme.console.print(f"[bold green]done[/bold green] → {ctx.run_dir}")

        run_menu(state, prompt_fn=lambda msg="> ": input(msg), runner_fn=_runner)
        return 0

    # The planned stage list, known before the run starts -- so the display
    # can show every stage from its first frame instead of only the ones
    # that happened to report in. Computed the same way execute() computes
    # it internally (build_stages() is pure/side-effect-free); a
    # StageContractViolation from a broken stage module is deliberately NOT
    # caught here, for the same reason main()'s _runner closure above does
    # not catch it -- it must surface as itself, not as a friendly message.
    from .ui.progress import ProgressReporter
    try:
        stage_names = [s.name for s in build_stages(config)]
    except ValueError as exc:
        theme.console.print(f"[bold red]error:[/bold red] {exc}")
        return 2

    with ProgressReporter(stage_names) as progress:
        try:
            ctx, results = execute(config, on_progress=progress,
                                   acknowledgements=cli_acks,
                                   auth_bundle=cli_auth)
        except SystemExit as exc:
            # SystemExit(0) is success; `or 1` turned it into a failure, and a
            # string code raised from int().
            code = exc.code
            if code is None:
                return 1
            return code if isinstance(code, int) else 1
        except ValueError as exc:
            # An unknown stage name in --stages must not traceback; it is a
            # configuration mistake, not a crash. A StageContractViolation is a
            # different kind of thing (a bug in a stage module, not a mistake
            # the operator made) and is deliberately not a ValueError, so it is
            # not caught here — it must surface as itself, not as exit 2.
            theme.console.print(f"[bold red]error:[/bold red] {exc}")
            return 2
    theme.console.print(f"[bold green]done[/bold green] → {ctx.run_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
