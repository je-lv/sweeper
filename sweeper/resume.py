"""Resume an interrupted or crashed run.

Artifacts flush incrementally, so a crash or SIGINT leaves everything
discovered so far on disk. Resuming reloads those artifacts and re-runs
only the stages that did not complete.

A NO_INPUT skip is NOT resumable: it means the stage had nothing to
consume, which is a correct outcome, not an interruption.

A RESUME IS A RUN. It executes the same binaries against the same client
with the same rules of engagement, so it goes through preflight exactly
like app.execute() does -- see resume_run(). This module used to call
run_stages() directly, which meant the ONE call site of run_preflight was
app.py and the whole --resume path bypassed it: no binary identity check,
no argument validation, no target-leak backstop, no auth check (an
`auth_mode: "auth"` manifest was restored verbatim and 112 requests went
out carrying no credentials while run.json said `auth_mode: auth,
degraded: false` and report.md said "All selected stages completed"), and
the operator's own settings -- custom templates, rate override, per-stage
time limit -- silently replaced by level defaults, one of them a 20x
increase over a rate chosen for a client no-DoS rule.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import preflight
from .artifacts import Artifact, ArtifactKind, Finding
from .context import RunConfig, RunContext
from .runner import AbortRun, run_stages
from .scope import ScopeGuard
from .stages.base import Coverage, FailureClass, StageResult
from .store import ArtifactStore
from .ui import theme

_KIND_FILES = {
    "hosts.jsonl": ArtifactKind.HOST,
    "dns_records.jsonl": ArtifactKind.DNS_RECORD,
    "ports.jsonl": ArtifactKind.PORT,
    "udp_ports.jsonl": ArtifactKind.UDP_PORT,
    "services.jsonl": ArtifactKind.HTTP_SERVICE,
}

# "partial" is resumable: the stage produced some output but exited
# non-zero, so re-running may yield the complete result.
RESUMABLE_STATUSES = ("pending", "running", "failed", "partial")


class ResumeError(RuntimeError):
    """A run directory cannot be resumed.

    Covers a missing run directory, a missing run.json, a corrupt (not
    valid JSON, or not a JSON object) run.json, and a run directory whose
    targets.txt is gone. The CLI catches this and prints a one-line
    operator-facing message with a non-zero exit -- never a traceback for
    what is, from the operator's side, just a bad path.
    """


def load_manifest(run_dir: Path) -> dict:
    path = Path(run_dir) / "run.json"
    if not path.exists():
        raise FileNotFoundError(f"no run.json in {run_dir}")
    return json.loads(path.read_text(encoding="utf-8"))


def requested_stages(manifest: dict) -> list[str]:
    """Every stage this run was ABOUT, whether or not it produced a result.

    coverage.stages_requested is the denominator app.execute() captures at
    intent time -- before preflight can disable a stage and before
    run_stages can run one -- and it is the only record of a stage that
    never reported in at all. manifest["stages"] is the numerator, and using
    it alone (as incomplete_stages did) makes a stage with no recorded
    result invisible to resume: everything after an AbortRun, and EVERY
    stage of a run preflight refused, has no entry there, so repeated
    --resume was a no-op on exactly the runs most worth resuming.

    Unioned rather than either alone, in requested-first order. A manifest
    written before coverage existed has no stages_requested, and a stage
    recorded but somehow absent from the denominator is still a stage this
    run ran; neither is allowed to disappear.
    """
    coverage = manifest.get("coverage")
    requested = coverage.get("stages_requested") if isinstance(coverage, dict) else None
    requested = [s for s in requested if isinstance(s, str)] \
        if isinstance(requested, list) else []
    recorded = manifest.get("stages")
    recorded = [n for n in recorded if isinstance(n, str)] \
        if isinstance(recorded, dict) else []
    return list(dict.fromkeys(requested + recorded))


def incomplete_stages(manifest: dict) -> list[str]:
    """Stages that did not finish, INCLUDING ones that never reported at all.

    Three sources of incompleteness, not one:

      - a recorded result with a resumable status (see RESUMABLE_STATUSES);
      - a recorded `skipped` that is not NO_INPUT (a missing binary, an
        operator interrupt -- both worth another attempt, unlike "there was
        nothing to consume", which is a correct outcome); and
      - a stage in coverage.stages_requested with NO recorded result. See
        requested_stages(): this is the whole tail of an aborted run and the
        entirety of a preflight-refused one.
    """
    recorded = manifest.get("stages")
    recorded = recorded if isinstance(recorded, dict) else {}
    out = set()
    for name in requested_stages(manifest):
        info = recorded.get(name)
        if not isinstance(info, dict):
            out.add(name)
            continue
        status = info.get("status")
        if status in RESUMABLE_STATUSES:
            out.add(name)
        elif status == "skipped" and info.get("failure") != "NO_INPUT":
            out.add(name)
    return sorted(out)


def with_downstream(selected: set[str], universe: list) -> set[str]:
    """`selected`, closed under "depends on something already selected".

    Re-running a stage can change the artifact pool a LATER stage reads, and
    that later stage may already be recorded `complete`. nuclei is the pure
    consumer that matters: it reads the HTTP_SERVICE pool every enricher
    contributes to, and registry.order exists precisely to guarantee it sees
    the complete pool. A resume that re-ran katana and left nuclei alone
    broke that guarantee after the fact -- three new services in the asset
    inventory that nothing scanned, reported under "All selected stages
    completed", which is this project's recurring defect (work that did not
    happen presenting as work that did) arriving through the resume path.

    The edges come from registry.dependencies(), the same graph
    registry.order() sorts by, so "downstream" cannot come to mean two
    different things in two modules. Transitive: invalidating a consumer can
    invalidate ITS consumers in turn.
    """
    from .stages import registry

    deps = registry.dependencies(universe)
    selected = set(selected)
    changed = True
    while changed:
        changed = False
        for name, prerequisites in deps.items():
            if name not in selected and prerequisites & selected:
                selected.add(name)
                changed = True
    return selected


def plan_stages(manifest: dict):
    """(stage instances to re-run, in run order; names invalidated downstream).

    Fresh instances, built here rather than taken from a caller, because a
    Stage may carry per-run state and the instances handed to run_stages
    must be the ones that actually execute.
    """
    from .app import ALL_STAGES
    from .stages import registry

    by_name = {}
    for cls in ALL_STAGES:
        instance = cls()
        by_name[instance.name] = instance
    # Only stages this run was about, and only ones that still exist. A
    # manifest naming a stage that has since been removed from ALL_STAGES
    # cannot be re-run; its old result is kept instead (see resume_run's
    # previous_results, which excludes only what is actually being re-run).
    universe = [by_name[n] for n in requested_stages(manifest) if n in by_name]

    incomplete = {n for n in incomplete_stages(manifest) if n in by_name}
    selected = with_downstream(incomplete, universe)
    invalidated = sorted(selected - incomplete)
    stages = registry.order([s for s in universe if s.name in selected])
    return stages, invalidated


def stages_to_rerun(manifest: dict) -> list[str]:
    """Names of every stage a resume of `manifest` would execute, in order.

    The CLI's progress display needs this before resume_run() starts, and it
    must be the SAME list resume_run computes -- a display seeded from
    incomplete_stages alone omits every stage invalidated downstream, so the
    operator watches stages appear that the display said were not running.
    """
    stages, _invalidated = plan_stages(manifest)
    return [s.name for s in stages]


def restore_store(ctx, run_dir: Path) -> int:
    """Reload artifacts and findings from a previous run directory."""
    artifacts_dir = Path(run_dir) / "artifacts"
    if not artifacts_dir.is_dir():
        return 0
    restored = 0
    for filename, kind in _KIND_FILES.items():
        path = artifacts_dir / filename
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            ctx.store.add(Artifact(kind, row["value"], meta=row.get("meta", {})))
            restored += 1

    findings_path = artifacts_dir / "findings.jsonl"
    if findings_path.exists():
        for line in findings_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            row.pop("id", None)
            try:
                ctx.store.add_finding(Finding(**row))
            except (TypeError, ValueError):
                continue
    return restored


def resume_run(run_dir: Path, on_progress=None):
    """Resume an interrupted or crashed run.

    Rebuilds a RunContext pointed at the SAME run directory `run_dir` --
    never a new one, since further artifacts and the rewritten reports must
    land alongside what the original run already produced. Restores
    already-produced artifacts so the stages that already finished are not
    re-derived, works out which stages never finished, and re-runs those plus
    everything downstream of them. Reports are rewritten at the end so
    report.md/report.html reflect the resumed state, not the interrupted one.

    PREFLIGHT RUNS FIRST, on exactly the stages about to be re-run -- see the
    module docstring. That single call is what restores four guarantees the
    resume path had none of: no packet leaves until every stage's real
    argument list has been validated against a dead endpoint; every binary's
    IDENTITY is verified in THIS execution rather than inherited from the old
    manifest's tool_versions; the target-leak and evidence-write backstops
    apply; and an `auth_mode: "auth"` manifest with no credentials is REFUSED
    rather than quietly scanning anonymously under a deliverable that says
    otherwise. There is no way to supply credentials to --resume, so that
    refusal is the correct outcome, not a limitation: a resumed authenticated
    run is a new authenticated run.

    On refusal, the manifest is rewritten with the results the ORIGINAL run
    recorded, plus aborted_reason -- never with an empty list. execute() can
    write an empty manifest on a preflight failure because it owns a fresh
    run directory; here the file being written is the only record of the
    stages that already succeeded.

    Raises ResumeError -- never lets a raw FileNotFoundError or
    json.JSONDecodeError escape -- if `run_dir` or its run.json is missing,
    unparseable, or not a JSON object, or if targets.txt is gone from the
    run directory. Raises SystemExit(2) if preflight refuses, matching
    app.execute().
    """
    run_dir = Path(run_dir)
    try:
        manifest = load_manifest(run_dir)
    except FileNotFoundError as exc:
        raise ResumeError(f"cannot resume {run_dir}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ResumeError(
            f"cannot resume {run_dir}: run.json is corrupt ({exc})"
        ) from exc
    if not isinstance(manifest, dict):
        raise ResumeError(f"cannot resume {run_dir}: run.json is not a JSON object")

    targets_file = run_dir / "targets.txt"
    if not targets_file.is_file():
        raise ResumeError(
            f"cannot resume {run_dir}: targets.txt is missing from the run directory"
        )

    # The FULL config the original run used, not a four-field reconstruction
    # of it. targets_file and outdir are pinned to this run directory and
    # deliberately not taken from the manifest -- see
    # RunConfig.from_manifest.
    saved_config = manifest.get("config")
    have_full_config = isinstance(saved_config, dict) and bool(saved_config)
    config = RunConfig.from_manifest(
        saved_config if have_full_config else {
            # Pre-"config" manifests recorded only these three settings.
            "level": manifest.get("level"),
            "auth_mode": manifest.get("auth_mode"),
            "proxy": manifest.get("proxy"),
        },
        targets_file=targets_file,
        outdir=run_dir.parent,
    )

    scope_manifest = manifest.get("scope") or {}
    scope = ScopeGuard(set())
    scope.allowed = set(scope_manifest.get("allowed") or [])
    scope.refusals = list(scope_manifest.get("refusals") or [])
    scope.extensions = list(scope_manifest.get("extensions") or [])
    scope.discoveries_refused = list(scope_manifest.get("discoveries_refused") or [])

    ctx = RunContext(config, run_dir, ArtifactStore(run_dir), scope)
    # Carried forward, then OVERWRITTEN for every binary preflight verifies
    # below. Carried forward because the stages that already completed were
    # produced by those versions and that is real evidence; overwritten
    # because a re-run stage's findings must be attributed to the binary
    # THIS execution verified, not to whatever the old manifest said. Any
    # disagreement between the two is recorded as a warning after preflight.
    previous_versions = dict(manifest.get("tool_versions") or {})
    ctx.tool_versions = dict(previous_versions)
    ctx.user_agent = manifest.get("user_agent") or ctx.user_agent
    ctx.started = manifest.get("started") or ctx.started
    ctx.acknowledgements = list(manifest.get("acknowledgements") or [])
    ctx.warnings = list(manifest.get("warnings") or [])
    cov = manifest.get("coverage") or {}
    ctx.coverage = Coverage(
        targets_requested=cov.get("targets_requested", 0),
        targets_permitted=cov.get("targets_permitted", 0),
        # requested_stages(), not the raw coverage list: a manifest written
        # before coverage existed has none, and a denominator of [] makes
        # is_degraded blind to every stage this run never reached.
        stages_requested=requested_stages(manifest),
    )

    if not have_full_config:
        _warn(ctx,
              f"run.json in {run_dir} predates full run-config persistence, so "
              "only the level, auth mode and proxy could be restored. Any "
              "custom nuclei template directory, rate override or per-stage "
              "time limit the original run used is NOT in effect for the "
              "stages re-run here; level defaults apply instead. Start a "
              "fresh run if those settings matter.")

    stages, invalidated = plan_stages(manifest)
    stage_names = {s.name for s in stages}
    if invalidated:
        _warn(ctx,
              "resume: re-running " + ", ".join(invalidated) + " even though "
              "the previous run recorded them complete -- each consumes "
              "artifacts a stage being re-run can still add to, and a "
              "consumer that scanned an incomplete pool is not covered by "
              "the run that says it is.")

    restore_store(ctx, run_dir)
    # Only the collisions of stages NOT being re-run: a re-run stage
    # re-detects its own, and taking its old rows back as well would
    # double-count them. See ArtifactStore.restore_finding_collisions for why
    # they cannot simply be re-derived from findings.jsonl, and why losing
    # them silently launders a known undercount. The held-back rows are kept
    # in `rerun_collisions` and put straight back if this resume refuses
    # before any stage runs -- see _record_untouched.
    all_collisions = [c for c in (manifest.get("finding_collisions") or [])
                      if isinstance(c, dict)]
    rerun_collisions = [c for c in all_collisions if c.get("stage") in stage_names]
    ctx.store.restore_finding_collisions(
        [c for c in all_collisions if c.get("stage") not in stage_names])
    # These rows are already on disk from the original run -- mark them
    # flushed so the next store.flush() doesn't duplicate them (see
    # ArtifactStore.mark_all_flushed's docstring).
    ctx.store.mark_all_flushed()

    recorded_results = [
        StageResult(
            stage=name,
            status=info.get("status", "complete"),
            failure=FailureClass[info.get("failure", "NONE")],
            reason=info.get("reason", ""),
            artifacts=info.get("artifacts", 0),
            findings=info.get("findings", 0),
            duration_s=info.get("duration_s", 0.0),
            command=info.get("command", []),
        )
        for name, info in (manifest.get("stages") or {}).items()
    ]
    # What survives into the resumed run's results: everything the original
    # run recorded EXCEPT the stages being re-run, whose rows this execution
    # replaces. recorded_results (all of them, untouched) is what a refusal
    # writes back -- see _record_untouched.
    previous_results = [r for r in recorded_results if r.stage not in stage_names]

    ctx.log(f"resume: {len(stages)} stage(s) to re-run: "
            f"{', '.join(s.name for s in stages) or 'none'}")

    from .app import _merge_stage_results
    from .report import write_reports
    from .triage import TriageState, default_triage_path

    # config.triage_file, restored with the rest of the config: an operator
    # who passed --triage-file to the original run gets the same triage state
    # annotating the resumed run's report, instead of silently falling back
    # to the default path.
    triage = TriageState(config.triage_file or default_triage_path())

    def _record(results):
        ctx.store.flush()
        ctx.write_manifest(results)
        write_reports(ctx, results, triage=triage)

    def _record_untouched():
        """The record for a resume that refused before any stage ran.

        Nothing executed, so the run directory's account of the ORIGINAL run
        has to come back exactly as it was: every stage row, including the
        incomplete ones this resume was going to re-run, and every finding
        collision, including the rows held back above for those stages.
        Writing `previous_results` here instead would delete the failed
        stage's own record -- its failure class, its reason, its command --
        as the price of trying to resume it, which is the opposite of what a
        refusal should cost. Only aborted_reason, the warnings and the
        coverage denominator are new.
        """
        ctx.store.restore_finding_collisions(rerun_collisions)
        _record(recorded_results)

    # A resume is a run: it goes through preflight exactly as execute() does.
    # See this function's docstring and the module docstring for each of the
    # guarantees that were absent while this call was not here.
    try:
        report = preflight.run_preflight(ctx, stages)
    except Exception as exc:
        # Same rule as execute(): a run that dies must leave a record, and
        # here the record must keep the ORIGINAL run's stage results rather
        # than overwrite them with an empty list.
        ctx.aborted_reason = f"{type(exc).__name__}: {exc}"
        ctx.log(f"ABORTED (resume): {ctx.aborted_reason}")
        _record_untouched()
        raise

    drifted = sorted(
        f"{name} {previous_versions[name]!r} -> {version!r}"
        for name, version in ctx.tool_versions.items()
        if name in previous_versions and previous_versions[name] != version
    )
    if drifted:
        _warn(ctx,
              "resume: binary version changed since the original run: "
              + "; ".join(drifted) + ". Findings from the stages re-run here "
              "were produced by the version named second; findings carried "
              "over from the original run were not.")

    ctx.log(f"preflight (resume): {report.target_count} targets, "
            f"{len(report.disabled_stages)} stages disabled")
    if not report.ok:
        reasons = report.errors + report.arg_errors
        for err in reasons:
            theme.console.print(f"[bold red]preflight:[/bold red] {err}")
        ctx.aborted_reason = "preflight failed: " + "; ".join(reasons)
        ctx.log(f"ABORTED (resume): {ctx.aborted_reason}")
        _record_untouched()
        raise SystemExit(2)

    run_results: list = []
    try:
        # report.runnable, never `stages`: preflight decides binary identity
        # exactly once and run_stages must not re-decide it. See
        # runner.run_stages' docstring.
        run_stages(ctx, report.runnable, on_progress=on_progress,
                   results=run_results)
    except AbortRun as exc:
        run_results = exc.results
        ctx.aborted_reason = str(exc)
        ctx.log(f"ABORTED (resume): {exc}")
    except Exception as exc:
        ctx.aborted_reason = f"{type(exc).__name__}: {exc}"
        ctx.log(f"ABORTED (resume): {ctx.aborted_reason}")
        results = previous_results + _merge_stage_results(
            stages, report.disabled_results, run_results)
        _record(results)
        raise

    results = previous_results + _merge_stage_results(
        stages, report.disabled_results, run_results)
    _record(results)
    return ctx, results


def _warn(ctx, message: str) -> None:
    """Say it, and record that it was said.

    Same treatment execute() gives its decide-and-inform notices: the console
    for the operator now, ctx.warnings so the manifest and both reports carry
    it afterwards, and sweep.log so it sits inline with the run's own output.
    A resume that quietly proceeds on fewer settings than the operator chose
    is exactly the silence this fix exists to remove.
    """
    theme.console.print(f"[bold yellow]warning:[/bold yellow] {message}")
    ctx.warnings.append(message)
    ctx.log(f"warning: {message}")
