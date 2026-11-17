"""Run-to-run comparison.

Works because `Finding.id` is a stable hash of (stage, target, template_id,
matcher) and deliberately excludes timestamps and evidence -- so the same
issue hashes identically across runs (see artifacts.finding_id, and the five
stages fixed in Plan 2 to derive `matcher` from something intrinsic and
repeatable rather than from an index or a timestamp).

THE RULE THIS MODULE EXISTS TO ENFORCE: **absence is only evidence when the
run actually looked.**

A finding is classified `new` or `fixed` by its ABSENCE from one of the two
runs, and an absence has two completely different causes:

  - the issue was not there  (a real fix, or a real regression), or
  - nobody looked  (the stage failed, was skipped, the run aborted, its
    findings file is truncated, or the stage hit an id collision and
    undercounted).

Telling an operator "12 findings fixed" when the second run's nuclei stage
crashed is exactly the defect class this project has produced most often --
incomplete work presenting as complete -- and it is worse here than
elsewhere, because "fixed" is what a client is told in a retest deliverable.
So every absence-based classification is checked against what the run's own
manifest says it covered, per stage, and anything that cannot be backed by
that evidence is marked unverified and rendered as such. `persisting` needs
no such check: both runs SAW the finding, and presence is self-evidencing.

"Nobody looked" is NOT only a question of which stages ran. A retest can run
every stage to completion and still not have looked, because it was pointed
somewhere else or told to do less:

  - a NARROWER targets file: the host the finding is on was never scanned;
  - a LOWER level: `-dast` and parameter mutation only happen at `full`, so
    a `full` -> `mid` retest never runs the checks that produced half the
    findings it is being compared against;
  - NO CREDENTIALS: an `auth` -> `unauth` retest cannot reach anything
    behind the login, and every finding there vanishes from its output.

All three are recorded in the manifest (`scope.allowed`, `level`,
`auth_mode`), so all three are checked here. A finding may be reported FIXED
only if the newer run looked for it with at LEAST the same reach; where the
newer run is narrower the result is UNVERIFIED with a caveat that leads.
Level and auth-mode shortfalls are blanket -- they bear on every finding --
while a target dropped from scope is checked per finding, against the same
ScopeGuard rule the runs themselves used, so a retest that merely dropped an
unrelated host still gets to attest the hosts it did re-test.

The failure direction is fail-closed throughout. An unreadable manifest, a
missing manifest, an unparseable row, a findings file shorter than the
manifest's own count -- all of them mean "not verified", never "verified".
An over-cautious diff is annoying; a confident one that is wrong is what
gets written into a report.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

from .artifacts import Finding
# The reach vocabulary, imported from where each is DEFINED and validated
# rather than restated: LEVELS is what --level accepts and what the stage
# registry gates on, AUTH_MODES is what profile.load validates against. A
# private copy here would let a new level be added without this comparison
# learning that it outranks the others -- and the failure would be silent
# and in the fixed-attesting direction.
from .profile import AUTH_MODES
from .scope import ScopeGuard, normalize
from .stages.base import LEVELS
# ONE definition of severity order and of code-span escaping, shared with the
# Markdown report rather than re-declared here. Two copies drift, and this
# project has already paid for that with is_degraded(); `_inline`/`_prose`
# are module-private by naming convention only -- importing them is the
# cheaper mistake than a second, subtly different escaper applied to the same
# attacker-influenced fields.
from .report.markdown import ORDER as SEVERITY_ORDER, _inline, _prose

FINDINGS_RELPATH = ("artifacts", "findings.jsonl")
MANIFEST_NAME = "run.json"

# Rendered when the comparison is not fully evidence-backed. A constant so a
# caller (and a test) can key off it rather than off prose.
UNRELIABLE_BANNER = "**COMPARISON NOT FULLY EVIDENCE-BACKED**"

_FINDING_FIELDS = frozenset(f.name for f in dataclasses.fields(Finding))
_SEVERITY_RANK = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
# Both tuples are ordered least-reaching first, which is the whole content of
# these two maps: a run only backs an absence recorded by a run of the same
# rank or lower. An unrecognised (or unrecorded) value is absent from the map
# and ranks None, which fails closed rather than sorting as "lowest".
_LEVEL_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}
_AUTH_RANK = {mode: i for i, mode in enumerate(AUTH_MODES)}

# A label that cannot be a real host, used to ask one run's ScopeGuard
# whether it would admit SUBdomains of another run's wildcard entry. It is a
# string comparison inside this process; it is never a target and never
# reaches the network.
_WILDCARD_PROBE = "sweeper-wildcard-probe"


# ---------------------------------------------------------------------------
# What one run says about itself
# ---------------------------------------------------------------------------

@dataclass
class RunStatus:
    """What `run.json` says about the completeness of its own run.

    `readable` is False for a missing, unparseable or wrong-shaped manifest,
    and every coverage question then answers "no" -- see RunSummary.covers().
    """
    run_dir: Path
    present: bool = False
    readable: bool = False
    error: str = ""
    degraded: bool = False
    aborted: bool = False
    aborted_reason: str = ""
    # None when the manifest does not record it; otherwise the run's own
    # count of what its store held, which artifacts/findings.jsonl must
    # reconcile to. See the finding-count reconciliation invariant.
    findings_stored: int | None = None
    # How far this run REACHED, as its own manifest records it. Empty string
    # / None mean "not recorded", which is not the same as "recorded as
    # narrow" and is treated as unknown -- i.e. unverifiable -- throughout.
    level: str = ""
    auth_mode: str = ""
    scope_allowed: frozenset[str] | None = None
    completed_stages: frozenset[str] = frozenset()
    incomplete_stages: tuple[str, ...] = ()
    # Stages that recorded a genuine finding-id collision. Their finding set
    # is an undercount by construction (store.add_finding keeps the first of
    # a colliding pair), so their absences prove nothing.
    collision_stages: frozenset[str] = frozenset()
    collisions: int = 0


def load_status(run_dir: Path) -> RunStatus:
    run_dir = Path(run_dir)
    path = run_dir / MANIFEST_NAME
    if not path.exists():
        return RunStatus(run_dir, error=f"no {MANIFEST_NAME}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return RunStatus(run_dir, present=True,
                         error=f"{MANIFEST_NAME} could not be read: {exc}")
    if not isinstance(raw, dict):
        return RunStatus(run_dir, present=True,
                         error=f"{MANIFEST_NAME} is not a JSON object")

    stages = raw.get("stages")
    stages = stages if isinstance(stages, dict) else {}
    completed = {
        name for name, entry in stages.items()
        if isinstance(entry, dict) and entry.get("status") == "complete"
    }
    coverage = raw.get("coverage")
    requested = coverage.get("stages_requested") if isinstance(coverage, dict) else []
    requested = [s for s in requested if isinstance(s, str)] \
        if isinstance(requested, list) else []
    # Recorded-but-not-complete, plus requested-but-never-recorded. The
    # second kind is the one a scan of `results` alone cannot see -- same
    # gap Coverage exists to close in stages/base.is_degraded.
    incomplete = sorted(
        (set(stages) - completed) | (set(requested) - set(stages))
    )

    collisions = raw.get("finding_collisions")
    collisions = collisions if isinstance(collisions, list) else []
    collision_stages = {
        c.get("stage", "") for c in collisions if isinstance(c, dict)
    }

    stored = raw.get("findings_stored")
    if isinstance(stored, bool) or not isinstance(stored, int):
        stored = None

    # Reach. Anything of the wrong shape reads as not recorded: a manifest
    # that says level: 12 tells us nothing about what ran.
    level = raw.get("level")
    level = level if isinstance(level, str) else ""
    auth_mode = raw.get("auth_mode")
    auth_mode = auth_mode if isinstance(auth_mode, str) else ""
    scope = raw.get("scope")
    allowed = scope.get("allowed") if isinstance(scope, dict) else None
    # None (not recorded) and frozenset() (recorded, and empty) are
    # deliberately distinct: the second is a run that was allowed to touch
    # nothing, which is a fact about it, not an absence of one.
    scope_allowed = (
        frozenset(a for a in allowed if isinstance(a, str))
        if isinstance(allowed, list) else None
    )

    return RunStatus(
        run_dir=run_dir,
        present=True,
        readable=True,
        degraded=bool(raw.get("degraded")),
        aborted=bool(raw.get("aborted")) or bool(raw.get("aborted_reason")),
        aborted_reason=str(raw.get("aborted_reason") or ""),
        findings_stored=stored,
        level=level,
        auth_mode=auth_mode,
        scope_allowed=scope_allowed,
        completed_stages=frozenset(completed),
        incomplete_stages=tuple(incomplete),
        collision_stages=frozenset(collision_stages),
        collisions=len(collisions),
    )


@dataclass
class RunSummary:
    """One run's findings, plus everything that bears on trusting them."""
    run_dir: Path
    findings: list[Finding] = field(default_factory=list)
    status: RunStatus = None            # type: ignore[assignment]
    file_present: bool = False
    # Rows that could not be turned into a Finding (bad JSON, bad severity,
    # not an object). Each one is a hole: a finding that will look fixed, or
    # look new, purely because it could not be read.
    unreadable_lines: int = 0
    # Rows whose recorded `id` disagrees with the one recomputed from the
    # identity fields -- an edited file, or a run written by a sweeper whose
    # id function differed.
    id_mismatches: int = 0
    # Field NAMES present on disk that this Finding does not define. Names
    # only, never values: the same rule finding_diff_fields() follows,
    # because scan-derived values can carry secret material.
    unknown_fields: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return self.run_dir.name or str(self.run_dir)

    @property
    def truncated(self) -> bool:
        """Does the findings file hold fewer findings than the run claims?

        Every code path flushes the store before writing the manifest, so a
        shortfall means the file was cut short after the fact (a crash mid
        copy, a partial transfer) and this side of the comparison is missing
        an unknown number of findings.
        """
        expected = self.status.findings_stored if self.status else None
        return expected is not None and len(self.findings) < expected

    @property
    def intact(self) -> bool:
        """Is this run's finding set trustworthy AS A WHOLE?"""
        return bool(
            self.status and self.status.readable
            and not self.truncated
            and not self.unreadable_lines
        )

    def covers(self, stage: str) -> bool:
        """Did this run actually look for what `stage` emits?

        Only a stage the manifest records as `complete` counts. `partial`
        (ran short but produced usable output), `failed`, and `skipped` --
        including NO_INPUT, which is a correct outcome for the run but still
        means nothing was looked for -- all answer no, because none of them
        licenses the inference "not reported, therefore not present".
        """
        if not self.intact:
            return False
        if stage in self.status.collision_stages:
            return False
        return stage in self.status.completed_stages

    @cached_property
    def scope_guard(self) -> ScopeGuard | None:
        """This run's own allowlist, read back through the class that
        enforced it, or None when the manifest does not record one.

        Rebuilding the guard rather than comparing allowlist strings is what
        keeps this comparison honest about wildcards, ports and URL forms:
        the entry `*.acc.example` covers `shop.acc.example`, and only
        ScopeGuard knows that. A second matching rule here would eventually
        disagree with the one the run actually enforced, and the direction it
        would disagree in is "counted as re-tested".
        """
        allowed = self.status.scope_allowed if self.status else None
        return None if allowed is None else ScopeGuard(set(allowed))

    def covers_target(self, target: str) -> bool:
        """Could this run have scanned `target` at all?

        A finding is on a host. If the run's allowlist did not admit that
        host, no stage of that run -- however completely it ran -- ever sent
        it a packet, so its silence about that host says nothing. A manifest
        with no recorded scope answers no, like every other unknown here.
        """
        guard = self.scope_guard
        if guard is None:
            return False
        # permits_discovery, not allows(): this is a read of a finished run's
        # manifest, and must not append to a refusal list as a side effect.
        return guard.permits_discovery(normalize(target))


def _finding_from_row(row: dict) -> tuple[Finding | None, bool, set[str]]:
    """(finding, id_mismatched, unknown_field_names) for one JSONL row."""
    unknown = set(row) - _FINDING_FIELDS
    known = {k: v for k, v in row.items() if k in _FINDING_FIELDS}
    recorded_id = str(known.pop("id", "") or "")
    try:
        # `id` is deliberately NOT passed through: __post_init__ recomputes
        # it from the identity fields. That is what lets two runs written by
        # different versions of this tool be compared on one basis -- and a
        # row whose stored id disagrees is reported (id_mismatches) rather
        # than silently trusted.
        finding = Finding(**known)
    except (TypeError, ValueError):
        return None, False, unknown
    return finding, bool(recorded_id and recorded_id != finding.id), unknown


def load_run(run_dir: Path) -> RunSummary:
    """Load one run's findings and the manifest context needed to trust them."""
    run_dir = Path(run_dir)
    summary = RunSummary(run_dir=run_dir, status=load_status(run_dir))
    path = run_dir.joinpath(*FINDINGS_RELPATH)
    if not path.exists():
        return summary
    summary.file_present = True
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        summary.status.error = summary.status.error or str(exc)
        summary.unreadable_lines += 1
        return summary

    # findings.jsonl is a JOURNAL, like every other artifacts/*.jsonl file
    # (see ArtifactStore.flush): a row may appear more than once and the LAST
    # row for an id is current. Keyed by id, so the first appearance fixes
    # the order and the newest row supplies the content.
    by_id: dict[str, Finding] = {}
    unknown: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            summary.unreadable_lines += 1
            continue
        if not isinstance(row, dict):
            summary.unreadable_lines += 1
            continue
        finding, mismatched, row_unknown = _finding_from_row(row)
        unknown |= row_unknown
        if finding is None:
            summary.unreadable_lines += 1
            continue
        if mismatched:
            summary.id_mismatches += 1
        by_id[finding.id] = finding
    summary.findings = list(by_id.values())
    summary.unknown_fields = tuple(sorted(unknown))
    return summary


def load_findings(run_dir: Path) -> list[Finding]:
    """Every distinct finding a run recorded, newest row per id winning."""
    return load_run(run_dir).findings


# ---------------------------------------------------------------------------
# The comparison
# ---------------------------------------------------------------------------

@dataclass
class DiffResult:
    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    persisting: list[Finding] = field(default_factory=list)
    old_run: RunSummary | None = None
    new_run: RunSummary | None = None
    # Ids whose classification rests on an absence that the relevant run
    # cannot back with evidence. See the module docstring.
    unverified_ids: frozenset[str] = frozenset()
    # Operator-facing reasons this comparison is not fully evidence-backed.
    caveats: list[str] = field(default_factory=list)

    @property
    def reliable(self) -> bool:
        return not self.caveats

    @property
    def unverified_new(self) -> list[Finding]:
        return [f for f in self.new if f.id in self.unverified_ids]

    @property
    def unverified_fixed(self) -> list[Finding]:
        return [f for f in self.fixed if f.id in self.unverified_ids]


def _run_caveats(summary: RunSummary, label: str) -> list[str]:
    """Everything about ONE run that weakens the comparison."""
    out: list[str] = []
    status = summary.status
    if not status.readable:
        out.append(
            f"{label} `{_inline(summary.label)}`: {_prose(status.error)} — "
            "there is no record of which stages ran, so nothing missing from "
            "this run can be treated as evidence of anything.")
    if status.aborted:
        out.append(
            f"{label} `{_inline(summary.label)}` was ABORTED and never "
            f"completed: {_prose(status.aborted_reason) or 'no reason recorded'}.")
    if status.degraded:
        out.append(
            f"{label} `{_inline(summary.label)}` is marked DEGRADED in its "
            "manifest — it did not achieve full coverage"
            + (f" (incomplete: {_prose(', '.join(status.incomplete_stages))})"
               if status.incomplete_stages else "") + ".")
    # A run that found nothing never creates the file at all (ArtifactStore
    # .flush() only opens it when there is a row to write), and that is the
    # ordinary shape of a clean run -- so it is a caveat only when the
    # manifest cannot corroborate that zero is the real number. Crying wolf
    # over every clean retest would train an operator to skip the banner
    # that the genuinely unsound comparisons depend on.
    if not summary.file_present and not (
            status.readable and status.findings_stored == 0):
        out.append(
            f"{label} `{_inline(summary.label)}` has no "
            f"`{'/'.join(FINDINGS_RELPATH)}` file, and its manifest does not "
            "confirm it stored zero findings — treated as zero findings.")
    if summary.truncated:
        out.append(
            f"{label} `{_inline(summary.label)}`: its manifest records "
            f"{status.findings_stored} findings but only "
            f"{len(summary.findings)} could be read from "
            f"`{'/'.join(FINDINGS_RELPATH)}` — the file is short of what the "
            "run actually found.")
    if summary.unreadable_lines:
        out.append(
            f"{label} `{_inline(summary.label)}`: {summary.unreadable_lines} "
            f"row(s) in `{'/'.join(FINDINGS_RELPATH)}` could not be read as a "
            "finding and are missing from this comparison.")
    if summary.id_mismatches:
        out.append(
            f"{label} `{_inline(summary.label)}`: {summary.id_mismatches} "
            "row(s) carry an id that does not match the one recomputed from "
            "their identity fields — the file was edited, or written by a "
            "different version of this tool.")
    if summary.unknown_fields:
        out.append(
            f"{label} `{_inline(summary.label)}`: rows carry field(s) this "
            f"version does not know ({_prose(', '.join(summary.unknown_fields))}) "
            "— written by a newer sweeper; they were ignored, and the "
            "comparison used only the fields below.")
    if status.collisions:
        out.append(
            f"{label} `{_inline(summary.label)}` recorded {status.collisions} "
            "finding-id collision(s) — its finding set is an UNDERCOUNT of "
            "what that run found"
            + (f" (stages: {_prose(', '.join(sorted(status.collision_stages)))})"
               if status.collision_stages else "") + ".")
    return out


def _entry_uncovered(entry: str, guard: ScopeGuard) -> bool:
    """Is one run's allowlist entry outside the OTHER run's allowlist?

    Asked through ScopeGuard rather than by set difference, because the two
    allowlists are not comparable as strings: a retest scoped to
    `*.acc.example` covers a baseline scoped to `acc.example`, and a set
    difference would report that WIDENING as a narrowing. A wildcard entry
    reaches the base host and every subdomain, so the other run covers it
    only if it reaches both -- which is what the probe label asks.
    """
    if entry.startswith("*."):
        base = entry[2:]
        return not (guard.permits_discovery(base)
                    and guard.permits_discovery(f"{_WILDCARD_PROBE}.{base}"))
    return not guard.permits_discovery(entry)


def _reach_caveats(newer: RunSummary,
                   older: RunSummary) -> tuple[list[str], bool]:
    """Did the NEWER run look as widely as the older one?

    Returns (caveats, blanket). `blanket` means the shortfall bears on every
    finding rather than on particular targets -- a lower level or a dropped
    credential changes what is looked FOR, not where -- and every finding
    absent from the newer run is then unverified. A narrowed target scope is
    not blanket: it is applied per finding by covers_target(), so a retest
    that dropped one host still attests the hosts it did re-test.
    """
    if not (newer.status.readable and older.status.readable):
        # A run whose manifest cannot be read already answers "no" to every
        # coverage question (see covers/covers_target) and is already led
        # with as unreadable. Three more caveats saying its level, auth mode
        # and scope are also unknown add noise, not information.
        return [], False

    out: list[str] = []
    blanket = False
    new_label, old_label = _inline(newer.label), _inline(older.label)

    new_rank = _LEVEL_RANK.get(newer.status.level)
    old_rank = _LEVEL_RANK.get(older.status.level)
    if new_rank is None or old_rank is None:
        blanket = True
        unknown = " and ".join(
            f"{name} `{lab}` records level `{_inline(lvl or 'none')}`"
            for name, lab, lvl, rank in (
                ("older run", old_label, older.status.level, old_rank),
                ("newer run", new_label, newer.status.level, new_rank))
            if rank is None)
        out.append(
            f"the two runs cannot be compared by LEVEL: {unknown}, which is "
            f"not one of {LEVELS} — so the newer run cannot be shown to have "
            "run the checks the older one did, and nothing missing from it "
            "is evidence of a fix.")
    elif new_rank < old_rank:
        blanket = True
        out.append(
            f"newer run `{new_label}` ran at level "
            f"`{_inline(newer.status.level)}`, LOWER than the older run "
            f"`{old_label}` at `{_inline(older.status.level)}` — the checks "
            "the higher level adds (DAST, parameter mutation) were never "
            "re-run, so a finding missing from the newer run was not "
            "re-tested. Do not report any of these as remediated.")

    new_auth = _AUTH_RANK.get(newer.status.auth_mode)
    old_auth = _AUTH_RANK.get(older.status.auth_mode)
    if new_auth is None or old_auth is None:
        blanket = True
        unknown = " and ".join(
            f"{name} `{lab}` records auth_mode `{_inline(mode or 'none')}`"
            for name, lab, mode, rank in (
                ("older run", old_label, older.status.auth_mode, old_auth),
                ("newer run", new_label, newer.status.auth_mode, new_auth))
            if rank is None)
        out.append(
            f"the two runs cannot be compared by AUTHENTICATION: {unknown}, "
            f"which is not one of {AUTH_MODES} — so the newer run cannot be "
            "shown to have reached everything the older one did.")
    elif new_auth < old_auth:
        blanket = True
        out.append(
            f"newer run `{new_label}` ran UNAUTHENTICATED where the older "
            f"run `{old_label}` ran with credentials — nothing behind the "
            "login was re-tested, and a finding there disappears from the "
            "newer run's output whether or not it was fixed. Do not report "
            "any of these as remediated.")

    if newer.status.scope_allowed is None:
        out.append(
            f"newer run `{new_label}` does not record `scope.allowed`, so "
            "there is no record of which targets it was permitted to scan "
            "and no finding can be shown to have been re-tested.")
    elif older.status.scope_allowed is None:
        out.append(
            f"older run `{old_label}` does not record `scope.allowed`, so "
            "the two runs' target scopes cannot be compared; findings are "
            "still checked against the newer run's scope individually.")
    else:
        guard = newer.scope_guard
        dropped = sorted(e for e in older.status.scope_allowed
                         if guard is not None and _entry_uncovered(e, guard))
        if dropped:
            out.append(
                f"newer run `{new_label}` was scoped MORE NARROWLY than the "
                f"older run `{old_label}`: {len(dropped)} target(s) in the "
                "older run's scope are outside the newer run's "
                f"({_prose(', '.join(dropped))}) — they were not re-tested.")
    return out, blanket


def diff_runs(run_a: Path, run_b: Path) -> DiffResult:
    """Compare two runs. `run_a` is the earlier run, `run_b` the later one."""
    old, new_ = load_run(run_a), load_run(run_b)
    before = {f.id: f for f in old.findings}
    after = {f.id: f for f in new_.findings}

    new_findings = [f for fid, f in after.items() if fid not in before]
    fixed = [f for fid, f in before.items() if fid not in after]
    persisting = [f for fid, f in after.items() if fid in before]

    # A `new` finding is absent from the OLD run: only the old run can back
    # that. A `fixed` finding is absent from the NEW run: only the new run
    # can back that. `persisting` is backed by both runs having seen it.
    #
    # For `fixed` there are three ways the newer run can fail to back the
    # absence: it did not complete the stage, it could not have reached the
    # target, or it looked for less than the older run did (lower level, no
    # credentials -- `reach_blanket`).
    reach, reach_blanket = _reach_caveats(new_, old)
    unverified = (
        {f.id for f in new_findings if not old.covers(f.stage)}
        | {f.id for f in fixed
           if reach_blanket
           or not new_.covers(f.stage)
           or not new_.covers_target(f.target)}
    )

    # Reach caveats first: they are about the comparison itself rather than
    # about one run's completeness, and render_diff prints them in order.
    caveats = (reach + _run_caveats(old, "older run")
               + _run_caveats(new_, "newer run"))
    unverified_new = sum(1 for f in new_findings if f.id in unverified)
    unverified_fixed = sum(1 for f in fixed if f.id in unverified)
    if unverified_fixed:
        caveats.append(
            f"{unverified_fixed} of {len(fixed)} finding(s) below are listed "
            "as FIXED only because the newer run does not report them, and "
            "the newer run cannot show it re-tested them. Do not report "
            "these as remediated.")
    if unverified_new:
        caveats.append(
            f"{unverified_new} of {len(new_findings)} finding(s) below are "
            "listed as NEW only because the older run does not report them, "
            "and the older run cannot show it looked for them. They may "
            "predate it.")

    return DiffResult(
        new=new_findings,
        fixed=fixed,
        persisting=persisting,
        old_run=old,
        new_run=new_,
        unverified_ids=frozenset(unverified),
        caveats=caveats,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _sort_key(f: Finding):
    return (_SEVERITY_RANK.get(f.severity, len(SEVERITY_ORDER)),
            f.target, f.template_id, f.title)


# Why an absence in this group could not be confirmed, per group. Presence
# needs no such note, so PERSISTING has none.
_UNVERIFIED_NOTE = {
    "NEW": "not confirmed absent from the older run",
    "FIXED": "not confirmed re-tested by the newer run",
}


def render_diff(result: DiffResult) -> str:
    lines = ["# Run comparison\n"]

    if result.old_run and result.new_run:
        lines.append(f"**Older run:** `{_inline(result.old_run.label)}` "
                     f"({len(result.old_run.findings)} findings) → "
                     f"**newer run:** `{_inline(result.new_run.label)}` "
                     f"({len(result.new_run.findings)} findings)\n")

    if result.caveats:
        # Led with, not footnoted: a reader who stops after the counts must
        # not walk away with "12 fixed" from a comparison that cannot
        # support it. Same placement rule as the report's DEGRADED banner.
        lines.append(f"> {UNRELIABLE_BANNER} — {len(result.caveats)} caveat"
                     f"{'s' if len(result.caveats) != 1 else ''}:\n>")
        for c in result.caveats:
            lines.append(f"> - {c}")
        lines.append("")

    for label, group in (("NEW", result.new), ("FIXED", result.fixed),
                         ("PERSISTING", result.persisting)):
        unverified = [f for f in group if f.id in result.unverified_ids]
        heading = f"## {label} ({len(group)}"
        if unverified:
            heading += f" — {len(unverified)} UNVERIFIED"
        lines.append(heading + ")\n")
        if unverified:
            lines.append(f"*{len(unverified)} of these "
                         f"{'is' if len(unverified) == 1 else 'are'} "
                         f"{_UNVERIFIED_NOTE.get(label, 'not confirmed')} — "
                         "marked UNVERIFIED below.*\n")
        for f in sorted(group, key=_sort_key):
            mark = " **[UNVERIFIED]**" if f.id in result.unverified_ids else ""
            lines.append(f"- [{_prose(f.severity)}] {_prose(f.title)} — "
                         f"`{_inline(f.target)}` "
                         f"(`{_inline(f.template_id)}`, stage "
                         f"`{_inline(f.stage)}`){mark}")
        lines.append("")

    return "\n".join(lines)
