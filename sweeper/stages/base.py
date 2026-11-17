"""The stage contract.

One module per external tool. A stage declares what artifact kind it reads
and which kinds it writes; the runner does the rest. Adding a tool later is
one new module plus one entry in `app.ALL_STAGES`.

`produces` is a SET so that DNS, TLS and port stages can emit findings
alongside their primary artifact.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Iterator, Protocol, runtime_checkable

from ..artifacts import Artifact, ArtifactKind, Finding

LEVELS = ("low", "mid", "high", "full")


class FailureClass(Enum):
    NONE = auto()
    ARG_ERROR = auto()       # fatal: aborts the whole run
    MISSING_BINARY = auto()  # skip stage, run is degraded
    NO_INPUT = auto()        # skip stage, not an error
    TRANSPORT = auto()       # record and continue
    PARTIAL = auto()         # non-zero exit but output exists
    # The binary produced output but the stage's own parse() raised on it.
    # Distinct from PARTIAL: PARTIAL means "ran short, what we got is
    # usable", PARSE_ERROR means "we could not read all of what we got".
    # Both degrade the run; keeping them apart is what tells an operator
    # whether to re-run the scan or fix the parser.
    PARSE_ERROR = auto()
    # The stage never ran (or never finished) because the operator
    # interrupted the run (SIGINT). Deliberately NOT NO_INPUT ("nothing to
    # consume" — a correct outcome that is_degraded() and resume.py's
    # incomplete_stages() both treat as non-resumable) and NOT TRANSPORT (a
    # network failure, which would mislead a reader about why the stage
    # never ran). Because this is its own member, both is_degraded() and
    # incomplete_stages() already do the right thing with it: an
    # interrupted skip degrades the run and is resumable, with no further
    # change to either function.
    INTERRUPTED = auto()


@dataclass
class Coverage:
    """The denominator: what this run was supposed to cover, captured at
    intent time — before any target is refused, any stage is skipped, or
    anything else happens that might keep a `StageResult` from ever being
    created.

    Without this, `is_degraded` can only react to `StageResult`s that
    exist. Every prior fix for this project's recurring defect worked by
    injecting a record for one specific absence someone thought of — but
    anything that never becomes a `StageResult` (a refused target, a stage
    dropped mid-abort) could never degrade a run, because there was nothing
    to compare against. This is the comparison: what was requested vs. what
    was recorded.

    targets_requested and targets_permitted count UNIQUE targets. Two
    identical lines in a targets file dedupe to one HOST artifact — counting
    raw lines would make a legitimately clean run look degraded.
    """
    targets_requested: int = 0
    targets_permitted: int = 0
    stages_requested: list[str] = field(default_factory=list)


def is_degraded(results: "list[StageResult]", coverage: "Coverage") -> bool:
    """Did this run fail to achieve full coverage?

    ONE definition, used by the manifest and by every report. Two copies
    drift: an earlier duplicate in the Markdown report exempted a failed
    stage carrying NO_INPUT, so the report printed clean while run.json said
    degraded. This project has produced the same class of defect many times
    — partial or failed work presenting as complete — so the rule lives in
    exactly one place.

    A stage skipped with NO_INPUT had nothing to consume: a correct outcome,
    not a gap. Everything else that did not complete degrades the run,
    including `partial` (exited non-zero but produced usable output) and any
    `failed` stage regardless of its failure class.

    `coverage` supplies the denominator the per-result checks above cannot
    see: a target the scope guard refused generates a refusal record, not a
    StageResult, so `any()` over results never notices it; a stage dropped
    from the results list (e.g. one never reached because an earlier stage
    aborted the run) is simply absent, not failed. Both are coverage gaps.
    """
    if any(
        r.status in ("failed", "partial")
        or (r.status == "skipped" and r.failure is not FailureClass.NO_INPUT)
        for r in results
    ):
        return True
    if coverage.targets_permitted < coverage.targets_requested:
        return True
    recorded = {r.stage for r in results}
    if any(name not in recorded for name in coverage.stages_requested):
        return True
    return False


@dataclass(frozen=True)
class CoverageGap:
    """One stage that did not run, or did not run to completion.

    `failure` is the FailureClass *name*, not the enum: this crosses into
    templates and JSON, and a report is a text artefact.
    """
    stage: str
    status: str
    failure: str
    reason: str


# The synthetic outcome for a stage that was requested and for which no
# StageResult exists at all. It is not a FailureClass member because nothing
# ran to fail -- there is no reason to show, because nothing about it was
# ever recorded, and that is precisely what makes it worth naming.
NOT_RECORDED = "NOT_RECORDED"
NOT_RECORDED_REASON = "requested but no result was ever recorded"


@dataclass(frozen=True)
class CoverageSummary:
    degraded: bool
    completed: list[str]
    gaps: list[CoverageGap]
    targets_requested: int
    targets_permitted: int

    @property
    def targets_refused(self) -> int:
        return max(0, self.targets_requested - self.targets_permitted)


def summarize_coverage(
    results: "list[StageResult]",
    coverage: "Coverage",
    aborted_reason: str = "",
) -> CoverageSummary:
    """What this run covered and what it did not — computed ONCE.

    Same reasoning as `is_degraded`, one level up. The Markdown report and
    the HTML report both need "which stages are a coverage gap, and what do
    we say about each" and both were computing it separately; the HTML copy
    under-reported, because it could only see the `StageResult`s that
    existed. Two renderings of the same run that disagree about what was
    scanned are worse than either one alone, because a reader has no way to
    tell which is lying. So the answer is derived here and both reports
    render it.

    A stage skipped with NO_INPUT appears in `gaps` but does not degrade the
    run: not-degrading and not-worth-reporting are different claims, and
    conflating them is how a report starts omitting things. `degraded` is
    delegated to `is_degraded` rather than recomputed — the rule stays in
    exactly one place.

    `aborted_reason` is folded in because a run that stopped early can have
    every recorded result `complete` (the stages that ran, ran fine) and so
    pass every per-result check while covering a fraction of what was asked
    for. `RunContext.write_manifest` applies the same `or`; the reports get
    it from here.
    """
    completed = [r.stage for r in results if r.status == "complete"]
    gaps = [
        CoverageGap(r.stage, r.status, r.failure.name, r.reason)
        for r in results
        if r.status in ("skipped", "failed", "partial")
    ]
    recorded = {r.stage for r in results}
    gaps += [
        CoverageGap(name, "missing", NOT_RECORDED, NOT_RECORDED_REASON)
        for name in coverage.stages_requested
        if name not in recorded
    ]
    return CoverageSummary(
        degraded=is_degraded(results, coverage) or bool(aborted_reason),
        completed=completed,
        gaps=gaps,
        targets_requested=coverage.targets_requested,
        targets_permitted=coverage.targets_permitted,
    )


@dataclass
class StageResult:
    stage: str
    status: str = "pending"   # pending|running|complete|failed|skipped
    failure: FailureClass = FailureClass.NONE
    reason: str = ""
    artifacts: int = 0
    findings: int = 0
    duration_s: float = 0.0
    command: list[str] = field(default_factory=list)
    #: How many times the tool was executed. 2 means the first attempt died
    #: without writing anything and the runner retried it once -- see
    #: runner.run_stages. Recorded rather than left implicit because it means
    #: the target was scanned twice: a client reading the manifest must be
    #: able to see that, and an operator diagnosing a flaky tool needs to
    #: know a clean result came from the second attempt.
    attempts: int = 1


@runtime_checkable
class Stage(Protocol):
    name: str
    requires: list[str]
    consumes: ArtifactKind
    produces: set[ArtifactKind]
    levels: dict[str, list[str]]
    optional: bool
    # The extension the runner uses for ctx.raw_path(stage.name, ...).
    # Default matches every stage before this task (dnsx, naabu, httpx,
    # cdncheck, nmap, subfinder), which all consume the runner's captured
    # stdout as JSONL.
    raw_suffix: str = "jsonl"
    # True when the tool writes ctx.raw_path(name, raw_suffix) itself
    # (ffuf's -o, arjun's -oJ) rather than emitting its result on stdout.
    # The runner must not overwrite that file with captured stdout when
    # this is True -- doing so is what silently zeroed vhost's and arjun's
    # output on every run before this task (see the Task 3.5 rationale).
    writes_own_raw: bool = False
    # True when this stage's real work is Python code, not an external
    # binary the runner shells out to (jsrecon: fetch_js). Such a stage
    # implements run_in_process(ctx) -> Path instead of relying on
    # build_command()'s argv being executed by the runner, and writes its
    # own raw evidence file rather than having the runner capture stdout.
    #
    # Setting this attribute here does NOT reach concrete stages at
    # runtime: DnsxStage, NaabuStage, JsreconStage etc. are plain classes
    # that duck-type Stage (see runtime_checkable above) -- they do not
    # inherit from this Protocol -- so a class attribute set on the
    # Protocol has zero effect on them. This exists purely to document the
    # contract. What actually supplies the default for every stage that
    # doesn't set in_process is the runner's own
    # getattr(stage, "in_process", False).
    in_process: bool = False

    def build_command(self, ctx: Any) -> list[str]: ...
    def parse(self, raw_path: Path) -> Iterator[Artifact | Finding]: ...
