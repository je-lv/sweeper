"""Typed artifacts exchanged between stages.

Stages never call each other. They read artifacts of the kind they consume
from the store and write artifacts of the kinds they produce. This is what
lets a new tool be added as one file with no changes to the runner.
"""
from __future__ import annotations

import dataclasses
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")


class ArtifactKind(Enum):
    HOST = auto()
    DNS_RECORD = auto()
    PORT = auto()
    UDP_PORT = auto()
    HTTP_SERVICE = auto()
    FINDING = auto()


@dataclass(frozen=True)
class Artifact:
    kind: ArtifactKind
    value: str
    meta: dict[str, Any] = field(default_factory=dict, compare=False)


def finding_id(stage: str, target: str, template_id: str, matcher: str = "") -> str:
    """Stable identity for a finding, enabling run-to-run diffing.

    Deliberately excludes timestamps and evidence text so the same issue
    hashes identically across runs.
    """
    raw = "|".join((stage, target, template_id, matcher))
    return hashlib.sha1(raw.encode()).hexdigest()


@dataclass
class Finding:
    stage: str
    severity: str
    title: str
    target: str
    template_id: str
    matcher: str = ""
    matched_at: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    first_seen: str = ""
    raw_ref: str = ""
    triage: str = "new"
    triage_note: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"severity must be one of {SEVERITIES}, got {self.severity!r}"
            )
        if not self.id:
            self.id = finding_id(
                self.stage, self.target, self.template_id, self.matcher
            )
        if not self.matched_at:
            self.matched_at = self.target


# Fields deliberately excluded from findings_are_equivalent()'s comparison,
# because a difference in one of these does NOT mean two findings describe
# different issues:
#   - id: it is what led the caller to compare two findings in the first
#     place (they share an id); comparing it again is redundant.
#   - first_seen: a timestamp stamped at discovery time. The same issue
#     found on a rerun, or found twice in one run, naturally gets a
#     different first_seen -- treating that as a difference would make
#     every legitimate rerun or duplicate look like a collision.
#   - raw_ref: a pointer into this run's raw/<stage>.jsonl (stage + line
#     number). The same fact can legitimately be re-emitted from a
#     different line of tool output (e.g. a host repeated in dnsx's JSONL
#     output), and that is still one fact, not two.
#   - triage / triage_note: operator metadata from sweeper/triage.py, not a
#     fact a stage discovered. A Finding fresh out of a stage always carries
#     the defaults ("new", ""); a copy annotated by TriageState.apply() for
#     reporting can carry anything. Neither should ever make an otherwise
#     identical finding look like a collision.
_EQUIVALENCE_IGNORED_FIELDS = ("id", "first_seen", "raw_ref", "triage", "triage_note")


def finding_diff_fields(a: Finding, b: Finding) -> list[str]:
    """Names of the fields where `a` and `b` differ (ignoring the same
    fields findings_are_equivalent() ignores), sorted for a stable message.

    Returns NAMES only, never the differing values. `evidence`,
    `description`, `matched_at` and `title` are scan-derived and, once
    secrets-detection lands, can carry live credentials extracted from
    harvested JavaScript -- material this codebase already goes out of its
    way not to write to a long-lived file (SecretBundle's redacting
    __repr__, the runner's argv redaction, the 0600/O_NOFOLLOW secret
    file). A collision log is exactly such a file: it lives for the life of
    the run directory and is the first place an operator looks. Naming
    *which* field differed is enough to diagnose and fix the emitting
    stage's matcher; the values themselves are already on disk in
    artifacts/findings.jsonl, inside the run directory's 0700 permissions,
    which is the right place for them -- not duplicated into a log line.
    """
    return sorted(
        f.name for f in dataclasses.fields(Finding)
        if f.name not in _EQUIVALENCE_IGNORED_FIELDS
        and getattr(a, f.name) != getattr(b, f.name)
    )


def findings_are_equivalent(a: Finding, b: Finding) -> bool:
    """Do `a` and `b` describe the SAME issue, modulo timestamp/provenance?

    Used to tell an innocuous resubmission of a finding (same issue,
    submitted again -- correct to dedupe) apart from two genuinely
    different findings that happen to share an id (a bug in the emitting
    stage's `matcher` -- must be surfaced, never silently dropped). Every
    field is compared except the ones in _EQUIVALENCE_IGNORED_FIELDS.
    """
    return not finding_diff_fields(a, b)
