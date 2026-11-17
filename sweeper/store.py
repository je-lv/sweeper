"""Normalized artifact store with incremental JSONL persistence.

Flushing incrementally is what makes a run resumable: a crash or SIGINT
leaves everything discovered so far on disk.
"""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

from .artifacts import Artifact, ArtifactKind, Finding, finding_diff_fields

_FILENAMES = {
    ArtifactKind.HOST: "hosts.jsonl",
    ArtifactKind.DNS_RECORD: "dns_records.jsonl",
    ArtifactKind.PORT: "ports.jsonl",
    ArtifactKind.UDP_PORT: "udp_ports.jsonl",
    ArtifactKind.HTTP_SERVICE: "services.jsonl",
    ArtifactKind.FINDING: "findings.jsonl",
}


class ArtifactStore:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = Path(run_dir)
        self.artifacts_dir = self.run_dir / "artifacts"
        self._by_kind: dict[ArtifactKind, dict[str, Artifact]] = {
            k: {} for k in ArtifactKind
        }
        self._findings: dict[str, Finding] = {}
        # Two DIFFERENT Findings that hash to the same id -- a bug in the
        # emitting stage, not a duplicate. See add_finding()'s docstring.
        # Kept here (not just logged) so a caller -- a test, a future
        # manifest writer -- can inspect exactly what collided without
        # scraping sweep.log.
        self._finding_collisions: list[dict] = []
        self._flushed_artifacts: dict[ArtifactKind, int] = {k: 0 for k in ArtifactKind}
        self._flushed_findings = 0
        # Values whose row is already on disk, and the subset of those whose
        # meta has been enriched since. See add() and flush().
        self._flushed_values: dict[ArtifactKind, set[str]] = {
            k: set() for k in ArtifactKind
        }
        self._dirty: dict[ArtifactKind, set[str]] = {k: set() for k in ArtifactKind}

    def add(self, artifact: Artifact) -> bool:
        """Merge an artifact in. First write wins PER META KEY, not per artifact.

        The previous rule was per-artifact `setdefault`: the first write of a
        value won and every later one was discarded whole. That silently
        defeated any stage that wanted to ANNOTATE a host it did not
        discover. `app.prepare()` seeds every permitted target as a HOST
        before any stage runs, so a HOST re-yielded by cdncheck (with
        cdn/waf/cloud detail), tlsx, httpx or nmap hit an existing key and
        the enrichment was dropped on the floor — the original
        {"src": "targets-file"} meta won forever. The stage looked like it
        worked: it reported the artifact count, and a test calling parse()
        directly saw correct meta, because the loss happens in the store and
        not in the parser.

        Merging per key keeps the useful half of the old rule (an existing
        value is never overwritten, so provenance set by the discoverer
        survives) while letting later stages fill in keys nobody has claimed
        yet. No caller has to opt in, so the next stage that enriches a host
        gets it for free rather than re-discovering the trap.

        Conflict rule: if two stages supply the same key with DIFFERENT
        values, the first writer still wins and the later value is dropped.
        That is deliberate — the alternative (last-wins) would let a
        late-running stage silently overwrite an earlier stage's finding-
        relevant fact, and "the value changed and nothing recorded that" is
        the failure class this project keeps hitting. Same-key disagreement
        between tools is a real signal (e.g. two sources disagreeing on an
        IP) but it needs somewhere to be RECORDED, not silently resolved;
        until there is such a place, the conservative rule is to keep the
        first and leave the second visible in the stage's own raw output.
        """
        existing = self._by_kind[artifact.kind].get(artifact.value)
        if existing is None:
            self._by_kind[artifact.kind][artifact.value] = artifact
            return True
        enriched = False
        for key, value in artifact.meta.items():
            if key not in existing.meta:
                existing.meta[key] = value
                enriched = True
            elif isinstance(existing.meta[key], list) and isinstance(value, list):
                merged = list(existing.meta[key])
                for item in value:
                    if item not in merged:
                        merged.append(item)
                if merged != existing.meta[key]:
                    existing.meta[key] = merged
                    enriched = True
        # An artifact enriched AFTER its row was already written needs that
        # row re-emitted, or the on-disk evidence trail keeps meta the
        # in-memory store has since corrected. Enrichment before the first
        # flush needs nothing: the first write already carries merged meta.
        if enriched and artifact.value in self._flushed_values[artifact.kind]:
            self._dirty[artifact.kind].add(artifact.value)
        return False

    def add_finding(self, finding: Finding) -> None:
        """Store `finding`, distinguishing a resubmission from a collision.

        `finding.id` is a hash of (stage, target, template_id, matcher) --
        deliberately not of evidence or timestamps, so the same issue hashes
        identically across runs and Plan 3's diffing can rely on that. That
        means id equality alone does NOT prove two Finding objects describe
        the same issue: it only proves those four fields matched. A stage
        whose `matcher` fails to distinguish two genuinely different
        findings (two private IPs on one host, two weak ciphers on one
        endpoint) produces two Findings with the same id but different
        content -- and the plain `setdefault` this replaced silently kept
        one and discarded the other. No error, no count, nothing in the
        manifest. In a pentest report that is under-reporting a real
        finding, the worst failure mode this tool has.

        So a same-id submission is handled in two different ways:

          - Same content (finding_diff_fields() returns an empty list, i.e.
            findings_are_equivalent -- which ignores first_seen and raw_ref,
            see its docstring): this is the same issue submitted again -- a
            rerun, or the same fact re-emitted from a different line of tool
            output. Deduping is correct here, and is what run-to-run diffing
            depends on: stable ids need a stable "already have this one"
            rule. Silently keep the first.

          - Different content: this is a bug in the emitting stage, and it
            must never again pass unnoticed. The first submission is still
            kept (deterministic, and it is real evidence, not a guess at
            which one is "right"), but the collision itself is recorded in
            self._finding_collisions (countable, inspectable) and logged to
            this run's sweep.log (so an operator reading the run's own
            output -- not a separate report -- sees it inline, the same
            place every stage's RUN/complete/PARSE_ERROR lines already go).

        Neither the collision record nor the log line carries `evidence`,
        `description`, `matched_at`, `title` OR `matcher` -- only field
        NAMES, from finding_diff_fields(). `evidence` etc. are scan-derived
        and, once secrets-detection lands, can hold a live credential
        extracted from harvested JavaScript; `matcher` is excluded for the
        same reason, because a stage that (correctly) derives its matcher
        from the offending secret itself -- so that two different secrets
        never collide onto one id -- means matcher CAN equal the secret
        value. sweep.log lives for the life of the run directory and is the
        first file an operator reads; it must never become a second place a
        secret is written in plaintext, alongside the redacted argv logging
        and the 0600/O_NOFOLLOW secret file this codebase already maintains
        that guarantee for. `id`, `stage`, `target` and `template_id` are
        identifiers, not secret material, and stay in the clear -- they are
        what makes the log line actionable. The full record, evidence
        included, is already on disk in artifacts/findings.jsonl inside the
        run directory's 0700 permissions, which is the right place for it.
        """
        existing = self._findings.get(finding.id)
        if existing is None:
            self._findings[finding.id] = finding
            return
        diff_fields = finding_diff_fields(existing, finding)
        if not diff_fields:
            return
        self._finding_collisions.append({
            "id": finding.id,
            "stage": finding.stage,
            "target": finding.target,
            "template_id": finding.template_id,
            "differing_fields": diff_fields,
        })
        self._log(
            f"FINDING ID COLLISION -- stage={finding.stage!r} "
            f"target={finding.target!r} template_id={finding.template_id!r} "
            f"id={finding.id} -- two DIFFERENT findings hashed to the same "
            f"id, differing in: {', '.join(diff_fields)}. This is a bug in "
            "the emitting stage: its matcher does not distinguish "
            "genuinely different findings. Field values (may include "
            "scan-derived or secret material) are deliberately not logged "
            "here -- see artifacts/findings.jsonl in this run directory, "
            "and store.finding_collisions."
        )

    def _log(self, msg: str) -> None:
        """Append one line to this run's sweep.log, in RunContext.log's format.

        Duplicated rather than calling RunContext.log(): ArtifactStore is
        constructed and used independently of RunContext (directly, in
        tests, and by any future caller), and does not hold a reference to
        one. Both write the identical "[timestamp] msg\\n" line to the same
        run_dir/sweep.log, so a reader sees a finding collision interleaved
        with every other stage's log line in the one place operators already
        look, rather than in a second, easy-to-miss file.
        """
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with (self.run_dir / "sweep.log").open("a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] {msg}\n")

    def get(self, kind: ArtifactKind) -> list[Artifact]:
        return list(self._by_kind[kind].values())

    def values(self, kind: ArtifactKind) -> list[str]:
        return [a.value for a in self.get(kind)]

    @property
    def findings(self) -> list[Finding]:
        return list(self._findings.values())

    @property
    def finding_collisions(self) -> list[dict]:
        """Every genuine id collision seen so far (see add_finding()).

        A non-empty list means some stage emitted two different findings
        that hashed to the same id -- a bug worth fixing in that stage's
        `matcher`, and worth flagging to whoever reads this run's output
        even before that stage is fixed, because it means the reported
        finding count is an undercount of what was actually found.
        """
        return list(self._finding_collisions)

    def restore_finding_collisions(self, rows) -> None:
        """Re-adopt collisions an earlier run of this run directory recorded.

        A collision is observable only at the instant two DIFFERENT findings
        with one id are submitted, and only the FIRST of the pair is ever
        written to artifacts/findings.jsonl -- so restore_store() cannot
        re-derive one by replaying that file. Without this, a resumed run
        reports zero collisions for a run that had them, and that is not
        cosmetic: a collision is what says the reported finding count is an
        UNDERCOUNT (see finding_collisions), the manifest's per-stage
        "collisions" numbers are computed from this list, both reports lead
        with it, and diff.py keys its undercount guard off exactly this
        field. Dropping it launders a known undercount into a stage a later
        retest treats as fully covering.

        The caller decides WHICH rows to hand back. resume passes only the
        rows belonging to stages it is not re-running: a re-run stage's every
        other number (status, artifacts, findings) is recomputed from this
        execution rather than carried over, and it will re-detect its own
        collisions the same way it detected them the first time -- taking its
        old rows back as well would double-count them.

        Rows of the wrong shape are ignored rather than raising: this input
        comes from a JSON file that may have been truncated by the very crash
        the resume exists to recover from.
        """
        for row in rows or []:
            if isinstance(row, dict):
                self._finding_collisions.append(dict(row))

    def mark_all_flushed(self) -> None:
        """Treat everything currently held as already persisted to disk.

        resume.restore_store() repopulates this store from a prior run's
        artifacts/*.jsonl files. Without this, the next flush() would see
        every restored row as new (a freshly constructed store's flushed
        high-water marks all start at 0) and duplicate it in those files,
        corrupting the append-only journal flush() otherwise guarantees.
        """
        for kind in ArtifactKind:
            if kind is ArtifactKind.FINDING:
                continue
            self._flushed_artifacts[kind] = len(self._by_kind[kind])
            self._flushed_values[kind] = set(self._by_kind[kind].keys())
            self._dirty[kind].clear()
        self._flushed_findings = len(self._findings)

    def flush(self) -> None:
        """Append what has not been written yet, plus re-emit enriched rows.

        Strictly append-only: the file is never reopened in 'w' and never
        rewritten, so anything else in it survives (pinned by
        test_artifact_flush_does_not_rewrite_existing_file). That is what
        makes a run resumable — a crash leaves everything found so far on
        disk.

        Append-only and "one row per value" cannot both hold once a stage can
        enrich an already-written artifact, so this file is a JOURNAL: a
        value may appear more than once and the LAST row for it is current.
        Re-emitting is the only way to keep the trail honest under
        append-only; the alternative is an on-disk row that contradicts the
        store, which is the stale-data-presenting-as-current problem this
        project keeps paying for.
        """
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        for kind, items in self._by_kind.items():
            if kind is ArtifactKind.FINDING:
                continue
            rows = list(items.values())
            start = self._flushed_artifacts[kind]
            new_rows = rows[start:]
            # Only values already on disk; an unflushed value is never marked
            # dirty, so it cannot be written twice by these two lists.
            dirty_rows = [items[v] for v in self._dirty[kind] if v in items]
            if not new_rows and not dirty_rows:
                continue
            path = self.artifacts_dir / _FILENAMES[kind]
            with path.open("a", encoding="utf-8") as fh:
                for a in [*new_rows, *dirty_rows]:
                    fh.write(json.dumps(
                        {"kind": a.kind.name, "value": a.value, "meta": a.meta}
                    ) + "\n")
            self._flushed_artifacts[kind] = len(rows)
            self._flushed_values[kind].update(a.value for a in new_rows)
            self._dirty[kind].clear()

        rows = list(self._findings.values())
        if len(rows) > self._flushed_findings:
            path = self.artifacts_dir / _FILENAMES[ArtifactKind.FINDING]
            with path.open("a", encoding="utf-8") as fh:
                for f in rows[self._flushed_findings:]:
                    fh.write(json.dumps(dataclasses.asdict(f)) + "\n")
            self._flushed_findings = len(rows)
