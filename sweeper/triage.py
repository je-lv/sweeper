"""Persistent triage state, keyed by the stable finding id.

Stored OUTSIDE any run directory so a re-scan inherits earlier decisions.
Without this, every re-run re-reports the same forty info findings and the
signal is lost in the noise.

Failure direction matters here. `Finding.id` deliberately excludes evidence
and timestamps (see sweeper/artifacts.py), so the same underlying issue
hashes identically across runs -- but that also means a THREE-WEEK-OLD
false-positive verdict silently keeps suppressing a finding whose evidence
changed underneath a stable id. This module does not try to detect that (no
signal to detect it from is stored), but it records `updated_at` and
`updated_by` on every verdict so a human reviewing the file, or a later
report, has enough context to notice a suspiciously old accepted-risk and
ask whether it still holds.

Any time this file cannot be trusted -- missing, empty, malformed JSON, or
written by a future schema this code does not understand -- the fail
direction is to treat every finding as untriaged ("new"), never to guess a
verdict from unreadable data. Losing triage state is the annoying version of
a failure (old decisions get re-litigated); losing a finding underneath a
false verdict inferred from garbage is the dangerous one. We only accept the
annoying one, and we say so loudly (a logged warning, and a `load_error`
attribute callers can surface) rather than silently starting over.
"""
from __future__ import annotations

import getpass
import json
import logging
import os
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUSES = ("new", "confirmed", "false-positive", "accepted-risk")

# Bumped only if the on-disk shape changes incompatibly. A file claiming a
# newer version than this code understands is treated as unreadable rather
# than guessed at -- see module docstring.
SCHEMA_VERSION = 1

# Owner read/write only. The file lives outside any run directory's 0700
# umbrella and free-text notes are operator-authored, not guaranteed free of
# engagement-sensitive detail, so it gets the same owner-only treatment
# sweeper/auth.py gives credential material.
TRIAGE_FILE_MODE = 0o600

logger = logging.getLogger(__name__)


def default_triage_path() -> Path:
    """Where triage state lives when a caller does not choose otherwise.

    Deliberately outside any run directory AND outside any engagement's
    output directory: inheriting earlier verdicts across a re-scan is this
    module's entire reason to exist (see the docstring above), and a file
    under `outdir/<run>/` could not do it. `~/.sweeper/` is per-operator,
    which is also what makes `updated_by` meaningful.
    """
    return Path.home() / ".sweeper" / "triage.json"


class TriageState:
    """Operator triage decisions, keyed by `Finding.id`.

    `path` is expected to live outside any run directory -- that is the
    entire point, it is what lets a re-scan inherit earlier decisions.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._data: dict[str, dict[str, Any]] = {}
        # Set by load() when the on-disk file exists but could not be
        # trusted (malformed JSON, wrong shape, unknown schema version).
        # None means either no file existed yet, or it loaded cleanly.
        self.load_error: str | None = None
        self._backed_up_corrupt = False
        self.load()

    # -- persistence ---------------------------------------------------

    def load(self) -> None:
        self._data = {}
        self.load_error = None
        if not self.path.exists():
            return
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            self._fail_closed(f"could not read {self.path}: {exc}")
            return
        if not text.strip():
            # An empty file is the same as no file -- e.g. `touch`'d by
            # tooling, or truncated by a prior crash before any write
            # landed. Nothing was ever recorded, so there is nothing to
            # warn about.
            return
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            self._fail_closed(f"{self.path} is not valid JSON: {exc}")
            return
        if not isinstance(raw, dict):
            self._fail_closed(
                f"{self.path} does not contain a JSON object at top level"
            )
            return
        version = raw.get("schema_version")
        if version != SCHEMA_VERSION:
            self._fail_closed(
                f"{self.path} has schema_version {version!r}, expected "
                f"{SCHEMA_VERSION!r} -- refusing to guess at an unknown "
                f"triage file format"
            )
            return
        findings = raw.get("findings")
        if not isinstance(findings, dict):
            self._fail_closed(
                f"{self.path} is missing a 'findings' object"
            )
            return
        clean: dict[str, dict[str, Any]] = {}
        for finding_id, entry in findings.items():
            if not isinstance(entry, dict) or entry.get("status") not in STATUSES:
                logger.warning(
                    "triage: dropping unreadable entry for %s in %s",
                    finding_id, self.path,
                )
                continue
            clean[finding_id] = entry
        self._data = clean

    def _fail_closed(self, message: str) -> None:
        self.load_error = message
        logger.warning("triage: %s -- treating all findings as untriaged", message)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._backup_corrupt_original_once()

        payload = {
            "schema_version": SCHEMA_VERSION,
            "findings": self._data,
        }
        body = json.dumps(payload, indent=2, sort_keys=True) + "\n"

        # Write to a sibling temp file and rename into place so a crash or
        # interruption mid-write can never leave a half-written,
        # corrupt-JSON triage.json behind for the next load() to trip over.
        fd, tmp_name = tempfile.mkstemp(
            dir=self.path.parent, prefix=f".{self.path.name}.", suffix=".tmp"
        )
        try:
            os.fchmod(fd, TRIAGE_FILE_MODE)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(body)
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _backup_corrupt_original_once(self) -> None:
        """Preserve an unreadable file before the first save() replaces it.

        Only fires the one time a save() follows a load() that could not be
        trusted, and only as a side effect of the operator actively writing
        new state -- never as a side effect of merely constructing or
        reading a TriageState, which must stay read-only.
        """
        if not self.load_error or self._backed_up_corrupt:
            return
        self._backed_up_corrupt = True
        if not self.path.exists():
            return
        backup = self.path.with_name(self.path.name + ".corrupt")
        try:
            backup.write_bytes(self.path.read_bytes())
            logger.warning(
                "triage: preserved unreadable file as %s before overwriting", backup
            )
        except OSError as exc:
            logger.warning(
                "triage: could not back up unreadable %s before overwriting: %s",
                self.path, exc,
            )

    # -- reads -----------------------------------------------------------

    def get(self, finding_id: str) -> str:
        return self._data.get(finding_id, {}).get("status", "new")

    def note(self, finding_id: str) -> str:
        return self._data.get(finding_id, {}).get("note", "")

    def meta(self, finding_id: str) -> dict[str, Any]:
        """Full audit record for a finding: status, note, and (if set) who
        recorded it and when. Empty dict for an untriaged finding.
        """
        return dict(self._data.get(finding_id, {}))

    # -- writes ------------------------------------------------------------

    def set(self, finding_id: str, status: str, note: str = "") -> None:
        if status not in STATUSES:
            raise ValueError(
                f"invalid triage status {status!r}; expected one of {STATUSES}"
            )
        self._data[finding_id] = {
            "status": status,
            # Always reflects exactly what was passed on THIS call, even ""
            # -- a stale note from a superseded verdict (e.g. a
            # false-positive's justification) must not linger and read as
            # the rationale for a later, different verdict.
            "note": note,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": _current_user(),
        }
        self.save()

    def apply(self, findings: list) -> list:
        """Return NEW Finding objects carrying triage state.

        Must not mutate `findings` in place: callers pass ctx.store.findings
        here, which are live references into the run's artifact store (see
        ArtifactStore.findings in sweeper/store.py). Rendering a report is a
        read of run state, not a write of it -- dataclasses.replace() gives
        each finding its own copy with .triage/.triage_note set, leaving the
        store's own instances exactly as they were.
        """
        return [
            replace(f, triage=self.get(f.id), triage_note=self.note(f.id))
            for f in findings
        ]


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
