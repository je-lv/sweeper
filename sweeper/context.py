"""Run configuration, run directory, and the manifest.

run.json records tool versions because a finding is only reproducible if
you know which binary and which template set produced it. It also records
every skipped stage and every scope refusal, so a degraded run can never be
mistaken for a clean one.
"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import useragents
from .scope import ScopeGuard
from .stages.base import Coverage, StageResult, is_degraded
from .store import ArtifactStore

# Owner-only, on the run directory and every directory created under it.
# Everything in a run directory is sensitive: the nuclei secret file holds
# live credentials outright, and raw tool output can echo an Authorization
# header straight back from the target. A plain mkdir() takes whatever the
# umask allows -- 0o775 under umask 002, which is normal on a shared-group
# box -- and a group-writable run directory is what makes a symlink swap on
# any file inside it possible in the first place. Verified against the mode
# on disk in the tests, because mkdir()'s mode argument is umask-masked.
RUN_DIR_MODE = 0o700


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mkdir_private(path: Path) -> Path:
    """mkdir -p, owner-only, without relaxing a directory that already exists.

    Only directories this call actually creates are chmod'ed: silently
    tightening an operator's pre-existing recon/ tree would be a surprising
    side effect, and it is not ours to change.
    """
    path = Path(path)
    missing = []
    probe = path
    while not probe.exists():
        missing.append(probe)
        if probe.parent == probe:
            break
        probe = probe.parent
    for directory in reversed(missing):
        directory.mkdir(mode=RUN_DIR_MODE, exist_ok=True)
        os.chmod(directory, RUN_DIR_MODE)   # mkdir's mode is umask-masked
    return path


def new_run_dir(outdir: Path) -> Path:
    """Create a fresh run directory, never reusing an existing one.

    The timestamp has second resolution, so two runs launched in the same
    second would otherwise share a directory: run.json overwritten,
    sweep.log and raw/ output interleaved, with no error and no way to
    separate them afterwards. For an audit trail that is an integrity
    problem, not a cosmetic one. Collisions get a -2, -3, ... suffix.

    Created 0o700. See RUN_DIR_MODE.
    """
    base = datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = _mkdir_private(outdir)
    candidate, suffix = outdir / base, 2
    while True:
        try:
            # exist_ok=False is load-bearing above (collision detection), so
            # the mode is enforced with a follow-up chmod rather than relying
            # on mkdir's umask-masked mode argument.
            candidate.mkdir(mode=RUN_DIR_MODE, exist_ok=False)
            os.chmod(candidate, RUN_DIR_MODE)
            return candidate
        except FileExistsError:
            candidate = outdir / f"{base}-{suffix}"
            suffix += 1


# Fields whose manifest form is a string (or null) rather than a plain JSON
# scalar. Named rather than type-sniffed because `Path | None` and a plain
# `str` field are indistinguishable once a manifest has been through json.
_PATH_FIELDS = ("targets_file", "outdir", "triage_file")

#: Sentinel for "this manifest value is not usable; fall back to the field's
#: own default". Distinct from None because None is a legal value for
#: triage_file.
_UNSET = object()


@dataclass
class RunConfig:
    targets_file: Path
    outdir: Path = Path("recon/sweeper")
    level: str = "mid"
    auth_mode: str = "unauth"
    stages: list[str] = field(default_factory=list)   # empty = all eligible
    proxy: str = ""
    # Empty means choose one browser UA per run as before. An explicit value
    # is needed when an engagement requires attributable or session-bound
    # traffic and must survive profiles/resume like every other run control.
    user_agent: str = ""
    rate_override: int = 0
    # The operator's port selection for naabu, as "top-100" or "80,443" or
    # "1-1024". Empty means "use the level's own range". Stored as the raw
    # string rather than parsed flags for the same reason as `resolver`
    # below: the manifest should record what the operator asked for, not
    # this version's spelling of it.
    #
    # This is the operator's control for narrowing a live `high` run. Scope
    # is enforced per HOST while services are
    # host:PORT, so an all-ports scan of an authorised name reaches every
    # service bound to that name's IP -- including, on shared
    # infrastructure, services the client does not own. No off-scope
    # hostname is resolved in that case, so ScopeGuard never sees anything
    # to refuse. See sweeper/ports.py.
    ports: str = ""
    # Independent UDP selection for the nmap_udp stage. Empty uses the
    # level profile (top-20/100/1000); it never inherits the TCP selection,
    # because TCP and UDP prevalence and scan cost are materially different.
    udp_ports: str = ""
    # May sweeper fall back to a public resolver when the system one cannot
    # resolve the scope? Only ever consulted when the operator named NO
    # resolver of their own -- see preflight. False for engagements where
    # sending the client's hostnames to a third party is out of the question.
    resolver_fallback: bool = True
    time_limit: str = ""
    subdomain_enum: bool = False
    preflight_timeout: float = 3.0   # see preflight.validate_arguments docstring
    verify_secrets: bool = False   # trufflehog verification egresses secrets
    # Path to an operator-supplied nuclei template directory, passed through
    # as `-t <path>` by stages/nuclei.py. Validated by
    # preflight.validate_custom_templates (existence + `nuclei -validate`)
    # before any packet reaches a target -- an unvalidated bad path here
    # would otherwise fail mid-sweep instead of at preflight. Empty string,
    # not None, so an old profile that never set it and a profile that
    # explicitly cleared it are indistinguishable, both meaning "no custom
    # templates" -- and so getattr(ctx.config, "custom_templates", "")
    # fallbacks already in stages/nuclei.py keep working unchanged.
    custom_templates: str = ""
    # Where this run's persistent triage state lives. None means "use the
    # default" (~/.sweeper/triage.json, see triage.default_triage_path) --
    # a plain attribute, not a getattr-with-default at the call site, so an
    # operator's --triage-file is never silently ignored if this field is
    # ever dropped: a missing attribute raises loudly instead of falling
    # back unnoticed.
    triage_file: Path | None = None
    # Comma-separated DNS resolvers, as IP or IP:port. Empty means "each
    # tool's own defaults", which is what every run did before this existed.
    #
    # Stored as the raw operator string rather than the parsed list so that
    # to_manifest() below stays a plain JSON scalar dump and --resume
    # restores exactly what was typed. sweeper.resolvers.parse() is the one
    # place that interprets it, and app.main validates it there before the
    # run starts -- a bad value must fail at argument time, not once a stage
    # is already sending queries somewhere unintended.
    #
    # NOT every stage can honour this: ffuf (vhost), arjun and jsrecon's
    # stdlib fetcher have no resolver option and use the system resolver.
    # That split is recorded in run.json's "resolver" block rather than left
    # for a reader to infer -- see RunContext.write_manifest.
    resolver: str = ""
    # Extra wordlists for the content-discovery stage, comma-separated paths.
    # The stage's own per-level lists are the baseline; these ADD to them,
    # unless content_wordlists_only is set. A bespoke path is in no SecLists
    # file, so an operator's own list is the only thing that will find it.
    content_wordlists: str = ""
    # Use ONLY the operator's lists, not the level's. For a curated list
    # aimed at one target, paying for 70k generic guesses alongside it is
    # not a service.
    content_wordlists_only: bool = False

    def to_manifest(self) -> dict:
        """This config as JSON-safe data, for run.json's "config" block.

        EVERY field, derived from dataclasses.fields() rather than listed
        here. A hand-written list is the shape that made --resume drop
        operator settings in the first place: run.json recorded only level,
        auth_mode, targets_file and proxy, so a resumed run silently lost the
        client's own --custom-templates (unrecoverable -- nothing else on
        disk records them), the per-stage --time-limit, and an operator's
        rate override, which fell back to the level default and multiplied
        the request rate by 20 against a client no-DoS rule. Deriving the
        list means the next field added to RunConfig is persisted, and
        restored, without anyone remembering to add it here.

        Nothing in RunConfig is secret: credentials live on ctx.auth and in
        the 0600 secret file, never in the config. The paths recorded here
        (targets_file, outdir, triage_file) are local paths the operator
        typed, and targets_file is already recorded at the top level.
        """
        out: dict = {}
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            if f.name in _PATH_FIELDS:
                out[f.name] = None if value is None else str(value)
            else:
                out[f.name] = value
        return out

    @classmethod
    def from_manifest(cls, data: dict, **overrides) -> "RunConfig":
        """Rebuild a RunConfig from a to_manifest() block.

        Fail-SOFT per field, not per document. This input is a JSON file that
        may have been truncated by the very crash the resume exists to
        recover from, and may have been written by an older sweeper that did
        not have some of today's fields. A value of the wrong shape (a
        `level` of 12, a `stages` that is a string) falls back to the field's
        own default rather than raising, so one bad key cannot make an
        otherwise recoverable run directory unresumable -- and a field of a
        type _coerce_config_value does not know is treated as unusable, i.e.
        the fallback is CLOSED, never "pass the raw JSON value through".

        `overrides` win over anything in `data` and are not type-checked:
        they are the caller's own values, not the file's. resume uses them to
        pin targets_file and outdir to the run directory being resumed, which
        must never come from the manifest -- the manifest's targets_file is
        wherever the operator's file lived at the time and may since have
        been edited, moved, or repointed at a different engagement, while
        run_dir/targets.txt is the copy this run actually swept.
        """
        data = data if isinstance(data, dict) else {}
        kwargs: dict = {}
        for f in dataclasses.fields(cls):
            if f.name in overrides or f.name not in data:
                continue
            value = _coerce_config_value(f, data[f.name])
            if value is not _UNSET:
                kwargs[f.name] = value
        kwargs.update(overrides)
        return cls(**kwargs)


def _coerce_config_value(field, value):
    """One manifest value as the type its RunConfig field declares, or _UNSET.

    The expected type comes from the field's own DEFAULT, so this needs no
    per-field table and cannot fall out of date with RunConfig. bool is
    checked before int deliberately -- bool is a subclass of int, so the
    other order would accept `subdomain_enum: 1` and, worse,
    `rate_override: true` as the rate 1.
    """
    if field.name in _PATH_FIELDS:
        if value is None:
            return None
        return Path(value) if isinstance(value, str) else _UNSET
    if field.default is not dataclasses.MISSING:
        default = field.default
    elif field.default_factory is not dataclasses.MISSING:   # type: ignore[misc]
        default = field.default_factory()                    # type: ignore[misc]
    else:
        return _UNSET
    if isinstance(default, bool):
        return value if isinstance(value, bool) else _UNSET
    if isinstance(default, int):
        return value if isinstance(value, int) \
            and not isinstance(value, bool) else _UNSET
    if isinstance(default, float):
        return float(value) if isinstance(value, (int, float)) \
            and not isinstance(value, bool) else _UNSET
    if isinstance(default, str):
        return value if isinstance(value, str) else _UNSET
    if isinstance(default, list):
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return list(value)
        return _UNSET
    # An unrecognised field type falls back to the default rather than
    # passing raw JSON through into a RunConfig field. Fail closed.
    return _UNSET


class AuthModeViolation(RuntimeError):
    """Live credentials were attached to a run whose auth_mode is not "auth".

    THE INVARIANT: ctx.auth carries credentials if and only if
    config.auth_mode == "auth". run.json's "auth_mode" and the report's
    "**Auth:**" line are rendered straight from config.auth_mode, so the
    moment those two disagree the deliverable asserts traffic that is not
    what was sent -- a client-facing integrity problem, and a rules-of-
    engagement one: running an authenticated pass and then an unauthenticated
    baseline pass is ordinary workflow, and the operator who switches back to
    "unauth" has to actually get an unauthenticated run.

    Enforced HERE, on the attribute itself, rather than at each call site
    that happens to set it. A condition in one caller only fixes that caller;
    the next entry point wired up (a --burp-request CLI flag, a resumed run,
    a scripted driver) would reintroduce it silently. Assignment is the
    choke point every one of them must pass through.

    Deliberately not a ValueError -- same reasoning as
    app.StageContractViolation and preflight.TargetLeakInProbe. app.main()'s
    `except ValueError` turns an unknown --stages name into a friendly
    exit-2, and _runner's catches the same to keep the REPL alive; neither
    must be able to swallow a credential leaking into a run that reports
    itself as unauthenticated.

    An EMPTY bundle is not credentials and is always allowed: it carries
    nothing to leak, and that is what "the operator cleared their
    credentials" looks like.
    """


class RunContext:
    def __init__(self, config: RunConfig, run_dir: Path,
                 store: ArtifactStore, scope: ScopeGuard) -> None:
        self.config = config
        self.run_dir = run_dir
        self.store = store
        self.scope = scope
        # None for a tool that reports no version (trufflehog, arjun). Recorded
        # rather than omitted: null says "checked, reports no version", where a
        # missing key would read as "never verified".
        self.tool_versions: dict[str, str | None] = {}
        # Live credentials, held in memory only. self.auth must never be
        # passed to log() or json.dumps() directly -- see auth.SecretBundle
        # and header_args(). self.secret_file is the on-disk nuclei
        # -secret-file path (if written); it is in scope for redaction
        # before any export, same as self.auth's source material.
        # Assignment is guarded -- see the `auth` property and
        # AuthModeViolation. self.config is set above, before this line,
        # because the setter reads it.
        self._auth = None           # SecretBundle | None
        self.auth = None
        self.secret_file = None     # Path | None
        # The coverage denominator. Left at its zero/empty default until
        # execute() populates it (before run_stages, with what was actually
        # requested) — see Coverage's docstring. A caller that never sets it
        # (a low-level test writing a manifest directly, say) gets a
        # denominator of 0/0/[] , which is_degraded treats as "nothing to
        # compare", not as a gap.
        self.coverage: Coverage = Coverage()
        # stage name -> can that stage pass this run's --resolver to its tool.
        # Populated by execute() from the stage objects (see app.execute); a
        # caller that never sets it gets {}, which write_manifest records as
        # an empty split rather than guessing.
        self.resolver_support: dict[str, bool] = {}
        # One UA per run, chosen once. A per-call draw would make
        # build_command non-deterministic: preflight would validate a
        # different argv than the runner executes, and the command recorded
        # in run.json would not be replayable. Recorded in the manifest so a
        # reader knows exactly what was sent.
        self.user_agent = config.user_agent or useragents.random_agent()
        self.acknowledgements: list[dict] = []
        # Operator-facing, decide-and-inform notices raised at run start --
        # distinct from acknowledgements (which gate an action before it is
        # allowed to happen) and from aborted_reason (which explains why a
        # run did NOT complete). A warning here means the run proceeded, but
        # the operator was told something about it they need for the report
        # -- e.g. arjun exposing live credentials via `ps` when both auth and
        # arjun are selected (see app.execute()). Recorded in the manifest so
        # "the operator was told" is not merely a console line nobody kept.
        self.warnings: list[str] = []
        # Set when a run is cut short. Recorded in the manifest and led with
        # in the report: an aborted run that presents as merely empty is
        # indistinguishable from one where no stages were selected.
        self.aborted_reason: str = ""
        self.started = utcnow()
        # Raw tool output can contain an Authorization header echoed back by
        # the target, so raw/ gets the run directory's mode rather than the
        # umask's. See RUN_DIR_MODE.
        _mkdir_private(self.run_dir / "raw")

    @property
    def auth(self):
        """Live credentials for this run, or None. See AuthModeViolation."""
        return self._auth

    @auth.setter
    def auth(self, bundle) -> None:
        # The one gate every assignment passes through, whatever set it.
        # Only a bundle that actually carries credentials is refused: None
        # and an empty bundle are both "no credentials", which is legal in
        # either mode. The converse half of the invariant -- auth_mode
        # "auth" with NO credentials -- is caught by preflight.run_preflight,
        # which refuses the run rather than silently scanning anonymously.
        # Together they mean: any run that actually proceeds has credentials
        # if and only if it reports auth_mode "auth".
        if bundle is not None and not bundle.is_empty() \
                and self.config.auth_mode != "auth":
            raise AuthModeViolation(
                "refusing to attach credentials to a run whose auth_mode is "
                f"{self.config.auth_mode!r}: run.json and the report render "
                "auth_mode verbatim, so this run would send authenticated "
                "traffic while its own deliverable states it did not. Set "
                "config.auth_mode = 'auth' to use these credentials, or do "
                "not attach them."
            )
        self._auth = bundle

    @classmethod
    def create(cls, config: RunConfig) -> "RunContext":
        run_dir = new_run_dir(config.outdir)
        shutil.copyfile(config.targets_file, run_dir / "targets.txt")
        targets = _parse_targets(config.targets_file)
        return cls(config, run_dir, ArtifactStore(run_dir), ScopeGuard(set(targets)))

    def load_targets(self) -> list[str]:
        return _parse_targets(self.config.targets_file)

    def raw_path(self, stage: str, ext: str = "jsonl") -> Path:
        return self.run_dir / "raw" / f"{stage}.{ext}"

    def log(self, msg: str) -> None:
        line = f"[{utcnow()}] {msg}\n"
        with (self.run_dir / "sweep.log").open("a", encoding="utf-8") as fh:
            fh.write(line)

    def write_manifest(self, results: list[StageResult],
                       final: bool = True) -> None:
        """Record the run so far. `final=False` marks it as a checkpoint.

        Written after every stage, not once at the end, because a process
        that never runs its handlers cannot write a record on the way out.
        On 2026-08-05 the box ran out of memory mid-scan and rebooted with
        seven stages complete; the run directory held every artifact they
        produced and --resume refused it with `no run.json`, so all of it
        was scanned again.

        The marker is what makes checkpointing safe. A truncated run that
        reads as a finished one is worse than no manifest at all -- it is
        this project's recurring failure (partial coverage presenting as
        complete) promoted to the file that describes the entire run. Every
        reader that treats `finished` as "this is what the scan covered"
        must check it.
        """
        # One definition, shared with every report. See is_degraded().
        degraded = is_degraded(results, self.coverage)
        # Filter to the run's FINAL level. Acknowledging `full` and then
        # loading a `mid` profile must not leave the `full` record in a mid
        # run's manifest -- it no longer describes what actually ran, and a
        # stale acknowledgement over-attests authorisation that was never
        # exercised for this run.
        current_acks = [
            a for a in self.acknowledgements if a.get("level") == self.config.level
        ]
        manifest = {
            "started": self.started,
            "finished": utcnow(),
            # "finished" is a TIMESTAMP, not a claim -- on a checkpoint it is
            # simply when this record was written. This is the field that says
            # whether the run got to the end.
            "run_status": "finished" if final else "in-progress",
            "level": self.config.level,
            "auth_mode": self.config.auth_mode,
            "targets_file": str(self.config.targets_file),
            "proxy": self.config.proxy,
            # The WHOLE RunConfig, not just the four fields rendered above.
            # Those four stay where they are (diff.py and both reports read
            # them by name), but they are a lossy summary: a resume that
            # rebuilt its config from them alone silently dropped
            # custom_templates, time_limit and rate_override. See
            # RunConfig.to_manifest().
            "config": self.config.to_manifest(),
            "tool_versions": self.tool_versions,
            "user_agent": self.user_agent,
            "acknowledgements": current_acks,
            "warnings": list(self.warnings),
            "degraded": degraded or bool(self.aborted_reason),
            # The denominator itself, not just the boolean it feeds into --
            # a reader should not have to infer what was requested from
            # what happens to be present elsewhere in this document.
            "coverage": dataclasses.asdict(self.coverage),
            "aborted": bool(self.aborted_reason),
            "aborted_reason": self.aborted_reason,
            "scope": {
                "allowed": sorted(self.scope.allowed),
                "refusals": self.scope.refusals,
                "extensions": self.scope.extensions,
                # Deliberately a separate key from "refusals": these are
                # routine tool discoveries admission control correctly kept
                # out of the store, not operator-supplied out-of-scope
                # targets. Conflating the two would flood "refusals" (a
                # discovery stage can turn up hundreds) and make an
                # expected, successful run's manifest look identical to one
                # with an RoE problem. See ScopeGuard.record_discovery_refusal.
                "discoveries_refused": self.scope.discoveries_refused,
            },
            # WHICH STAGES ACTUALLY USED THE OPERATOR'S RESOLVER.
            #
            # Recorded explicitly because the split is invisible everywhere
            # else and silently changes what a run means. ffuf (vhost), arjun
            # and jsrecon's stdlib fetcher have no resolver option, so on a
            # split-horizon engagement they resolve through the scanning
            # box's own DNS while every other stage resolves through the
            # client's -- the two halves of one run can be looking at two
            # different sets of hosts. Left to be inferred, that reads as a
            # normal run with fewer findings, which is this project's
            # recurring defect. "value" is the raw operator string; [] for
            # both lists means the run predates a stage list being recorded.
            "resolver": {
                "value": self.config.resolver,
                # True when the operator named NO resolver, the system one
                # could not resolve the scope, and preflight adopted a public
                # fallback. It belongs in the record because those queries
                # disclosed the scope's hostnames to a third party, and
                # because on a split-horizon scope the addresses are the
                # EXTERNAL view -- possibly different hosts under the same
                # names. See preflight's resolver-fallback branch.
                "fallback": bool(getattr(self, "resolver_is_fallback", False)),
                "entries": _resolver_entries(self.config.resolver),
                "honored_by": sorted(
                    n for n, ok in self.resolver_support.items() if ok
                ),
                "system_dns": sorted(
                    n for n, ok in self.resolver_support.items() if not ok
                ),
            },
            "stages": {
                r.stage: {
                    "status": r.status,
                    "failure": r.failure.name,
                    "reason": r.reason,
                    "artifacts": r.artifacts,
                    # 2 means the tool died having written nothing and the
                    # runner ran it a second time (see runner.run_stages).
                    # That is a second sweep of the target, so it belongs in
                    # the record the client may read -- and it tells an
                    # operator that an otherwise clean result came from a
                    # retry, i.e. that the tool is flaky here.
                    "attempts": r.attempts,
                    # What run_stages() actually stored for this stage --
                    # never larger than what ctx.store holds. See
                    # runner.py's Finding branch.
                    "findings": r.findings,
                    # Genuine finding-id collisions (two DIFFERENT findings
                    # sharing an id -- a bug in this stage's matcher, see
                    # store.add_finding's docstring) attributed to this
                    # stage. "findings" above already excludes these -- a
                    # collision was never counted as stored -- so
                    # findings + collisions reconstructs how many distinct
                    # Finding objects this stage actually submitted (modulo
                    # a true resubmission of an already-stored finding,
                    # which is correct to dedupe silently and was never a
                    # collision).
                    "collisions": sum(
                        1 for c in self.store.finding_collisions
                        if c["stage"] == r.stage
                    ),
                    "duration_s": round(r.duration_s, 2),
                    "command": r.command,
                }
                for r in results
            },
            # The run-wide totals the per-stage numbers above must reconcile
            # to: findings_stored is exactly len(self.store.findings) (what
            # a reader of artifacts/findings.jsonl will find), and
            # finding_collisions is the full, inspectable list backing every
            # per-stage "collisions" count -- identity only (id, stage,
            # target, template_id, differing field NAMES), never evidence,
            # matcher, or any other value that can carry scan-derived or
            # secret material. See store.add_finding's and
            # finding_diff_fields' docstrings for why those fields are
            # withheld even here.
            "findings_stored": len(self.store.findings),
            "finding_collisions": self.store.finding_collisions,
        }
        # Serialise BEFORE touching the file. A manifest that cannot be
        # rendered must leave the last good one intact rather than truncate
        # it, and the rename below is only atomic if there is nothing left to
        # fail after it.
        rendered = json.dumps(manifest, indent=2) + "\n"
        path = self.run_dir / "run.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(rendered, encoding="utf-8")
        # Atomic replace: the crash this checkpointing exists for can land
        # mid-write just as easily as between stages, and resume refuses a
        # CORRUPT manifest exactly as firmly as a missing one -- a different
        # route to losing the same run.
        os.replace(tmp, path)


def _resolver_entries(value: str) -> list[str]:
    """The normalised resolver list for the manifest, never raising.

    app.main validates --resolver before the run starts, so by the time a
    manifest is written the value is already known-good. This still refuses
    to raise: write_manifest is the call that records WHY a run died, and a
    manifest that itself throws would erase the record of every other
    failure -- including one whose cause was the resolver.
    """
    from . import resolvers
    try:
        return resolvers.parse(value or "")
    except ValueError:
        return []


def _parse_targets(path: Path) -> list[str]:
    out: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out
