"""Stage execution with an explicit failure taxonomy.

One stage failing must not kill a run — but an argument error affects every
stage, so it aborts immediately rather than repeating the same error N
times. Raw tool output is written before parsing and never rewritten: it is
the evidence trail.

Binary identity is decided exactly once, in preflight.run_preflight(), which
verifies each binary's identity (not merely that a file exists at its path)
and hands back only the stages that passed. run_stages() trusts that list
completely and must never call binaries.resolve()/verify() itself — a second,
weaker check here (existence only) is how an impostor at a candidate path
gets executed after preflight already disabled it.
"""
from __future__ import annotations

import os
import re
import signal
import subprocess
import time
import traceback

from .artifacts import Artifact, ArtifactKind, Finding
from .preflight import _looks_like_arg_error, first_meaningful_line
from .scope import normalize
from .stages.base import FailureClass, StageResult


def _checkpoint(ctx, results) -> None:
    """Persist what has completed so far, never raising.

    A checkpoint is a safety net, and a safety net that can throw would
    convert a survivable run into a dead one -- and on the `finally` path
    below it would REPLACE the exception the operator actually needs to see
    with a manifest-writing error. Failing to checkpoint costs the record;
    raising here costs the run.
    """
    try:
        ctx.write_manifest(results, final=False)
    except Exception:
        pass


def _partial_exit_reason(rc: int) -> str:
    """Why a stage stopped, in terms an operator can act on.

    Popen reports death-by-signal as a NEGATIVE return code, and `exit -9`
    is accurate and useless: it reads as "the tool broke", so the operator
    goes and looks at the tool. Measured on a live run 2026-08-05, katana
    went partial after 124 seconds under a NINETY-MINUTE limit, and the
    kernel log had the real answer -- `oom-kill: task=katana`, 9.3 GB
    resident on a 15 GB box. Nothing was wrong with katana. The box was too
    small for that scope at that level, which is a different action
    entirely: narrow the scope, lower the level, or get more memory.

    It does NOT claim the OOM killer did it. A SIGKILL can equally come from
    an operator, a supervisor or a container runtime, and a confident wrong
    cause in a run record is the failure this project keeps closing. It
    names what is certain -- the system killed this, sweeper did not -- and
    the one command that settles the rest.
    """
    if rc >= 0:
        return f"exit {rc} with partial output"
    try:
        name = signal.Signals(-rc).name
    except ValueError:
        name = f"signal {-rc}"
    base = (f"killed by {name} with partial output — the system killed this "
            "stage, sweeper did not.")
    if -rc != signal.SIGKILL:
        # Only SIGKILL gets the memory hint. The OOM killer sends SIGKILL and
        # nothing else, so a SIGTERM is an operator, a supervisor or a
        # container runtime stopping the stage. Naming memory in those cases
        # would be a confident wrong cause in a run record, which is the
        # failure this taxonomy exists to prevent, just relocated into the
        # reason string.
        return base
    return (
        f"{base} The usual cause is the kernel running out of memory; "
        "confirm with: journalctl -k | grep -i 'killed process'"
    )


# --- Admission control: the choke point ------------------------------------
#
# Every OTHER control in this project (scope.filter() calls scattered across
# five stages, soon eleven) is a downstream filter: it depends on each stage
# author remembering to call it. This is the opposite shape -- nothing a
# stage's parse() yields reaches ctx.store unless it passes here, so
# ctx.store.values(...) is trustworthy BY CONSTRUCTION and no future stage
# has to remember anything. The five existing scope.filter() calls in
# dnsx/naabu/httpx/cdncheck/nmap stay in place as defence in depth; they are
# no longer the only thing standing between a discovered host and a live
# scan of it.
#
# _ARTIFACT_HOST_SOURCE is a closed table, one entry per ArtifactKind that
# admission control knows how to check. .get() returning None -- for a kind
# with no entry -- is deliberately treated as "refuse", not "admit". THIS is
# the load-bearing line in the whole change: a new ArtifactKind added later
# (tlsx, vhost, katana, jsrecon, arjun and nuclei are coming) and forgotten
# here fails CLOSED. The alternative -- falling through to admitted when a
# kind is unrecognised -- is exactly the silent-bypass failure mode this
# choke point exists to close off, just moved one layer down instead of
# eliminated. See test_unrecognised_artifact_kind_is_refused_not_admitted.
#
# Every extractor hands its raw string to scope.normalize() rather than
# parsing "host:port" or a URL's authority itself. normalize() already
# defends against a userinfo-section masquerade -- "acc.example:80@evil.test"
# addresses evil.test, not acc.example, see its docstring -- and hand-rolling
# that parsing again here per-kind is exactly how that defence would end up
# intact for one call site and quietly undone for another.


def _host_value(artifact: Artifact) -> str:
    return artifact.value


def _meta_host_or_value(artifact: Artifact) -> str:
    # PORT ("host:port") and HTTP_SERVICE (a URL): every producer in this
    # codebase sets meta["host"], but the fallback still goes through
    # normalize() rather than being trusted verbatim, for the same reason
    # meta["host"] itself is never trusted verbatim below.
    return artifact.meta.get("host") or artifact.value


def _meta_host_only(artifact: Artifact) -> str:
    # DNS_RECORD's value is "host TYPE value" (space-separated, not a URL or
    # host:port), so there is no safe way to recover a host from it if meta
    # is missing one -- an empty string here correctly fails closed below.
    return artifact.meta.get("host") or ""


_ARTIFACT_HOST_SOURCE = {
    ArtifactKind.HOST: _host_value,
    ArtifactKind.PORT: _meta_host_or_value,
    ArtifactKind.UDP_PORT: _meta_host_or_value,
    ArtifactKind.HTTP_SERVICE: _meta_host_or_value,
    ArtifactKind.DNS_RECORD: _meta_host_only,
}


def _admission_host(artifact: Artifact) -> str | None:
    """The normalized host to scope-check for one artifact, or None.

    None means "refuse" and is returned for two distinct reasons the caller
    treats identically: the ArtifactKind has no registered extractor (an
    unrecognised or future kind -- the fail-closed default), or the
    registered extractor's raw value normalizes to no host at all (empty or
    unparseable). Neither gets the benefit of the doubt.
    """
    source = _ARTIFACT_HOST_SOURCE.get(artifact.kind)
    if source is None:
        return None
    raw = source(artifact)
    if not raw:
        return None
    host = normalize(raw)
    return host or None


class AbortRun(RuntimeError):
    """Raised on an argument error: every stage would hit the same wall.

    Carries the results gathered so far. Without them the caller has nothing
    to record, and a caller that writes an empty manifest overwrites the one
    run_stages already wrote — destroying the only account of why the run
    died, at exactly the moment an operator needs it.
    """

    def __init__(self, message: str, results: "list[StageResult] | None" = None):
        super().__init__(message)
        self.results = results or []


def run_stages(ctx, stages, on_progress=None,
               results: "list[StageResult] | None" = None) -> list[StageResult]:
    """Execute `stages` exactly as given.

    `stages` must already be preflight's `report.runnable` — every binary
    identity decision was made there. This function does not, and must not,
    independently decide whether a stage's binary is trustworthy.

    `results` may be supplied by the caller and is mutated in place. This is
    what lets a caller recover the stages that completed when something
    OTHER than AbortRun escapes this function (a stage's own parse()
    raising, say): AbortRun carries its partial results explicitly, but a
    bare exception does not, and a local variable's contents are lost the
    moment the frame that held it is gone. A list the caller already holds a
    reference to is not.
    """
    if results is None:
        results = []

    # SIGINT handling: a Ctrl-C'd run must not present as clean and
    # complete. The FIRST interrupt sets a flag checked at the top of the
    # loop below, so the CURRENTLY RUNNING stage finishes (raw evidence for
    # it is never left half-written) and every stage after it is recorded
    # as INTERRUPTED rather than silently absent. A SECOND interrupt raises
    # KeyboardInterrupt immediately, for an operator who really does want
    # out right now.
    interrupted = {"flag": False}
    # The stage subprocess currently running, so the SIGINT handler can reach
    # it. Needed because each child now runs in its OWN process group (see
    # the Popen call below): terminal SIGINT goes to the foreground group
    # only, so Ctrl-C no longer reaches the tool the way it used to.
    #
    # That is what this function's docstring always claimed happened -- "the
    # CURRENTLY RUNNING stage finishes" -- and never did: the child shared
    # the group and was killed alongside sweeper, leaving half-written
    # evidence. Now it genuinely finishes.
    #
    # The cost is that the SECOND interrupt, the operator's "out right now"
    # escape hatch, would otherwise abandon a running tool and every child it
    # spawned -- creating exactly the orphan this change exists to prevent.
    # So it kills the group before raising.
    active_child: dict = {"proc": None}

    def _on_sigint(signum, frame):
        if interrupted["flag"]:
            _kill_process_group(active_child.get("proc"))
            raise KeyboardInterrupt("second interrupt — exiting immediately")
        interrupted["flag"] = True
        # See sweeper/context.py's write_manifest (ORs this into
        # "degraded") and its "aborted"/"aborted_reason" fields, and
        # sweeper/report/markdown.py's RUN ABORTED banner, which reads this
        # same field. Setting it here is what makes both correct for an
        # interrupted run -- do not drop this line.
        ctx.aborted_reason = "interrupted by operator (SIGINT)"
        ctx.log("SIGINT received — finishing current stage, then stopping")

    previous_handler = signal.signal(signal.SIGINT, _on_sigint)
    try:
        # Ids already in the store when this call begins -- a caller composing
        # more than one run_stages() call against one ctx, or a resumed run --
        # so a later stage's resubmission of an earlier stage's finding is never
        # miscounted as newly stored by the later stage. See the Finding branch
        # below for why this, and not a per-stage recount, is what result.findings
        # is measured against.
        known_finding_ids = {f.id for f in ctx.store.findings}
        for stage in stages:
            # Before this stage starts, so everything ALREADY done is on
            # disk. The stage about to run is deliberately not in it: at
            # most one stage of work is lost to a kill, instead of all of
            # it. Every `continue` path below is covered by this being at
            # the top rather than the bottom, and the last stage by the
            # `finally` at the end of the loop.
            _checkpoint(ctx, results)
            if interrupted["flag"]:
                results.append(StageResult(
                    stage=stage.name, status="skipped",
                    failure=FailureClass.INTERRUPTED, reason="run interrupted"))
                continue
            result = StageResult(stage=stage.name)
            results.append(result)

            consume_kinds = set(getattr(stage, "consumes_any", None) or ())
            if not consume_kinds and stage.consumes is not None:
                consume_kinds.add(stage.consumes)
            if consume_kinds and not any(ctx.store.get(k) for k in consume_kinds):
                result.status = "skipped"
                result.failure = FailureClass.NO_INPUT
                names = ", ".join(sorted(k.name for k in consume_kinds))
                result.reason = f"no {names} artifacts to consume"
                ctx.log(f"{stage.name}: SKIP — {result.reason}")
                _notify(on_progress, stage.name, "skipped")
                continue

            _notify(on_progress, stage.name, "running")
            result.status = "running"
            started = time.time()

            if getattr(stage, "in_process", False):
                # This stage's real work is Python code, not an external
                # binary -- see stages/base.py's Stage protocol and
                # stages/jsrecon.py's module docstring, the first stage to use
                # this path. There is no argv to redact or log, no subprocess
                # to time out, and no exit code to classify -- the stage
                # writes its own raw evidence file and hands back its Path.
                ctx.log(f"{stage.name}: RUN — in-process")
                result.command = ["<in-process>"]
                try:
                    raw_path = stage.run_in_process(ctx)
                except Exception as exc:                      # noqa: BLE001
                    # Same TRANSPORT classification a subprocess failure with no
                    # output gets below: this stage's own I/O failed before it
                    # could produce anything to parse, and one stage's failure
                    # here must not take the whole run down (see the docstring
                    # on the parse try/except further down for why the same
                    # containment logic applies).
                    result.status = "failed"
                    result.failure = FailureClass.TRANSPORT
                    result.reason = f"{type(exc).__name__}: {exc}"
                    ctx.log(f"{stage.name}: TRANSPORT — {result.reason}")
                    _notify(on_progress, stage.name, "failed")
                    ctx.store.flush()
                    continue
                result.duration_s = time.time() - started
            else:
                cmd = stage.build_command(ctx)
                if not cmd:
                    # A stage that cannot construct a command has nothing it
                    # can legitimately do this run -- vhost with no domain to
                    # append to its Host header is the first such case. This
                    # is NO_INPUT for the same reason an empty consume pool
                    # is: a correct outcome, not a failure, and it must be
                    # RECORDED rather than crashing subprocess.run([]) or,
                    # worse, running a command that cannot match anything and
                    # reporting the empty result as a clean scan.
                    result.status = "skipped"
                    result.failure = FailureClass.NO_INPUT
                    result.reason = "stage could not build a command for this input"
                    ctx.log(f"{stage.name}: SKIP — {result.reason}")
                    _notify(on_progress, stage.name, "skipped")
                    continue
                # cmd itself -- the real argv, live credentials included -- is
                # what actually executes below. Only the copy that gets LOGGED
                # or PERSISTED is redacted; subprocess.run must still see the
                # real values, or an authenticated stage would silently scan
                # unauthenticated.
                logged_cmd = _redact_command(cmd, ctx)
                result.command = logged_cmd
                ctx.log(f"{stage.name}: RUN — {' '.join(logged_cmd)}")

                # A stage whose tool writes its own result file (ffuf's -o,
                # arjun's -oJ) declares raw_suffix/writes_own_raw so the runner
                # computes the SAME path the tool was told to write to, instead
                # of always defaulting to "<name>.jsonl" -- a file the tool
                # never touches. See stages/base.py's Stage protocol.
                raw_suffix = getattr(stage, "raw_suffix", "jsonl")
                writes_own_raw = getattr(stage, "writes_own_raw", False)
                raw_path = ctx.raw_path(stage.name, raw_suffix)
                # Popen with start_new_session, not subprocess.run. A stage's
                # tool may spawn CHILDREN of its own -- nuclei launches a
                # headless browser for some templates -- and
                # subprocess.run(timeout=...) kills only the process it
                # started. The browsers survived: 66 orphaned chromium
                # processes accumulated across 11 sessions on one machine,
                # each still holding its profile directory.
                #
                # That is a scope problem, not just an untidy one. An
                # orphaned browser goes on loading pages and fetching
                # subresources after the run that spawned it is gone --
                # traffic to the client with no run to attribute it to, and
                # invisible to ctx.scope because sweeper is no longer the one
                # making it. Its own process group is what makes it killable
                # as a unit; see _kill_process_group.
                # ONE retry, and only for a tool that died having written
                # nothing at all. Measured against the lab on 2026-08-04:
                # naabu 2.6.1 hung and self-aborted at its own 180-second
                # deadline in 4 of 16 invocations, no output, no pattern --
                # and naabu produces the PORT artifacts every later stage
                # consumes, so its death empties the entire run.
                #
                # Deliberately narrow, because a retry is more traffic to a
                # client's estate:
                #   * partial output means the tool DID work -- re-running
                #     duplicates it, and the findings already parsed from the
                #     first attempt are real;
                #   * a --time-limit stop is the operator's own bound, often
                #     an engagement term, and retrying spends it twice;
                #   * an ARG_ERROR will be rejected identically (and aborts
                #     the run below regardless).
                for attempt in (1, 2):
                    result.attempts = attempt
                    proc = None
                    timed_out = False
                    try:
                        proc = subprocess.Popen(
                            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            # DEVNULL, never inherited. Every ProjectDiscovery
                            # tool reads its target list from stdin when stdin
                            # is a pipe rather than a terminal -- that is how
                            # `cat hosts.txt | httpx` works. Inheriting
                            # sweeper's stdin means that whenever sweeper is
                            # launched non-interactively with a pipe on stdin
                            # (cron, CI, a wrapper -- the --no-menu automation
                            # path), the tool blocks reading a pipe nothing
                            # ever writes to, until its own internal deadline
                            # kills it. That presented as a naabu "flake" in
                            # ~25% of runs: no output, no pattern, and an
                            # empty run behind it, because naabu feeds every
                            # later stage. It is also right interactively --
                            # a stage's tool must not eat the operator's
                            # keystrokes at the menu prompt.
                            stdin=subprocess.DEVNULL,
                            text=True, start_new_session=True,
                        )
                        active_child["proc"] = proc
                        stdout, stderr = proc.communicate(timeout=_timeout(ctx))
                        rc = proc.returncode
                    except subprocess.TimeoutExpired:
                        timed_out = True
                        _kill_process_group(proc)
                        # communicate() again to reap and collect whatever the
                        # tool managed to write before the limit. Without this the
                        # pipes stay open and the partial output -- which the
                        # evidence file is about to be written from -- is lost.
                        try:
                            stdout, stderr = proc.communicate(timeout=10)
                        except Exception:                             # noqa: BLE001
                            stdout, stderr = "", ""
                        stderr, rc = "timed out", 1
                    except OSError as exc:
                        _kill_process_group(proc)
                        stdout, stderr, rc = "", str(exc), 1
                    finally:
                        active_child["proc"] = None

                    retryable = (
                        rc != 0
                        and not stdout.strip()
                        and not timed_out
                        and not _looks_like_arg_error(stdout, stderr)
                    )
                    if attempt == 2 or not retryable:
                        break
                    ctx.log(
                        f"{stage.name}: died with no output "
                        f"({first_meaningful_line(stdout, stderr, f'exit {rc}')[:120]})"
                        " — retrying once"
                    )

                result.duration_s = time.time() - started
                raw_path.parent.mkdir(parents=True, exist_ok=True)
                if not writes_own_raw:
                    raw_path.write_text(stdout, encoding="utf-8")   # before parsing, always
                # else: the tool already wrote raw_path itself. Overwriting it with
                # captured stdout here is exactly the bug that left vhost and arjun
                # parsing an empty file on every run -- ffuf's -s suppresses stdout
                # entirely, and arjun's stdout is just \r-terminated progress text.
                elif rc == 0 and not raw_path.exists():
                    # The tool exited cleanly and wrote NO output file at all.
                    # For arjun that is its documented behaviour on a null
                    # result -- it prints "No parameters were discovered." and
                    # writes nothing, verified against 2.2.7 -- so this is not
                    # a failure and the status stays `complete`.
                    #
                    # It is recorded all the same, because without it the
                    # manifest cannot tell "the tool ran and found nothing"
                    # apart from "the tool died before writing", and those are
                    # the two readings this project exists to keep separate.
                    # parse() sees a missing file either way and yields
                    # nothing either way; only the runner still knows the exit
                    # code that distinguishes them, so only the runner can
                    # record it.
                    result.reason = ("tool exited 0 and wrote no output file "
                                     "(no results to report)")
                    ctx.log(f"{stage.name}: no output file — {result.reason}")

                # Same helper preflight uses, so the two cannot drift apart.
                if rc != 0 and _looks_like_arg_error(stdout, stderr):
                    result.status = "failed"
                    result.failure = FailureClass.ARG_ERROR
                    result.reason = first_meaningful_line(
                        stdout, stderr, "argument rejected"
                    )
                    ctx.log(f"{stage.name}: ARG_ERROR — {result.reason}")
                    # Do NOT write the manifest here. ctx.aborted_reason is set by
                    # the caller only AFTER this raises, so a manifest written at
                    # this point would record aborted:false for a run that is, in
                    # fact, aborting. execute() already writes the manifest on
                    # every path (success, AbortRun, preflight failure, any other
                    # exception) using the results AbortRun carries below — a
                    # second write site here is exactly the kind of duplicate
                    # decision that drifts from the one in execute().
                    raise AbortRun(
                        f"{stage.name} rejected its argument list: {result.reason}. "
                        "This affects every stage, so the run is aborting.",
                        results=results,
                    )

                if rc != 0:
                    if stdout.strip():
                        # Set status too. Leaving it unset falls through to
                        # "complete" below, and the manifest's degraded flag keys off
                        # status — so a stage that exited non-zero with half its
                        # output would be recorded as a clean completion. That is
                        # precisely the silent-partial-coverage failure this taxonomy
                        # exists to prevent.
                        result.status = "partial"
                        result.failure = FailureClass.PARTIAL
                        # A stage stopped by --time-limit and a stage that
                        # exited non-zero on its own are both "partial", and
                        # they used to carry the same reason text. They call
                        # for opposite responses: one means "raise the limit
                        # or accept less coverage", the other means "something
                        # is wrong with the tool or the target". A reader of
                        # the report cannot tell them apart from the status
                        # alone, so the reason has to.
                        result.reason = (
                            f"stopped at the {ctx.config.time_limit} time "
                            f"limit with partial output"
                            if timed_out
                            else _partial_exit_reason(rc)
                        )
                    else:
                        result.status = "failed"
                        result.failure = FailureClass.TRANSPORT
                        result.reason = (
                            f"stopped at the {ctx.config.time_limit} time "
                            "limit before producing any output"
                            if timed_out
                            else first_meaningful_line(
                                stdout, stderr, f"exit {rc}"
                            )[:200]
                        )
                        ctx.log(f"{stage.name}: TRANSPORT — {result.reason}")
                        _notify(on_progress, stage.name, "failed")
                        ctx.store.flush()
                        continue

            # Shared by both paths: parse whatever raw_path now holds. The
            # in-process `except` above and the subprocess ARG_ERROR/TRANSPORT
            # paths above either `raise` or `continue`, so control only reaches
            # here with a raw_path that is actually meant to be parsed.
            #
            # Contain EVERY parse exception. This function's contract is "one
            # stage failing must not kill a run", and that was enforced for
            # subprocess failures but not for parse failures — the same fail-open
            # gap one layer up. nmap cut short by the per-stage timeout yields a
            # truncated XML document, and taking the whole run down over it is
            # precisely what the PARTIAL class set a few lines above exists to
            # prevent.
            #
            # The catch is broad on purpose, including for what are plainly
            # PARSER BUGS rather than bad tool output. Weighing the two field
            # outcomes decides it: containing gives the operator 8 of 9 stages
            # plus a loud PARSE_ERROR on a degraded run, and the worst case is
            # that they normalise the failure; propagating loses every other
            # stage's results inside a scan window that may not come back. The
            # second is worse. "Fail loudly" is satisfied by a degraded run that
            # names the stage — it does not require aborting.
            #
            # What keeps a contained BUG debuggable rather than silently
            # absorbed: `reason` carries the exception type and message (not a
            # generic "parse failed"), and the full traceback goes to sweep.log.
            # A contained programming error that leaves no traceback is how a bug
            # survives for months.
            #
            # `except Exception` deliberately does NOT catch KeyboardInterrupt or
            # SystemExit, which are BaseException and must keep propagating: Ctrl-C
            # has to interrupt a wedged parser, and Plan 3's SIGINT handling
            # depends on that staying true.
            try:
                for item in stage.parse(raw_path):
                    if isinstance(item, Finding):
                        # result.findings must count what the store actually
                        # KEPT, not every Finding this stage yielded -- the
                        # store may keep fewer. A dedupe (same id, same
                        # content -- a legitimate rerun or resubmission) and a
                        # genuine collision (same id, DIFFERENT content -- a
                        # bug in this stage's matcher, already recorded in
                        # ctx.store.finding_collisions and sweep.log by
                        # add_finding itself) both leave the store's size
                        # unchanged, and neither was "stored" a second time.
                        # Counting every yield here (the previous behaviour)
                        # let run.json and the report claim a number the store
                        # could not back up -- an internal contradiction in a
                        # document that is evidence. See context.py's
                        # write_manifest for how the collision count is
                        # surfaced separately, so the two reconcile.
                        is_new = item.id not in known_finding_ids
                        ctx.store.add_finding(item)
                        if is_new:
                            known_finding_ids.add(item.id)
                            result.findings += 1
                    else:
                        host = _admission_host(item)
                        if host is not None and ctx.scope.permits_discovery(host):
                            if ctx.store.add(item):
                                result.artifacts += 1
                        else:
                            # Counted and visible, never silently dropped -- but
                            # in ctx.scope.discoveries_refused, NOT
                            # ctx.scope.refusals: this is a routine tool
                            # discovery landing outside scope, not an
                            # operator-supplied out-of-scope target. See the
                            # module-level comment above and ScopeGuard's
                            # docstrings for why the two are kept apart.
                            ctx.scope.record_discovery_refusal(
                                stage=stage.name, kind=item.kind.name,
                                value=item.value, host=host or "",
                            )
                            ctx.log(
                                f"{stage.name}: discovery refused (out of scope) "
                                f"— {item.kind.name} {item.value!r}"
                            )
            except Exception as exc:
                result.status = "failed"
                result.failure = FailureClass.PARSE_ERROR
                result.reason = (
                    f"parse failed after {result.artifacts} artifacts, "
                    f"{result.findings} findings: {type(exc).__name__}: {exc}"
                )[:200]
                # One-liner for the report, full stack for the log.
                ctx.log(f"{stage.name}: PARSE_ERROR — {result.reason}")
                ctx.log(
                    f"{stage.name}: PARSE_ERROR traceback —\n"
                    + "".join(traceback.format_exception(
                        type(exc), exc, exc.__traceback__
                    )).rstrip()
                )
                _notify(on_progress, stage.name, "failed")
                ctx.store.flush()
                continue

            # Some tools exit 0 with an empty stream when a runtime dependency
            # disappears. httpx does this when its configured proxy refuses
            # connections, which otherwise turns a Burp restart into a false
            # clean scan. Stages may diagnose that narrow case without making
            # every legitimately empty result a failure.
            empty_check = getattr(stage, "empty_result_error", None)
            if empty_check is None and ctx.config.proxy:
                from .preflight import PROXY_STAGES, proxy_reachable
                if stage.name in PROXY_STAGES:
                    def empty_check(current_ctx):
                        try:
                            reachable = proxy_reachable(
                                current_ctx.config.proxy
                            )
                        except ValueError as exc:
                            return f"invalid proxy configuration: {exc}"
                        if not reachable:
                            return (
                                "configured proxy became unreachable and "
                                "the stage produced no normalized results"
                            )
                        return ""
            if (result.artifacts == 0 and result.findings == 0
                    and result.status not in ("failed", "partial")
                    and empty_check is not None):
                reason = empty_check(ctx)
                if reason:
                    result.status = "failed"
                    result.failure = FailureClass.TRANSPORT
                    result.reason = reason[:200]
                    ctx.log(f"{stage.name}: TRANSPORT — {result.reason}")
                    _notify(on_progress, stage.name, "failed")
                    ctx.store.flush()
                    continue

            if result.status not in ("failed", "partial"):
                result.status = "complete"
            ctx.store.flush()
            # The reason, not just the status. It was already in run.json and
            # in the report's coverage table, and an operator WATCHING the run
            # saw only "partial — 2824 artifacts, 0 findings" and had nothing
            # to act on until the run finished. A stage that stopped early has
            # to say why where the person watching it will see it.
            because = f" ({result.reason})" if result.reason else ""
            ctx.log(f"{stage.name}: {result.status} — "
                    f"{result.artifacts} artifacts, "
                    f"{result.findings} findings{because}")
            _notify(on_progress, stage.name, result.status)
    finally:
        # The last stage's own result, and every abnormal exit: this runs on
        # KeyboardInterrupt, on AbortRun, and on a stage's parse() raising,
        # which the per-iteration checkpoint above cannot cover because there
        # is no next iteration to write it. Still marked in-progress -- only
        # execute() knows the run reached the end, and only it says finished.
        _checkpoint(ctx, results)
        # Anything escaping the loop -- KeyboardInterrupt, AbortRun, a stage's
        # parse() raising -- leaves the running tool and its children alive,
        # and now that each child has its OWN session they are not even
        # reachable by a group kill aimed at sweeper. That would make this
        # change a net loss on the abnormal-exit path while fixing the
        # timeout one. The per-stage `finally` clears this on the ordinary
        # path, so a non-None value here means the run is unwinding with a
        # tool still running.
        _kill_process_group(active_child.get("proc"))
        signal.signal(signal.SIGINT, previous_handler)
        ctx.store.flush()
    return results


def _kill_process_group(proc) -> None:
    """SIGKILL the process group `proc` leads. Never raises.

    Killing `proc` alone is what left the orphans: a tool that spawned its
    own children (nuclei -> headless chromium) hands them to init and they
    keep running, and keep making requests at the client, after the run is
    over.

    Requires the child to have been started with start_new_session=True, or
    getpgid returns SWEEPER'S OWN group and this kills the scan. That
    pairing is asserted by
    test_the_child_is_started_in_its_own_process_group.

    Silent on every failure by design: this runs on paths that are already
    handling a timeout or an OSError, and a cleanup that raises would
    replace a recorded stage failure with an unhandled exception. A process
    that is already dead is a success here, not an error.
    """
    if proc is None or proc.pid is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        # Already gone, or never had its own group. Fall back to the direct
        # child so a partial failure still kills what it can.
        try:
            proc.kill()
        except Exception:                                    # noqa: BLE001
            pass


def _timeout(ctx) -> int | None:
    """Parse a time limit like "45s", "45m", "2h". Never raise.

    A malformed value must not kill the run. The previous form did
    int(spec[:-1]) unguarded, so "abc", "m" or a bare "5" raised ValueError
    from inside a try that only catches TimeoutExpired and OSError — a typo
    in one config field aborted every stage. A bare "45" also silently
    misparsed to a wrong scale rather than being rejected.
    """
    spec = (getattr(ctx.config, "time_limit", "") or "").strip().lower()
    if not spec:
        return None
    match = re.fullmatch(r"(\d+)\s*([smh])", spec)
    if not match:
        ctx.log(f"time_limit {spec!r} is not of the form 45s / 45m / 2h "
                "— ignoring, no per-stage limit applied")
        return None
    value, unit = int(match.group(1)), match.group(2)
    return value * {"s": 1, "m": 60, "h": 3600}[unit]


def _redact_command(cmd: list[str], ctx) -> list[str]:
    """A copy of `cmd` with every live value from `ctx.auth` replaced.

    This is the ONE place a stage's command line is prepared for logging
    (ctx.log) or persistence (result.command, which context.py serialises
    into run.json) -- every present and future stage's build_command()
    output passes through here, so no stage author has to remember to
    redact their own argv. It keys off the actual secret VALUES (header
    values, cookie values, and the composed "k=v; k2=v2" Cookie string from
    SecretBundle.cookie_header()), not off flag names or argument shape:
    arjun (Task 7) carries a live value as one line inside a --headers
    block, which looks nothing like -H "Authorization: ...". Matching by
    value catches both the same way, with no per-stage code required.

    Does NOT touch `cmd` itself, only the returned copy -- subprocess.run
    still executes the real, unredacted argv.
    """
    auth = getattr(ctx, "auth", None)
    if auth is None or auth.is_empty():
        return list(cmd)
    secrets = {v for v in auth.headers.values() if v}
    secrets.update(v for v in auth.cookies.values() if v)
    if auth.cookies:
        secrets.add(auth.cookie_header())
    if not secrets:
        return list(cmd)
    redacted = []
    for arg in cmd:
        for value in secrets:
            if value in arg:
                arg = arg.replace(value, "[REDACTED]")
        redacted.append(arg)
    return redacted


def _notify(cb, name: str, state: str) -> None:
    if cb:
        cb(name, state)
