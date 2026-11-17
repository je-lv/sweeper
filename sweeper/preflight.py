# sweeper/preflight.py
"""Validate everything locally before a single packet reaches a target.

A printed command line does not prove validity. Composite flags in several
of these tools silently imply other flags and conflict with them; the only
authority on whether an argument list is acceptable is the binary itself.
So every stage's real argument list is executed against a dead local port.
"""
from __future__ import annotations

import json
import re
import socket
import subprocess
from urllib.parse import urlsplit
from contextlib import contextmanager
from dataclasses import dataclass, field

from types import SimpleNamespace

from . import binaries, resolvers
from .artifacts import ArtifactKind
from .scope import multi_host_error
from .scope import normalize as normalize_target
from .stages.base import FailureClass, StageResult

DEAD_ENDPOINT = "127.0.0.1:1"
# Ceiling on `nuclei -validate` in validate_custom_templates. Generous
# because a large template tree genuinely takes a while to parse, and a
# timeout here refuses the run (fail-closed) rather than degrading it.
CUSTOM_TEMPLATE_VALIDATE_TIMEOUT = 120
# Directory a probe's own tool output is redirected into. It lives inside
# the run's raw/ directory (inheriting its 0o700 mode, discarded with the
# run) but is dot-prefixed and separate from every real evidence file,
# matching the ".preflight-targets.txt" convention already used beside it.
PROBE_OUTPUT_DIR = ".preflight-out"
# An argument error sits at a BOUNDARY of the output, never in the middle:
# Go and cobra print it first; Python argparse (arjun) prints a usage block
# first and the error last. ARG_ERROR_SCAN_LINES bounds how many non-JSON
# lines are considered at each end, keeping detection while preventing scan
# content (katana emits crawled page bodies) from tripping a marker.
ARG_ERROR_SCAN_LINES = 5
# Every phrase here was captured from a real binary on this machine, not
# guessed. The first narrowing of this list used clap wording against
# Go-based tools and silently missed two of Go's three flag-error classes,
# so a mistyped rate/timeout value would have passed preflight and reached
# the target. Bare "error:" and "usage:" stay out: cobra CLIs print a usage
# block on ANY non-zero exit, and ARG_ERROR aborts the whole run.
ARG_ERROR_MARKERS = (
    # Go flag / goflags — dnsx, naabu, httpx, nuclei, subfinder, katana, tlsx
    "flag provided but not defined",   # unknown flag name
    "flag needs an argument",          # flag given without its value
    "invalid value",                   # value present but unparseable
    # cobra
    "unknown flag",
    "unknown shorthand flag",
    # clap (Rust)
    "error: the argument",
    "cannot be used with",
    # GNU getopt — nmap, ffuf
    "unrecognized option",
    "invalid option",
    "requires an argument",
    # Python argparse — arjun
    "unrecognized arguments",
    "expected one argument",
    "invalid int value",
    "the following arguments are required",
)


PROXY_STAGES = {
    "httpx", "vhost", "content", "katana", "jsrecon", "arjun", "nuclei",
}


def proxy_endpoint(proxy: str) -> tuple[str, int]:
    """Return the network endpoint for a configured HTTP(S) proxy.

    Keep credentials out of diagnostics by returning only host and port.
    A proxy is an execution dependency for every web stage that receives it;
    treating a dead listener as an empty scan is a silent coverage failure.
    """
    try:
        parsed = urlsplit(proxy)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("proxy URL has an invalid port") from exc
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("proxy must be an http:// or https:// URL with a host")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return parsed.hostname, port


def proxy_reachable(proxy: str, timeout: float = 1.0) -> bool:
    """Whether the configured proxy currently accepts a TCP connection."""
    host, port = proxy_endpoint(proxy)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class EvidenceWriteInProbe(RuntimeError):
    """A stage's preflight probe argv points at a real run evidence path.

    Sibling of TargetLeakInProbe, and fail-closed for the same reason. A
    probe is a dry run against a dead endpoint; runner.py's contract is that
    raw tool output "is written before parsing and never rewritten: it is
    the evidence trail". Those two are incompatible the moment a probe can
    write where the real run writes -- the first thing in a run's raw
    evidence file becomes preflight's dead-endpoint dummy rather than the
    tool's real output.

    The general property being enforced is "a preflight probe must not write
    anywhere the real run will write". It is enforced WITHOUT enumerating
    output flags (-o, -oJ, -oX, ...), which would be a per-tool allowlist
    that silently omits the next tool: instead, every stage that writes its
    own result file already has to derive that path from ctx.raw_path() --
    the runner computes the very same call to decide what to hand parse(),
    so a stage that hardcodes a path elsewhere is already broken in a way
    Task 3.5's contract catches. probe_output_redirected() swaps that ONE
    factory, and this exception is the backstop for a stage that bypassed it
    anyway.
    """


@contextmanager
def probe_output_redirected(ctx):
    """Point ctx.raw_path() into a throwaway directory for the duration.

    Scope is deliberately just the build_command() call: it is the only
    place a stage decides where its tool will write, and swapping the
    factory there means neither preflight nor any individual stage has to
    know which flag carries that path. Restores the original attribute
    state on the way out, including the case where ctx never had a
    per-instance raw_path to begin with (the normal case -- it is a class
    method, so the swap is an instance attribute shadowing it).
    """
    scratch = ctx.run_dir / "raw" / PROBE_OUTPUT_DIR
    scratch.mkdir(parents=True, exist_ok=True)

    def probe_raw_path(stage: str, ext: str = "jsonl"):
        return scratch / f"{stage}.{ext}"

    had_own = "raw_path" in vars(ctx)
    original = vars(ctx).get("raw_path")
    ctx.raw_path = probe_raw_path
    try:
        yield scratch
    finally:
        if had_own:
            ctx.raw_path = original
        else:
            vars(ctx).pop("raw_path", None)


def _find_evidence_write(probe: list[str], evidence_path) -> str | None:
    """First probe argument naming the stage's real evidence file, if any.

    Substring rather than equality: a tool may take "path:KEYWORD" or
    similar composite forms, and any argument CONTAINING the real path is
    equally capable of writing to it.
    """
    needle = str(evidence_path)
    for arg in probe:
        if needle in arg:
            return arg
    return None


class TargetLeakInProbe(RuntimeError):
    """A stage's preflight probe argv still contains a real target value.

    preflight exists to guarantee that no packet reaches a real target until
    every stage's argument list has been validated — see the module
    docstring. validate_arguments enforces that by substituting a dead
    endpoint into each argument SHAPE it recognises (a URL, a *.txt input
    file). That substitution is an allowlist: any argument shape it does
    not recognise — a bare hostname passed as positional argv, say — passes
    through untouched, and the probe that exists to protect the target
    scans the target instead of 127.0.0.1:1. That happened for real: a new
    nmap stage passed targets as bare argv and preflight scanned production
    with it. The stage was fixed; this exception is the design fix — a
    fail-closed backstop that checks the built probe for real target VALUES
    by content, after substitution, instead of trusting the shapes that
    were substituted.

    Deliberately a RuntimeError, not a ValueError: this is a programming
    error in a stage's build_command (or in preflight's own substitution),
    not a mistake an operator can fix by retyping something, and it must not
    be swallowed by the bare `except ValueError` in app.main() that turns a
    bad --stages name into a friendly exit — see StageContractViolation in
    app.py, which exists for exactly the same reason.

    It IS caught, in exactly one place: run_preflight's per-stage loop, which
    turns it into a report.errors entry and sets report.ok False. That is the
    same treatment validate_custom_templates' fail-closed branches get, and
    for the same reason its docstring gives — run_preflight is called from
    execute() and an escaping exception left a run directory with no run.json
    and no report, and killed the menu REPL (whose _runner catches only
    SystemExit/ValueError), discarding every setting and credential the
    operator had entered. Recorded instead, it becomes an ordinary preflight
    refusal: both artefacts written, SystemExit(2), REPL survives.

    That is NOT a downgrade to "degraded". report.ok False means execute()
    refuses the run outright — no stage is executed, no packet is sent, and
    the reason is led with in run.json and in the report. Nothing about the
    fail-closed guarantee changes; only the crash does.

    The message deliberately does NOT contain the offending argument's value.
    _find_leak returns an INDEX, not the argument, so it cannot: a stage's
    argv can carry live credentials (arjun's --headers block is one literal
    string holding the session Cookie — see stages/arjun.py), and this
    message is printed to the console, written to sweep.log and recorded in
    run.json's aborted_reason. Rendering the argument verbatim put a live
    session cookie in all three.
    """


# A normalized target shorter than this cannot be told apart from an
# incidental substring of an unrelated argument (a flag letter, a path
# segment, a version number) with any real confidence — "a.io" is a
# syntactically valid hostname and also a substring of "banana.io". The
# label-boundary regex in _target_pattern already rules that particular
# case out, but a single character or empty string has no boundary to
# anchor on at all. The shortest real-world apex domains run about four
# characters (e.g. "x.co"), so anything shorter is either degenerate input
# (an empty target line, a bare "/") or too short to check without risking
# the guard firing on ordinary flag characters and path segments — and a
# check that fires on everything is a check the next stage author disables.
MIN_TARGET_LEN = 4


def probe_argv(cmd: list[str], probe_input) -> list[str]:
    """A stage's argv rewritten so it contacts only DEAD_ENDPOINT.

    PUBLIC, and deliberately the ONE definition of this substitution. It used
    to live inline in validate_arguments with a second hand-written copy in
    the vhost tests; the copy silently went stale the moment a new argument
    shape was added here, so the test kept asserting against a substitution
    the real preflight no longer performed. Same rule as registry.dependencies
    and is_degraded: one definition, both callers.

    Three shapes are neutralised:

      * a URL -> the dead endpoint;
      * a *.txt path (every stage routes targets through -l/-list/-iL) ->
        a throwaway file holding only the dead endpoint;
      * an HTTP `Host:` header -> the dead endpoint's address.

    The Host header is a ROUTING HINT, not a destination: the connection goes
    wherever the URL says, and that URL is already rewritten above, so the
    probe still contacts only 127.0.0.1:1 and no name in the header is ever
    resolved. It is neutralised anyway because the fail-closed content check
    in validate_arguments matches by VALUE, and the vhost stage's entire
    purpose is fuzzing "Host: FUZZ.<target-domain>" -- unlike a bare
    positional target there is no file to route that through, so without this
    branch every run including that stage would be refused. Only the header
    VALUE is rewritten, so a real target smuggled into any other argument
    still trips the guard.
    """
    probe = []
    for arg in cmd:
        if arg.startswith(("http://", "https://")):
            probe.append("http://" + DEAD_ENDPOINT)
        elif arg.endswith(".txt"):
            probe.append(str(probe_input))
        elif _is_host_header(arg):
            probe.append("Host: " + DEAD_ENDPOINT.split(":")[0])
        else:
            probe.append(arg)
    return probe


def _is_host_header(arg: str) -> bool:
    """Is this argv element an HTTP `Host:` header value?

    Deliberately narrow: only the Host header, only at the start of the
    argument, and only the "Header: value" form tools take after -H. Every
    OTHER header (including any carrying credentials) is left alone, so the
    target-leak guard keeps its full strictness everywhere it matters. See
    the substitution branch in validate_arguments for why this one is safe.
    """
    return arg.lower().startswith("host:")


def _real_targets(ctx) -> list[str]:
    """Real target hostnames a probe argv must never contain.

    Two sources, unioned, because neither is authoritative alone:

    - ctx.load_targets() re-reads the targets file directly, independent of
      run lifecycle. It is populated even when a caller builds a RunContext
      without going through app.prepare() — every test in this module does
      exactly that (RunContext.create() leaves ctx.store empty) — so
      relying on the store alone would make the guard silently a no-op for
      that whole shape of caller.
    - ctx.store's HOST artifacts are the live pool stage build_command()
      methods actually read from (dnsx, naabu, cdncheck all call
      ctx.store.values(ArtifactKind.HOST), not ctx.load_targets()). That
      pool is not guaranteed to equal the targets file: it is scope-
      filtered, and in a real run it can grow with hosts a stage discovers
      that were never in the targets file at all (subfinder output, for
      instance). preflight builds every stage's command from this same
      ctx, so checking only the static file would miss anything sourced
      from the store instead.

    Each candidate is normalized to a bare hostname with the same
    scope.normalize() used for allowlist comparison, so "https://x/",
    "x:443" and "x" all collapse to one comparable form, then deduped and
    filtered by MIN_TARGET_LEN.
    """
    raw = list(ctx.load_targets()) + list(ctx.store.values(ArtifactKind.HOST))
    targets: dict[str, None] = {}
    for value in raw:
        host = normalize_target(value)
        if len(host) < MIN_TARGET_LEN:
            continue
        targets.setdefault(host, None)
    return list(targets)


def _target_pattern(target: str) -> re.Pattern:
    """A target matches itself, a subdomain of itself, or itself embedded
    behind a non-hostname delimiter (scheme, port colon, path slash, comma)
    — never a fragment of a longer, unrelated label.

    Same label-boundary idea as dnsx.TAKEOVER_SUFFIXES's
    `cn.endswith("." + s)`, generalised to both sides and to mid-string
    matches. Left side allows a preceding '.' (so "www.acc.example" and
    "sub.acc.example" match, the subdomain case) but not a preceding
    alnum/dash (so "notacc.example" does not). Right side allows anything
    that is not a hostname-continuation character (so "acc.example:443",
    "acc.example/x" and a trailing "," all match) but excludes '.' too (so
    "acc.example.evil.com" — the real target used as an attacker-chosen
    subdomain label, not the real target itself — does not).
    """
    return re.compile(
        r"(?<![A-Za-z0-9-])" + re.escape(target) + r"(?![A-Za-z0-9.-])",
        re.IGNORECASE,
    )


def _elide(arg: str, safe_values) -> str:
    """`arg` with every safe value blanked out, leaving the rest to be checked.

    Elision, not whole-argument comparison. Exact comparison ("is this
    argument byte-for-byte a safe value?") only clears an argument that IS
    the safe value and nothing else, which is false for every real
    output-path argument: a stage writes "-o" and the path as two argv
    elements, but the path itself sits inside a run directory the OPERATOR
    named, and `--outdir recon/acc.example` is a standard layout. That made
    every writes_own_raw stage's own scratch output path — a local file
    preflight itself redirected them to — read as a leaked target.

    Blanked with a SPACE rather than removed. A space is not a hostname
    character, so eliding can only ever break a hostname apart, never splice
    two surviving fragments into one that matches; the operation is
    fail-closed in the only direction that matters. Longest value first so an
    overlapping pair cannot leave half of one behind, and empty values are
    dropped — str.replace("", " ") interleaves spaces through the whole
    string, which WOULD destroy a real match.
    """
    for value in sorted({v for v in safe_values if v}, key=len, reverse=True):
        arg = arg.replace(value, " ")
    return arg


def _find_leak(probe: list[str], safe_values: set[str], targets: list[str]):
    """First (argument INDEX, target) pair where a real target survived
    substitution, or None if the probe is clean.

    Returns the index, never the argument. That is a safety property of the
    signature, not a convention the caller has to remember: the argument that
    trips this guard can be a live credential — arjun passes ctx.auth as one
    literal --headers string, and a Burp-imported cookie whose value carries
    a "returnUrl=https://<target>/..." matches by content like anything else
    — and the caller's exception message is printed, logged, and persisted.
    A function that cannot hand back the value cannot leak it. See
    TargetLeakInProbe.

    safe_values are matched by CONTENT, not by position or by which branch of
    the substitution loop produced them: a value preflight constructed itself
    is safe wherever it appears and whoever put it there. That also covers
    the edge case where a real in-scope target happens to normalize to
    "127.0.0.1" itself — the DEAD_ENDPOINT substitute must never trip this
    guard (see validate_arguments), and checking substituted values against
    the target list at all is precisely what would trip it in that case.
    """
    patterns = [(t, _target_pattern(t)) for t in targets]
    for index, arg in enumerate(probe):
        candidate = _elide(arg, safe_values)
        for target, pattern in patterns:
            if pattern.search(candidate):
                return index, target
    return None


@dataclass
class PreflightReport:
    target_count: int = 0
    permitted_count: int = 0
    binary_statuses: dict = field(default_factory=dict)
    disabled_stages: list[str] = field(default_factory=list)
    # One pre-populated StageResult per disabled stage (status=skipped,
    # failure=MISSING_BINARY, reason=BinaryStatus.reason). run_stages never
    # re-decides which stages are runnable — it only sees `runnable` below —
    # so there is exactly one place that turns a failed identity check into
    # a decision not to execute a binary.
    disabled_results: list = field(default_factory=list)
    # Stages preflight cleared to run. run_stages consumes this list
    # directly; it must never call binaries.resolve()/verify() itself.
    runnable: list = field(default_factory=list)
    arg_errors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    ok: bool = True


def first_meaningful_line(stdout: str, stderr: str, default: str) -> str:
    """First non-blank line across BOTH streams.

    Must search stdout, not just stderr: these tools write argument errors to
    stdout (goflags redirects; Go's flag package would normally use stderr).
    Reading stderr alone yields nothing, so every diagnostic degrades to its
    placeholder — and ARG_ERROR is the one class that kills the whole run, so
    that is precisely when the operator most needs the real message.
    """
    for line in f"{stdout}\n{stderr}".splitlines():
        if line.strip():
            return line.strip()
    return default


def _candidate_lines(stdout: str, stderr: str) -> list[str]:
    """Lines that could plausibly carry an argument error.

    Two shapes have to be covered at once. Go and cobra emit the error first;
    Python argparse emits a usage block first and the error LAST, measured at
    line 7 for arjun — outside a head-only window. But simply widening the
    window lets scan content trip a marker, which is why the bound exists:
    katana emits crawled page bodies inside its JSON.

    Both are handled by one rule rather than a per-tool exception. An argument
    error is never valid JSON and always sits at a boundary; scan output from
    these tools always IS valid JSON. So drop the JSON and look at both ends.
    """
    lines = [l for l in f"{stdout}\n{stderr}".splitlines() if l.strip()]
    plain = []
    for line in lines:
        try:
            json.loads(line)
        except (ValueError, TypeError):
            plain.append(line)
    return plain[:ARG_ERROR_SCAN_LINES] + plain[-ARG_ERROR_SCAN_LINES:]


def _looks_like_arg_error(stdout: str, stderr: str) -> bool:
    """Match argument-error markers against the head and tail of the output.

    These tools write argument errors to STDOUT, not stderr — verified on
    dnsx/naabu/httpx 2026-07-29: with stderr discarded the message is still
    there; with stdout discarded it is gone. Go's flag package normally uses
    stderr, but goflags redirects. So stderr-only matching would miss every
    argument error on those tools — do not "fix" it that way. See
    _candidate_lines for why both ends of the output, not just the start,
    have to be scanned.
    """
    head_and_tail = "\n".join(_candidate_lines(stdout, stderr)).lower()
    return any(marker in head_and_tail for marker in ARG_ERROR_MARKERS)


def validate_arguments(stage, ctx, timeout: float = 3.0) -> str:
    """Return '' if the binary accepts the argument list, else the error text.

    The default timeout is short on purpose. Every argument-error class we
    match on — Go flag, cobra, clap, GNU getopt, argparse — is a synchronous
    parse-time failure that surfaces before any network I/O, in milliseconds.
    Anything still running after that has already ACCEPTED its arguments and
    is out probing the dead endpoint, which we treat as success anyway. So a
    long timeout buys nothing and is paid on every stage of every real run,
    not just in tests: six stages at 25s each is over two minutes of preflight
    before a scan starts.

    Caveat for future stage authors: this assumes the binary does not block on
    I/O *before* rejecting bad flags — none of dnsx/naabu/httpx do. A tool that
    resolved a hostname argument during parsing would need a longer value.

    Target substitution matters here. build_command() writes the run's REAL
    targets into its input file, so preflight must not let the tool read it —
    that would scan the targets during a check that is supposed to touch
    nothing. But replacing the file PATH with a bare endpoint makes the tool
    fail to open its input, which is a different failure than the one we are
    probing for. Instead, point the tool at a throwaway file containing only
    the dead endpoint: flags still parse, input still reads, and the only
    host contacted is 127.0.0.1:1.

    OUTPUT redirection is the mirror of that same rule. A stage whose tool
    writes its own result file (writes_own_raw: ffuf's -o, arjun's -oJ)
    builds that path from ctx.raw_path(), which is the real run's evidence
    path — so probing with the unmodified ctx made preflight's dead-endpoint
    dummy the FIRST thing written to a run's raw evidence file, contradicting
    runner.py's "written before parsing and never rewritten: it is the
    evidence trail". probe_output_redirected() swaps that one path factory
    for the duration of build_command(), which covers every present and
    future writes_own_raw stage without preflight knowing any tool's output
    flag by name.
    """
    with probe_output_redirected(ctx):
        cmd = stage.build_command(ctx)
    if not cmd:
        # A stage that builds no command has no arguments to validate, so
        # there is nothing here that could be wrong -- and subprocess.run([])
        # raises IndexError rather than reporting anything useful. The
        # runner reaches the same conclusion independently and records the
        # stage as NO_INPUT (see runner.run_stages); this only keeps
        # preflight from turning "nothing to do" into a crash.
        #
        # vhost is the first stage that can do this: with an empty targets
        # file there is no domain to build a Host header from, so it
        # correctly declines to send 5000 unroutable requests.
        return ""
    probe_input = ctx.run_dir / "raw" / ".preflight-targets.txt"
    probe_input.parent.mkdir(parents=True, exist_ok=True)
    probe_input.write_text(DEAD_ENDPOINT + "\n", encoding="utf-8")

    probe = probe_argv(cmd, probe_input)

    # Fail-closed backstop: the substitution above is an allowlist of
    # argument SHAPES (URL, *.txt path) and anything shaped differently —
    # a bare hostname positional argument, say — passed through untouched
    # a few lines up. Before this probe goes anywhere, check what actually
    # survived by CONTENT against the run's real targets, not by trusting
    # the shapes that were substituted. See TargetLeakInProbe. This must
    # run before subprocess.run below — nothing above this point performs
    # any I/O beyond writing the local probe-input file.
    #
    # The safe values are the two things preflight itself put in this argv
    # and the run's own directory tree:
    #
    #   - the dead-endpoint URL substituted above; and
    #   - str(ctx.run_dir). Every path in a probe argv that is not a target
    #     is derived from ctx.run_dir -- the probe-input file written just
    #     above, the scratch output path probe_output_redirected() pointed
    #     ctx.raw_path() at, nuclei's -secret-file, katana's header file.
    #     run_dir is outdir/<timestamp>, and outdir is whatever the operator
    #     typed: "--outdir recon/acc.example" is a standard layout, and it
    #     made all four of those read as leaked targets. A path under the
    #     run directory is a local file this process created; no tool can
    #     contact a host by being told to write there. Whitelisting the tree
    #     rather than enumerating the four flags is what keeps the fifth
    #     sidecar a future stage adds from re-opening this.
    #
    # Not whitelisted: anything derived from ctx.auth. A credential VALUE
    # that contains the target -- a Burp-imported "returnUrl" cookie is the
    # ordinary case -- still trips this guard, and that is deliberate. The
    # only way to clear it would be to elide operator-supplied secret values
    # from the argv before matching, and a cookie whose value is exactly the
    # target hostname would then erase a genuine bare-positional leak from
    # every argument. Refusing the run (recorded, with the value withheld
    # from the message) is the fail-closed side of that trade; the operator's
    # remedy is to drop arjun from the stage list or the cookie from the
    # bundle. See TargetLeakInProbe.
    leak = _find_leak(
        probe,
        safe_values={"http://" + DEAD_ENDPOINT, str(ctx.run_dir)},
        targets=_real_targets(ctx),
    )
    if leak is not None:
        index, target = leak
        raise TargetLeakInProbe(
            f"{stage.name}: preflight probe argument #{index} still contains "
            f"real target {target!r} after substitution. The argument's value "
            "is withheld from this message on purpose -- a stage's argv can "
            "carry live credentials (arjun's --headers block does) and this "
            "message is printed, logged and recorded in run.json. This stage "
            "passes a target through a shape validate_arguments does not "
            "neutralise (it is neither a URL nor a *.txt input file path). "
            "Route targets through a -l/-list/-iL <file>.txt input, the way "
            "dnsx/naabu/httpx/cdncheck/nmap do, instead of bare positional "
            "argv."
        )

    # Second fail-closed backstop, same shape as the one above but for
    # WRITES rather than reads. probe_output_redirected() already pointed
    # ctx.raw_path() at a scratch directory, so a stage that follows the
    # writes_own_raw contract cannot reach its real evidence path. This
    # catches the stage that hardcoded the path instead of deriving it --
    # the only way the redirect can be bypassed. See EvidenceWriteInProbe.
    evidence_path = ctx.raw_path(stage.name, getattr(stage, "raw_suffix", "jsonl"))
    offender = _find_evidence_write(probe, evidence_path)
    if offender is not None:
        raise EvidenceWriteInProbe(
            f"{stage.name}: preflight probe argument {offender!r} names the "
            f"real run evidence path {str(evidence_path)!r}. A probe is a dry "
            "run against a dead endpoint and must never write where the real "
            "run writes, or the first content in that file is preflight's "
            "dummy output rather than the tool's. Derive the output path from "
            "ctx.raw_path(self.name, self.raw_suffix) inside build_command() "
            "instead of hardcoding it, so preflight can redirect it."
        )

    try:
        # stdin=DEVNULL for the reason runner.py's Popen states: a tool that
        # reads stdin when stdin is a pipe will block on an inherited one.
        # It is worse here than there, because the TimeoutExpired below is
        # read as "arguments were accepted" -- so an inherited-stdin hang
        # makes every probe time out and every stage pass validation, and
        # preflight silently validates nothing at all.
        proc = subprocess.run(probe, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired:
        # It got far enough to start working; arguments were accepted.
        return ""
    except OSError as exc:
        return f"could not execute: {exc}"

    if proc.returncode != 0 and _looks_like_arg_error(proc.stdout, proc.stderr):
        return first_meaningful_line(proc.stdout, proc.stderr, "argument rejected")
    return ""


def validate_custom_templates(ctx) -> list[str]:
    """Custom templates must exist and parse, or the run dies mid-sweep.

    Two checks, both fail-closed and both cheap relative to the run they
    protect: the directory must exist (a typo'd --custom-templates path
    would otherwise reach nuclei's argv and fail only once the scan is
    already underway), and nuclei itself must accept it via `-validate` (a
    directory that exists but holds malformed or non-template YAML is
    caught the same way, before a single request goes out).
    """
    from pathlib import Path

    from . import binaries

    path = getattr(ctx.config, "custom_templates", "")
    if not path:
        return []
    template_dir = Path(path)
    if not template_dir.exists():
        return [f"custom template directory not found: {template_dir}"]

    binary = binaries.resolve("nuclei")
    if binary is None:
        return []
    try:
        proc = subprocess.run(
            [str(binary), "-validate", "-t", str(template_dir)],
            capture_output=True, text=True,
            # Same reason as the probe above: nuclei is one of the tools that
            # reads stdin when stdin is a pipe.
            stdin=subprocess.DEVNULL,
            timeout=CUSTOM_TEMPLATE_VALIDATE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        # RETURNED as an error, never raised. run_preflight() is called from
        # execute() BEFORE the try: that wraps run_stages, so an exception
        # escaping here propagates out of execute() uncaught and leaves a run
        # directory with no run.json and no report -- the one outcome every
        # other preflight failure path is careful to avoid. Worse on the
        # interactive path: _runner catches only SystemExit/ValueError, and
        # run_menu's guard wraps apply_choice rather than runner_fn, so the
        # REPL would die with a raw traceback and discard every setting the
        # operator had entered. Returned, it becomes an ordinary
        # report.errors entry: both artifacts written, SystemExit(2), REPL
        # survives.
        #
        # Fails CLOSED. A timeout means the templates could not be checked,
        # not that they are fine -- and `nuclei -validate` has been observed
        # hanging on a trivially small directory through local port
        # contention, so the elapsed time carries no information about
        # template validity in either direction.
        return [
            f"custom template validation timed out after "
            f"{CUSTOM_TEMPLATE_VALIDATE_TIMEOUT}s: {template_dir}. The "
            "templates could not be checked, so the run is refused rather "
            "than started with templates that may fail mid-sweep. Re-run "
            "without custom templates to scan with the standard set."
        ]
    except OSError as exc:
        # Same rule as validate_arguments' OSError branch: an unexecutable
        # binary is a diagnosable local problem, not a crash.
        return [f"could not run nuclei -validate: {exc}"]
    if proc.returncode != 0:
        first = next((l for l in proc.stderr.splitlines() if l.strip()),
                     "template validation failed")
        return [f"custom templates failed validation: {first.strip()}"]
    return []


#: How many targets to test before concluding the resolver is dead. A dead
#: resolver fails on the first few as surely as on four hundred, and each
#: failure costs a full timeout -- on the box where this was found, ~15s per
#: name. Checking all of a large scope would turn preflight into the slowest
#: part of the run for no extra certainty.
RESOLUTION_SAMPLE = 8
RESOLUTION_TIMEOUT = 5.0


def _query_a(host: str, server: str, port: int, timeout: float) -> bool:
    """One A query, straight to `server`, no system resolver involved.

    Hand-rolled rather than pulled from a DNS library because this must ask
    the SAME nameserver the scan will. On a split-horizon engagement the
    system resolver returns NXDOMAIN for the entire scope -- precisely the
    case --resolver exists for -- so a check that consulted it would refuse
    every split-horizon run.

    True only for NOERROR with at least one answer record. SERVFAIL, NXDOMAIN,
    a refusal and a timeout are all "this name did not resolve here".
    """
    import random
    import socket
    import struct

    qname = b"".join(
        bytes([len(label)]) + label
        for label in host.encode("idna").split(b".") if label
    ) + b"\x00"
    txid = random.getrandbits(16)
    query = (struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
             + qname + struct.pack(">HH", 1, 1))
    try:
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (server, port))
            data, _ = sock.recvfrom(4096)
    except (OSError, UnicodeError):
        return False
    if len(data) < 12:
        return False
    reply_id, flags, _, ancount = struct.unpack(">HHHH", data[:8])
    if reply_id != txid:
        return False                      # not our answer
    return (flags & 0x000F) == 0 and ancount > 0


def _resolves(host: str, ctx) -> bool:
    """Does `host` resolve, using whatever this run will actually use?

    With --resolver, the operator's nameservers, asked directly. Without it,
    getaddrinfo -- which is what the tools fall back to, and which also
    consults /etc/hosts, so a scope mapped there (the lab does this) is not
    reported as unresolvable.
    """
    from . import resolvers

    entries = resolvers.parse(getattr(ctx.config, "resolver", "") or "")
    if entries:
        for entry in entries:
            server, _, port = entry.rpartition(":")
            server = server.strip("[]")
            try:
                port_num = int(port)
            except ValueError:
                port_num = 53
            if _query_a(host, server, port_num, RESOLUTION_TIMEOUT):
                return True
        return False

    import socket
    from concurrent.futures import ThreadPoolExecutor
    from concurrent.futures import TimeoutError as FutureTimeout

    def lookup():
        try:
            socket.getaddrinfo(host, None)
            return True
        except (socket.gaierror, UnicodeError, OSError):
            return False

    # getaddrinfo takes no timeout and blocks for the full resolver retry
    # schedule -- ~15s per name against the dead NAT resolver this was found
    # on. Bounded here so preflight cannot outlast the scan.
    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            return pool.submit(lookup).result(timeout=RESOLUTION_TIMEOUT)
        except FutureTimeout:
            return False


#: Reserved for documentation and testing by RFC 2606 and RFC 6761. They do
#: not resolve in public DNS BY DEFINITION, so "nothing resolved" says nothing
#: about the operator's resolver -- and querying a public fallback for them
#: would be a guaranteed-useless third-party disclosure. The lab's scope is
#: entirely `.test`; a real engagement never is.
RESERVED_TLDS = (".example", ".test", ".invalid", ".localhost")


def _needs_dns(target: str) -> bool:
    """False for anything no resolver is meaningfully consulted for.

    Two cases: an address literal (nothing to resolve), and a reserved
    documentation/test name (guaranteed not to resolve, so its failure
    carries no information about the resolver).
    """
    import ipaddress
    host = normalize_target(target)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return False
    return not host.endswith(RESERVED_TLDS)


def run_preflight(ctx, stages) -> PreflightReport:
    report = PreflightReport()

    if ctx.config.auth_mode == "auth" and (
        getattr(ctx, "auth", None) is None or ctx.auth.is_empty()
    ):
        report.errors.append(
            "auth mode selected but no credentials configured — import a Burp "
            "request or enter headers via menu option 7"
        )
        report.ok = False

    template_errors = validate_custom_templates(ctx)
    if template_errors:
        report.errors.extend(template_errors)
        report.ok = False

    targets = ctx.load_targets()
    report.target_count = len(targets)
    if not targets:
        report.errors.append("no targets: the targets file is empty after "
                             "stripping comments and blank lines")
        report.ok = False

    proxy = (getattr(ctx.config, "proxy", "") or "").strip()
    if proxy and any(stage.name in PROXY_STAGES for stage in stages):
        try:
            reachable = proxy_reachable(proxy)
        except ValueError as exc:
            report.errors.append(f"invalid proxy configuration: {exc}")
            report.ok = False
        else:
            if not reachable:
                report.errors.append(
                    "configured proxy is unreachable; refusing to let web "
                    "stages report an empty scan as complete"
                )
                report.ok = False

    # A targets line the scanners expand -- CIDR in either family, an
    # nmap/naabu octet range, a glob -- is swept in full while the allowlist
    # holds only the single hostname normalize() could salvage from it. The
    # rest of the range is scanned, refused by admission control on the way
    # back in, and filed under discoveries_refused, the one bucket that by
    # design never marks a run degraded: unauthorised hosts scanned, their
    # findings dropped, and a deliverable reading "1 requested, 1 in scope.
    # No findings." with degraded:false.
    #
    # Refused here rather than expanded into the allowlist. Expansion is only
    # defined for ranges small enough to enumerate -- a /16 is 65k entries,
    # an IPv6 /64 cannot be enumerated at all -- so it moves the cliff rather
    # than removing it, and it would widen scope on the operator's behalf
    # from a line that proves authorisation for nothing. See
    # scope.multi_host_error for the full rationale and for why a "*."
    # wildcard is exempt (its ENTRY covers every host it admits; a CIDR's
    # does not).
    #
    # ScopeGuard refuses these lines too, so nothing reaches ctx.store even
    # if this check is bypassed. This is the half that gives the operator a
    # reason instead of a silent drop, and it fires on a MIXED file, where
    # the other targets are fine and the generic no-permitted-targets check
    # below would stay quiet.
    for target in targets:
        why = multi_host_error(target)
        if why:
            report.errors.append(
                f"targets line {target!r} denotes more than one host ({why}), "
                "but an allowlist entry is a single host — this line would be "
                "scanned in full while only one address of it was ever in "
                "scope. Refusing the run rather than widening scope for you. "
                "List each authorised host on its own line, or use a "
                '"*.<domain>" entry for a DNS scope.'
            )
            report.ok = False

    # A target can be well-formed and still be refused by the allowlist. If
    # EVERY target is refused, the run has nothing in scope to scan — that is
    # not "naabu found no ports" (NO_INPUT, benign); it is the allowlist
    # rejecting the whole engagement, and must fail preflight the same way an
    # empty targets file does.
    permitted, refused = ctx.scope.filter(targets)
    report.permitted_count = len(permitted)
    if targets and not permitted:
        report.errors.append(
            f"no permitted targets: all {len(targets)} target line(s) were "
            "refused by the scope allowlist"
        )
        report.ok = False

    # NOT ONE target resolves -- the resolver is broken, or is the wrong one
    # for this scope. Every DNS-based stage will then "complete" having found
    # nothing, naabu will die with `no valid ipv4 or ipv6 targets were found`,
    # and every stage after it skips for want of a single port. That is the
    # whole run decided before the first packet, and on the live run where
    # this was found it read as a scope problem rather than a dead resolver.
    #
    # "Not one", never "some": a scope may legitimately hold names that do
    # not resolve -- a decommissioned host, a dangling CNAME's label, an
    # internal name absent from the view being scanned. Those are findings.
    # Zero out of all of them is a configuration failure.
    needs_dns = [t for t in permitted if _needs_dns(t)]
    sample = [normalize_target(t) for t in needs_dns[:RESOLUTION_SAMPLE]]
    if sample and not any(_resolves(h, ctx) for h in sample):
        configured = (getattr(ctx.config, "resolver", "") or "").strip()
        if configured:
            # NEVER silently replaced. Naming a resolver is a deliberate
            # choice, and almost always means the scope is split-horizon or
            # internal -- re-asking a public resolver would return the
            # EXTERNAL view and scan a different set of hosts under the same
            # names, which is worse than not scanning at all.
            report.errors.append(
                f"no target resolved: {len(sample)} of {len(needs_dns)} "
                f"target(s) were queried against the resolver(s) you gave "
                f"({configured}) and none returned an address. Every "
                "DNS-based stage would report `complete` having found "
                "nothing, and the port scan would fail with no targets. "
                "Check the resolver is reachable and serves this zone. "
                "Not falling back to public DNS: you named this resolver, "
                "and on a split-horizon scope a public one answers for "
                "different hosts."
            )
            report.ok = False
        elif not getattr(ctx.config, "resolver_fallback", True):
            report.errors.append(
                f"no target resolved: {len(sample)} of {len(needs_dns)} "
                "target(s) were queried against the system resolver "
                "(/etc/resolv.conf) and none returned an address, and "
                "--no-resolver-fallback forbids trying a public resolver. "
                "Fix the system resolver, or pass --resolver <nameserver>."
            )
            report.ok = False
        else:
            adopted = ""
            for candidate in resolvers.FALLBACKS:
                probe = SimpleNamespace(config=SimpleNamespace(
                    resolver=candidate,
                    resolver_fallback=False,
                ))
                if any(_resolves(h, probe) for h in sample):
                    adopted = candidate
                    break
            if adopted:
                # Adopted for the whole run, and SAID SO in three places.
                # A report that cannot be read without knowing which
                # nameserver produced the scope it covers is the point: the
                # answers came from a third party who has now seen the
                # client's hostnames.
                ctx.config.resolver = adopted
                ctx.resolver_is_fallback = True
                note = (
                    f"the system resolver could not resolve any target, so "
                    f"this run used the public resolver {adopted} instead. "
                    "Those queries disclosed the scope's hostnames to a "
                    "third party. If this scope is split-horizon or internal, "
                    "the addresses are the EXTERNAL view and may not be the "
                    "hosts you meant to scan — re-run with "
                    "--resolver <client's DNS>, or --no-resolver-fallback to "
                    "refuse this."
                )
                ctx.warnings.append(note)
                ctx.log(f"preflight: RESOLVER FALLBACK — {note}")
            else:
                report.errors.append(
                    f"no target resolved: {len(sample)} of {len(needs_dns)} "
                    "target(s) failed against the system resolver "
                    "(/etc/resolv.conf) AND against every fallback "
                    f"({', '.join(resolvers.FALLBACKS)}). This box has no "
                    "working DNS, or the scope does not exist in public DNS. "
                    "If it resolves only in the client's own nameservers, "
                    "pass --resolver <their DNS>."
                )
                report.ok = False

    for stage in stages:
        missing = []
        for binname in stage.requires:
            st = binaries.verify(binname)
            report.binary_statuses[binname] = st
            if st.ok:
                ctx.tool_versions[binname] = st.version
            else:
                missing.append(f"{binname}: {st.reason}")
        if missing:
            reason = "; ".join(missing)
            report.disabled_stages.append(stage.name)
            report.disabled_results.append(StageResult(
                stage=stage.name, status="skipped",
                failure=FailureClass.MISSING_BINARY, reason=reason,
            ))
            ctx.log(f"preflight: disabling {stage.name} — {reason}")
        else:
            report.runnable.append(stage)

    for stage in report.runnable:
        try:
            err = validate_arguments(
                stage, ctx, timeout=getattr(ctx.config, "preflight_timeout", 3.0)
            )
        except TargetLeakInProbe as exc:
            # RECORDED as an error, not allowed to escape -- the same rule
            # validate_custom_templates' fail-closed branches follow, and for
            # the same reason its comment gives: run_preflight is called from
            # execute() and an exception escaping here left a run directory
            # with no run.json and no report, and killed the menu REPL along
            # with every setting and credential the operator had entered.
            #
            # Still fail-CLOSED, and not a downgrade to "degraded":
            # report.ok False makes execute() refuse the run outright, so no
            # stage runs and no packet is sent -- the guard's guarantee is
            # untouched. The only thing that changes is that the refusal
            # leaves the record every other preflight failure already leaves.
            #
            # `continue`, not `break`: each stage's probe is guarded
            # independently and the offending one never ran, so checking the
            # rest costs nothing and gives the operator every problem at once
            # rather than one per re-run.
            report.errors.append(str(exc))
            report.ok = False
            continue
        if err:
            report.arg_errors.append(f"{stage.name}: {err}")
            report.ok = False

    return report
