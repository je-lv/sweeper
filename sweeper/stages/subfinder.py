"""subfinder stage — subdomain enumeration. Opt-in, output gated.

Everything this stage finds was, by definition, absent from the targets
file. That makes it the one stage in this project whose own output is not
safe to trust the way every other stage's is: dnsx, cdncheck, naabu and
httpx all read ctx.store.values(ArtifactKind.HOST) and scope-filter it
before building a command, which is correct because every HOST artifact
already in the store passed the allowlist on the way in (see
app.prepare()). A host subfinder just discovered has not.

So parse() here does NOT get the free ride other stages' parse() output
gets. It yields Artifact(HOST, ..., meta={"confirmed": False}) so a caller
can inspect what was found (and so the fixture-driven tests below can pin
the parser against real subfinder output), but nothing calls
ctx.store.add() on those artifacts, and this module must never be wired
into the ordinary run_stages() loop the way DnsxStage/NaabuStage/HttpxStage
are: run_stages() adds every artifact a stage's parse() yields to ctx.store
unconditionally (see runner.py) with no notion of "confirmed" — routing
this stage through that loop the normal way would put unapproved hosts in
the shared pool and rely on every future consumer to scope-filter it back
out. That is a downstream filter standing in for a gate, and this project
does not accept that pattern here: a host is authorized or it is not
scanned, full stop.

The only door into ctx.store for a subfinder discovery is
confirm_discovered(): it takes the operator's explicit approval list,
widens scope through ScopeGuard.extend() (recorded in run.json with a
reason), and only then adds the approved hosts as HOST artifacts. Anything
not named in `approved` never touches ctx.store, no matter how it was
discovered.

`pending_hosts` holds the last parse()'s discovered hostnames, unfiltered,
so an operator-facing caller (the menu, Task 8's wiring) has something to
show and ask "approve which of these?" without needing to re-read the raw
file itself.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..artifacts import Artifact, ArtifactKind


class SubfinderStage:
    name = "subfinder"
    #: This tool takes an operator-supplied resolver; see
    #: sweeper.resolvers and run.json's "resolver" block.
    honors_resolver = True
    requires = ["subfinder"]
    consumes = None
    produces = {ArtifactKind.HOST}
    optional = True
    # subfinder's own sources are all passive (crt.sh, github, etc.); -all
    # widens which passive sources are queried, it does not add active
    # brute-force. Verified against subfinder v2.14.0 -h: no -b/-brute flag
    # exists in this build at all, so there is nothing intrusive to
    # accidentally request. -silent is required at every level: without it
    # subfinder prints its own banner and source-by-source progress lines
    # ahead of the hostnames, which parse() would otherwise have to filter
    # out of a JSONL-shaped stream that no longer is one.
    levels = {
        "low":  ["-silent"],
        "mid":  ["-silent"],
        "high": ["-silent", "-all"],
        "full": ["-silent", "-all"],
    }

    def __init__(self) -> None:
        # Discovered-but-not-yet-approved hostnames from the most recent
        # parse(). Never written to ctx.store by anything in this class;
        # see the module docstring for why.
        self.pending_hosts: list[str] = []

    def build_command(self, ctx) -> list[str]:
        from .. import binaries
        from ..rate import replace_value_flag
        infile = ctx.run_dir / "raw" / "subfinder-input.txt"
        infile.parent.mkdir(parents=True, exist_ok=True)
        roots = ctx.load_targets()
        infile.write_text("\n".join(roots) + "\n", encoding="utf-8")
        from .. import resolvers
        flags = replace_value_flag(
            self.levels[ctx.config.level], ("-rl", "-rate-limit"),
            "-rl", ctx.config.rate_override,
        )
        return [str(binaries.resolve("subfinder")), "-dL", str(infile),
                "-duc", *flags,
                *resolvers.flag_args(ctx)]

    def parse(self, raw_path: Path) -> Iterator[Artifact]:
        """Yield each discovered host as an unconfirmed Artifact.

        This is a pure generator like every other stage's parse() — it
        performs no I/O on ctx and no store writes. Calling it (the same
        call the runner makes for every stage) must never, by itself, make
        a discovered host reachable by a scanning stage. See the module
        docstring and confirm_discovered() below, the only path that does.
        """
        hosts: list[str] = []
        for line in Path(raw_path).read_text(encoding="utf-8").splitlines():
            host = line.strip()
            if not host or host.startswith("#"):
                continue
            hosts.append(host)
        # Recorded before yielding so a caller that only consumes part of
        # the generator still gets the full discovered set on pending_hosts.
        self.pending_hosts = hosts
        for host in hosts:
            yield Artifact(ArtifactKind.HOST, host,
                           meta={"src": "subfinder", "confirmed": False})


def confirm_discovered(ctx, discovered: list[str], approved: list[str]) -> int:
    """Widen scope to operator-approved discoveries only, and only those.

    This is the sole path by which anything subfinder finds can reach
    ctx.store: scope is widened first, through ScopeGuard.extend() (which
    records the reason in run.json), and a HOST artifact is added only for
    a host that both appears in `discovered` and was named in `approved`.
    Everything else — including every other host in `discovered` — is
    simply never written anywhere.

    Raises if an approval names something that was never discovered — that
    would be an arbitrary scope widening dressed up as a confirmation.
    """
    discovered_set = {d.strip().lower() for d in discovered}
    unknown = [a for a in approved if a.strip().lower() not in discovered_set]
    if unknown:
        raise ValueError(
            f"cannot approve hosts that were not discovered: {', '.join(unknown)}"
        )
    if not approved:
        return 0
    ctx.scope.extend(approved, reason="operator-confirmed subfinder output")
    for host in approved:
        ctx.store.add(Artifact(ArtifactKind.HOST, host,
                               meta={"src": "subfinder", "confirmed": True}))
    ctx.log(f"scope: extended by {len(approved)} operator-confirmed host(s)")
    ctx.store.flush()
    return len(approved)
