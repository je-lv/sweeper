"""Stage contract validation and dependency ordering.

Order is derived from consumes/produces, so declaration order is irrelevant
and a new stage slots itself into the right position.

There is deliberately no registry here. An earlier design had a mutable
module-global populated by a `register()` decorator, but the stage list is
`app.ALL_STAGES` — a plain tuple — and nothing ever called `register()`. Two
sources of truth for "which stages exist" is exactly the shape that lets a
stage vanish from a run with nothing recording that it did. The tuple is the
one source; both functions here are pure and take the stages as an argument.
"""
from __future__ import annotations

from ..artifacts import ArtifactKind
from .base import LEVELS, Stage


#: The two facet attributes a stage may declare (see `order`). Optional --
#: a stage that declares neither behaves exactly as it did before facets
#: existed, which is why no stage outside this finding's scope needed
#: touching.
FACET_ATTRS = ("requires_facets", "provides_facets")


def facets(stage: Stage, attr: str) -> frozenset[str]:
    """The named facet set `attr` of `stage`, defaulting to empty.

    getattr with a default rather than a hard attribute access: facets are
    an OPTIONAL part of the contract, and a stage that declares neither is
    exactly the pre-facet stage this module has always ordered.
    """
    return frozenset(getattr(stage, attr, None) or ())


def validate(stage: Stage) -> list[str]:
    errs: list[str] = []
    if not getattr(stage, "name", ""):
        errs.append("missing name")
    for attr in FACET_ATTRS:
        declared = getattr(stage, attr, None)
        if declared is None:
            continue
        if not isinstance(declared, (set, frozenset)):
            errs.append(f"{attr} must be a set of str")
        elif any(not isinstance(f, str) for f in declared):
            errs.append(f"{attr} contains a non-str facet")
    if not isinstance(getattr(stage, "produces", None), set):
        errs.append("produces must be a set of ArtifactKind")
    else:
        for p in stage.produces:
            if not isinstance(p, ArtifactKind):
                errs.append(f"produces contains non-ArtifactKind: {p!r}")
    consumes = getattr(stage, "consumes", None)
    if consumes is not None and not isinstance(consumes, ArtifactKind):
        errs.append("consumes must be an ArtifactKind or None")
    consumes_any = getattr(stage, "consumes_any", None)
    if consumes_any is not None:
        if not isinstance(consumes_any, (set, frozenset)):
            errs.append("consumes_any must be a set of ArtifactKind")
        elif any(not isinstance(k, ArtifactKind) for k in consumes_any):
            errs.append("consumes_any contains a non-ArtifactKind")
    levels = getattr(stage, "levels", None)
    if not isinstance(levels, dict):
        errs.append("levels must be a dict")
    else:
        for lvl in LEVELS:
            if lvl not in levels:
                errs.append(f"levels missing key {lvl!r}")
    enabled = getattr(stage, "enabled_levels", None)
    if enabled is not None:
        if not isinstance(enabled, (set, frozenset)):
            errs.append("enabled_levels must be a set/frozenset")
        else:
            unknown = set(enabled) - set(LEVELS)
            if unknown:
                errs.append(
                    "enabled_levels contains unknown levels: "
                    + ", ".join(sorted(unknown))
                )
    return errs


def dependencies(stages: list[Stage]) -> dict[str, set[str]]:
    """The prerequisite edges `order` sorts by: name -> names it must follow.

    Extracted from `order` rather than reimplemented anywhere else, because
    there is a SECOND consumer of these edges that is not about ordering at
    all: resume. Re-running an enricher can add artifacts to a pool a pure
    consumer already scanned and recorded `complete`, so a resume must
    invalidate that consumer and run it again -- three new services appeared
    in an asset inventory that nothing scanned, under "All selected stages
    completed". "Which stages are downstream of this one" is exactly this
    graph, and a second copy of the rule in resume.py is how the two would
    come to disagree about what "downstream" means the next time a facet or
    a kind is added. See `order` for the full rationale for every edge.
    """
    producers: dict[ArtifactKind, set[str]] = {}
    for s in stages:
        for kind in s.produces:
            producers.setdefault(kind, set()).add(s.name)

    by_name = {s.name: s for s in stages}
    deps: dict[str, set[str]] = {s.name: set() for s in stages}
    for s in stages:
        kinds = set(getattr(s, "consumes_any", None) or ())
        if not kinds and s.consumes is not None:
            kinds.add(s.consumes)
        for kind in kinds:
            # Is `s` itself an enricher of the kind it consumes, or a pure
            # consumer of it? That decides whether the OTHER enrichers of
            # this kind are its peers or its prerequisites.
            s_enriches = kind in s.produces
            for producer_name in producers.get(kind, set()):
                if producer_name == s.name:
                    continue
                producer = by_name[producer_name]
                producer_kinds = set(
                    getattr(producer, "consumes_any", None) or ()
                )
                if not producer_kinds and producer.consumes is not None:
                    producer_kinds.add(producer.consumes)
                if kind in producer_kinds and s_enriches:
                    # Both enrich the same kind: peers, neither orders the
                    # other. A pure consumer, by contrast, depends on this
                    # enricher so its input pool is complete. A facet can
                    # lift the peer exemption when one supplies what the
                    # other requires.
                    supplies = (facets(producer, "provides_facets")
                                - facets(producer, "requires_facets"))
                    if not (supplies & facets(s, "requires_facets")):
                        continue
                deps[s.name].add(producer_name)
    return deps


def order(stages: list[Stage]) -> list[Stage]:
    """Topological sort by artifact dependency, ties broken by name.

    Three ROLES per artifact kind K decide every edge. A stage that
    produces K without consuming it is a PURE PRODUCER (httpx turns PORT
    into HTTP_SERVICE and never reads HTTP_SERVICE). One that both consumes
    and produces K is an ENRICHER (vhost, katana, jsrecon and arjun each
    read the HTTP_SERVICE pool and add more to it; cdncheck enriches HOST,
    nmap enriches PORT). One that consumes K without producing it is a PURE
    CONSUMER (nuclei reads HTTP_SERVICE and emits only FINDINGs).

    The rule:

      * every pure producer of K is a prerequisite of every consumer of K;
      * every enricher of K is a prerequisite of every PURE consumer of K;
      * enrichers of the same K are PEERS -- neither orders the other,
        UNLESS one supplies a FACET the other's input must carry (below).

    FACETS: existing-artifact-of-kind-K is not always enough.
    ---------------------------------------------------------
    "Enricher" turned out to be two things wearing one label. katana and
    vhost DISCOVER more K: hand either one a bare origin and it does its
    job. jsrecon READS what a K artifact points AT: it only fetches an
    HTTP_SERVICE that is identifiably JavaScript (a `content_type` in meta,
    or a URL whose path ends `.js` -- see jsrecon._looks_like_js). httpx,
    the only PURE producer of HTTP_SERVICE, emits bare `scheme://host:port`
    with no path and no content_type, so under the peers-only rule jsrecon
    was tie-broken alphabetically ahead of katana and its candidate list was
    EMPTY ON EVERY DEFAULT RUN -- a whole stage's capability lost while the
    report said "All selected stages completed". Same defect this module
    already exists to prevent (work that did not happen presenting as work
    that did), one level finer: not "did the pool have members?" but "did
    its members carry what the next stage reads?".

    So a stage may additionally declare, as plain sets of names:

      * `requires_facets` -- properties its input artifacts must carry for
        its candidate selection to select anything;
      * `provides_facets` -- properties it puts ON the artifacts it emits.

    and the peer exemption above is lifted when a peer SUPPLIES a facet
    this stage REQUIRES. Both attributes are optional; a stage declaring
    neither orders exactly as before.

    Supplies means `provides_facets - requires_facets`, not `provides_facets`.
    That subtraction is what keeps a single facet structurally acyclic, by
    the same three-layer argument as the kind rule one level up: for facet
    F the providers ({F in provides, F not in requires}) and the requirers
    ({F in requires}) are disjoint by construction and every F-edge runs
    provider -> requirer, so no F-edge can run backwards and no set of
    F-edges alone can close a loop. As with kinds, a cycle still needs two
    or more facets in a genuinely circular provide/require relationship
    (p provides F requires G, s provides G requires F) -- a real contract
    error, which must raise rather than be quietly linearized. The
    exhaustive-subset cycle test covers exactly this.

    Facet NAMES are deliberately not an enum here. A facet is a claim a
    stage makes about the artifacts it reads or writes, so it belongs in
    the stage that makes the claim; centralising the vocabulary would mean
    a new stage cannot describe its own input without editing this module,
    which is the coupling the module docstring's "no registry here" note
    already argues against. `validate` type-checks them; agreement on
    spelling is what the pipeline tests assert.

    THE PROPERTY THIS GUARANTEES, and the thing to understand before
    touching any of it: **a pure consumer of K runs only after every stage
    that can contribute a K artifact has run, so it sees the COMPLETE
    artifact pool for its kind.** nuclei produces the findings the whole
    report is built from; scanning a pool that vhost or katana had not yet
    contributed to would silently under-report coverage -- fewer findings
    with nothing recording that anything was missed. That is this project's
    recurring defect (work that did not happen presenting as work that
    did), and here it would arrive through the scheduler rather than
    through a parser.

    Enrichers are peers because none of them is genuinely upstream of
    another: each merely adds more K to a pool the others already read.
    Making every producer of K a prerequisite of every consumer of K --
    the original rule -- therefore made all four HTTP_SERVICE enrichers
    plus nuclei mutually dependent, i.e. a cycle. Dropping enricher edges
    altogether -- the first fix -- broke the cycle but left nuclei ordered
    before vhost purely because "nuclei" < "vhost" alphabetically:
    correctness by alphabet, which a rename would have silently undone.

    Same-kind edges therefore run strictly pure producer -> enricher ->
    pure consumer. That is three layers with no edge inside a layer and no
    edge backwards, so no single kind can produce a cycle. A cycle still
    needs two or more kinds with genuinely circular consume/produce
    relationships (A: PORT -> HTTP_SERVICE, B: HTTP_SERVICE -> PORT), which
    is a real contract error and must still raise -- see the cycle tests.

    Peers, and stages with no dependency relationship at all, are ordered
    by name so a run's stage order is reproducible: this tool's output is
    evidence.

    The edges themselves live in `dependencies()`, which resume also reads
    to decide which already-complete stages a re-run invalidates.
    """
    by_name = {s.name: s for s in stages}
    deps = dependencies(stages)

    ordered: list[Stage] = []
    done: set[str] = set()
    while len(ordered) < len(stages):
        ready = sorted(n for n in by_name
                       if n not in done and deps[n] <= done)
        if not ready:
            remaining = sorted(set(by_name) - done)
            raise ValueError(f"cycle in stage dependencies: {remaining}")
        for n in ready:
            ordered.append(by_name[n])
            done.add(n)
    return ordered
