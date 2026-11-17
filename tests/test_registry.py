import signal
from contextlib import contextmanager

import pytest
from sweeper.artifacts import ArtifactKind
from sweeper.stages import base, registry


@contextmanager
def time_limit(seconds=5):
    """Fail rather than stall if order() ever loops forever.

    Cycle tests must prove order() raises *promptly*. Without this guard a
    regression that spins instead of raising would hang the whole suite
    rather than reporting a failure.
    """
    def _handler(signum, frame):
        raise TimeoutError(f"order() did not return within {seconds}s")

    previous = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class FakeStage:
    name = "fake"
    requires = ["dnsx"]
    consumes = ArtifactKind.HOST
    produces = {ArtifactKind.PORT}
    levels = {"low": [], "mid": [], "high": [], "full": []}
    optional = False

    def build_command(self, ctx):
        return ["/bin/true"]

    def parse(self, raw_path):
        return iter(())


def make(name, consumes, produces, levels=None, requires=(), provides=()):
    s = FakeStage()
    s.name = name
    s.consumes = consumes
    s.produces = produces
    # Set unconditionally, including to the empty frozenset: a stage that
    # declares neither facet attribute is a DIFFERENT case (registry.facets
    # must default it) and is covered by leaving these at their defaults.
    s.requires_facets = frozenset(requires)
    s.provides_facets = frozenset(provides)
    if levels is not None:
        s.levels = levels
    return s


def test_validate_accepts_conforming_stage():
    assert registry.validate(FakeStage()) == []


def test_validate_rejects_missing_level_key():
    s = make("x", ArtifactKind.HOST, {ArtifactKind.PORT},
             levels={"low": [], "mid": []})
    errs = registry.validate(s)
    assert any("high" in e for e in errs)
    assert any("full" in e for e in errs)


def test_validate_rejects_unknown_enabled_level():
    s = FakeStage()
    s.enabled_levels = frozenset({"mid", "maximum"})
    assert any("unknown levels" in e for e in registry.validate(s))


def test_validate_rejects_non_set_produces():
    s = make("x", ArtifactKind.HOST, ArtifactKind.PORT)  # not a set
    assert any("produces" in e for e in registry.validate(s))


def test_order_places_producer_before_consumer():
    # The names are DELIBERATELY ANTI-ALPHABETICAL. Do not "tidy" them.
    # `zeta` produces PORT, `alpha` consumes PORT, so the dependency requires
    # zeta BEFORE alpha -- the exact opposite of alphabetical order. This is
    # what makes the test discriminating: an implementation that ignored
    # consumes/produces and merely returned sorted(stages, key=name) would
    # put alpha first and fail here.
    zeta = make("zeta", ArtifactKind.HOST, {ArtifactKind.PORT})
    alpha = make("alpha", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE})
    ordered = [s.name for s in registry.order([alpha, zeta])]
    assert ordered.index("zeta") < ordered.index("alpha")
    assert ordered == ["zeta", "alpha"]


def test_consumes_any_orders_after_every_input_producer():
    tcp = make("z_tcp", ArtifactKind.HOST, {ArtifactKind.PORT})
    udp = make("z_udp", ArtifactKind.HOST, {ArtifactKind.UDP_PORT})
    assessor = make("a_assessor", ArtifactKind.HTTP_SERVICE,
                    {ArtifactKind.FINDING})
    assessor.consumes_any = {
        ArtifactKind.HTTP_SERVICE, ArtifactKind.PORT, ArtifactKind.UDP_PORT,
    }
    ordered = [s.name for s in registry.order([assessor, udp, tcp])]
    assert ordered.index("z_tcp") < ordered.index("a_assessor")
    assert ordered.index("z_udp") < ordered.index("a_assessor")


def test_order_is_deterministic_for_independent_stages():
    a = make("alpha", ArtifactKind.HOST, {ArtifactKind.DNS_RECORD})
    b = make("beta", ArtifactKind.HOST, {ArtifactKind.PORT})
    assert [s.name for s in registry.order([b, a])] == \
           [s.name for s in registry.order([a, b])]


def test_order_raises_on_cycle():
    a = make("a", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE})
    b = make("b", ArtifactKind.HTTP_SERVICE, {ArtifactKind.PORT})
    with time_limit():
        with pytest.raises(ValueError, match="cycle"):
            registry.order([a, b])


def test_order_raises_on_three_stage_cycle():
    # A -> B -> C -> A. The raise path must be cycle-LENGTH-agnostic, not
    # special-cased to the two-stage case, and must raise promptly rather
    # than spinning (guarded by time_limit).
    a = make("a", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE})
    b = make("b", ArtifactKind.HTTP_SERVICE, {ArtifactKind.DNS_RECORD})
    c = make("c", ArtifactKind.DNS_RECORD, {ArtifactKind.PORT})
    with time_limit():
        with pytest.raises(ValueError, match="cycle"):
            registry.order([a, b, c])


def test_order_ignores_self_edge_for_stage_consuming_what_it_produces():
    # katana and jsrecon both read HTTP_SERVICE and emit more HTTP_SERVICE.
    # That must NOT become a self-dependency, which would deadlock the sort.
    # Names are again DELIBERATELY ANTI-ALPHABETICAL: the self-consuming
    # stage sorts first by name but must be ordered LAST by dependency.
    a_katana = make("a_katana", ArtifactKind.HTTP_SERVICE,
                    {ArtifactKind.HTTP_SERVICE})

    # Half 1: alone, the self-edge must not deadlock.
    with time_limit():
        assert [s.name for s in registry.order([a_katana])] == ["a_katana"]

    # Half 2: it must still be ordered after a DIFFERENT HTTP_SERVICE producer.
    z_httpx = make("z_httpx", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE})
    with time_limit():
        ordered = [s.name for s in registry.order([a_katana, z_httpx])]
    assert ordered.index("z_httpx") < ordered.index("a_katana")
    assert ordered == ["z_httpx", "a_katana"]


def test_failure_classes_exist():
    for n in ("ARG_ERROR", "MISSING_BINARY", "NO_INPUT",
              "TRANSPORT", "PARTIAL", "NONE"):
        assert hasattr(base.FailureClass, n)


def test_order_resolves_the_five_stage_http_service_cycle():
    # Reproduces the real cycle, verified live against the actual
    # vhost/katana/jsrecon/arjun/nuclei stages before this fix:
    #   ValueError: cycle in stage dependencies:
    #   ['arjun', 'jsrecon', 'katana', 'nuclei', 'vhost']
    # Each of vhost/katana/jsrecon/arjun both reads and enriches
    # HTTP_SERVICE; nuclei reads it without producing it. Under the OLD
    # rule ("every producer of K depends on every OTHER producer of K, and
    # every consumer of K depends on every producer of K") all five became
    # mutually dependent. Under the NEW rule none of the four enrichers is
    # a prerequisite of any other, or of nuclei, because each of them also
    # consumes HTTP_SERVICE — only the pure producer (httpx) is.
    httpx = make("httpx", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE})
    vhost = make("vhost", ArtifactKind.HTTP_SERVICE,
                 {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING})
    katana = make("katana", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE})
    jsrecon = make("jsrecon", ArtifactKind.HTTP_SERVICE,
                   {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING})
    arjun = make("arjun", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE})
    nuclei = make("nuclei", ArtifactKind.HTTP_SERVICE, {ArtifactKind.FINDING})

    with time_limit():
        ordered = [s.name for s in
                   registry.order([nuclei, vhost, katana, jsrecon, arjun, httpx])]

    assert ordered[0] == "httpx"
    assert set(ordered[1:]) == {"arjun", "jsrecon", "katana", "nuclei", "vhost"}


def test_httpx_precedes_every_http_service_consumer():
    httpx = make("httpx", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE})
    vhost = make("vhost", ArtifactKind.HTTP_SERVICE,
                 {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING})
    katana = make("katana", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE})
    nuclei = make("nuclei", ArtifactKind.HTTP_SERVICE, {ArtifactKind.FINDING})

    ordered = [s.name for s in registry.order([nuclei, katana, vhost, httpx])]
    for consumer in ("vhost", "katana", "nuclei"):
        assert ordered.index("httpx") < ordered.index(consumer)


def test_peer_order_is_deterministic_across_runs():
    # Same five stages as the cycle test. None is a prerequisite of another
    # (all are peers under the new rule), so their relative order comes
    # entirely from the name-sort tiebreak and must not depend on the
    # order stages were passed in.
    httpx = make("httpx", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE})
    vhost = make("vhost", ArtifactKind.HTTP_SERVICE,
                 {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING})
    katana = make("katana", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE})
    jsrecon = make("jsrecon", ArtifactKind.HTTP_SERVICE,
                   {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING})
    arjun = make("arjun", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE})
    nuclei = make("nuclei", ArtifactKind.HTTP_SERVICE, {ArtifactKind.FINDING})
    stages = [httpx, vhost, katana, jsrecon, arjun, nuclei]

    import random
    first = [s.name for s in registry.order(stages)]
    for _ in range(5):
        random.shuffle(stages)
        assert [s.name for s in registry.order(stages)] == first


# --- A pure consumer must see the COMPLETE pool for its kind ----------------
# The rule orders pure producer -> enricher -> pure consumer. The property
# that matters: nuclei (pure consumer of HTTP_SERVICE, producing only
# FINDINGs) must run after every stage that can contribute an HTTP_SERVICE,
# or it scans a smaller set than the run actually discovered and the report
# under-reports with nothing recording the gap.


def _roles(stages, kind):
    """Partition `stages` by role with respect to `kind`, by ATTRIBUTES.

    Deliberately derived from consumes/produces rather than from a hardcoded
    list of today's stage names, so these tests keep their meaning when a
    sixth HTTP_SERVICE stage is added.
    """
    pure_producers, enrichers, pure_consumers = [], [], []
    for s in stages:
        produces = kind in s.produces
        consumes = s.consumes == kind
        if produces and not consumes:
            pure_producers.append(s.name)
        elif produces and consumes:
            enrichers.append(s.name)
        elif consumes and not produces:
            pure_consumers.append(s.name)
    return pure_producers, enrichers, pure_consumers


def _http_service_pipeline():
    """httpx (pure producer), four enrichers, nuclei (pure consumer)."""
    return [
        make("httpx", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE}),
        make("vhost", ArtifactKind.HTTP_SERVICE,
             {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING}),
        make("katana", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE}),
        make("jsrecon", ArtifactKind.HTTP_SERVICE,
             {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING}),
        make("arjun", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE}),
        make("nuclei", ArtifactKind.HTTP_SERVICE, {ArtifactKind.FINDING}),
    ]


def test_pure_consumer_orders_after_every_enricher_of_its_kind():
    # Asserted BY ROLE, not by listing today's names: every enricher of
    # HTTP_SERVICE must precede every pure consumer of HTTP_SERVICE.
    stages = _http_service_pipeline()
    with time_limit():
        ordered = [s.name for s in registry.order(stages)]
    producers, enrichers, consumers = _roles(stages, ArtifactKind.HTTP_SERVICE)
    assert enrichers and consumers, "fixture no longer exercises the rule"
    for consumer in consumers:
        for enricher in enrichers:
            assert ordered.index(enricher) < ordered.index(consumer), (
                f"{consumer!r} (pure consumer) ran before {enricher!r} "
                "(enricher), so it scanned an incomplete pool"
            )
        for producer in producers:
            assert ordered.index(producer) < ordered.index(consumer)


def test_pipeline_order_is_invariant_under_renaming():
    """The test the previous, incomplete rule would have failed.

    Names are chosen so ALPHABETICAL order puts the pure consumer FIRST and
    the enricher LAST -- the exact opposite of the required order. Under the
    previous rule the consumer had no dependency on the enricher at all, so
    it came out first and the run scanned an incomplete pool; that only
    looked correct for the real stage set because "nuclei" happens to sort
    after "arjun", "jsrecon" and "katana". The determinism test cannot catch
    this -- it checks stability, not correctness.
    """
    producer = make("mmm_producer", ArtifactKind.PORT,
                    {ArtifactKind.HTTP_SERVICE})
    enricher = make("zzz_enricher", ArtifactKind.HTTP_SERVICE,
                    {ArtifactKind.HTTP_SERVICE})
    consumer = make("aaa_consumer", ArtifactKind.HTTP_SERVICE,
                    {ArtifactKind.FINDING})
    with time_limit():
        ordered = [s.name for s in
                   registry.order([consumer, enricher, producer])]
    assert ordered == ["mmm_producer", "zzz_enricher", "aaa_consumer"]


def _twelve_stage_pipeline():
    """The full realistic pipeline: the six shipped stages' own declared
    consumes/produces, plus the six from Tasks 4-8.

    Note the shipped set already contains two enrichers of kinds other than
    HTTP_SERVICE -- cdncheck enriches HOST, nmap enriches PORT -- so the
    completed rule also makes dnsx/naabu wait for cdncheck and httpx wait
    for nmap. tlsx is modelled as a pure consumer of PORT; only its ROLE
    matters to ordering, not its exact produces set.
    """
    return [
        make("subfinder", None, {ArtifactKind.HOST}),
        make("cdncheck", ArtifactKind.HOST,
             {ArtifactKind.HOST, ArtifactKind.FINDING}),
        make("dnsx", ArtifactKind.HOST,
             {ArtifactKind.DNS_RECORD, ArtifactKind.FINDING}),
        make("naabu", ArtifactKind.HOST, {ArtifactKind.PORT}),
        make("nmap", ArtifactKind.PORT,
             {ArtifactKind.PORT, ArtifactKind.FINDING}),
        make("tlsx", ArtifactKind.PORT, {ArtifactKind.FINDING}),
        make("httpx", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE}),
        make("vhost", ArtifactKind.HTTP_SERVICE,
             {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING}),
        # katana/jsrecon carry the real stages' declared facets: katana
        # crawls from a bare origin and yields pathful URLs tagged with a
        # content type; jsrecon can only read artifacts that carry one of
        # those. Modelled here so the cycle and determinism properties
        # below are exercised against the pipeline actually shipped.
        make("katana", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE},
             provides={"content_type", "url_path"}),
        make("jsrecon", ArtifactKind.HTTP_SERVICE,
             {ArtifactKind.HTTP_SERVICE, ArtifactKind.FINDING},
             requires={"content_type", "url_path"}),
        make("arjun", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE}),
        make("nuclei", ArtifactKind.HTTP_SERVICE, {ArtifactKind.FINDING}),
    ]


def test_twelve_stage_pipeline_has_no_cycle():
    stages = _twelve_stage_pipeline()
    with time_limit():
        ordered = [s.name for s in registry.order(stages)]
    assert len(ordered) == 12
    assert set(ordered) == {s.name for s in stages}


def test_twelve_stage_pipeline_puts_every_pure_consumer_after_all_contributors():
    # The same role property across every kind in the real pipeline at once
    # -- HOST (cdncheck enriches), PORT (nmap enriches) and HTTP_SERVICE
    # (four enrichers) -- not just the HTTP_SERVICE case that prompted it.
    stages = _twelve_stage_pipeline()
    with time_limit():
        ordered = [s.name for s in registry.order(stages)]
    for kind in (ArtifactKind.HOST, ArtifactKind.PORT,
                 ArtifactKind.HTTP_SERVICE):
        producers, enrichers, consumers = _roles(stages, kind)
        for consumer in consumers:
            for earlier in producers + enrichers:
                assert ordered.index(earlier) < ordered.index(consumer), (
                    f"{consumer!r} consumes {kind.name} but ran before "
                    f"{earlier!r}, which contributes {kind.name}"
                )


def test_twelve_stage_pipeline_order_is_deterministic():
    import random
    stages = _twelve_stage_pipeline()
    first = [s.name for s in registry.order(stages)]
    for _ in range(5):
        random.shuffle(stages)
        assert [s.name for s in registry.order(stages)] == first


# --- Facets: existing-artifact-of-kind-K is not always enough ---------------
# Two enrichers of the same kind are peers, tie-broken by name, UNLESS one
# supplies a facet the other's input must carry. Without this, jsrecon (which
# reads only artifacts identifiable as JavaScript) sorted ahead of katana (the
# only stage that tags artifacts with a content type or a path) and its
# candidate list was empty on every default run. See registry.order's FACETS
# section; the end-to-end property lives in test_app_full_pipeline.py.


def test_facets_defaults_to_empty_when_a_stage_declares_neither():
    # The whole reason no stage outside the fix's scope needed touching.
    assert registry.facets(FakeStage(), "requires_facets") == frozenset()
    assert registry.facets(FakeStage(), "provides_facets") == frozenset()


def test_facets_tolerates_an_explicit_none():
    s = FakeStage()
    s.requires_facets = None
    assert registry.facets(s, "requires_facets") == frozenset()


def test_validate_rejects_non_set_facets():
    s = make("x", ArtifactKind.HOST, {ArtifactKind.PORT})
    s.provides_facets = "content_type"     # a str is iterable: easy to get wrong
    assert any("provides_facets" in e for e in registry.validate(s))


def test_validate_rejects_non_str_facet_member():
    s = make("x", ArtifactKind.HOST, {ArtifactKind.PORT})
    s.requires_facets = frozenset({ArtifactKind.HOST})
    assert any("requires_facets" in e for e in registry.validate(s))


def test_validate_accepts_a_stage_with_no_facet_attributes_at_all():
    assert registry.validate(FakeStage()) == []


def test_facet_supplier_precedes_facet_requirer_against_the_name_tiebreak():
    """The B7 defect in miniature, with the names FORCING the wrong answer.

    Both stages are enrichers of the same kind, so the old rule made them
    peers and broke the tie by name. The supplier is named so it sorts LAST
    and the requirer so it sorts FIRST -- the exact opposite of the required
    order -- so an implementation that ignored facets and fell back to the
    alphabet fails here. (The real pair passes today only because "jsrecon"
    < "katana" is the wrong way round and the facet edge overrides it.)
    """
    producer = make("aaa_httpx", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE})
    requirer = make("bbb_requirer", ArtifactKind.HTTP_SERVICE,
                    {ArtifactKind.HTTP_SERVICE}, requires={"content_type"})
    supplier = make("zzz_supplier", ArtifactKind.HTTP_SERVICE,
                    {ArtifactKind.HTTP_SERVICE}, provides={"content_type"})
    with time_limit():
        ordered = [s.name for s in registry.order([requirer, supplier, producer])]
    assert ordered == ["aaa_httpx", "zzz_supplier", "bbb_requirer"]


def test_unrelated_facets_do_not_create_an_edge():
    """The rule must be an INTERSECTION, not "declares any facet at all".

    Two enrichers that traffic in different facets are still peers, so their
    order is still the name tiebreak. An implementation that ordered any
    provider ahead of any requirer regardless of facet name would reverse
    these two.
    """
    producer = make("aaa_httpx", ArtifactKind.PORT, {ArtifactKind.HTTP_SERVICE})
    requirer = make("bbb_requirer", ArtifactKind.HTTP_SERVICE,
                    {ArtifactKind.HTTP_SERVICE}, requires={"content_type"})
    supplier = make("zzz_supplier", ArtifactKind.HTTP_SERVICE,
                    {ArtifactKind.HTTP_SERVICE}, provides={"form_fields"})
    with time_limit():
        ordered = [s.name for s in registry.order([requirer, supplier, producer])]
    assert ordered == ["aaa_httpx", "bbb_requirer", "zzz_supplier"]


def test_a_single_facet_cannot_produce_a_cycle_even_when_mutually_declared():
    """`supplies` is provides-MINUS-requires, and this is why.

    Two enrichers that each both provide and require the SAME facet describe
    a pool they both read and both enrich -- the peer case, exactly as for
    the kind one level up. Taking provides_facets at face value would make
    each a prerequisite of the other and deadlock the sort on a declaration
    that is not actually a contract error.
    """
    a = make("a", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE},
             requires={"url_path"}, provides={"url_path"})
    b = make("b", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE},
             requires={"url_path"}, provides={"url_path"})
    with time_limit():
        ordered = [s.name for s in registry.order([b, a])]
    assert ordered == ["a", "b"]


def test_circular_facet_declarations_still_raise():
    """A genuine contract error must raise, not be quietly linearized.

    Two facets in a circular provide/require relationship (p provides F and
    requires G; s provides G and requires F) is the facet-level twin of the
    cross-KIND cycle the module has always rejected. Silently dropping one
    of these edges is what "correctness by alphabet" looked like the first
    time; it must fail loudly instead.
    """
    p = make("p", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE},
             requires={"g"}, provides={"f"})
    s = make("s", ArtifactKind.HTTP_SERVICE, {ArtifactKind.HTTP_SERVICE},
             requires={"f"}, provides={"g"})
    with time_limit():
        with pytest.raises(ValueError, match="cycle"):
            registry.order([p, s])


# --- Exhaustive cycle check ------------------------------------------------


def test_every_subset_of_the_twelve_stage_pipeline_linearizes():
    """Brute force over all 2**12 subsets, not just the full set.

    A run is a SUBSET: --stages picks one, subdomain_enum drops subfinder,
    and build_stages orders whatever survives. A rule can be acyclic on the
    complete pipeline and cyclic on some subset -- removing a stage removes
    edges but also removes the stage that made a mutual pair reachable in
    one direction only. The full-pipeline check cannot see that, so it is
    the subsets that carry the "no cycle" claim. Extended from the full-set
    check when facet edges were added, because facet edges are the first
    same-kind edges in this module that are not structurally acyclic across
    more than one facet.
    """
    import itertools

    stages = _twelve_stage_pipeline()
    checked = 0
    with time_limit(60):
        for r in range(len(stages) + 1):
            for subset in itertools.combinations(stages, r):
                subset = list(subset)
                ordered = registry.order(subset)
                assert [s.name for s in ordered] == \
                       [s.name for s in registry.order(subset[::-1])]
                assert {s.name for s in ordered} == {s.name for s in subset}
                checked += 1
    assert checked == 2 ** len(stages)


def test_every_subset_containing_both_orders_katana_before_jsrecon():
    """The facet edge survives subsetting.

    Asserted over every subset that contains both, so it cannot be satisfied
    by an accident of which other stages happen to be present.
    """
    import itertools

    stages = _twelve_stage_pipeline()
    others = [s for s in stages if s.name not in ("katana", "jsrecon")]
    katana = next(s for s in stages if s.name == "katana")
    jsrecon = next(s for s in stages if s.name == "jsrecon")
    checked = 0
    with time_limit(60):
        for r in range(len(others) + 1):
            for rest in itertools.combinations(others, r):
                names = [s.name for s in
                         registry.order([jsrecon, katana, *rest])]
                assert names.index("katana") < names.index("jsrecon")
                checked += 1
    assert checked == 2 ** len(others)


# --- dependencies(): the same edges, exposed for resume --------------------
#
# resume reads this graph to decide which already-complete stages a re-run
# invalidates. It has to be the graph order() sorts by, not a second copy of
# the rule, or "downstream" comes to mean two different things.

def test_dependencies_is_the_graph_order_sorts_by():
    """Property, not an enumeration: in the full pipeline every stage appears
    after every one of its dependencies, and the graph is not empty."""
    stages = _twelve_stage_pipeline()
    deps = registry.dependencies(stages)
    names = [s.name for s in registry.order(stages)]
    assert set(deps) == set(names)
    assert any(deps.values())
    for name, prerequisites in deps.items():
        for prerequisite in prerequisites:
            assert names.index(prerequisite) < names.index(name)


def test_a_pure_consumer_depends_on_every_enricher_of_its_kind():
    stages = _twelve_stage_pipeline()
    deps = registry.dependencies(stages)
    # nuclei is the pure consumer of HTTP_SERVICE; vhost/katana/jsrecon/arjun
    # all enrich it. That edge is what resume needs to know that re-running
    # katana invalidates a nuclei that already ran.
    assert {"vhost", "katana", "jsrecon", "arjun", "httpx"} <= deps["nuclei"]


def test_enrichers_of_one_kind_are_not_each_others_dependencies():
    stages = _twelve_stage_pipeline()
    deps = registry.dependencies(stages)
    assert "vhost" not in deps["katana"]
    assert "katana" not in deps["vhost"]
