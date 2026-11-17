"""arjun must run after the stages that discover endpoints.

THE DEFECT, and it is the one registry.order's docstring already describes
for jsrecon -- missed for arjun when facets were introduced.

arjun declared no facets, so it was an ordinary HTTP_SERVICE enricher and a
PEER of katana, tie-broken alphabetically: a-r-j < k-a-t. It therefore ran
BEFORE the crawler, and its input was whatever httpx had produced -- bare
origins, `https://host:443`, with no path.

Parameter discovery against a bare origin tests parameters on `/`. Every
hidden parameter worth finding lives somewhere else:

    /product/<id>?preview=1     unpublished products
    /account?debug=1            session, SECRET_KEY, db path
    /account?role=admin         privilege escalation
    /api/status?admin=1         every user with role and API token
    /api/orders?user_id=<n>     any user's orders, unauthenticated

Measured against the lab: arjun received 28 origins, ran for 59 seconds, and
reported `complete -- 0 artifacts, 0 findings` while katana went on to
discover 625 endpoints it never saw. The stage could not have found anything
on any target, and nothing in the run said so.

`url_path` is exactly the facet katana already declares and jsrecon already
requires for the same structural reason.
"""
from sweeper.stages import registry
from sweeper.stages.arjun import ArjunStage
from sweeper.stages.katana import KatanaStage
from sweeper.stages.httpx import HttpxStage
from sweeper.stages.jsrecon import JsreconStage
from sweeper.stages.nuclei import NucleiStage
from sweeper.stages.vhost import VhostStage


def order_names(stages):
    return [s.name for s in registry.order(stages)]


def test_arjun_requires_a_path_bearing_artifact():
    """The declaration itself. Without it the ordering below is alphabetical
    luck, and a rename would silently undo it."""
    assert "url_path" in registry.facets(ArjunStage(), "requires_facets")


def test_arjun_runs_after_katana():
    order = order_names([ArjunStage(), KatanaStage(), HttpxStage()])
    assert order.index("katana") < order.index("arjun"), order


def test_arjun_still_runs_before_nuclei():
    """nuclei is a pure consumer and must see every artifact arjun adds.

    arjun emits HTTP_SERVICE artifacts for the parameters it discovers; if
    nuclei ran first those endpoints would never be scanned, which is the
    same complete-pool guarantee registry.order exists to provide.
    """
    order = order_names([ArjunStage(), KatanaStage(), NucleiStage(),
                         HttpxStage(), VhostStage(), JsreconStage()])
    assert order.index("arjun") < order.index("nuclei"), order


def test_the_full_pipeline_still_orders_without_a_cycle():
    """Adding a facet requirement must not make the graph unsatisfiable."""
    from sweeper.app import ALL_STAGES
    order = order_names([cls() for cls in ALL_STAGES])
    assert len(order) == len(ALL_STAGES)
    assert order.index("httpx") < order.index("katana") < order.index("arjun")


def test_arjun_and_jsrecon_both_wait_for_the_crawler():
    """They are the two stages that READ what an artifact points at, rather
    than discovering more artifacts from a bare origin."""
    order = order_names([ArjunStage(), JsreconStage(), KatanaStage(),
                         HttpxStage()])
    assert order.index("katana") < order.index("arjun")
    assert order.index("katana") < order.index("jsrecon")
