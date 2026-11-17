"""nuclei must not spend its budget on protocol-mismatch services.

httpx runs with -nf so it probes BOTH schemes per port; that is deliberate,
and it is what stops a real HTTPS service on a non-443 port from being erased
by the plain-HTTP 400 in front of it (see stages/httpx.py). The consequence
is that the store legitimately holds entries like

    http://shop.client.example:443   400  "The plain HTTP request was sent to HTTPS port"

alongside the real `https://shop.client.example:443`. arjun and vhost already
filter those out. nuclei did not.

Measured on the first live run: three of the targets handed to nuclei were
these 400s -- the same three hosts already present under https -- and nuclei
hit its 20-minute limit having produced nothing at all. Every request spent
on a protocol mismatch is a request not spent on the service behind it, and
it is traffic the client is charged for in rate budget.
"""
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.nuclei import NucleiStage


def input_for(tmp_path, services):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    for value, meta in services:
        ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, value, meta=meta))
    NucleiStage().build_command(ctx)
    return (ctx.run_dir / "raw" / "nuclei-input.txt").read_text().split()


def test_a_plain_http_request_to_a_tls_port_is_not_scanned(tmp_path):
    lines = input_for(tmp_path, [
        ("http://acc.example:443", {"status": "400",
                                    "title": "400 The plain HTTP request was "
                                             "sent to HTTPS port"}),
        ("https://acc.example:443", {"status": "200"}),
    ])
    assert "http://acc.example:443" not in lines
    assert "https://acc.example:443" in lines


def test_an_ordinary_400_is_still_scanned(tmp_path):
    """A 400 that is NOT a protocol mismatch is a real HTTP response from a
    real service, and nuclei templates fire on plenty of them."""
    lines = input_for(tmp_path, [
        ("https://acc.example/api", {"status": "400", "title": "Bad Request"}),
    ])
    assert "https://acc.example/api" in lines


def test_a_service_with_no_recorded_status_is_kept(tmp_path):
    """Not every HTTP_SERVICE comes from httpx -- katana and jsrecon add
    URLs with no status. Dropping those would silently shrink the scan."""
    lines = input_for(tmp_path, [("https://acc.example/app.js", {})])
    assert "https://acc.example/app.js" in lines
