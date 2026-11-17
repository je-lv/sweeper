"""Which services arjun is given, and why a non-200 must never be one.

THE DEFECT. arjun 2.2.7 crashes outright on a target that answers anything
other than 200 when it is run over a LIST of URLs:

    File "/usr/lib/python3/dist-packages/arjun/__main__.py", line 135
      print('%s Target returned HTTP %i, ...' % (bad, request.status_code))
    AttributeError: 'dict' object has no attribute 'status_code'

That is an upstream bug (in multi-URL mode `request` is a dict, not a
response object), and it fires while arjun is warning about the non-200 --
so the very first such target kills the process. Measured against the lab:
arjun died on target 1 of 27, in 0.1s, and the whole stage was recorded as
`partial -- 0 artifacts, 0 findings`. Non-200s are ordinary on any real
estate, so as wired this stage was going to contribute nothing on most
engagements while reporting only that it ran short.

The fix is not a workaround for someone else's bug -- it is what this stage
should have been doing anyway. Parameter discovery brute-forces query
parameters against a page and compares responses; a 400, 404 or 500 has no
parameters to discover and no stable baseline to compare against, so those
targets were always pure cost. Sweeper already knows each service's status
code (httpx records it in artifact meta), so the filter is free.
"""
import pytest

from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.arjun import ArjunStage


def ctx_with(tmp_path, services):
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    for url, status in services:
        meta = {"host": "acc.example"}
        if status is not None:
            meta["status_code"] = status
        ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, url, meta=meta))
    return ctx


def input_lines(ctx):
    ArjunStage().build_command(ctx)
    return [l for l in (ctx.run_dir / "raw" / "arjun-input.txt")
            .read_text(encoding="utf-8").splitlines() if l.strip()]


def test_a_400_service_is_not_given_to_arjun(tmp_path):
    """The exact shape that killed the stage: nginx's plain-HTTP-to-HTTPS 400."""
    ctx = ctx_with(tmp_path, [
        ("http://acc.example:8443", 400),
        ("http://acc.example:80", 200),
    ])
    assert input_lines(ctx) == ["http://acc.example:80"]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 500, 502, 503])
def test_no_error_status_reaches_arjun(tmp_path, status):
    ctx = ctx_with(tmp_path, [
        (f"http://acc.example:{status}", status),
        ("http://acc.example:80", 200),
    ])
    assert f"http://acc.example:{status}" not in input_lines(ctx)


@pytest.mark.parametrize("status", [200, 201, 204, 301, 302, 307])
def test_success_and_redirect_statuses_are_kept(tmp_path, status):
    """A redirect still has parameters worth discovering behind it."""
    ctx = ctx_with(tmp_path, [(f"http://acc.example:{status}", status)])
    assert input_lines(ctx) == [f"http://acc.example:{status}"]


def test_a_service_with_no_recorded_status_is_kept(tmp_path):
    """Absence of evidence is not evidence of a broken target.

    Not every HTTP_SERVICE comes from httpx -- katana, vhost and jsrecon all
    contribute artifacts that may carry no status_code. Dropping those would
    silently shrink arjun's scope to whatever httpx alone confirmed, which
    is the same class of quiet coverage loss this filter exists to prevent.
    """
    ctx = ctx_with(tmp_path, [("http://acc.example/discovered", None)])
    assert input_lines(ctx) == ["http://acc.example/discovered"]


def test_an_unparseable_status_is_kept(tmp_path):
    ctx = ctx_with(tmp_path, [("http://acc.example/x", "not-a-number")])
    assert input_lines(ctx) == ["http://acc.example/x"]


def test_the_stage_builds_no_command_when_every_service_is_broken(tmp_path):
    """No probe-able target must mean NO RUN, not a run that crashes.

    Handing arjun an empty list is how it was crashing in the first place;
    the runner records an empty argv as NO_INPUT, which is the honest answer.
    """
    ctx = ctx_with(tmp_path, [("http://acc.example:8443", 400)])
    assert ArjunStage().build_command(ctx) == []


# --- endpoint dedupe -------------------------------------------------------
# arjun runs after the crawler now, so its input is every discovered endpoint
# and the same page arrives several times over: http and https, :80 and :443.
# arjun brute-forces parameter NAMES, so each duplicate costs a wordlist's
# worth of requests against the client for nothing the first pass could not
# find -- and arjun takes no rate flag at this level to cap that with.

def test_the_same_endpoint_over_http_and_https_is_fuzzed_once(tmp_path):
    from sweeper.stages.arjun import dedupe_endpoints
    got = dedupe_endpoints([
        "https://acc.example:443/account",
        "http://acc.example:80/account",
    ])
    assert len(got) == 1


def test_distinct_paths_are_all_kept(tmp_path):
    from sweeper.stages.arjun import dedupe_endpoints
    got = dedupe_endpoints([
        "https://acc.example/account",
        "https://acc.example/api/status",
        "https://acc.example/product/9",
    ])
    assert len(got) == 3


def test_the_same_path_on_a_different_host_is_kept(tmp_path):
    """Two hosts are two applications until proven otherwise."""
    from sweeper.stages.arjun import dedupe_endpoints
    got = dedupe_endpoints([
        "https://a.acc.example/account",
        "https://b.acc.example/account",
    ])
    assert len(got) == 2


def test_dedupe_is_deterministic(tmp_path):
    """build_command must be deterministic or preflight validates a
    different argv than the runner executes."""
    from sweeper.stages.arjun import dedupe_endpoints
    urls = ["https://acc.example/b", "https://acc.example/a",
            "http://acc.example/a"]
    assert dedupe_endpoints(urls) == dedupe_endpoints(list(reversed(urls)))
