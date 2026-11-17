"""httpx must not let a wrong scheme guess erase a whole service.

THE DEFECT. Given a bare `host:port`, httpx probes one scheme, and if it
gets ANY response it stops -- it does not try the other. nginx answers a
plain-HTTP request to a TLS port with `400 The plain HTTP request was sent
to HTTPS port`, which is a response, so:

    host:8443  ->  http://host:8443   400   (recorded as a live service)
                   https://host:8443  200   (never probed, never recorded)

Measured against the lab, before the fix: eighteen `http://...:8443` entries
in the artifact store, every one of them a protocol mismatch, and not a
single one of the real HTTPS services behind them. The consequences were not
confined to httpx either -- those bogus entries are what vhost picked as its
fuzzing origin and what crashed arjun.

nginx is not an edge case; it is most of the web. Any HTTPS service on a
non-443 port behind it was invisible to this tool.

`-nf` (no-fallback) makes httpx report BOTH probed protocols instead of the
first one that answers. The bogus half is still recorded -- it IS what the
port returned to an HTTP request -- and the consumers that care filter on
status (see stages/arjun.probeable and stages/vhost.select_origin).
"""
import pytest

from sweeper import binaries, preflight
from sweeper.context import RunConfig, RunContext
from sweeper.stages.base import LEVELS
from sweeper.stages.httpx import HttpxStage


@pytest.mark.parametrize("level", LEVELS)
def test_both_protocols_are_reported_at_every_level(level, tmp_path):
    """Including `low`.

    An extra probe per port is a smaller cost than never seeing a service at
    all, and `low` is the level most likely to be pointed at an estate
    nobody has mapped yet -- exactly where a silently missed HTTPS service
    does the most damage.
    """
    assert "-nf" in HttpxStage().levels[level], (
        f"{level} lets a wrong scheme guess drop a service entirely"
    )


def test_no_fallback_is_in_the_built_command(tmp_path):
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    assert "-nf" in [str(a) for a in HttpxStage().build_command(ctx)]


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("httpx") is None,
                    reason="httpx not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_the_real_binary_accepts_the_flag_set(level, tmp_path):
    """-nf must not collide with any other flag this stage passes.

    An unknown or conflicting flag is an ARG_ERROR, which aborts the entire
    run before a packet is sent -- so this is checked against the binary
    rather than against a constant.
    """
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out", level=level))
    assert preflight.validate_arguments(HttpxStage(), ctx) == ""
