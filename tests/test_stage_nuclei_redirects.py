"""nuclei must not follow a redirect off the allowlist.

THE ESCAPE, measured against the lab rather than reasoned about. An in-scope
URL (`/assets/js/legacy-tracker.js`) answers 302 with
`Location: http://offscope.example.test/leaked.js` -- a host in a different
registrable domain, in no allowlist. With sweeper's own flags, nuclei
FOLLOWED it:

    "matched-at": "http://offscope.example.test/leaked.js"
    curl-command: ... 'http://offscope.example.test/leaked.js'

and the target's off-scope tripwire recorded the hit. With `-dr` the same
scan is clean and the 302 is still reported, matched at the IN-SCOPE url --
so the finding survives and only the hop is refused.

WHY IT REACHES SO MANY TEMPLATES. The hop is not nuclei's CLI default; it
comes from `redirects: true` set inside individual template YAML, which 1575
shipped templates do -- including ones tagged `misconfiguration`, one of the
tags sweeper selects at every level. A per-template setting is not something
an allowlist can bound, which is exactly why the control has to be global.

Same defect and same fix as katana (commit "N1: a redirect is outside every
scope flag katana has, so refuse it"). The scope guard only ever sees the
URL sweeper hands the tool; the tool's own redirect handling is a second,
independent way out of scope, and it has to be closed per tool.

`-fhr` (follow same-host redirects only) also kept the tripwire clean when
measured, and would in principle preserve same-host hops that `-dr` gives
up. It is NOT used: no test here could demonstrate it actually following a
same-host redirect, and a control whose benefit cannot be shown is not worth
the ambiguity when the alternative is a proven fail-closed one.
"""
import pytest

from sweeper import binaries, preflight
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.base import LEVELS
from sweeper.stages.nuclei import NucleiStage


def ctx_for(tmp_path, level="mid"):
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out", level=level))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                           meta={"host": "acc.example"}))
    return ctx


@pytest.mark.parametrize("level", LEVELS)
def test_redirects_are_disabled_at_every_level(level, tmp_path):
    """Unconditional, like katana's -dr.

    A scope escape that only fails closed at some levels is not closed: the
    level chosen for an unfamiliar estate is the one most likely to meet an
    unexpected redirect.
    """
    argv = [str(a) for a in NucleiStage().build_command(ctx_for(tmp_path, level))]
    assert "-dr" in argv, f"{level} lets nuclei follow a redirect off-scope"


def test_the_enabling_flags_are_never_passed(tmp_path):
    """-fr / -fhr would re-open what -dr closes."""
    argv = [str(a) for a in NucleiStage().build_command(ctx_for(tmp_path))]
    assert "-fr" not in argv
    assert "-follow-redirects" not in argv


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("nuclei") is None,
                    reason="nuclei not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_the_real_binary_accepts_the_flag_set(level, tmp_path):
    """-dr must not collide with anything else this stage passes.

    An unknown or conflicting flag is an ARG_ERROR, which aborts the whole
    run before a packet is sent.
    """
    assert preflight.validate_arguments(NucleiStage(), ctx_for(tmp_path, level)) == ""
