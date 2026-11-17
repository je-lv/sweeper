from pathlib import Path
import pytest
from sweeper import binaries, preflight
from sweeper.artifacts import ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.subfinder import SubfinderStage, confirm_discovered

FIX = Path(__file__).parent / "fixtures" / "subfinder.txt"


def ctx_for(tmp_path):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                       subdomain_enum=True))


def test_contract():
    assert registry.validate(SubfinderStage()) == []


def test_stage_is_optional_and_consumes_nothing():
    s = SubfinderStage()
    assert s.optional is True
    assert s.consumes is None


def test_parse_yields_discovered_hosts():
    vals = [a.value for a in SubfinderStage().parse(FIX)]
    assert "admin.acc.example" in vals
    assert len(vals) == 4


def test_discovered_hosts_are_marked_unconfirmed():
    a = next(iter(SubfinderStage().parse(FIX)))
    assert a.meta["confirmed"] is False
    assert a.meta["src"] == "subfinder"


def test_unconfirmed_hosts_are_not_in_scope(tmp_path):
    ctx = ctx_for(tmp_path)
    assert ctx.scope.allows("admin.acc.example") is False


def test_confirming_extends_scope_with_a_reason(tmp_path):
    ctx = ctx_for(tmp_path)
    n = confirm_discovered(ctx, ["admin.acc.example", "api.acc.example"],
                           approved=["admin.acc.example"])
    assert n == 1
    assert ctx.scope.allows("admin.acc.example") is True
    assert ctx.scope.allows("api.acc.example") is False
    assert ctx.scope.extensions[0]["reason"].startswith("operator-confirmed")


def test_confirming_none_widens_nothing(tmp_path):
    ctx = ctx_for(tmp_path)
    assert confirm_discovered(ctx, ["admin.acc.example"], approved=[]) == 0
    assert ctx.scope.extensions == []


def test_confirmed_hosts_enter_the_store(tmp_path):
    ctx = ctx_for(tmp_path)
    confirm_discovered(ctx, ["admin.acc.example"], approved=["admin.acc.example"])
    assert "admin.acc.example" in ctx.store.values(ArtifactKind.HOST)


def test_cannot_approve_a_host_that_was_not_discovered(tmp_path):
    ctx = ctx_for(tmp_path)
    with pytest.raises(ValueError, match="not discovered"):
        confirm_discovered(ctx, ["admin.acc.example"], approved=["evil.test"])


def test_unapproved_hosts_never_enter_the_store(tmp_path):
    """The central risk this stage exists to guard against: a host subfinder
    discovers but the operator does NOT approve must never reach the shared
    artifact pool other stages read from -- not "filtered later", absent.
    """
    ctx = ctx_for(tmp_path)
    discovered = [a.value for a in SubfinderStage().parse(FIX)]
    confirm_discovered(ctx, discovered, approved=["admin.acc.example"])
    stored = ctx.store.values(ArtifactKind.HOST)
    assert "admin.acc.example" in stored
    for host in discovered:
        if host != "admin.acc.example":
            assert host not in stored


def test_parse_does_not_write_to_the_store_by_itself(tmp_path):
    """parse() is a pure generator like every other stage's. Nothing about
    calling it -- the same call the runner makes for every stage -- may put
    a discovered host into ctx.store; only confirm_discovered() may do that.
    """
    ctx = ctx_for(tmp_path)
    list(SubfinderStage().parse(FIX))
    assert ctx.store.values(ArtifactKind.HOST) == []


def test_pending_hosts_tracks_the_last_parse(tmp_path):
    stage = SubfinderStage()
    discovered = [a.value for a in stage.parse(FIX)]
    assert set(stage.pending_hosts) == set(discovered)


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("subfinder") is None,
                    reason="subfinder not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    """Ask subfinder itself whether each level's flag set parses.

    Same convention as dnsx/naabu/cdncheck: several plan defects in this
    project have been an invented flag that only a real binary invocation
    catches.
    """
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out",
                                      level=level))
    err = preflight.validate_arguments(SubfinderStage(), ctx)
    assert err == "", f"subfinder rejected the {level!r} flag set: {err}"
