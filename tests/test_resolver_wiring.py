"""--resolver, end to end: config -> argv -> manifest.

The load-bearing test here is
test_honors_resolver_matches_what_build_command_actually_does. Every other
check in this file pins one stage; that one makes the CLAIM and the ARGV
impossible to drift apart, which is the failure this whole feature is
vulnerable to -- a stage that says it honours the resolver and silently
does not is exactly the "ran, exited 0, found nothing" defect the flag
exists to fix, only harder to see.
"""
from pathlib import Path

import pytest

from sweeper import binaries, preflight, resolvers
from sweeper.app import ALL_STAGES
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.base import LEVELS

RESOLVER = "127.0.0.1:15353"


def make_ctx(tmp_path, resolver=RESOLVER, level="mid"):
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out",
                                      level=level,
                                      resolver=resolver))
    # Seed one artifact of every kind a stage might consume, so that
    # build_command has something to write into its input file.
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    ctx.store.add(Artifact(ArtifactKind.PORT, "acc.example:443",
                           meta={"tls": True}))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                           meta={"content_type": "application/javascript"}))
    return ctx


def argv_of(stage, ctx):
    return [str(a) for a in stage.build_command(ctx)]


def resolver_is_in(argv, ctx):
    """Did this argv actually carry the resolver, by value or by file?"""
    if RESOLVER in " ".join(argv):
        return True
    # nuclei takes a FILE of resolvers rather than a list. Only files the run
    # itself wrote are inspected -- argv[0] is the tool BINARY, and reading
    # that as text is both meaningless and a UnicodeDecodeError.
    raw_dir = ctx.run_dir / "raw"
    for arg in argv:
        p = Path(arg)
        if p.parent != raw_dir or not p.is_file():
            continue
        try:
            if RESOLVER in p.read_text(encoding="utf-8"):
                return True
        except (OSError, UnicodeDecodeError):
            continue
    return False


@pytest.mark.parametrize("cls", ALL_STAGES, ids=lambda c: c().name)
def test_honors_resolver_matches_what_build_command_actually_does(cls, tmp_path):
    """The declaration and the argv must agree, for every stage.

    A stage claiming honors_resolver = True whose build_command forgets to
    append the flag would run against the WRONG nameserver while run.json
    reported it as honouring the operator's -- worse than not supporting it
    at all, because the manifest actively vouches for it.
    """
    stage = cls()
    ctx = make_ctx(tmp_path)
    claimed = bool(getattr(stage, "honors_resolver", False))
    actual = resolver_is_in(argv_of(stage, ctx), ctx)
    assert claimed == actual, (
        f"{stage.name}: honors_resolver={claimed} but the resolver "
        f"{'IS' if actual else 'is NOT'} in its command"
    )


@pytest.mark.parametrize("cls", ALL_STAGES, ids=lambda c: c().name)
def test_no_stage_carries_a_resolver_when_none_was_configured(cls, tmp_path):
    """Empty --resolver must reproduce the pre-flag argv exactly."""
    stage = cls()
    ctx = make_ctx(tmp_path, resolver="")
    argv = argv_of(stage, ctx)
    assert "-r" not in argv
    assert "--dns-servers" not in argv


@pytest.mark.parametrize("cls", ALL_STAGES, ids=lambda c: c().name)
def test_every_stage_declares_resolver_support_explicitly(cls):
    """No stage may leave the question unanswered.

    getattr-with-default would let a NEW stage silently join the
    system_dns bucket in run.json without its author ever considering the
    question. The attribute is required, and must be a bool.
    """
    stage = cls()
    assert hasattr(stage, "honors_resolver"), (
        f"{stage.name} does not declare honors_resolver"
    )
    assert isinstance(stage.honors_resolver, bool)


@pytest.mark.parametrize("cls", ALL_STAGES, ids=lambda c: c().name)
def test_non_honoring_stages_say_why(cls):
    """A False needs a reason, or the manifest records an unexplained gap."""
    stage = cls()
    if stage.honors_resolver:
        return
    note = getattr(stage, "resolver_note", "")
    assert note and isinstance(note, str), (
        f"{stage.name} declines the resolver without a resolver_note"
    )


def test_build_command_is_deterministic_with_a_resolver(tmp_path):
    """preflight validates the argv the runner will execute, not another one."""
    from sweeper.stages.dnsx import DnsxStage
    ctx = make_ctx(tmp_path)
    stage = DnsxStage()
    assert argv_of(stage, ctx) == argv_of(stage, ctx)


def test_nuclei_gets_a_file_not_a_list(tmp_path):
    """nuclei's -r is the odd one out: a path, not a comma-separated value.

    Passing the list form makes nuclei try to open "127.0.0.1:15353" as a
    filename, which is not an argument error -- it starts, finds no
    resolvers, and scans anyway.
    """
    from sweeper.stages.nuclei import NucleiStage
    argv = argv_of(NucleiStage(), make_ctx(tmp_path))
    idx = argv.index("-r")
    value = Path(argv[idx + 1])
    assert value.is_file(), "nuclei -r must be given a path"
    assert value.read_text(encoding="utf-8").strip() == RESOLVER


def test_resolver_file_lives_in_the_run_evidence_dir(tmp_path):
    from sweeper.stages.nuclei import NucleiStage
    ctx = make_ctx(tmp_path)
    argv = argv_of(NucleiStage(), ctx)
    path = Path(argv[argv.index("-r") + 1])
    assert path.parent == ctx.run_dir / "raw"


def test_manifest_records_the_resolver_split(tmp_path):
    ctx = make_ctx(tmp_path)
    ctx.resolver_support = {"dnsx": True, "vhost": False, "arjun": False}
    ctx.write_manifest([])
    import json
    manifest = json.loads((ctx.run_dir / "run.json").read_text())
    block = manifest["resolver"]
    assert block["value"] == RESOLVER
    assert block["entries"] == [RESOLVER]
    assert block["honored_by"] == ["dnsx"]
    assert block["system_dns"] == ["arjun", "vhost"]


def test_manifest_resolver_block_survives_a_bad_value(tmp_path):
    """write_manifest is the record of WHY a run died; it must not die too."""
    ctx = make_ctx(tmp_path, resolver="")
    ctx.config.resolver = "not-an-ip"
    ctx.write_manifest([])
    import json
    manifest = json.loads((ctx.run_dir / "run.json").read_text())
    assert manifest["resolver"]["value"] == "not-an-ip"
    assert manifest["resolver"]["entries"] == []


def test_config_roundtrips_through_the_manifest(tmp_path):
    """--resume must not silently drop the resolver.

    A resumed run that reverts to the scanning box's own DNS would rescan a
    split-horizon scope as NXDOMAIN and record it as a completed run.
    """
    ctx = make_ctx(tmp_path)
    assert ctx.config.to_manifest()["resolver"] == RESOLVER


@pytest.mark.slow
@pytest.mark.parametrize("cls", [c for c in ALL_STAGES
                                 if getattr(c, "honors_resolver", False)],
                         ids=lambda c: c().name)
def test_the_real_binary_accepts_the_resolver_flag(cls, tmp_path):
    """Ask each tool itself whether its resolver flag parses.

    The flag differs per tool (-r as a list for most, -r as a FILE for
    nuclei) and a wrong form is an ARG_ERROR that aborts the entire run
    before a packet is sent. Probing the real binary is the only check that
    cannot be fooled by a plausible-looking constant.
    """
    stage = cls()
    if binaries.resolve(stage.requires[0]) is None:
        pytest.skip(f"{stage.requires[0]} not installed")
    ctx = make_ctx(tmp_path)
    err = preflight.validate_arguments(stage, ctx)
    assert err == "", f"{stage.name} rejected the resolver flag: {err}"
