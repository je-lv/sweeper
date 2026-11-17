from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.cdncheck import CdncheckStage
from sweeper.stages.dnsx import DnsxStage
from sweeper.stages.httpx import HttpxStage
from sweeper.stages.katana import KatanaStage
from sweeper.stages.naabu import NaabuStage
from sweeper.stages.subfinder import SubfinderStage
from sweeper.stages.tlsx import TlsxStage


def test_projectdiscovery_update_checks_are_disabled(tmp_path):
    """Assessment tools must not call vendor infrastructure implicitly."""
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(
        targets_file=targets,
        outdir=tmp_path / "out",
        proxy="http://127.0.0.1:8080",
    ))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    ctx.store.add(Artifact(ArtifactKind.PORT, "acc.example:443",
                           meta={"host": "acc.example", "port": "443"}))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                           "https://acc.example/",
                           meta={"host": "acc.example", "port": "443"}))

    stages = (
        NaabuStage(), DnsxStage(), HttpxStage(), TlsxStage(),
        KatanaStage(), SubfinderStage(), CdncheckStage(),
    )
    for stage in stages:
        command = stage.build_command(ctx)
        assert command.count("-duc") == 1, (stage.name, command)
