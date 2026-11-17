"""The operator's --rate ceiling must reach every active traffic stage."""
import urllib.error

from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.arjun import ArjunStage
from sweeper.stages.dnsx import DnsxStage
from sweeper.stages.httpx import HttpxStage
from sweeper.stages.katana import KatanaStage
from sweeper.stages.maildns import MaildnsStage
from sweeper.stages.nmap import NmapStage
from sweeper.stages.nmap_udp import NmapUdpStage
from sweeper.stages.nuclei import NucleiStage
from sweeper.stages.subfinder import SubfinderStage
from sweeper.stages.tlsx import TlsxStage
from sweeper.stages.vhost import VhostStage
from sweeper.stages import jsrecon as jsrecon_module


def context(tmp_path, rate=7):
    tmp_path.mkdir(parents=True, exist_ok=True)
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(
        targets_file=targets, outdir=tmp_path / "out", level="high",
        rate_override=rate,
    ))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    ctx.store.add(Artifact(
        ArtifactKind.PORT, "acc.example:443",
        meta={"host": "acc.example", "port": "443"},
    ))
    ctx.store.add(Artifact(
        ArtifactKind.HTTP_SERVICE, "https://acc.example/app.js",
        meta={"host": "acc.example", "port": "443", "status_code": 200,
              "content_type": "application/javascript"},
    ))
    return ctx


def value_after(cmd, flag):
    assert cmd.count(flag) == 1, cmd
    return cmd[cmd.index(flag) + 1]


def test_native_rate_flags_receive_the_override(tmp_path):
    cases = [
        (DnsxStage(), "-rl"),
        (SubfinderStage(), "-rl"),
        (HttpxStage(), "-rl"),
        (KatanaStage(), "-rl"),
        (NucleiStage(), "-rate-limit"),
        (VhostStage(), "-rate"),
        (ArjunStage(), "--rate-limit"),
    ]
    for index, (stage, flag) in enumerate(cases):
        cmd = stage.build_command(context(tmp_path / str(index)))
        assert value_after(cmd, flag) == "7", (stage.name, cmd)


def test_nmap_tcp_and_udp_receive_max_rate(tmp_path):
    for index, stage in enumerate((NmapStage(), NmapUdpStage())):
        cmd = stage.build_command(context(tmp_path / str(index)))
        assert value_after(cmd, "--max-rate") == "7"


def test_tlsx_serializes_workers_when_rate_is_operator_bounded(tmp_path):
    cmd = TlsxStage().build_command(context(tmp_path))
    assert value_after(cmd, "-c") == "1"
    assert value_after(cmd, "-cec") == "1"
    assert value_after(cmd, "-delay") == "143ms"


def test_maildns_translates_rate_to_inter_domain_wait(tmp_path):
    cmd = MaildnsStage().build_command(context(tmp_path, rate=2))
    assert value_after(cmd, "--wait") == "0.5"


def test_jsrecon_translates_rate_to_sequential_pause(tmp_path, monkeypatch):
    sleeps = []

    def no_network(*args, **kwargs):
        raise urllib.error.URLError("test")

    monkeypatch.setattr(jsrecon_module, "_urlopen", no_network)
    monkeypatch.setattr(jsrecon_module.time, "sleep", sleeps.append)
    ctx = context(tmp_path, rate=2)
    jsrecon_module.fetch_js(
        ctx,
        ["https://acc.example/a.js", "https://acc.example/b.js"],
        tmp_path / "js",
    )
    assert sleeps == [0.5]
