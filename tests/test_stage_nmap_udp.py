from pathlib import Path

from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.nmap_udp import NmapUdpStage


FIX = Path(__file__).parent / "fixtures" / "nmap-tcp-udp-collision.xml"


def ctx_for(tmp_path, **kwargs):
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(
        targets_file=targets, outdir=tmp_path / "out", **kwargs,
    ))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    return ctx


def test_contract():
    assert registry.validate(NmapUdpStage()) == []


def test_parser_keeps_only_udp_and_uses_distinct_artifact_kind():
    parsed = list(NmapUdpStage().parse(FIX))
    ports = [x for x in parsed if isinstance(x, Artifact)]
    findings = [x for x in parsed if isinstance(x, Finding)]
    assert [(x.kind, x.value) for x in ports] == [
        (ArtifactKind.UDP_PORT, "acc.example:53"),
    ]
    assert ports[0].meta["protocol"] == "udp"
    assert len(findings) == 1
    assert findings[0].stage == "nmap_udp"
    assert findings[0].target == "acc.example:53/udp"


def test_mid_defaults_to_top_100_udp_ports(tmp_path):
    cmd = NmapUdpStage().build_command(ctx_for(tmp_path))
    assert "-sU" in cmd
    assert cmd[cmd.index("--top-ports") + 1] == "100"


def test_udp_port_override_replaces_level_default(tmp_path):
    cmd = NmapUdpStage().build_command(ctx_for(tmp_path, udp_ports="53,161"))
    assert "--top-ports" not in cmd
    assert cmd[cmd.index("-p") + 1] == "53,161"


def test_high_defaults_to_top_1000_udp_ports(tmp_path):
    cmd = NmapUdpStage().build_command(ctx_for(tmp_path, level="high"))
    assert cmd[cmd.index("--top-ports") + 1] == "1000"


def test_open_filtered_udp_is_preserved_as_candidate(tmp_path):
    raw = tmp_path / "udp.xml"
    raw.write_text("""<?xml version='1.0'?>
<nmaprun><host><address addr='192.0.2.4' addrtype='ipv4'/>
<hostnames><hostname name='acc.example'/></hostnames><ports>
<port protocol='udp' portid='161'><state state='open|filtered'/></port>
</ports></host></nmaprun>""")
    ports = [x for x in NmapUdpStage().parse(raw) if isinstance(x, Artifact)]
    assert len(ports) == 1
    assert ports[0].value == "acc.example:161"
    assert ports[0].meta["state"] == "open|filtered"
