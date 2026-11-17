"""nuclei must be given the non-HTTP services too.

The stage consumed HTTP_SERVICE alone, so nuclei only ever saw web URLs.
Every network-protocol template in the library was therefore unreachable no
matter what was discovered: on this box that is 20 SNMP templates, 157 SSH,
3 SMTP user-enumeration, plus the FTP, database and network-level TLS checks.

naabu finds those ports and tlsx probes their certificates, so the services
were discovered, listed in the asset inventory, and then never assessed --
the exact shape of gap this project keeps finding, and invisible because the
stage still reports `complete`.

The web URLs stay as they are: nuclei needs the scheme to run HTTP templates,
and `host:port` alone would demote every web finding to a network one.
"""
from pathlib import Path

from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.nuclei import NucleiStage


def ctx_for(tmp_path, http=(), ports=()):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    for u in http:
        ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, u))
    for p in ports:
        host, _, port = p.rpartition(":")
        ctx.store.add(Artifact(ArtifactKind.PORT, p,
                               meta={"host": host, "port": port}))
    return ctx


def input_lines(tmp_path, **kw):
    ctx = ctx_for(tmp_path, **kw)
    NucleiStage().build_command(ctx)
    return (ctx.run_dir / "raw" / "nuclei-input.txt").read_text().split()


def test_non_http_services_are_given_to_nuclei(tmp_path):
    lines = input_lines(tmp_path,
                        http=("https://acc.example:443",),
                        ports=("acc.example:22", "acc.example:161",
                               "acc.example:25"))
    assert "acc.example:22" in lines, "SSH port withheld from nuclei"
    assert "acc.example:161" in lines, "SNMP port withheld from nuclei"
    assert "acc.example:25" in lines, "SMTP port withheld from nuclei"


def test_web_urls_are_still_passed_with_their_scheme(tmp_path):
    """Without the scheme nuclei runs network templates against a web port
    and every HTTP template is skipped."""
    lines = input_lines(tmp_path, http=("https://acc.example:443",),
                        ports=("acc.example:443",))
    assert "https://acc.example:443" in lines


def test_a_port_already_covered_as_a_web_service_is_not_duplicated(tmp_path):
    """Scanning the same endpoint twice doubles the traffic to a client for
    no extra coverage."""
    lines = input_lines(tmp_path, http=("https://acc.example:443",),
                        ports=("acc.example:443",))
    assert "acc.example:443" not in lines


def test_out_of_scope_ports_are_never_passed(tmp_path):
    """Admission control applies to this input exactly as it does to the
    HTTP services -- a port artifact is not a licence to scan its host."""
    ctx = ctx_for(tmp_path, ports=("acc.example:22",))
    ctx.store.add(Artifact(ArtifactKind.PORT, "evil.test:22",
                           meta={"host": "evil.test", "port": "22"}))
    NucleiStage().build_command(ctx)
    lines = (ctx.run_dir / "raw" / "nuclei-input.txt").read_text()
    assert "evil.test" not in lines


def test_the_stage_declares_that_it_consumes_ports(tmp_path):
    """The registry orders stages by what they consume. A stage that reads
    PORT artifacts without declaring it can be scheduled before naabu."""
    from sweeper.stages import registry
    assert registry.validate(NucleiStage()) == []
