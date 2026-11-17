"""Which ports tlsx is asked about.

THE DEFECT. The stage selected ports with
`a.meta.get("tls") or a.value.endswith((":443", ":8443"))`, and the first
half of that never fires: `meta["tls"]` comes from naabu, which does not do
TLS detection and reports False for everything (verified across a full run --
56 PORT artifacts, zero with tls=true). So selection was, in practice, a
hardcoded two-port list.

That is backwards. TLS on a NON-standard port is a thing worth finding, not
a thing to assume away, and the assumption silently removed whole ports from
the one stage that can judge them. Measured against the lab, which serves a
different broken certificate on each of 443/8443/9443/10443:

    :9443   CN=totally-different-host  -> hostname mismatch   MISSED
    :10443  TLS 1.0/1.1, no forward secrecy -> weak protocol  MISSED

Neither port is exotic; they were simply not in the literal.

tlsx is the tool whose entire job is deciding whether something speaks TLS.
It handles a non-TLS port correctly by emitting nothing for it (verified:
port 80 in a mixed list produces no row and no error), and it defaults to
300-way concurrency with a 5s timeout, so the cost of asking about a port
that turns out to be plain HTTP is negligible. Ask about all of them.
"""
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.tlsx import TlsxStage


def ctx_with_ports(tmp_path, ports):
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    for value, meta in ports:
        ctx.store.add(Artifact(ArtifactKind.PORT, value, meta=meta))
    return ctx


def input_lines(ctx):
    TlsxStage().build_command(ctx)
    return [l for l in (ctx.run_dir / "raw" / "tlsx-input.txt")
            .read_text(encoding="utf-8").splitlines() if l.strip()]


def test_non_standard_tls_ports_are_probed(tmp_path):
    """The two ports the old literal dropped, both carrying a real defect."""
    ctx = ctx_with_ports(tmp_path, [
        ("acc.example:9443", {"host": "acc.example", "port": "9443", "tls": False}),
        ("acc.example:10443", {"host": "acc.example", "port": "10443", "tls": False}),
    ])
    lines = input_lines(ctx)
    assert "acc.example:9443" in lines
    assert "acc.example:10443" in lines


def test_the_standard_ports_are_still_probed(tmp_path):
    ctx = ctx_with_ports(tmp_path, [
        ("acc.example:443", {"host": "acc.example", "port": "443", "tls": False}),
        ("acc.example:8443", {"host": "acc.example", "port": "8443", "tls": False}),
    ])
    lines = input_lines(ctx)
    assert "acc.example:443" in lines
    assert "acc.example:8443" in lines


def test_a_plain_http_port_is_still_asked_about(tmp_path):
    """Not an oversight -- the point.

    Deciding in advance that :80 cannot be TLS is the same assumption that
    lost :9443. tlsx answers "no TLS here" by emitting nothing, which costs
    one timed-out handshake out of 300 concurrent ones.
    """
    ctx = ctx_with_ports(tmp_path, [
        ("acc.example:80", {"host": "acc.example", "port": "80", "tls": False}),
    ])
    assert input_lines(ctx) == ["acc.example:80"]


def test_out_of_scope_ports_are_still_refused(tmp_path):
    """Widening the port selection must not widen SCOPE."""
    ctx = ctx_with_ports(tmp_path, [
        ("acc.example:443", {"host": "acc.example", "port": "443"}),
        ("evil.example:443", {"host": "evil.example", "port": "443"}),
    ])
    lines = input_lines(ctx)
    assert "acc.example:443" in lines
    assert not any("evil.example" in l for l in lines)
