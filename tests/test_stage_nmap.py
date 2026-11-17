from pathlib import Path
import pytest
from sweeper import binaries, preflight
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.nmap import NmapStage

FIX = Path(__file__).parent / "fixtures" / "nmap.xml"
COLLISION_FIX = Path(__file__).parent / "fixtures" / "nmap-tcp-udp-collision.xml"


def parsed():
    return list(NmapStage().parse(FIX))


def test_contract():
    assert registry.validate(NmapStage()) == []


def test_open_ports_enriched_with_service_and_version():
    a = next(a for a in parsed() if a.value == "acc.example:443")
    assert a.meta["service"] == "https"
    assert a.meta["product"] == "nginx"
    assert a.meta["version"] == "1.24.0"


def test_closed_ports_are_skipped():
    """parsed() also yields Finding objects (e.g. the OpenSSH match below),
    which have no .value — filter to Artifacts, the same way every other
    test in this file and test_stage_dnsx.py already does.
    """
    from sweeper.artifacts import Artifact
    ports = [a for a in parsed() if isinstance(a, Artifact)]
    assert not any(a.value.endswith(":8080") for a in ports)


def test_outdated_openssh_produces_a_finding():
    from sweeper.artifacts import Finding
    f = [x for x in parsed() if isinstance(x, Finding)]
    assert any("OpenSSH" in x.evidence for x in f)


# --- finding-id collision: tcp and udp sharing a port number ---------------
# target is host:portid only (no protocol) and template_id is derived from
# the service label, which nmap routinely assigns identically to tcp and
# udp on the same port (53/domain being the everyday case). Before the
# matcher fix, two GENUINELY DIFFERENT banners on the two protocols hashed
# to one finding_id and only the first-submitted survived
# store.add_finding().


def test_tcp_and_udp_on_the_same_port_produce_two_findings():
    from sweeper.artifacts import Finding
    findings = [f for f in NmapStage().parse(COLLISION_FIX) if isinstance(f, Finding)]
    assert len(findings) == 2
    assert {f.matcher for f in findings} == {"tcp:OpenSSH 6.6", "udp:OpenSSH 6.7"}


def test_tcp_and_udp_findings_have_distinct_ids():
    from sweeper.artifacts import Finding
    findings = [f for f in NmapStage().parse(COLLISION_FIX) if isinstance(f, Finding)]
    assert len({f.id for f in findings}) == 2
    # Same target and template_id -- the collision-prone pair -- is exactly
    # what makes the matcher the only thing keeping the ids apart.
    assert len({f.target for f in findings}) == 1
    assert len({f.template_id for f in findings}) == 1


def test_nmap_finding_ids_are_identical_across_two_parses_of_the_same_scan():
    """finding_id must stay stable across an identical rerun -- the matcher
    is derived from protocol+banner, never a timestamp or ordering index.
    """
    from sweeper.artifacts import Finding
    first = {f.id for f in NmapStage().parse(COLLISION_FIX) if isinstance(f, Finding)}
    second = {f.id for f in NmapStage().parse(COLLISION_FIX) if isinstance(f, Finding)}
    assert first == second
    assert len(first) == 2


def test_tcp_and_udp_findings_reach_the_store_with_no_collision(tmp_path):
    """End-to-end through the real store: both protocol-distinct findings
    must survive add_finding() with nothing recorded in finding_collisions.
    """
    from sweeper.store import ArtifactStore
    store = ArtifactStore(tmp_path)
    for f in NmapStage().parse(COLLISION_FIX):
        if hasattr(f, "matcher"):  # a Finding, not a PORT Artifact
            store.add_finding(f)
    assert len(store.findings) == 2
    assert store.finding_collisions == []


def test_level_flags_escalate():
    """Escalation is now carried by --version-intensity, not by -sC.

    -sC was dropped: it aborts nmap 7.98 with an NSE assertion failure
    (SIGABRT, stage produces nothing), and parse() never read its <script>
    output. See tests/test_stage_nmap_no_default_scripts.py.
    """
    s = NmapStage()
    assert s.levels["low"] == []
    assert "-sV" in s.levels["mid"]
    assert "-sV" in s.levels["high"]
    assert (s.levels["high"][s.levels["high"].index("--version-intensity") + 1]
            > s.levels["mid"][s.levels["mid"].index("--version-intensity") + 1])


# Every NSE category that is intrusive, DoS-adjacent, or an active attack.
# Verified against nmap 7.98: of the 127 scripts in the `default` category
# that -sC selects, ZERO are tagged `intrusive` or `dos`, so -sC is safe and
# these categories can only ever appear via an explicit --script request.
FORBIDDEN_SCRIPT_CATEGORIES = ("dos", "exploit", "intrusive", "brute", "vuln",
                               "malware", "fuzzer")


@pytest.mark.parametrize("level", LEVELS)
def test_no_intrusive_or_dos_adjacent_script_categories(level):
    """`-sC` is --script=default, a curated set excluding intrusive/dos.

    A guard narrower than the constraint it names is worse than no guard,
    because it reads as covered: checking only "vuln" would wave through
    `--script dos` or `--script brute`. The engagement's no-DoS/no-ReDoS
    constraint is a rules-of-engagement term, not a preference, and it binds
    every level — including timing, hence the -T check.
    """
    args = NmapStage().levels[level]
    joined = " ".join(args).lower()
    for category in FORBIDDEN_SCRIPT_CATEGORIES:
        assert category not in joined, \
            f"{level}: DoS-adjacent/intrusive script category {category!r} requested"
    assert not any(a.startswith("-T") for a in args), \
        f"{level}: explicit timing template requested"
    # --script in any form needs a human to check the requested categories
    # against the constraint above; -sC (the curated default set) is the only
    # script selection this stage is cleared for.
    assert not any(a.startswith("--script") for a in args), \
        f"{level}: explicit --script selection needs ROE review"


def ctx_for(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)
    )
    ctx.store.add(Artifact(ArtifactKind.PORT, "acc.example:443",
                            meta={"host": "acc.example", "port": "443"}))
    ctx.store.add(Artifact(ArtifactKind.PORT, "acc.example:22",
                            meta={"host": "acc.example", "port": "22"}))
    return ctx


def test_targets_go_through_a_file_not_bare_argv(tmp_path):
    """Bare hostname positional args are invisible to preflight's ".txt"
    substitution, so the real targets would be the ones the preflight
    dry-run actually contacts. Confirm nmap's targets are routed through a
    -iL file instead, the same idiom naabu/dnsx/httpx use.
    """
    cmd = NmapStage().build_command(ctx_for(tmp_path))
    assert "-iL" in cmd
    hosts_file = Path(cmd[cmd.index("-iL") + 1])
    assert hosts_file.suffix == ".txt"
    assert "acc.example" not in cmd  # not present as a bare positional arg
    assert "acc.example" in hosts_file.read_text()


def test_all_current_addresses_are_resolved_and_scanned(tmp_path):
    assert "--resolve-all" in NmapStage().build_command(ctx_for(tmp_path))


def test_p_flag_present_and_sorted_when_ports_are_known(tmp_path):
    cmd = NmapStage().build_command(ctx_for(tmp_path))
    assert "-p" in cmd
    assert cmd[cmd.index("-p") + 1] == "22,443"


def test_p_flag_omitted_when_store_has_no_ports_yet(tmp_path):
    """This is exactly preflight's own calling shape: preflight validates
    every stage's build_command() before ANY stage has run, so naabu (which
    produces the PORT artifacts this stage consumes) has not executed yet —
    ctx.store.get(PORT) is genuinely empty at that point even in a real run.
    `-p ""` makes nmap exit with "Error #485: Your port specifications are
    illegal", a message that matches none of preflight's ARG_ERROR_MARKERS,
    so it would silently "pass" a probe that never actually exercised
    whether -sV/-sC/--version-intensity are accepted. Omitting -p when there
    is nothing to scan avoids that trap.
    """
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    cmd = NmapStage().build_command(ctx)
    assert "-p" not in cmd


def test_xml_goes_to_stdout_not_a_side_file(tmp_path):
    """The runner captures a stage's stdout to raw/<stage>.jsonl (always
    that extension, regardless of the tool's real format — see
    ctx.raw_path) and hands THAT path to parse(). Writing XML to a separate
    "-oX <path>" file means parse() would never see it: `-oX -` is required
    so the XML actually lands in the file the runner passes to parse().
    """
    cmd = NmapStage().build_command(ctx_for(tmp_path))
    assert cmd[cmd.index("-oX") + 1] == "-"


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("nmap") is None,
                    reason="nmap not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    """Ask nmap itself whether each level's flag set parses.

    Probed with an empty PORT store, matching exactly how preflight itself
    calls build_command in a real run (before naabu has produced anything) —
    see test_p_flag_omitted_when_store_has_no_ports_yet for why that matters
    here specifically.
    """
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out",
                                      level=level))
    err = preflight.validate_arguments(NmapStage(), ctx)
    assert err == "", f"nmap rejected the {level!r} flag set: {err}"


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("nmap") is None,
                    reason="nmap not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_with_a_real_port_list(tmp_path, level):
    """Same probe, but with the PORT store populated the way it is by the
    time nmap actually executes in run_stages() (after naabu has run) —
    covers the -p branch that the empty-store probe above cannot reach.
    """
    ctx = ctx_for(tmp_path, level=level)
    err = preflight.validate_arguments(NmapStage(), ctx)
    assert err == "", f"nmap rejected the {level!r} flag set with -p set: {err}"


TRUNC = Path(__file__).parent / "fixtures" / "nmap-truncated.xml"


def test_truncated_xml_does_not_raise():
    """nmap emits ONE document, so truncation costs 100% of the scan.

    And truncation is routine, not exotic: runner.py's per-stage timeout
    kills the subprocess, keeps the partial stdout, marks the stage PARTIAL,
    then still calls parse() on it. The fixture is real nmap 7.98 output cut
    mid-element the way a SIGKILL leaves it -- ET.fromstring raises
    "unclosed token" on it.
    """
    assert isinstance(list(NmapStage().parse(TRUNC)), list)


def test_truncated_xml_still_yields_every_complete_host():
    """A scan that got 80% through should yield 80% of its data.

    The fixture holds one complete <host> plus a partial second one; the
    complete host's open port must survive.
    """
    from sweeper.artifacts import Artifact
    ports = [a for a in NmapStage().parse(TRUNC) if isinstance(a, Artifact)]
    assert "127.0.0.1:8080" in [a.value for a in ports]


def test_truncated_xml_skips_the_incomplete_host():
    """The partial element is dropped, not guessed at."""
    from sweeper.artifacts import Artifact
    ports = [a for a in NmapStage().parse(TRUNC) if isinstance(a, Artifact)]
    assert not any(a.value.startswith("127.0.0.2:") for a in ports)


def test_truncated_xml_recovers_the_same_data_as_the_intact_document(tmp_path):
    """Salvage is not a lossy special case: for the hosts that ARE complete,
    it must produce byte-identical artifacts to the normal parse path.
    """
    from sweeper.artifacts import Artifact
    full = TRUNC.read_text() + "\n</host>\n</nmaprun>\n"
    intact = tmp_path / "intact.xml"
    intact.write_text(full, encoding="utf-8")

    salvaged = [(a.value, a.meta) for a in NmapStage().parse(TRUNC)
                if isinstance(a, Artifact)]
    from_intact = [(a.value, a.meta) for a in NmapStage().parse(intact)
                   if isinstance(a, Artifact) and a.value.startswith("127.0.0.1:")]
    assert salvaged == from_intact


def test_garbage_that_is_not_xml_at_all_yields_nothing_rather_than_raising():
    """nmap writes plain-text errors to stdout in some failure modes."""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as fh:
        fh.write("QUITTING!\nsomething went wrong\n")
        p = Path(fh.name)
    assert list(NmapStage().parse(p)) == []


def test_host_block_scan_is_not_confused_by_hostnames_elements():
    """"<host" also prefixes "<hostnames"/"<hostname"; real nmap output has
    both inside every host element, so a naive prefix match mis-slices.
    """
    from sweeper.stages.nmap import complete_host_blocks
    text = ('<nmaprun><host><hostnames><hostname name="a.example"/>'
            '</hostnames></host></nmaprun>')
    assert list(complete_host_blocks(text)) == [
        '<host><hostnames><hostname name="a.example"/></hostnames></host>'
    ]


def test_host_port_falls_back_lazily_without_raising():
    """The eager default in `meta.get("port", value.rsplit(":", 1)[1])` raised
    IndexError on a colon-less value even when meta["port"] was present and
    the fallback was never going to be used.
    """
    from sweeper.artifacts import Artifact
    from sweeper.stages.nmap import host_port

    # meta present, value has no colon: must not raise, must prefer meta.
    a = Artifact(ArtifactKind.PORT, "acc.example",
                 meta={"host": "acc.example", "port": "443"})
    assert host_port(a) == ("acc.example", "443")

    # no meta at all, colon-less value: degrade, do not raise.
    b = Artifact(ArtifactKind.PORT, "acc.example")
    assert host_port(b) == ("acc.example", "")

    # no meta, normal value: split it.
    c = Artifact(ArtifactKind.PORT, "acc.example:8443")
    assert host_port(c) == ("acc.example", "8443")

    # IPv6-ish value with several colons: split on the LAST one.
    d = Artifact(ArtifactKind.PORT, "::1:443")
    assert host_port(d) == ("::1", "443")


def test_build_command_survives_a_colon_less_port_artifact(tmp_path):
    """Unreachable via naabu today, but a colon-less PORT artifact from any
    future producer must not crash command construction.
    """
    from sweeper.artifacts import Artifact
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.PORT, "acc.example",
                           meta={"host": "acc.example"}))
    cmd = NmapStage().build_command(ctx)      # must not raise
    assert "-p" not in cmd                    # no usable port number
