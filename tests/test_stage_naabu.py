from pathlib import Path
import json
import pytest
from sweeper import binaries, preflight
from sweeper.artifacts import ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.naabu import NaabuStage

FIX = Path(__file__).parent / "fixtures" / "naabu.jsonl"


def test_stage_satisfies_contract():
    assert registry.validate(NaabuStage()) == []


def test_ports_parsed_as_host_colon_port():
    vals = [a.value for a in NaabuStage().parse(FIX)]
    assert "acc.example:443" in vals
    assert "acc.example:80" in vals


def test_duplicate_rows_are_deduped():
    vals = [a.value for a in NaabuStage().parse(FIX)]
    assert vals.count("acc.example:443") == 1


def test_row_without_host_falls_back_to_ip():
    vals = [a.value for a in NaabuStage().parse(FIX)]
    assert "93.184.216.35:8080" in vals


def test_tls_flag_preserved_in_meta():
    a = next(a for a in NaabuStage().parse(FIX) if a.value == "acc.example:443")
    assert a.meta["tls"] is True


def test_port_ranges_widen_with_level():
    """Pin the actual port specification per level, not just "a flag with a
    dash appears somewhere" -- "-" in " ".join(...) is satisfied by ANY
    flag prefix (-top-ports, -rate, ...) regardless of what the level
    actually scans, so it asserted nothing about the level -> port-range
    mapping. That mapping is the DoS-adjacency control: `high`/`full`
    scanning all 65535 ports vs `low`/`mid` scanning a small top-N is
    exactly the distinction the confirmation gates (C1/I5) exist to guard.
    """
    s = NaabuStage()
    assert s.levels["low"][:2] == ["-top-ports", "100"]
    assert s.levels["mid"][:2] == ["-top-ports", "1000"]
    assert s.levels["high"][:2] == ["-p", "1-65535"]
    assert s.levels["full"][:2] == ["-p", "1-65535"]
    # Genuinely widening: low scans fewer ports than mid, and neither
    # low nor mid scans the full range that high/full do.
    assert s.levels["low"] != s.levels["mid"]
    assert "-p" not in s.levels["low"] and "-p" not in s.levels["mid"]


def ctx_for(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)
    )


def test_rate_override_replaces_the_level_rate_rather_than_duplicating(tmp_path):
    """One -rate on the line, carrying the override's value.

    Appending a second -rate works against naabu only because Go's flag
    package takes the last occurrence — parser luck, not construction.
    clap-based tools reject duplicate arguments outright, and
    "error: the argument" / "cannot be used with" are in
    ARG_ERROR_MARKERS, so preflight would classify that as ARG_ERROR and
    abort the whole run. The next stage that copies this pattern for a
    non-Go binary must not inherit the bug.
    """
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level="mid",
                                             rate_override=42))
    assert cmd.count("-rate") == 1
    assert cmd[cmd.index("-rate") + 1] == "42"
    assert "500" not in cmd          # the mid level's own rate is gone


def test_rate_override_replaces_at_every_level(tmp_path):
    for level in LEVELS:
        cmd = NaabuStage().build_command(
            ctx_for(tmp_path, level=level, rate_override=7)
        )
        assert cmd.count("-rate") == 1, f"{level}: {cmd}"
        assert cmd[cmd.index("-rate") + 1] == "7"


def test_without_an_override_the_level_rate_survives_intact(tmp_path):
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level="mid"))
    assert cmd.count("-rate") == 1
    assert cmd[cmd.index("-rate") + 1] == "500"


def test_every_resolved_address_is_scanned(tmp_path):
    cmd = NaabuStage().build_command(ctx_for(tmp_path))
    assert "-scan-all-ips" in cmd


def test_rows_for_multiple_addresses_are_preserved_in_meta(tmp_path):
    raw = tmp_path / "naabu.jsonl"
    rows = [
        {"host": "acc.example", "ip": "192.0.2.1", "port": 443},
        {"host": "acc.example", "ip": "192.0.2.2", "port": 443},
    ]
    raw.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    [artifact] = list(NaabuStage().parse(raw))
    assert artifact.value == "acc.example:443"
    assert artifact.meta["ips"] == ["192.0.2.1", "192.0.2.2"]


def test_rate_override_does_not_eat_neighbouring_flags(tmp_path):
    """Stripping -rate must remove exactly the flag and its value.

    An off-by-one in the skip logic would silently drop -top-ports or its
    value, quietly changing what gets scanned.
    """
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level="mid",
                                             rate_override=42))
    assert "-top-ports" in cmd
    assert cmd[cmd.index("-top-ports") + 1] == "1000"


# --- --ports: the operator's own selection --------------------------------
# See tests/test_ports_override.py for why this exists. Here we only care
# that the flag REPLACES the level's port selection rather than joining it:
# a command carrying both "-p 1-65535" and "-p 80,443" has not been narrowed.


def test_a_top_n_override_replaces_the_levels_full_range(tmp_path):
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level="high",
                                             ports="top-100"))
    assert cmd.count("-top-ports") == 1
    assert cmd[cmd.index("-top-ports") + 1] == "100"
    assert "-p" not in cmd            # high's own -p 1-65535 is gone
    assert "1-65535" not in cmd


def test_an_explicit_list_override_replaces_the_levels_full_range(tmp_path):
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level="high",
                                             ports="80,443,8443"))
    assert cmd.count("-p") == 1
    assert cmd[cmd.index("-p") + 1] == "80,443,8443"
    assert "1-65535" not in cmd


def test_an_override_replaces_the_top_ports_form_too(tmp_path):
    """low/mid select ports with -top-ports, high/full with -p. An override
    has to strip whichever form the level used, not just the one it shares a
    flag name with."""
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level="mid",
                                             ports="80,443"))
    assert "-top-ports" not in cmd
    assert "1000" not in cmd
    assert cmd[cmd.index("-p") + 1] == "80,443"


@pytest.mark.parametrize("level", LEVELS)
def test_an_override_replaces_at_every_level(tmp_path, level):
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level=level,
                                             ports="top-50"))
    assert cmd.count("-top-ports") == 1, f"{level}: {cmd}"
    assert cmd[cmd.index("-top-ports") + 1] == "50"
    assert "-p" not in cmd, f"{level}: {cmd}"


def test_without_an_override_the_levels_own_selection_survives(tmp_path):
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level="high"))
    assert cmd[cmd.index("-p") + 1] == "1-65535"


def test_stripping_the_port_flag_does_not_eat_the_rate(tmp_path):
    """The mirror of the -rate test above. An off-by-one in either skip
    would silently change the other control -- and -rate is the client's
    no-DoS engagement term."""
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level="high",
                                             ports="top-100"))
    assert cmd.count("-rate") == 1
    assert cmd[cmd.index("-rate") + 1] == "800"


def test_ports_and_rate_overrides_coexist_each_appearing_once(tmp_path):
    cmd = NaabuStage().build_command(ctx_for(tmp_path, level="high",
                                             ports="80,443", rate_override=10))
    assert cmd.count("-p") == 1
    assert cmd.count("-rate") == 1
    assert cmd[cmd.index("-p") + 1] == "80,443"
    assert cmd[cmd.index("-rate") + 1] == "10"
    assert "1-65535" not in cmd and "800" not in cmd


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("naabu") is None,
                    reason="naabu not installed; cannot probe the real binary")
@pytest.mark.parametrize("ports", ["top-100", "80,443,8443", "1-1024"])
def test_override_flag_sets_are_accepted_by_the_real_binary(tmp_path, ports):
    """Same reasoning as the per-level probe below: ask naabu itself.

    A rewritten command that naabu rejects is an ARG_ERROR, and preflight
    aborts the whole run on one -- so a narrowed scan would fail to start
    rather than scan narrowly.
    """
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out",
                                      level="high", ports=ports))
    err = preflight.validate_arguments(NaabuStage(), ctx)
    assert err == "", f"naabu rejected --ports {ports!r}: {err}"


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("naabu") is None,
                    reason="naabu not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    """Ask naabu itself whether each level's flag set parses.

    A flag that takes a value but is passed bare makes the binary emit
    "flag needs an argument", one of preflight's ARG_ERROR_MARKERS, which
    aborts the ENTIRE run before a single target is touched. Probing the
    real binary catches that and any future defect in the same family
    (unknown flag, missing value, unparseable value) without hardcoding
    flag names.
    """
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out",
                                      level=level))
    err = preflight.validate_arguments(NaabuStage(), ctx)
    assert err == "", f"naabu rejected the {level!r} flag set: {err}"
