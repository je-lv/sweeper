from pathlib import Path
import json
import pytest
from sweeper import binaries, preflight
from sweeper.artifacts import ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.httpx import HttpxStage
from sweeper.useragents import USER_AGENTS

FIX = Path(__file__).parent / "fixtures" / "httpx.jsonl"


def test_stage_satisfies_contract():
    assert registry.validate(HttpxStage()) == []


def test_consumes_ports_produces_services():
    s = HttpxStage()
    assert s.consumes is ArtifactKind.PORT
    assert s.produces == {ArtifactKind.HTTP_SERVICE}


def test_live_services_parsed_as_urls():
    vals = [a.value for a in HttpxStage().parse(FIX)]
    assert "https://acc.example" in vals
    assert "http://acc.example" in vals


def test_failed_rows_are_skipped():
    vals = [a.value for a in HttpxStage().parse(FIX)]
    assert not any("8080" in v for v in vals)


def test_burp_connection_error_page_is_not_a_service(tmp_path):
    raw = tmp_path / "httpx.jsonl"
    raw.write_text(json.dumps({
        "url": "http://acc.example:53",
        "host": "acc.example",
        "port": "53",
        "scheme": "http",
        "status_code": 200,
        "title": "Burp Suite",
        "failed": False,
        "knowledgebase": {"PageType": "error", "pHash": 0},
    }) + "\n")
    assert list(HttpxStage().parse(raw)) == []


def test_real_page_named_burp_suite_is_not_dropped_without_error_fingerprint(tmp_path):
    raw = tmp_path / "httpx.jsonl"
    raw.write_text(json.dumps({
        "url": "https://acc.example",
        "host": "acc.example",
        "port": "443",
        "scheme": "https",
        "status_code": 200,
        "title": "Burp Suite",
        "failed": False,
    }) + "\n")
    assert [a.value for a in HttpxStage().parse(raw)] == ["https://acc.example"]


def test_metadata_captured():
    a = next(a for a in HttpxStage().parse(FIX) if a.value == "https://acc.example")
    assert a.meta["status_code"] == 200
    assert a.meta["title"] == "ACC Shop"
    assert a.meta["webserver"] == "nginx"
    assert "Nginx" in a.meta["tech"]


def test_resolved_and_observed_addresses_are_preserved(tmp_path):
    raw = tmp_path / "httpx.jsonl"
    raw.write_text(json.dumps({
        "url": "https://acc.example",
        "host": "acc.example",
        "port": "443",
        "scheme": "https",
        "status_code": 200,
        "a": ["192.0.2.10", "192.0.2.11"],
        "ip": "192.0.2.12",
        "failed": False,
    }) + "\n")

    [artifact] = HttpxStage().parse(raw)
    assert artifact.meta["ips"] == [
        "192.0.2.10", "192.0.2.11", "192.0.2.12",
    ]


def test_missing_optional_fields_do_not_crash():
    a = next(a for a in HttpxStage().parse(FIX) if a.value == "http://acc.example")
    assert a.meta["title"] == ""


def ctx_for(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)
    )


def test_build_command_sends_a_browser_user_agent(tmp_path):
    """The UA must actually reach the command line, not just exist.

    useragents is unit-tested in isolation, so a refactor could drop the
    call from build_command and every test would still pass — while every
    scan quietly became a measurement of the target's WAF rather than of
    the application. This pins the wiring.
    """
    cmd = HttpxStage().build_command(ctx_for(tmp_path))
    assert "-H" in cmd
    value = cmd[cmd.index("-H") + 1]
    assert value.startswith("User-Agent: Mozilla/5.0")
    assert value[len("User-Agent: "):] in USER_AGENTS


def test_build_command_probes_every_resolved_address(tmp_path):
    assert "-probe-all-ips" in HttpxStage().build_command(ctx_for(tmp_path))


def test_proxy_disables_direct_per_address_probing(tmp_path):
    cmd = HttpxStage().build_command(ctx_for(
        tmp_path, proxy="http://127.0.0.1:8080"))
    assert "-proxy" in cmd
    assert "-probe-all-ips" not in cmd


def test_user_agent_is_sent_at_every_level(tmp_path):
    for level in LEVELS:
        cmd = HttpxStage().build_command(ctx_for(tmp_path, level=level))
        assert "-H" in cmd, f"{level} sends no User-Agent"
        assert cmd[cmd.index("-H") + 1][len("User-Agent: "):] in USER_AGENTS


def test_no_tool_signature_appears_in_the_user_agent(tmp_path):
    """Nothing in the UA should announce a scanner to a WAF."""
    cmd = HttpxStage().build_command(ctx_for(tmp_path))
    ua = cmd[cmd.index("-H") + 1].lower()
    for token in ("curl", "python-requests", "nuclei", "ffuf", "go-http-client"):
        assert token not in ua


def test_build_command_is_deterministic_for_one_context(tmp_path):
    """The regression guard for the whole non-determinism defect.

    A fresh UA draw per call made build_command return a different argv each
    time, so preflight validated a command line the runner never executed and
    the command recorded in run.json could not be replayed.

    Repeated rather than called twice on purpose: the shortlist has only six
    entries, so two calls under the old per-call draw would coincide about one
    time in six and the guard would pass by luck. Twenty identical calls make
    that (1/6)**19.
    """
    ctx = ctx_for(tmp_path)
    stage = HttpxStage()
    argvs = {tuple(stage.build_command(ctx)) for _ in range(20)}
    assert len(argvs) == 1, "build_command is not deterministic for a fixed ctx"


def test_build_command_sends_the_contexts_chosen_user_agent(tmp_path):
    ctx = ctx_for(tmp_path)
    cmd = HttpxStage().build_command(ctx)
    assert cmd[cmd.index("-H") + 1] == f"User-Agent: {ctx.user_agent}"


def test_user_agent_still_varies_across_runs(tmp_path):
    """Each run picks its own UA, so traffic still blends across runs.

    Asserts membership, never that two contexts differ: with six agents the
    same one is drawn twice often enough that a difference assertion would
    flake.
    """
    for i in range(5):
        run_dir = tmp_path / f"run{i}"
        run_dir.mkdir()
        ctx = ctx_for(run_dir)
        cmd = HttpxStage().build_command(ctx)
        assert cmd[cmd.index("-H") + 1][len("User-Agent: "):] in USER_AGENTS


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("httpx") is None,
                    reason="httpx not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    """Ask httpx itself whether each level's flag set parses.

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
    err = preflight.validate_arguments(HttpxStage(), ctx)
    assert err == "", f"httpx rejected the {level!r} flag set: {err}"
