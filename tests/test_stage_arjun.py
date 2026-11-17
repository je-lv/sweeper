import json
from pathlib import Path

import pytest

from sweeper import binaries, preflight
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.stages import registry
from sweeper.stages.arjun import ArjunStage
from sweeper.stages.base import LEVELS

FIX = Path(__file__).parent / "fixtures" / "arjun.json"


def test_contract():
    assert registry.validate(ArjunStage()) == []


def test_only_runs_at_high_and_full():
    s = ArjunStage()
    assert s.levels["low"] == [] and s.levels["mid"] == []
    assert s.levels["high"] and s.levels["full"]


def test_discovered_params_become_parameterised_urls():
    vals = [a.value for a in ArjunStage().parse(FIX)]
    assert any("debug=" in v for v in vals)
    assert any("admin_preview=" in v for v in vals)


def test_all_params_combined_into_one_url():
    vals = [a.value for a in ArjunStage().parse(FIX)]
    combined = [v for v in vals if v.count("=") == 4]
    assert combined, "expected one URL carrying every discovered parameter"


def test_meta_records_discovered_names():
    a = next(iter(ArjunStage().parse(FIX)))
    assert "debug" in a.meta["params"]


def test_meta_host_is_set_for_the_admission_choke_point():
    """runner.py's admission control (_meta_host_or_value) scope-checks
    meta["host"] for every HTTP_SERVICE artifact -- see katana.py's and
    vhost.py's identical contract. Omitting it here was exactly the class
    of defect that starved downstream stages silently in vhost.
    """
    a = next(iter(ArjunStage().parse(FIX)))
    assert a.meta["host"] == "acc.example"


def test_malformed_url_does_not_discard_the_remaining_rows(tmp_path):
    """A malformed authority ("http://[::1/broken" -> "Invalid IPv6 URL")
    must not take the whole generator down with it. parse() is consumed
    inside runner.py's single broad try/except, so an escaping ValueError
    loses every LATER row too -- one bad key silently discarding real
    discoveries, surfacing only as a generic PARSE_ERROR.

    Routed through scope.normalize() (the same function katana.py,
    jsrecon.py and the admission choke point use) it normalizes to "" and
    admission control refuses just that row.

    build_command()'s ctx.scope.filter() does NOT protect this: parse()
    takes a bare path with no ctx or scope coupling at all, so a stale or
    resumed raw file, or any direct .parse(path) call, bypasses it.
    """
    raw = tmp_path / "a.json"
    raw.write_text(
        '{"http://[::1/broken": {"method": "GET", "params": ["evil"]},'
        ' "https://acc.example/ok": {"method": "GET", "params": ["good"]}}'
    )
    arts = list(ArjunStage().parse(raw))
    # The well-formed row survives -- this is what an escaping ValueError
    # would have destroyed.
    assert any("good=" in a.value for a in arts)
    # The malformed one normalizes to "", which admission control refuses
    # (runner._admission_host returns None for an empty host).
    assert all(a.meta["host"] == ""
               for a in arts if "evil=" in a.value)


def test_hostname_goes_through_the_shared_scope_normalizer(tmp_path):
    """Reuse, not a third convention. scope.normalize() resolves a userinfo
    masquerade -- "acc.example:80@evil.test" addresses evil.test, not
    acc.example -- and it is the SAME function the admission choke point
    uses, so this stage's judgement cannot drift from the one that admits
    the artifact.
    """
    from sweeper.scope import normalize
    url = "https://acc.example:80@evil.test/search"
    raw = tmp_path / "a.json"
    raw.write_text(json.dumps({url: {"method": "GET", "params": ["q"]}}))
    art = next(iter(ArjunStage().parse(raw)))
    assert art.meta["host"] == normalize(url) == "evil.test"


def _ctx(tmp_path, auth_mode="unauth"):
    """A high-level run context.

    auth_mode must be "auth" before ctx.auth will accept a non-empty bundle
    -- see context.AuthModeViolation: a run whose manifest says "unauth"
    must not send authenticated traffic.
    """
    from sweeper.context import RunConfig, RunContext
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    return RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                       level="high", auth_mode=auth_mode))


def test_auth_headers_are_included_when_configured(tmp_path):
    from sweeper.auth import SecretBundle
    ctx = _ctx(tmp_path, auth_mode="auth")
    ctx.auth = SecretBundle(headers={"Authorization": "Bearer testtoken123"},
                            cookies={"session": "abc123"})
    cmd = ArjunStage().build_command(ctx)
    block = cmd[cmd.index("--headers") + 1]
    assert "Authorization: Bearer testtoken123" in block
    assert "Cookie: session=abc123" in block


def test_no_auth_headers_when_unconfigured(tmp_path):
    cmd = ArjunStage().build_command(_ctx(tmp_path))
    block = cmd[cmd.index("--headers") + 1]
    assert "Authorization" not in block
    assert "Cookie" not in block


def test_writes_own_raw_declared():
    s = ArjunStage()
    assert s.raw_suffix == "json"
    assert s.writes_own_raw is True


def test_output_file_is_the_same_path_the_runner_will_hand_to_parse(tmp_path):
    ctx = _ctx(tmp_path)
    cmd = ArjunStage().build_command(ctx)
    outfile = Path(cmd[cmd.index("-oJ") + 1])
    expected = ctx.raw_path(ArjunStage().name, ArjunStage().raw_suffix)
    assert outfile == expected


def test_produces_declaration_matches_what_parse_actually_yields():
    stage = ArjunStage()
    emitted = {a.kind for a in stage.parse(FIX)}
    assert emitted == stage.produces


# --- residual `ps` exposure -------------------------------------------------
# arjun has no file-based --headers form (verified against the installed
# 2.2.7 package's own source, arjun/core/utils.py -- see the module
# docstring). A live credential therefore appears in argv for the lifetime
# of the arjun process; it is redacted from sweep.log/run.json (Task 3.5's
# runner-level redaction) but NOT from `ps`. This test pins that argv shape
# down so a future "fix" that quietly drops the header block is caught, and
# documents that the exposure is a recorded decision, not an oversight.


def test_auth_values_travel_in_argv_not_a_file(tmp_path):
    from sweeper.auth import SecretBundle
    ctx = _ctx(tmp_path, auth_mode="auth")
    ctx.auth = SecretBundle(headers={"Authorization": "Bearer testtoken123"})
    cmd = ArjunStage().build_command(ctx)
    # The live value is literally present in argv -- ps-visible. There is no
    # "-headers <file>" form for this tool, unlike katana's.
    assert any("testtoken123" in arg for arg in cmd)


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("arjun") is None,
                    reason="arjun not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    from sweeper.context import RunConfig, RunContext
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      level=level))
    err = preflight.validate_arguments(ArjunStage(), ctx)
    assert err == "", f"arjun rejected the {level!r} flag set: {err}"
