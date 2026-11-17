"""When the system resolver cannot resolve the scope, fall back — loudly.

Found on the first live run: the box's system resolver (a VM NAT gateway) had
stopped answering. Every DNS stage reported `complete` having resolved
nothing, naabu died with `no valid ipv4 or ipv6 targets were found`, and ten
stages skipped for want of a port. The scan was dead on arrival for a reason
that had nothing to do with the target.

Falling back is right, and it is not free. A public resolver sees every
hostname asked of it, so a fallback SENDS THE CLIENT'S SCOPE TO A THIRD PARTY.
That is a confidentiality decision, not a connectivity one, which is why:

  * it never overrides an explicit --resolver. An operator who named a
    nameserver made a deliberate choice, almost always because the scope is
    split-horizon or internal; silently re-asking Cloudflare would resolve
    the EXTERNAL view and scan a different set of hosts under the same name.
    A named resolver that fails is an error, not an invitation.
  * every use is recorded -- a run warning, the manifest, and the console --
    so a report can never be read without knowing which nameserver produced
    the scope it covers.
  * --no-resolver-fallback turns it off for engagements where third-party
    DNS is out of the question.
"""
import pytest
from sweeper import preflight, resolvers
from sweeper.context import RunConfig, RunContext


def ctx_for(tmp_path, lines=("a.client.example.net",), **kw):
    t = tmp_path / "targets.txt"
    t.write_text("\n".join(lines) + "\n")
    return RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw))


@pytest.fixture
def system_dns_is_dead(monkeypatch):
    """Nothing resolves without an explicit resolver."""
    def fake(host, ctx):
        return bool((getattr(ctx.config, "resolver", "") or "").strip())
    monkeypatch.setattr(preflight, "_resolves", fake)


def test_a_dead_system_resolver_falls_back_instead_of_failing(tmp_path,
                                                              system_dns_is_dead):
    ctx = ctx_for(tmp_path)
    report = preflight.run_preflight(ctx, [])
    assert report.ok is True
    assert ctx.config.resolver, "no fallback resolver was adopted"
    assert ctx.config.resolver in resolvers.FALLBACKS


def test_the_fallback_is_recorded_as_a_run_warning(tmp_path, system_dns_is_dead):
    """A report must never be readable without knowing which nameserver
    produced the scope it covers."""
    ctx = ctx_for(tmp_path)
    preflight.run_preflight(ctx, [])
    blob = " ".join(ctx.warnings).lower()
    assert "resolver" in blob
    assert ctx.config.resolver in " ".join(ctx.warnings)


def test_an_explicit_resolver_is_never_silently_replaced(tmp_path, monkeypatch):
    """The split-horizon case. Re-asking a public resolver would resolve the
    external view and scan a different set of hosts under the same names."""
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    ctx = ctx_for(tmp_path, resolver="10.0.0.53")
    report = preflight.run_preflight(ctx, [])
    assert report.ok is False, "a named resolver that fails must be an error"
    assert ctx.config.resolver == "10.0.0.53", "the operator's choice was overwritten"
    assert not any(f in ctx.config.resolver for f in resolvers.FALLBACKS)


def test_fallback_can_be_refused_outright(tmp_path, system_dns_is_dead):
    """Some engagements forbid third-party DNS for the scope entirely."""
    ctx = ctx_for(tmp_path, resolver_fallback=False)
    report = preflight.run_preflight(ctx, [])
    assert report.ok is False
    assert not ctx.config.resolver


def test_a_working_system_resolver_is_left_alone(tmp_path, monkeypatch):
    """No fallback, no warning, no third-party query when nothing is wrong."""
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: True)
    ctx = ctx_for(tmp_path)
    preflight.run_preflight(ctx, [])
    assert ctx.config.resolver == ""
    assert not [w for w in ctx.warnings if "resolver" in w.lower()]


def test_when_every_fallback_also_fails_the_run_is_refused(tmp_path, monkeypatch):
    """Not silently proceeding with a resolver that answers nothing."""
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    ctx = ctx_for(tmp_path)
    report = preflight.run_preflight(ctx, [])
    assert report.ok is False
    assert ctx.config.resolver == "", "a non-working fallback must not be adopted"


def test_an_ip_only_scope_never_triggers_a_third_party_query(tmp_path, monkeypatch):
    """Scanning by address consults no resolver, so no hostname should ever
    leave the box."""
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    ctx = ctx_for(tmp_path, lines=("198.51.100.10",))
    report = preflight.run_preflight(ctx, [])
    assert report.ok is True
    assert ctx.config.resolver == ""


def test_the_manifest_records_which_resolver_actually_answered(tmp_path,
                                                               system_dns_is_dead):
    import json
    ctx = ctx_for(tmp_path)
    preflight.run_preflight(ctx, [])
    ctx.write_manifest([])
    data = json.loads((ctx.run_dir / "run.json").read_text())
    assert data["resolver"]["value"] == ctx.config.resolver
    assert data["resolver"]["fallback"] is True
