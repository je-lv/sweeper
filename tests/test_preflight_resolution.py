"""Preflight must refuse a run whose scope does not resolve at all.

Found 2026-08-04 on the first live run. The box's system resolver was dead --
`192.168.159.2#53: timed out`, a VM NAT gateway that had stopped answering --
and no `--resolver` was given, so every tool fell back to it.

What the operator saw:

    cdncheck  done      9.6s     (0 artifacts)
    dnsx      done      5.1s     (0 artifacts)
    naabu     failed    5.3s
    nmap ... nuclei     skipped  0.0s

Two stages reporting `done` having resolved nothing, one cryptic failure, and
ten stages skipped for want of a single port. Nothing anywhere said "DNS is
broken" -- the operator's reasonable first reading was a scope problem.

This is the defect class the project exists to catch: a stage that ran, exited
0, reported complete, and was structurally incapable of doing its job. The
whole run is decided before the first packet, so preflight is where it belongs.

Deliberately "not ONE target resolved", not "some target failed": a scope can
legitimately contain names that do not resolve -- a decommissioned host, a
dangling CNAME's label, an internal name absent from the split-horizon view
being scanned. Those are findings, not configuration errors. Zero out of all
of them is a broken resolver.
"""
import pytest
from sweeper import preflight
from sweeper.context import RunConfig, RunContext


def ctx_for(tmp_path, lines, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("\n".join(lines) + "\n")
    return RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw))


def test_a_scope_where_nothing_resolves_fails_preflight(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    ctx = ctx_for(tmp_path, ["a.client.example.net", "b.client.example.net"])
    report = preflight.run_preflight(ctx, [])
    assert report.ok is False
    blob = " ".join(report.errors).lower()
    assert "resolve" in blob


def test_the_error_names_the_resolver_actually_in_use(tmp_path, monkeypatch):
    """"Nothing resolved" without saying WHICH resolver was asked sends the
    operator to check their scope, which is not what is wrong."""
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    ctx = ctx_for(tmp_path, ["a.client.example.net"], resolver="10.0.0.53")
    report = preflight.run_preflight(ctx, [])
    assert "10.0.0.53" in " ".join(report.errors)


def test_with_no_resolver_the_error_points_at_the_system_one(tmp_path, monkeypatch):
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    ctx = ctx_for(tmp_path, ["a.client.example.net"])
    report = preflight.run_preflight(ctx, [])
    blob = " ".join(report.errors).lower()
    assert "system" in blob or "resolv.conf" in blob
    assert "--resolver" in " ".join(report.errors)


def test_one_resolving_target_is_enough_to_proceed(tmp_path, monkeypatch):
    """A scope may legitimately hold names that do not resolve -- a dangling
    CNAME's label, a decommissioned host. Those are findings, not a broken
    run, and must not block the targets that do resolve."""
    monkeypatch.setattr(preflight, "_resolves",
                        lambda host, ctx: host == "b.client.example.net")
    ctx = ctx_for(tmp_path, ["a.client.example.net", "b.client.example.net"])
    report = preflight.run_preflight(ctx, [])
    assert not [e for e in report.errors if "resolve" in e.lower()]


def test_an_ip_literal_scope_needs_no_dns_at_all(tmp_path, monkeypatch):
    """Scanning by address does not consult a resolver, so a dead one is
    irrelevant. Failing here would refuse a run that would have worked."""
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    ctx = ctx_for(tmp_path, ["198.51.100.10"])
    report = preflight.run_preflight(ctx, [])
    assert not [e for e in report.errors if "resolve" in e.lower()]


def test_the_check_is_skipped_when_there_are_no_targets(tmp_path, monkeypatch):
    """The empty-targets error already covers this. Two errors for one cause
    reads as two problems."""
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    ctx = ctx_for(tmp_path, [])
    report = preflight.run_preflight(ctx, [])
    assert not [e for e in report.errors if "resolve" in e.lower()]


def test_resolves_uses_the_operators_resolver_not_the_system_one(tmp_path):
    """The check must ask the same nameserver the scan will.

    On a split-horizon engagement the system resolver returns NXDOMAIN for
    the entire scope -- exactly the case --resolver exists for. A check that
    consulted it would refuse every split-horizon run.
    """
    ctx = ctx_for(tmp_path, ["a.client.example.net"], resolver="127.0.0.1:1")
    # Nothing answers on port 1; the point is that it ASKED there rather
    # than falling back to a system resolver that might answer.
    assert preflight._resolves("one.one.one.one", ctx) is False


def test_reserved_documentation_names_never_trigger_the_check(tmp_path, monkeypatch):
    """`.example` / `.test` / `.invalid` / `.localhost` are reserved by RFC
    2606 and RFC 6761 and do not resolve in public DNS by definition.

    "Nothing resolved" for those says nothing about the operator's resolver,
    and querying a public fallback for them would be a guaranteed-useless
    disclosure of the scope to a third party. The lab's scope is entirely
    `.test`; a real engagement never is.
    """
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    for name in ("a.acc.example", "www.vulnshop.test", "x.invalid", "y.localhost"):
        ctx = ctx_for(tmp_path, [name])
        report = preflight.run_preflight(ctx, [])
        assert not [e for e in report.errors if "resolve" in e.lower()], name
        assert ctx.config.resolver == "", f"{name} triggered a fallback"


def test_a_real_name_among_reserved_ones_is_still_checked(tmp_path, monkeypatch):
    """A mixed scope must not be excused by its lab entries."""
    monkeypatch.setattr(preflight, "_resolves", lambda host, ctx: False)
    ctx = ctx_for(tmp_path, ["lab.acc.example", "shop.client.example.net"],
                  resolver_fallback=False)
    report = preflight.run_preflight(ctx, [])
    assert [e for e in report.errors if "resolve" in e.lower()]
