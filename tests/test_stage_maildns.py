"""maildns stage — the mail-authentication questions dnsx cannot answer.

dnsx returns TXT strings; this stage evaluates them. The gap it closes,
measured against the live scope on 2026-08-05:

  - An SPF record that exceeds the 10-DNS-lookup limit is INVALID. Every
    receiver returns permerror and treats the domain as unauthenticated,
    and dnsx -- which sees only the string -- reports it as a published
    policy. A domain can look protected and authenticate nothing.
  - DMARC is evaluated at the ORGANIZATIONAL domain. A subdomain with no
    `_dmarc` record of its own inherits its parent's policy, so dnsx's
    "no DMARC published" is wrong whenever the parent publishes one.
    `dmarc.location` is what names the domain the policy actually came
    from.
  - `rua=` pointing at a domain that has not authorized it means the
    reports are silently discarded, which is invisible from the record.

ABSENCE STAYS WITH dnsx. It already emits dns-spf-missing and
dns-dmarc-missing at every level; re-reporting them here would double every
absence in the report the moment `high` is selected.
"""

import json

import pytest

from sweeper.artifacts import ArtifactKind, Finding
from sweeper.stages import registry
from sweeper.stages.maildns import MaildnsStage


def _write(tmp_path, payload):
    p = tmp_path / "maildns.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _entry(domain="acc.example", **kw):
    """A checkdmarc result with everything absent, as the live scope is."""
    base = {
        "domain": domain,
        "base_domain": "example",
        "mx": {"hosts": [], "warnings": []},
        "spf": {"record": None, "valid": False,
                "error": "An SPF record does not exist."},
        "dmarc": {"record": None, "valid": False,
                  "error": "A DMARC record does not exist."},
    }
    base.update(kw)
    return base


def test_contract():
    assert registry.validate(MaildnsStage()) == []


def test_runs_only_at_high_and_full():
    """Every check here is DNS, but it is a SECOND DNS tool over the same
    names -- depth, which is what high buys, not a baseline check."""
    s = MaildnsStage()
    assert s.levels["low"] == []
    assert s.levels["mid"] == []
    assert s.levels["high"] != []
    assert s.levels["full"] != []


def test_smtp_testing_is_always_skipped(tmp_path):
    """checkdmarc opens SMTP connections to the target's MX unless told not
    to. No stage sends traffic the operator did not ask for, and a mail
    server is not in a web scope's rules of engagement."""
    cmd = MaildnsStage().build_command(_ctx(tmp_path))
    assert "--skip-tls" in cmd


def test_an_spf_record_over_the_lookup_limit_is_reported(tmp_path):
    """11 lookups is not a warning, it is an invalid record: receivers
    permerror and the domain authenticates nothing. dnsx sees a published
    SPF string and says the domain is covered."""
    raw = _write(tmp_path, [_entry(spf={
        "record": "v=spf1 include:a include:b -all",
        "valid": False, "dns_lookups": 11, "warnings": [],
    })])

    out = [f for f in MaildnsStage().parse(raw) if isinstance(f, Finding)]

    hit = [f for f in out if f.template_id == "mail-spf-lookup-limit"]
    assert hit, [f.template_id for f in out]
    assert hit[0].severity == "medium"
    assert "11" in hit[0].evidence


def test_a_published_but_invalid_spf_record_is_reported(tmp_path):
    raw = _write(tmp_path, [_entry(spf={
        "record": "v=spf1 include:broken~all", "valid": False,
        "error": "Expected mechanism at position 9", "warnings": [],
    })])

    out = [f for f in MaildnsStage().parse(raw) if isinstance(f, Finding)]

    assert [f.template_id for f in out if f.template_id == "mail-spf-invalid"]


def test_absence_is_left_to_dnsx(tmp_path):
    """The whole live scope looks like this: nothing published anywhere.
    dnsx already reports it, at every level."""
    raw = _write(tmp_path, [_entry()])

    out = [f for f in MaildnsStage().parse(raw) if isinstance(f, Finding)]

    assert [f.template_id for f in out
            if "missing" in f.template_id or "absent" in f.template_id] == []


def test_a_policy_inherited_from_the_parent_is_named(tmp_path):
    """The correction to dnsx's blind spot: this subdomain publishes no
    _dmarc record of its own and IS still covered, because DMARC resolves
    at the organizational domain."""
    raw = _write(tmp_path, [_entry(
        domain="shop.acc.example",
        dmarc={"record": "v=DMARC1; p=reject;", "valid": True,
               "location": "acc.example", "warnings": [],
               "tags": {"p": {"value": "reject", "explicit": True}}},
    )])

    out = [f for f in MaildnsStage().parse(raw) if isinstance(f, Finding)]

    hit = [f for f in out if f.template_id == "mail-dmarc-inherited"]
    assert hit, [f.template_id for f in out]
    assert "acc.example" in hit[0].evidence


def test_a_policy_published_on_the_name_itself_is_not_called_inherited(
        tmp_path):
    raw = _write(tmp_path, [_entry(
        domain="acc.example",
        dmarc={"record": "v=DMARC1; p=reject;", "valid": True,
               "location": "acc.example", "warnings": [],
               "tags": {"p": {"value": "reject", "explicit": True}}},
    )])

    out = [f for f in MaildnsStage().parse(raw) if isinstance(f, Finding)]

    assert not [f for f in out if f.template_id == "mail-dmarc-inherited"]


def test_a_dmarc_warning_becomes_a_finding(tmp_path):
    """checkdmarc's warnings are where the report-destination authorization
    failures land -- reports silently discarded, invisible in the record."""
    raw = _write(tmp_path, [_entry(dmarc={
        "record": "v=DMARC1; p=none; rua=mailto:x@elsewhere.example",
        "valid": True, "location": "acc.example",
        "warnings": ["elsewhere.example does not indicate that it accepts "
                     "DMARC reports about acc.example"],
        "tags": {"p": {"value": "none", "explicit": True}},
    })])

    out = [f for f in MaildnsStage().parse(raw) if isinstance(f, Finding)]

    hit = [f for f in out if f.template_id == "mail-dmarc-warning"]
    assert hit
    assert "elsewhere.example" in hit[0].evidence


def test_a_domain_that_receives_mail_with_no_authentication_is_reported(
        tmp_path):
    """The live finding, in one statement. Five Google Workspace MX records
    and neither SPF nor DMARC: the domain accepts mail AND anyone may send
    as it. dnsx reports the two absences separately and never correlates
    them with the MX it also holds."""
    raw = _write(tmp_path, [_entry(mx={
        "hosts": [{"hostname": "aspmx.l.google.com", "preference": 1}],
        "warnings": [],
    })])

    out = [f for f in MaildnsStage().parse(raw) if isinstance(f, Finding)]

    hit = [f for f in out if f.template_id == "mail-no-sender-auth-with-mx"]
    assert hit, [f.template_id for f in out]
    assert hit[0].severity == "medium"
    assert "aspmx.l.google.com" in hit[0].evidence


def test_no_mx_means_no_correlation_finding(tmp_path):
    """A domain with no MX receives no mail. Absent SPF/DMARC still matters
    -- anyone can send AS it -- but that is dnsx's absence finding, not a
    claim about a mail service that does not exist."""
    raw = _write(tmp_path, [_entry()])

    out = [f for f in MaildnsStage().parse(raw) if isinstance(f, Finding)]

    assert not [f for f in out
                if f.template_id == "mail-no-sender-auth-with-mx"]


def test_a_healthy_domain_produces_nothing(tmp_path):
    """Measured against google.com: valid SPF at 1 lookup, valid DMARC
    p=reject published on the name itself, no warnings."""
    raw = _write(tmp_path, [_entry(
        mx={"hosts": [{"hostname": "aspmx.l.google.com"}], "warnings": []},
        spf={"record": "v=spf1 include:_spf.google.com ~all", "valid": True,
             "dns_lookups": 1, "warnings": []},
        dmarc={"record": "v=DMARC1; p=reject;", "valid": True,
               "location": "acc.example", "warnings": [],
               "tags": {"p": {"value": "reject", "explicit": True}}},
    )])

    assert [f for f in MaildnsStage().parse(raw) if isinstance(f, Finding)] == []


@pytest.mark.parametrize("body", ["", "   ", "not json at all", "null"])
def test_silence_is_never_evidence(tmp_path, body):
    """A tool that did not run must not become "this domain is fine". The
    three invalid tripwire verdicts during lab validation were all this
    shape: a tool that never ran and a tool that behaved produced identical
    silence."""
    p = tmp_path / "maildns.json"
    p.write_text(body, encoding="utf-8")

    assert list(MaildnsStage().parse(p)) == []


def test_a_missing_raw_file_does_not_raise(tmp_path):
    assert list(MaildnsStage().parse(tmp_path / "nope.json")) == []


def _ctx(tmp_path, **kw):
    from sweeper.context import RunConfig, RunContext
    t = tmp_path / "t.txt"
    t.write_text("acc.example\n", encoding="utf-8")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      level="high", **kw))
    from sweeper.artifacts import Artifact
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    return ctx


def test_build_command_names_the_real_binary(tmp_path):
    """binaries.resolve returns None for an UNREGISTERED tool, and str(None)
    is the string "None" -- a command that runs nothing while every
    flag-shaped assertion about it still passes. Assert the path exists."""
    from pathlib import Path
    cmd = MaildnsStage().build_command(_ctx(tmp_path))
    if cmd[0] == "None":
        pytest.skip("checkdmarc is not installed")
    assert Path(cmd[0]).is_file(), f"argv[0] is not a binary: {cmd[0]!r}"
    assert cmd[0].endswith("checkdmarc")


def test_the_resolver_limitation_is_declared_not_hidden(tmp_path):
    """checkdmarc's -n takes addresses only and always queries port 53, so
    it cannot express --resolver on another port -- nmap's exact limitation,
    declared nmap's exact way. Passing the bare address anyway would query
    :53 of that host, a different service or nothing, while run.json vouched
    for the operator's setting. A manifest that asserts a capability the
    argv does not deliver is worse than one that admits the gap."""
    stage = MaildnsStage()
    assert stage.honors_resolver is False
    assert stage.resolver_note, "a stage declining the resolver must say why"
    cmd = stage.build_command(_ctx(tmp_path, resolver="127.0.0.1:15353"))
    assert "-n" not in cmd
    assert "127.0.0.1" not in " ".join(cmd)


def test_the_domain_list_is_scope_filtered(tmp_path):
    """The sidecar is what the tool reads; an out-of-scope host reaching it
    is a scope escape with the scope guard none the wiser."""
    from sweeper.artifacts import Artifact
    ctx = _ctx(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HOST, "evil.test"))
    MaildnsStage().build_command(ctx)
    listed = (ctx.run_dir / "raw" / "maildns-input.txt").read_text().split()
    assert "acc.example" in listed
    assert "evil.test" not in listed
