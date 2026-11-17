import stat
from pathlib import Path

import pytest
import yaml

from sweeper import binaries, preflight
from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.auth import (NO_AUTHORITY_REGEX, SecretBundle,
                          to_nuclei_secret_file)
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.nuclei import NucleiStage

FIX = Path(__file__).parent / "fixtures" / "nuclei.jsonl"


def ctx_for(tmp_path, level="mid"):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    return RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                       level=level))


def test_contract():
    assert registry.validate(NucleiStage()) == []


def test_dos_excluded_at_every_level(tmp_path):
    for level in ("low", "mid", "high", "full"):
        cmd = NucleiStage().build_command(ctx_for(tmp_path, level))
        joined = " ".join(cmd)
        assert "-exclude-tags" in cmd
        assert "dos" in joined, f"dos not excluded at level {level}"
        # Not just present anywhere -- it must be the VALUE of -exclude-tags,
        # never smuggled in as e.g. a tag name that merely contains "dos".
        assert cmd[cmd.index("-exclude-tags") + 1] == "dos"


def test_update_check_disabled_at_every_level(tmp_path):
    """No phone-home to ProjectDiscovery mid-engagement, at any level.

    Confirmed empirically against the pinned v3.11.0: without -duc a scan
    rewrites ~/.config/nuclei/.templates-config.json, refreshing its
    "nuclei-latest-version" field -- a value only a remote source can
    supply. With -duc the file is untouched.

    It matters twice over: an undisclosed outbound connection to a third
    party during a client engagement (ctx.scope governs where SCAN traffic
    goes and would never have caught this), and a hang risk on an
    egress-filtered box that silently consumes the stage's whole timeout
    before a single template runs.
    """
    for level in LEVELS:
        cmd = NucleiStage().build_command(ctx_for(tmp_path, level))
        assert "-duc" in cmd, f"update check not disabled at level {level}"


def test_every_resolved_address_is_scanned(tmp_path):
    assert "-scan-all-ips" in NucleiStage().build_command(ctx_for(tmp_path))


def test_udp_only_endpoint_reaches_network_template_input(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.store.add(Artifact(
        ArtifactKind.UDP_PORT,
        "acc.example:161",
        meta={"host": "acc.example", "protocol": "udp"},
    ))

    cmd = NucleiStage().build_command(ctx)
    infile = Path(cmd[cmd.index("-list") + 1])

    assert infile.read_text(encoding="utf-8").splitlines() == [
        "acc.example:161",
    ]


def test_dast_only_at_full(tmp_path):
    for level in ("low", "mid", "high"):
        assert "-dast" not in NucleiStage().build_command(ctx_for(tmp_path, level))
    assert "-dast" in NucleiStage().build_command(ctx_for(tmp_path, "full"))


def test_oast_disabled_at_low_enabled_above(tmp_path):
    assert "-no-interactsh" in NucleiStage().build_command(ctx_for(tmp_path, "low"))
    for level in ("mid", "high", "full"):
        assert "-no-interactsh" not in NucleiStage().build_command(ctx_for(tmp_path, level))


def test_uses_pinned_pdtm_binary_not_usr_bin(tmp_path):
    cmd = NucleiStage().build_command(ctx_for(tmp_path))
    if cmd[0] == "None":
        pytest.skip("the pinned pdtm nuclei binary is not installed")
    assert "/usr/bin/nuclei" not in cmd[0]
    assert ".pdtm" in cmd[0]


def test_findings_parsed_with_severity_and_template(tmp_path):
    out = [f for f in NucleiStage().parse(FIX) if isinstance(f, Finding)]
    ids = {f.template_id: f.severity for f in out}
    assert ids["git-config-exposure"] == "high"
    assert ids["CVE-2021-44228"] == "critical"


def test_matched_at_preserved(tmp_path):
    f = next(f for f in NucleiStage().parse(FIX)
             if f.template_id == "git-config-exposure")
    assert f.matched_at == "https://acc.example/.git/config"


def test_references_and_remediation_carried(tmp_path):
    f = next(f for f in NucleiStage().parse(FIX)
             if f.template_id == "git-config-exposure")
    assert f.references == ["https://example.com/ref"]
    assert f.remediation == "Block .git"


def test_extracted_results_become_evidence(tmp_path):
    f = next(f for f in NucleiStage().parse(FIX)
             if f.template_id == "CVE-2021-44228")
    assert "evidence-blob" in f.evidence


def test_unknown_severity_falls_back_to_info(tmp_path, monkeypatch):
    raw = tmp_path / "n.jsonl"
    raw.write_text('{"template-id":"x","info":{"name":"X","severity":"weird"},'
                   '"host":"acc.example","matched-at":"https://acc.example/"}\n')
    f = next(iter(NucleiStage().parse(raw)))
    assert f.severity == "info"


def test_produces_declaration_matches_what_parse_actually_yields():
    """A stage that declares a kind it never emits silently starves every
    downstream consumer -- a real defect in vhost. The previous form of this
    test could not catch it: it built the set as
    `{ArtifactKind.FINDING for f in ... if isinstance(f, Finding)}`, which
    hardcodes the answer and filters out any non-Finding item BEFORE the
    comparison, so an undeclared Artifact kind would pass unnoticed.

    Classify every item parse() actually yields -- Finding has no `.kind`,
    so FINDING is inferred from its type and everything else reports its own
    `.kind` -- then compare that against the declaration.
    """
    stage = NucleiStage()
    emitted = {
        ArtifactKind.FINDING if isinstance(item, Finding) else item.kind
        for item in stage.parse(FIX)
    }
    assert emitted == stage.produces


def test_produces_check_would_catch_an_undeclared_kind():
    """Proves the test above can actually fail -- the reason the previous
    version survived review is that its name implied a guarantee it did not
    provide. A subclass that also yields an HTTP_SERVICE artifact (a kind
    nuclei does NOT declare) must be detected.
    """
    class _LeakyNuclei(NucleiStage):
        def parse(self, raw_path):
            yield from super().parse(raw_path)
            yield Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                           meta={"host": "acc.example"})

    stage = _LeakyNuclei()
    emitted = {
        ArtifactKind.FINDING if isinstance(item, Finding) else item.kind
        for item in stage.parse(FIX)
    }
    assert emitted != stage.produces
    assert ArtifactKind.HTTP_SERVICE in emitted


# --- finding-id collision: nuclei is the highest-risk stage for this -------
# One template CAN match the same host more than once (directory-listing
# hitting several paths, an extractor pulling multiple secrets off one
# page). Real nuclei v3.11.0 output confirms "matcher-name" is frequently
# ABSENT (only emitted when a template declares more than one named
# matcher -- verified directly against the binary, not inferred). A naive
# `matcher=row.get("matcher-name", "")` therefore collapses two genuinely
# different matches onto the same (stage, target, template_id, matcher)
# tuple and ArtifactStore.add_finding() would keep only the first --
# already-seen defect class in dnsx/tlsx/vhost/nmap.


def test_two_matches_of_one_template_on_one_target_produce_two_findings(tmp_path):
    raw = tmp_path / "n2.jsonl"
    raw.write_text(
        '{"template-id":"exposed-panel","info":{"name":"Exposed Panel",'
        '"severity":"medium"},"host":"acc.example",'
        '"matched-at":"https://acc.example/admin"}\n'
        '{"template-id":"exposed-panel","info":{"name":"Exposed Panel",'
        '"severity":"medium"},"host":"acc.example",'
        '"matched-at":"https://acc.example/wp-admin"}\n'
    )
    findings = list(NucleiStage().parse(raw))
    assert len(findings) == 2
    assert len({f.id for f in findings}) == 2


def test_two_extractions_of_one_template_at_one_url_produce_two_findings(tmp_path):
    """Same template, same matched-at, but a different extracted value each
    time (e.g. two distinct secrets pulled off the same page) -- matched-at
    alone would still collide, so extracted-results must also feed matcher.
    """
    raw = tmp_path / "n3.jsonl"
    raw.write_text(
        '{"template-id":"secret-leak","info":{"name":"Secret Leak",'
        '"severity":"high"},"host":"acc.example",'
        '"matched-at":"https://acc.example/config.js",'
        '"extracted-results":["key-alpha"]}\n'
        '{"template-id":"secret-leak","info":{"name":"Secret Leak",'
        '"severity":"high"},"host":"acc.example",'
        '"matched-at":"https://acc.example/config.js",'
        '"extracted-results":["key-beta"]}\n'
    )
    findings = list(NucleiStage().parse(raw))
    assert len(findings) == 2
    assert len({f.id for f in findings}) == 2


def test_finding_ids_are_stable_across_a_rerun_of_the_same_scan():
    """Plan 3's run-to-run diffing depends on finding_id being stable for an
    identical rerun -- matcher must be derived from something intrinsic and
    repeatable (matched-at / extracted-results), never a timestamp, index
    or counter.
    """
    first = {f.id for f in NucleiStage().parse(FIX)}
    second = {f.id for f in NucleiStage().parse(FIX)}
    assert first == second
    assert len(first) == 3


def test_all_findings_reach_the_store_with_no_collisions(tmp_path):
    """End-to-end through the real runner: two genuinely different matches
    of one template on one target must both survive store.add_finding(),
    and neither should be recorded as a finding-id collision (that would
    mean the matcher fix did not actually distinguish them).
    """
    from sweeper.runner import run_stages

    class _StubbedNuclei(NucleiStage):
        """NucleiStage with the subprocess replaced by /bin/cat over a
        canned JSONL file. writes_own_raw is False for nuclei (real nuclei
        prints -jsonl to stdout, it does not write its own result file), so
        the runner captures THIS command's stdout into raw/nuclei.jsonl
        itself -- writing raw_path directly here would just be clobbered by
        that capture, the same way build_command() cannot pre-populate it
        for the real binary either.
        """
        def __init__(self, jsonl: str):
            self._jsonl = jsonl

        def build_command(self, ctx):
            src = ctx.run_dir / "raw" / "_stub_nuclei_src.jsonl"
            src.parent.mkdir(parents=True, exist_ok=True)
            src.write_text(self._jsonl, encoding="utf-8")
            return ["/bin/cat", str(src)]

    jsonl = (
        '{"template-id":"exposed-panel","info":{"name":"Exposed Panel",'
        '"severity":"medium"},"host":"acc.example",'
        '"matched-at":"https://acc.example/admin"}\n'
        '{"template-id":"exposed-panel","info":{"name":"Exposed Panel",'
        '"severity":"medium"},"host":"acc.example",'
        '"matched-at":"https://acc.example/wp-admin"}\n'
    )
    t = tmp_path / "targets.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example",
                           meta={"host": "acc.example"}))
    [result] = run_stages(ctx, [_StubbedNuclei(jsonl)])

    assert result.findings == 2
    assert ctx.store.finding_collisions == []


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("nuclei") is None,
                    reason="nuclei not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    ctx = ctx_for(tmp_path, level)
    err = preflight.validate_arguments(NucleiStage(), ctx)
    assert err == "", f"nuclei rejected the {level!r} flag set: {err}"


# --- the credential is scoped to the hosts THIS run will scan ---------------
# nuclei is the only stage driven with `-list`, so its secret file is the one
# place a credential can be offered to more hosts than it belongs to. The
# authority patterns' behaviour on the wire is pinned in test_auth.py against
# the real binary; what is asserted here is the other half -- that
# build_command feeds that machinery the run's own scope-filtered targets and
# hands nuclei the file it just rescoped.

def _auth_ctx(tmp_path, services=("https://acc.example:8443",)):
    """A ctx shaped like an authenticated run at the moment nuclei starts."""
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out",
                                      level="mid", auth_mode="auth"))
    ctx.auth = SecretBundle(headers={"Authorization": "Bearer CANARY"},
                            cookies={"session": "abc"})
    # Written exactly the way app.execute() writes it: before any stage has
    # run, so with no authorities known yet.
    ctx.secret_file = to_nuclei_secret_file(
        ctx.auth, ctx.run_dir / "auth" / "secrets.yaml", run_dir=ctx.run_dir)
    for url in services:
        ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, url,
                               meta={"host": url}))
    return ctx


def _domains_regex(path):
    return yaml.safe_load(Path(path).read_text())["static"][0]["domains-regex"]


def test_secret_file_written_before_the_run_matches_no_authority(tmp_path):
    """The state app.execute() leaves on disk. No HTTP_SERVICE artifact
    exists that early, so the credential must be attached to nothing until
    this stage rescopes it -- not to everything.
    """
    ctx = _auth_ctx(tmp_path)
    assert _domains_regex(ctx.secret_file) == [NO_AUTHORITY_REGEX]


def test_build_command_rescopes_the_secret_file_to_the_run_targets(tmp_path):
    ctx = _auth_ctx(tmp_path)
    cmd = NucleiStage().build_command(ctx)

    assert _domains_regex(ctx.secret_file) == [r"^acc\.example(?::\d+)?$"], (
        "the credential was not anchored to the hosts this run scans"
    )
    # The rescoped file is the one nuclei is actually pointed at. Rescoping a
    # file the argv does not name would be a no-op that every content
    # assertion above still passes.
    assert cmd[cmd.index("-secret-file") + 1] == str(ctx.secret_file)


def test_an_out_of_scope_service_never_enters_the_credential_scope(tmp_path):
    """The store is not the allowlist. `permitted` is what build_command
    writes into `-list`, so it is also what the credential must be anchored
    to -- anchoring to the raw store would offer the client's session token
    to a host the operator never authorised.
    """
    ctx = _auth_ctx(tmp_path, services=("https://acc.example",
                                        "https://evil.test"))
    NucleiStage().build_command(ctx)

    patterns = _domains_regex(ctx.secret_file)
    assert patterns == [r"^acc\.example(?::\d+)?$"]
    assert not any("evil" in p for p in patterns)


def test_rescoping_keeps_the_credential_itself_intact(tmp_path):
    ctx = _auth_ctx(tmp_path)
    NucleiStage().build_command(ctx)
    entry = yaml.safe_load(Path(ctx.secret_file).read_text())["static"][0]
    assert {h["key"]: h["value"] for h in entry["headers"]} == {
        "Authorization": "Bearer CANARY", "Cookie": "session=abc",
    }


def test_rescoping_preserves_the_owner_only_mode(tmp_path):
    """A rewrite is a fresh write of live credentials, so it re-earns the
    0600 guarantee rather than inheriting it -- see auth.SECRET_FILE_MODE.
    """
    ctx = _auth_ctx(tmp_path)
    NucleiStage().build_command(ctx)
    assert stat.S_IMODE(Path(ctx.secret_file).stat().st_mode) == 0o600


def test_no_service_yet_leaves_the_credential_attached_to_nothing(tmp_path):
    """Preflight builds this command before httpx has run, so the target set
    is legitimately empty. That must fail closed -- and must stay a pattern,
    since nuclei treats an empty domains-regex as fatal (see test_auth).
    """
    ctx = _auth_ctx(tmp_path, services=())
    NucleiStage().build_command(ctx)
    assert _domains_regex(ctx.secret_file) == [NO_AUTHORITY_REGEX]


def test_a_secret_file_with_no_bundle_is_passed_through_untouched(tmp_path):
    """preflight-level callers set ctx.secret_file without ctx.auth (see
    tests/test_preflight.py). There is nothing to rewrite the file from, and
    the file already on disk is the fail-closed one, so it is passed through
    rather than replaced with an empty-credential file.
    """
    ctx = ctx_for(tmp_path)
    ctx.secret_file = ctx.run_dir / "auth" / "secrets.yaml"
    cmd = NucleiStage().build_command(ctx)
    assert cmd[cmd.index("-secret-file") + 1] == str(ctx.secret_file)
    assert not Path(ctx.secret_file).exists(), (
        "build_command invented a secret file with no credentials to put in it"
    )
