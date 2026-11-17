from pathlib import Path
import pytest
from sweeper import binaries, preflight
from sweeper.artifacts import ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.cdncheck import CdncheckStage

FIX = Path(__file__).parent / "fixtures" / "cdncheck.jsonl"


def parsed():
    return list(CdncheckStage().parse(FIX))


def test_contract():
    assert registry.validate(CdncheckStage()) == []


def test_cdn_membership_recorded_in_host_meta():
    hosts = [a for a in parsed() if getattr(a, "kind", None) is ArtifactKind.HOST]
    fronted = next(a for a in hosts if a.value == "acc.example")
    assert fronted.meta["cdn"] is True
    assert fronted.meta["cdn_name"] == "cloudflare"


def test_non_cdn_host_flagged_as_origin_exposure():
    """origin.acc.example never appears in cdncheck's own output at all —
    verified against the real v1.2.46 binary, a host with no CDN/WAF match
    produces no JSON line, not a {"cdn": false} row. The finding comes from
    diffing the query list (tests/fixtures/cdncheck-input.txt) against what
    came back, gated on at least one sibling being genuinely fronted.
    """
    f = [x for x in parsed()
         if isinstance(x, Finding) and x.template_id == "cdn-origin-exposed"]
    assert len(f) == 1
    assert f[0].target == "origin.acc.example"
    assert f[0].severity == "low"


def test_waf_detection_recorded():
    hosts = [a for a in parsed() if getattr(a, "kind", None) is ArtifactKind.HOST]
    waf = next(a for a in hosts if a.value == "waf.acc.example")
    assert waf.meta["waf"] is True


def test_no_findings_when_no_sibling_is_fronted(tmp_path):
    """A batch where nothing is CDN/WAF-fronted has no baseline to call any
    single host an outlier against — that is simply a site with no CDN/WAF,
    not a finding. Flagging every host in that case would be pure noise.
    """
    raw = tmp_path / "cdncheck.jsonl"
    raw.write_text("", encoding="utf-8")  # cdncheck: "No results found."
    (tmp_path / "cdncheck-input.txt").write_text(
        "plain.acc.example\nother.acc.example\n", encoding="utf-8"
    )
    findings = [x for x in CdncheckStage().parse(raw) if isinstance(x, Finding)]
    assert findings == []


def test_missing_sidecar_yields_no_finding_and_does_not_crash(tmp_path):
    """No cdncheck-input.txt beside the raw output (e.g. a caller invoking
    parse() directly with no companion file) means there is no query list to
    diff against — degrade to "nothing to say" rather than raising.
    """
    raw = tmp_path / "cdncheck.jsonl"
    raw.write_text(
        '{"input":"acc.example","ip":"1.2.3.4","cdn":true,"cdn_name":"x"}\n',
        encoding="utf-8",
    )
    findings = [x for x in CdncheckStage().parse(raw) if isinstance(x, Finding)]
    assert findings == []


def test_cloud_only_sibling_still_counts_as_exposed(tmp_path):
    """cdncheck's `cloud` is a hosting fact, not an edge-protection fact.

    A bare EC2/Azure box with a public IP is cloud:true with no CDN or WAF in
    front of it. Counting `cloud` as fronted would suppress exactly the
    origin exposures this finding exists to catch, since most exposed origins
    ARE cloud-hosted. This pins the exclusion so nobody "fixes" it by adding
    `or m["cloud"]` to the fronted set.
    """
    raw = tmp_path / "cdncheck.jsonl"
    raw.write_text(
        '{"input":"edge.acc.example","ip":"104.20.23.154","cdn":true,'
        '"cdn_name":"cloudflare"}\n'
        '{"input":"origin.acc.example","ip":"52.1.2.3","cloud":true,'
        '"cloud_name":"aws"}\n',
        encoding="utf-8",
    )
    (tmp_path / "cdncheck-input.txt").write_text(
        "edge.acc.example\norigin.acc.example\n", encoding="utf-8"
    )
    out = list(CdncheckStage().parse(raw))

    findings = [x for x in out if isinstance(x, Finding)]
    assert [f.target for f in findings] == ["origin.acc.example"]

    # The cloud detail is still recorded on the host artifact — excluded
    # from `fronted`, not discarded.
    hosts = [a for a in out if getattr(a, "kind", None) is ArtifactKind.HOST]
    origin = next(a for a in hosts if a.value == "origin.acc.example")
    assert origin.meta["cloud"] is True
    assert origin.meta["cloud_name"] == "aws"
    assert origin.meta["cdn"] is False and origin.meta["waf"] is False


def test_enrichment_survives_a_host_already_seeded_by_prepare(tmp_path):
    """Route parse() output through ctx.store, the way the runner does.

    Every other test here asserts on parse() in isolation, which is exactly
    how the real defect stayed invisible: app.prepare() seeds each target as
    a HOST artifact before any stage runs, and the store's old per-artifact
    `setdefault` meant a re-yielded HOST was dropped whole — enrichment and
    all. parse() was correct the entire time; the store threw the result
    away. Any stage annotating a known host has the same exposure, so the
    assertion has to cross the store boundary to mean anything.
    """
    from sweeper.artifacts import Artifact
    from sweeper.store import ArtifactStore

    store = ArtifactStore(tmp_path / "run")
    # What app.prepare() does, before any stage runs.
    store.add(Artifact(ArtifactKind.HOST, "acc.example",
                       meta={"src": "targets-file"}))
    store.flush()

    raw = tmp_path / "cdncheck.jsonl"
    raw.write_text(
        '{"input":"acc.example","ip":"104.20.23.154","cdn":true,'
        '"cdn_name":"cloudflare"}\n',
        encoding="utf-8",
    )
    for item in CdncheckStage().parse(raw):
        if not isinstance(item, Finding):
            store.add(item)

    host = next(a for a in store.get(ArtifactKind.HOST)
                if a.value == "acc.example")
    assert host.meta["cdn"] is True, "cdncheck's enrichment was dropped"
    assert host.meta["cdn_name"] == "cloudflare"
    # The discoverer's provenance is not clobbered by the enrichment.
    assert host.meta["src"] == "targets-file"


def ctx_for(tmp_path, **kw):
    t = tmp_path / "targets.txt"
    t.write_text("acc.example\n")
    return RunContext.create(
        RunConfig(targets_file=t, outdir=tmp_path / "out", **kw)
    )


@pytest.mark.slow
@pytest.mark.skipif(binaries.resolve("cdncheck") is None,
                    reason="cdncheck not installed; cannot probe the real binary")
@pytest.mark.parametrize("level", LEVELS)
def test_every_level_flag_set_is_accepted_by_the_real_binary(tmp_path, level):
    """Ask cdncheck itself whether each level's flag set parses.

    cdncheck's levels are all empty lists today, but this still catches a
    regression in the fixed part of the command (-i/-jsonl/-silent/-resp)
    the same way the naabu/dnsx probes do for theirs.
    """
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out",
                                      level=level))
    err = preflight.validate_arguments(CdncheckStage(), ctx)
    assert err == "", f"cdncheck rejected the {level!r} flag set: {err}"
