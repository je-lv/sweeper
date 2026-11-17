import json
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.runner import run_stages
from sweeper.stages.jsrecon import JsreconStage


def ctx_for(tmp_path):
    t = tmp_path / "t.txt"; t.write_text("acc.example\n")
    return RunContext.create(RunConfig(targets_file=t, outdir=tmp_path / "out"))


def test_stage_declares_itself_in_process():
    assert JsreconStage().in_process is True


def test_every_other_stage_defaults_to_subprocess():
    from sweeper.stages.dnsx import DnsxStage
    assert getattr(DnsxStage(), "in_process", False) is False


def test_in_process_stage_writes_its_own_raw_file(tmp_path, monkeypatch):
    ctx = ctx_for(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                           "https://acc.example/app.js",
                           meta={"content_type": "application/javascript"}))
    monkeypatch.setattr(
        "sweeper.stages.jsrecon.fetch_js",
        lambda ctx, urls, js_dir, timeout=20: _fake_fetch(js_dir),
    )
    results = run_stages(ctx, [JsreconStage()])
    assert results[0].status == "complete"
    raw = ctx.raw_path("jsrecon")
    assert raw.exists()
    rows = [json.loads(l) for l in raw.read_text().splitlines() if l.strip()]
    assert any(r["url"].endswith("app.js") for r in rows)


def _fake_fetch(js_dir):
    js_dir.mkdir(parents=True, exist_ok=True)
    (js_dir / "bundle0000.js").write_text(
        'const k="sk_live_51H8xQ2eZvKYlo2CabcdefghijklmnopQ";'
        'fetch("/api/v2/orders");'
    )
    (js_dir / "bundle0000.url").write_text("https://acc.example/app.js")
    return 1


def test_findings_reach_the_store(tmp_path, monkeypatch):
    ctx = ctx_for(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/app.js",
                           meta={"content_type": "application/javascript"}))
    monkeypatch.setattr("sweeper.stages.jsrecon.fetch_js",
                        lambda ctx, urls, js_dir, timeout=20: _fake_fetch(js_dir))
    run_stages(ctx, [JsreconStage()])
    assert any(f.severity == "critical" for f in ctx.store.findings)


def test_only_javascript_services_are_fetched(tmp_path):
    ctx = ctx_for(tmp_path)
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/page.html",
                           meta={"content_type": "text/html"}))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, "https://acc.example/a.js",
                           meta={"content_type": "application/javascript"}))
    urls = JsreconStage().js_urls(ctx)
    assert urls == ["https://acc.example/a.js"]
