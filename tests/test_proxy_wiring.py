import urllib.request

from sweeper import preflight
from sweeper.stages import content as content_module
from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.content import ContentStage
from sweeper.stages.arjun import ArjunStage
from sweeper.stages.httpx import HttpxStage
from sweeper.stages.jsrecon import fetch_js
from sweeper.stages.katana import KatanaStage
from sweeper.stages.nuclei import NucleiStage
from sweeper.stages.vhost import VhostStage
from sweeper.report.markdown import render_markdown
from sweeper.report.html import render_html


PROXY = "http://127.0.0.1:8080"


def context(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    targets = tmp_path / "targets.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(
        targets_file=targets, outdir=tmp_path / "out", level="high",
        proxy=PROXY,
    ))
    ctx.store.add(Artifact(ArtifactKind.HOST, "acc.example"))
    ctx.store.add(Artifact(
        ArtifactKind.HTTP_SERVICE, "https://acc.example/",
        meta={"host": "acc.example", "port": "443", "status_code": 200},
    ))
    return ctx


def test_all_http_stages_are_covered_by_proxy_health_preflight():
    assert preflight.PROXY_STAGES == {
        "httpx", "vhost", "content", "katana", "jsrecon", "arjun",
        "nuclei",
    }


def test_ffuf_stages_receive_the_configured_proxy(tmp_path, monkeypatch):
    def fake_wordlist(level, destination, extra=(), only=False):
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text("admin\n")
        return 1

    monkeypatch.setattr(content_module, "build_wordlist", fake_wordlist)
    for index, stage in enumerate((VhostStage(), ContentStage())):
        cmd = stage.build_command(context(tmp_path / str(index)))
        assert cmd.count("-x") == 1, (stage.name, cmd)
        assert cmd[cmd.index("-x") + 1] == PROXY


def test_external_http_stages_receive_the_configured_proxy(tmp_path):
    cases = [
        (HttpxStage(), "-proxy"),
        (KatanaStage(), "-proxy"),
        (NucleiStage(), "-proxy"),
        (ArjunStage(), "--proxy"),
    ]
    for index, (stage, flag) in enumerate(cases):
        cmd = stage.build_command(context(tmp_path / str(index)))
        assert cmd.count(flag) == 1, (stage.name, cmd)
        assert cmd[cmd.index(flag) + 1] == PROXY


def test_js_fetcher_installs_explicit_proxy_for_both_schemes(
    tmp_path, monkeypatch,
):
    captured = []

    class DummyOpener:
        pass

    def fake_build_opener(*handlers):
        captured.extend(handlers)
        return DummyOpener()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    fetch_js(context(tmp_path), [], tmp_path / "js")

    proxy_handlers = [h for h in captured
                      if isinstance(h, urllib.request.ProxyHandler)]
    assert len(proxy_handlers) == 1
    assert proxy_handlers[0].proxies == {"http": PROXY, "https": PROXY}


def test_reports_state_http_proxy_and_direct_raw_transport_split(tmp_path):
    ctx = context(tmp_path)
    md = render_markdown(ctx, [])
    html = render_html(ctx, [])
    for report in (md, html):
        assert "HTTP proxy" in report
        assert PROXY in report
        assert "TCP" in report and "UDP" in report
        assert "direct" in report
