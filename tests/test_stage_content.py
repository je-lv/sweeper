"""Content discovery: the paths nothing links to.

THE GAP THIS CLOSES. Every other discovery stage follows a reference --
katana follows links, jsrecon follows script tags and chunk maps, dnsx
follows records. None can reach a path nothing points at. Measured against a
lab whose crawl produced 17744 artifacts: `/api/debug/config` returns 200 and
dumps the application config with third-party credentials, and the pipeline
never found it, because nothing links to it. Same for `/.git/config` and
`/backup.zip`.
"""
import json

import pytest

from sweeper.artifacts import Artifact, ArtifactKind, Finding
from sweeper.context import RunConfig, RunContext
from sweeper.stages import registry
from sweeper.stages.base import LEVELS
from sweeper.stages.content import (SENSITIVE, ContentStage, build_wordlist,
                                    classify, origins)


def ctx_for(tmp_path, level="mid", services=()):
    targets = tmp_path / "t.txt"
    targets.write_text("acc.example\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out", level=level))
    for url, meta in services:
        ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, url, meta=meta))
    return ctx


@pytest.fixture
def hermetic_wordlists(tmp_path, monkeypatch):
    """Keep command-construction tests independent of a host SecLists install."""
    import sweeper.stages.content as mod
    words = tmp_path / "content-words.txt"
    words.write_text(".env\n.git/config\nbackup.zip\n", encoding="utf-8")
    previous = ()
    for index, level in enumerate(LEVELS):
        extra = tmp_path / f"content-words-{index}.txt"
        extra.write_text(f"level-{index}\n", encoding="utf-8")
        previous = previous + (str(extra),)
        monkeypatch.setitem(mod.WORDLISTS, level, (str(words),) + previous)


def test_stage_satisfies_contract():
    assert registry.validate(ContentStage()) == []


# --- origin reduction ------------------------------------------------------

def test_thousands_of_crawled_urls_reduce_to_their_origins():
    """The crawl feeds this stage every discovered URL.

    Fuzzing a wordlist against `https://h/a/b` asks "what exists under
    /a/b", a different and much narrower question -- and each duplicate
    re-runs the ENTIRE wordlist against the client.
    """
    urls = [f"https://acc.example/page/{i}" for i in range(500)]
    urls.append("https://acc.example/")
    assert origins([Artifact(ArtifactKind.HTTP_SERVICE, u) for u in urls],
                   urls) == ["https://acc.example"]


def test_distinct_ports_and_schemes_are_distinct_origins():
    urls = ["https://acc.example:443/x", "http://acc.example:80/x",
            "https://acc.example:8443/y"]
    got = origins([Artifact(ArtifactKind.HTTP_SERVICE, u) for u in urls], urls)
    assert len(got) == 3


def test_out_of_scope_urls_are_dropped():
    urls = ["https://acc.example/a", "https://evil.example/a"]
    got = origins([Artifact(ArtifactKind.HTTP_SERVICE, u) for u in urls],
                  ["https://acc.example/a"])
    assert got == ["https://acc.example"]


def test_origin_order_is_deterministic():
    """build_command must be deterministic or preflight validates a
    different argv than the runner executes."""
    urls = ["https://b.example/x", "https://a.example/x"]
    arts = [Artifact(ArtifactKind.HTTP_SERVICE, u) for u in urls]
    assert origins(arts, urls) == origins(list(reversed(arts)), urls)


# --- wordlist merging ------------------------------------------------------

def test_wordlists_are_merged_and_deduped(tmp_path, monkeypatch):
    """No single SecLists file covers the ordinary cases, measured:

        quickhits.txt  has .git/config .env backup.zip  -- no server-status
        common.txt     has .git/config .env server-status -- no backups
    """
    import sweeper.stages.content as mod
    a = tmp_path / "a.txt"; a.write_text(".env\n.git/config\nshared\n")
    b = tmp_path / "b.txt"; b.write_text("server-status\nshared\n")
    monkeypatch.setitem(mod.WORDLISTS, "mid", (str(a), str(b)))
    dest = tmp_path / "words.txt"
    count = build_wordlist("mid", dest)
    words = dest.read_text().split()
    assert count == 4
    assert sorted(words) == [".env", ".git/config", "server-status", "shared"]


def test_leading_slashes_and_comments_are_normalised(tmp_path, monkeypatch):
    import sweeper.stages.content as mod
    src = tmp_path / "w.txt"
    src.write_text("# a comment\n/.env\n\n  spaced  \n")
    monkeypatch.setitem(mod.WORDLISTS, "mid", (str(src),))
    dest = tmp_path / "words.txt"
    build_wordlist("mid", dest)
    assert dest.read_text().split() == [".env", "spaced"]


def test_a_missing_wordlist_file_is_skipped_not_fatal(tmp_path, monkeypatch):
    import sweeper.stages.content as mod
    real = tmp_path / "real.txt"; real.write_text(".env\n")
    monkeypatch.setitem(mod.WORDLISTS, "mid",
                        (str(tmp_path / "nope.txt"), str(real)))
    assert build_wordlist("mid", tmp_path / "w.txt") == 1


# --- level gating ----------------------------------------------------------

@pytest.mark.parametrize("level", LEVELS)
def test_enabled_at_every_level(level, tmp_path, hermetic_wordlists):
    """`low` gets the small high-signal list rather than nothing.

    These are read-only, rate-limited GETs, and what the short list catches
    -- .env, .git, backups -- is exactly what is worth catching on a first
    pass. Escalation is in the WORDLIST SIZE, not in whether it runs.
    """
    ctx = ctx_for(tmp_path, level,
                  [("https://acc.example/", {"host": "acc.example"})])
    assert ContentStage().build_command(ctx) != []


def test_no_wordlists_on_this_machine_means_no_command(tmp_path, monkeypatch):
    """Running ffuf against an empty list finds nothing, which is
    indistinguishable from a target with nothing to find."""
    import sweeper.stages.content as mod
    monkeypatch.setitem(mod.WORDLISTS, "mid", (str(tmp_path / "absent.txt"),))
    ctx = ctx_for(tmp_path, "mid",
                  [("https://acc.example/", {"host": "acc.example"})])
    assert ContentStage().build_command(ctx) == []


# --- the command -----------------------------------------------------------

def test_wordlists_are_cumulative_across_levels():
    """Each level is the previous list plus more.

    A `full` that carried the same lists as `high` would look like an
    escalation and change nothing about what the stage can find -- which is
    what the first draft of this table did.
    """
    import sweeper.stages.content as mod
    seen = [set(mod.WORDLISTS[l]) for l in ("low", "mid", "high", "full")]
    for smaller, larger in zip(seen, seen[1:]):
        assert smaller < larger, "levels must strictly grow"


def test_operator_wordlists_add_to_the_level_lists():
    from sweeper.stages.content import WORDLISTS, sources_for
    got = sources_for("mid", ("/opt/mine.txt",))
    assert set(WORDLISTS["mid"]).issubset(got)
    assert "/opt/mine.txt" in got


def test_operator_wordlists_can_replace_the_level_lists():
    """A curated list aimed at one target should not have to carry 70k
    generic guesses alongside it."""
    from sweeper.stages.content import sources_for
    assert sources_for("full", ("/opt/mine.txt",), only=True) == ("/opt/mine.txt",)


def test_soft_404_calibration_is_always_on(tmp_path):
    """A target answering 200 for every path -- an ordinary SPA default --
    otherwise reports the WHOLE wordlist as discovered."""
    for level in LEVELS:
        assert "-ac" in ContentStage().levels[level], level


def test_calibration_is_per_host(tmp_path):
    """The load-bearing half, and the one the first draft missed.

    This stage fuzzes several origins in ONE clusterbomb run, and plain -ac
    calibrates once: a well-behaved first host sets the filter and a
    catch-all origin later in the list sails straight through it.

    Measured against the lab, where 127.0.0.1:8080 was the operator's own
    Burp Suite answering 200 to everything: id_rsa, .htpasswd, .svn/entries,
    phpinfo.php and a dozen more were reported as exposed on that origin.
    False positives in a client deliverable are worse than finding nothing.
    """
    for level in LEVELS:
        assert "-ach" in ContentStage().levels[level], level


def test_rate_and_concurrency_are_both_bounded(tmp_path):
    """-t bounds threads in flight, -rate bounds requests per second; they
    are not substitutes. Same reasoning as stages/vhost.py."""
    for level in LEVELS:
        flags = ContentStage().levels[level]
        assert "-t" in flags and "-rate" in flags, level


def test_one_invocation_covers_every_origin(tmp_path, hermetic_wordlists):
    """Origins and paths are two wordlists combined by ffuf, so the whole
    matrix is a single command -- the one-command-per-stage contract."""
    ctx = ctx_for(tmp_path, "mid", [
        ("https://a.example/", {"host": "a.example"}),
        ("https://b.example/", {"host": "b.example"}),
    ])
    ctx.store.add(Artifact(ArtifactKind.HOST, "a.example"))
    argv = [str(x) for x in ContentStage().build_command(ctx)]
    assert "HFUZZ/WFUZZ" in argv
    assert "clusterbomb" in argv


def test_the_wordlist_lands_in_the_run_evidence(tmp_path, hermetic_wordlists):
    """A finding that cannot be reproduced from the run's own artifacts is a
    weaker finding: SecLists changes under package upgrades."""
    ctx = ctx_for(tmp_path, "mid",
                  [("https://acc.example/", {"host": "acc.example"})])
    ContentStage().build_command(ctx)
    assert (ctx.run_dir / "raw" / "content-words.txt").is_file()


# --- classification --------------------------------------------------------

@pytest.mark.parametrize("path,severity", [
    ("/.env", "critical"),
    ("/.git/config", "high"),
    ("/backup.sql", "high"),
    ("/server-status", "medium"),
    ("/.DS_Store", "low"),
])
def test_sensitive_paths_are_classified(path, severity):
    got = classify(path)
    assert got is not None and got[0] == severity


def test_an_ordinary_path_is_not_a_finding():
    """"This path exists" is not by itself a finding. A stage that reports
    every 200 is noise a reader learns to skip."""
    assert classify("/about") is None
    assert classify("/api/users") is None


def test_the_longest_match_wins():
    """`.git/config` must not be classified by a bare `config` entry."""
    got = classify("/.git/config")
    assert got is not None and "Git" in got[1]


# --- parsing ---------------------------------------------------------------

def write_ffuf(tmp_path, results):
    p = tmp_path / "content.json"
    p.write_text(json.dumps({"results": results, "config": {}}))
    return p


def test_every_hit_becomes_a_service_artifact(tmp_path):
    raw = write_ffuf(tmp_path, [
        {"url": "https://acc.example/about", "status": 200, "length": 12},
        {"url": "https://acc.example/.env", "status": 200, "length": 40},
    ])
    arts = [x for x in ContentStage().parse(raw)
            if getattr(x, "kind", None) is ArtifactKind.HTTP_SERVICE]
    assert {a.value for a in arts} == {"https://acc.example/about",
                                       "https://acc.example/.env"}


def test_artifacts_carry_host_meta_for_admission_control(tmp_path):
    """runner.py's choke point scope-checks meta["host"], not the URL."""
    raw = write_ffuf(tmp_path, [
        {"url": "https://acc.example/x", "status": 200, "length": 1}])
    art = next(x for x in ContentStage().parse(raw)
               if getattr(x, "kind", None) is ArtifactKind.HTTP_SERVICE)
    assert art.meta["host"] == "acc.example"


def test_only_sensitive_paths_produce_findings(tmp_path):
    raw = write_ffuf(tmp_path, [
        {"url": "https://acc.example/about", "status": 200, "length": 12},
        {"url": "https://acc.example/.env", "status": 200, "length": 40},
    ])
    findings = [x for x in ContentStage().parse(raw) if isinstance(x, Finding)]
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_two_sensitive_paths_on_one_origin_are_two_findings(tmp_path):
    """Without a distinguishing matcher they collapse onto one finding id
    and store.add_finding keeps only the first -- the collision class this
    project has hit repeatedly."""
    raw = write_ffuf(tmp_path, [
        {"url": "https://acc.example/.env", "status": 200, "length": 40},
        {"url": "https://acc.example/backup.sql", "status": 200, "length": 90},
    ])
    findings = [x for x in ContentStage().parse(raw) if isinstance(x, Finding)]
    assert len({f.id for f in findings}) == 2


def test_duplicate_rows_are_emitted_once(tmp_path):
    raw = write_ffuf(tmp_path, [
        {"url": "https://acc.example/.env", "status": 200, "length": 40},
        {"url": "https://acc.example/.env", "status": 200, "length": 40},
    ])
    arts = [x for x in ContentStage().parse(raw)
            if getattr(x, "kind", None) is ArtifactKind.HTTP_SERVICE]
    assert len(arts) == 1


def test_a_missing_or_malformed_file_degrades_to_nothing(tmp_path):
    assert list(ContentStage().parse(tmp_path / "absent.json")) == []
    bad = tmp_path / "bad.json"; bad.write_text("{not json")
    assert list(ContentStage().parse(bad)) == []


def test_the_client_rate_cap_applies_to_this_stage(tmp_path, hermetic_wordlists):
    """--rate is the no-DoS engagement term, and this stage is the heaviest
    request generator in the tool -- `full` is ~700k requests against ten
    origins. An override that did not reach here would be missing from the
    one place it matters most."""
    ctx = ctx_for(tmp_path, "mid",
                  [("https://acc.example/", {"host": "acc.example"})])
    ctx.config.rate_override = 7
    argv = [str(x) for x in ContentStage().build_command(ctx)]
    assert argv[argv.index("-rate") + 1] == "7"
    assert argv.count("-rate") == 1, "the level's -rate must be replaced, not doubled"


# --- catch-all origins -----------------------------------------------------
# An origin that answers 200 for every path turns the whole wordlist into
# "findings". ffuf's calibration filters on response SIZE, so an origin that
# echoes the requested path back (Burp Suite's error page does) defeats it --
# -ac and -ach are both on and neither helps. Caught here instead, on the one
# signal that separates them cleanly: hits as a fraction of the wordlist.
#
#     real origins            25 hits    0.4% of a 7134-word list
#     the catch-all         7134 hits    100%

def write_run(tmp_path, results, words):
    (tmp_path / "content-words.txt").write_text("\n".join(words) + "\n")
    p = tmp_path / "content.json"
    p.write_text(json.dumps({"results": results, "config": {}}))
    return p


def test_a_catchall_origin_yields_one_finding_not_hundreds(tmp_path):
    words = [f"w{i}" for i in range(100)]
    raw = write_run(tmp_path, [
        {"url": f"https://catchall.example/{w}", "status": 200, "length": 10}
        for w in words
    ], words)
    findings = [x for x in ContentStage().parse(raw) if isinstance(x, Finding)]
    assert len(findings) == 1
    assert findings[0].template_id == "content-catchall"


def test_a_catchall_origin_emits_no_service_artifacts(tmp_path):
    """Thousands of imaginary endpoints would otherwise flood nuclei and
    arjun, which consume the HTTP_SERVICE pool."""
    words = [f"w{i}" for i in range(100)]
    raw = write_run(tmp_path, [
        {"url": f"https://catchall.example/{w}", "status": 200, "length": 10}
        for w in words
    ], words)
    arts = [x for x in ContentStage().parse(raw)
            if getattr(x, "kind", None) is ArtifactKind.HTTP_SERVICE]
    assert arts == []


def test_a_normal_origin_is_untouched(tmp_path):
    """0.4% of the wordlist is an ordinary result and must survive."""
    words = [f"w{i}" for i in range(100)]
    raw = write_run(tmp_path, [
        {"url": "https://real.example/.env", "status": 200, "length": 40},
        {"url": "https://real.example/backup.sql", "status": 200, "length": 90},
    ], words)
    out = list(ContentStage().parse(raw))
    findings = [x for x in out if isinstance(x, Finding)]
    assert {f.severity for f in findings} == {"critical", "high"}
    assert not any(f.template_id == "content-catchall" for f in findings)


def test_one_catchall_does_not_suppress_a_healthy_origin(tmp_path):
    """The measured case exactly: a good host and a catch-all in one run."""
    words = [f"w{i}" for i in range(100)]
    results = [{"url": f"https://catchall.example/{w}", "status": 200,
                "length": 10} for w in words]
    results.append({"url": "https://real.example/.env", "status": 200,
                    "length": 40})
    raw = write_run(tmp_path, results, words)
    out = list(ContentStage().parse(raw))
    arts = [x for x in out if getattr(x, "kind", None) is ArtifactKind.HTTP_SERVICE]
    assert [a.value for a in arts] == ["https://real.example/.env"]
    assert any(f.template_id == "content-catchall" for f in out
               if isinstance(f, Finding))
    assert any(f.severity == "critical" for f in out if isinstance(f, Finding))


def test_without_the_sidecar_nothing_is_suppressed(tmp_path):
    """No denominator means no way to judge a hit rate. Fail OPEN here: a
    suppressed real finding is worse than a noisy one."""
    p = tmp_path / "content.json"
    p.write_text(json.dumps({"results": [
        {"url": "https://x.example/.env", "status": 200, "length": 4}],
        "config": {}}))
    findings = [x for x in ContentStage().parse(p) if isinstance(x, Finding)]
    assert any(f.severity == "critical" for f in findings)
