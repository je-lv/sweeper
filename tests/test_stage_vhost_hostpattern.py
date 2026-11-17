"""The Host header vhost fuzzing actually sends.

THE DEFECT THIS PINS. The stage sent `-H "Host: FUZZ"` with a wordlist of
bare DNS LABELS ("admin", "www2", "ns"), so every request carried
`Host: admin` rather than `Host: admin.vulnshop.test`. No virtual host on
any server matches a bare label, so every guess fell through to the default
vhost and returned the identical wildcard response -- which the baseline
filter then correctly suppressed as noise. Net effect: the stage ran,
exited 0, wrote a 1.3 MB evidence file, reported "complete -- 0 artifacts,
0 findings", and could never have found a vhost against ANY target.

Measured against the lab: `Host: admin` -> 200/645 (the wildcard default),
`Host: admin.vulnshop.test` -> 200/2426 (the find). The whole capability
turned on that suffix.
"""
import pytest

from sweeper.artifacts import Artifact, ArtifactKind
from sweeper.context import RunConfig, RunContext
from sweeper.stages.vhost import VhostStage, fuzz_host_pattern


def make_ctx(tmp_path, services, allowed=None):
    targets = tmp_path / "targets.txt"
    # The service hosts must be in the allowlist or build_command's own
    # scope filter drops them and the stage correctly builds nothing --
    # which would make these assertions pass vacuously.
    if allowed is None:
        allowed = ["git.vulnshop.test", "vulnshop.test"]
    targets.write_text("\n".join(allowed) + "\n")
    ctx = RunContext.create(RunConfig(targets_file=targets,
                                      outdir=tmp_path / "out"))
    for s in services:
        ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, s))
    return ctx


@pytest.mark.parametrize("host,expected", [
    # A subdomain: fuzz its PARENT, so the wordlist's labels land beside it.
    ("git.vulnshop.test", "FUZZ.vulnshop.test"),
    ("www.vulnshop.test", "FUZZ.vulnshop.test"),
    # An apex: dropping a label would leave the bare TLD, so keep the whole
    # name. "FUZZ.test" would fuzz someone else's namespace entirely.
    ("vulnshop.test", "FUZZ.vulnshop.test"),
    ("example.com", "FUZZ.example.com"),
    # Deeper names fuzz beside the target, not at the registrable root.
    ("api.staging.example.com", "FUZZ.staging.example.com"),
])
def test_pattern_appends_the_right_domain(host, expected):
    assert fuzz_host_pattern(host, []) == expected


def test_an_ip_target_falls_back_to_an_allowlisted_domain():
    """An IP has no domain to append, but the engagement does.

    Fuzzing `Host: FUZZ` against an IP is the original defect in miniature:
    it cannot match anything. The authorized domain is the only sensible
    suffix, and the scope allowlist is where it lives.
    """
    assert fuzz_host_pattern("10.0.0.5", ["vulnshop.test"]) == "FUZZ.vulnshop.test"


def test_an_ip_target_with_no_allowlisted_domain_yields_nothing():
    """Refuse rather than send a header that cannot match.

    Returning "FUZZ" here would reinstate exactly the bug: thousands of
    requests that no server can route, reported as a clean empty result.
    """
    assert fuzz_host_pattern("10.0.0.5", ["10.0.0.5"]) == ""


def test_wildcard_allowlist_entries_are_usable_as_a_suffix():
    assert fuzz_host_pattern("10.0.0.5", ["*.vulnshop.test"]) == "FUZZ.vulnshop.test"


def test_a_broken_origin_is_not_chosen_when_a_working_one_exists(tmp_path):
    """The stage fuzzes ONE origin, so picking a dead one wastes the stage.

    Observed against the lab: httpx records nginx's "plain HTTP request was
    sent to HTTPS port" 400 as a live HTTP service, and vhost -- which took
    whatever sorted first -- fuzzed exactly that. 5000 requests, every one
    answered 400, zero results, reported as a clean empty stage.
    """
    ctx = make_ctx(tmp_path, [], allowed=["api.vulnshop.test",
                                          "www.vulnshop.test"])
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                           "http://api.vulnshop.test:8443",
                           meta={"host": "api.vulnshop.test", "status_code": 400}))
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                           "http://www.vulnshop.test:80",
                           meta={"host": "www.vulnshop.test", "status_code": 200}))
    argv = [str(a) for a in VhostStage().build_command(ctx)]
    assert argv[argv.index("-u") + 1] == "http://www.vulnshop.test:80", argv


def test_a_standard_port_is_preferred_over_an_odd_one(tmp_path):
    """Both answer, but :80 is the unambiguous one for Host-header routing.

    On an https origin the TLS SNI comes from the URL while the vhost under
    test comes from the Host header, so the two disagree by construction and
    a server that routes on SNI never shows the vhost at all.
    """
    ctx = make_ctx(tmp_path, [], allowed=["www.vulnshop.test"])
    for url, port in (("https://www.vulnshop.test:10443", "10443"),
                      ("http://www.vulnshop.test:80", "80")):
        ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE, url,
                               meta={"host": "www.vulnshop.test",
                                     "port": port, "status_code": 200}))
    argv = [str(a) for a in VhostStage().build_command(ctx)]
    assert argv[argv.index("-u") + 1] == "http://www.vulnshop.test:80", argv


def test_selection_is_deterministic(tmp_path):
    """Two runs of the same store must fuzz the same origin.

    build_command is called by preflight and again by the runner; if they
    disagree, preflight validated a command that was never executed.
    """
    def build():
        ctx = make_ctx(tmp_path, [], allowed=["a.vulnshop.test",
                                              "b.vulnshop.test"])
        for host in ("b.vulnshop.test", "a.vulnshop.test"):
            ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                                   f"http://{host}:80",
                                   meta={"host": host, "status_code": 200}))
        return [str(x) for x in VhostStage().build_command(ctx)]
    first, second = build(), build()
    assert first[first.index("-u") + 1] == second[second.index("-u") + 1]


def test_an_all_broken_pool_still_fuzzes_something(tmp_path):
    """No working origin is not a reason to do nothing.

    A 4xx everywhere can simply mean the default vhost rejects unknown
    names, which is exactly the condition vhost discovery exists for.
    """
    ctx = make_ctx(tmp_path, [], allowed=["www.vulnshop.test"])
    ctx.store.add(Artifact(ArtifactKind.HTTP_SERVICE,
                           "http://www.vulnshop.test:80",
                           meta={"host": "www.vulnshop.test", "status_code": 404}))
    argv = [str(a) for a in VhostStage().build_command(ctx)]
    assert "-u" in argv


def test_build_command_sends_a_qualified_host_header(tmp_path):
    ctx = make_ctx(tmp_path, ["http://git.vulnshop.test:80"])
    argv = [str(a) for a in VhostStage().build_command(ctx)]
    assert "Host: FUZZ.vulnshop.test" in argv, argv
    assert "Host: FUZZ" not in argv, (
        "a bare label cannot match any virtual host; this is the defect"
    )


def test_the_stage_is_skipped_when_no_pattern_can_be_built(tmp_path):
    """No usable suffix must mean NO REQUESTS, not unroutable ones."""
    ctx = make_ctx(tmp_path, ["http://10.0.0.5:80"], allowed=["10.0.0.5"])
    assert VhostStage().build_command(ctx) == []


def test_preflight_does_not_crash_on_a_stage_that_builds_no_command(tmp_path):
    """subprocess.run([]) raises IndexError, which is not a validation result.

    preflight probes every stage's argv before the run; a stage that
    declines to build one has nothing to validate, and must read as "no
    argument error" rather than taking the whole run down.
    """
    from sweeper import preflight
    ctx = make_ctx(tmp_path, ["http://10.0.0.5:80"], allowed=["10.0.0.5"])
    assert preflight.validate_arguments(VhostStage(), ctx) == ""


def test_discovered_vhost_is_reported_as_a_fully_qualified_name(tmp_path):
    """parse() must emit admin.vulnshop.test, not the bare label 'admin'.

    A finding that says "admin" is not actionable and does not match the
    allowlist, so the runner's admission check would refuse the artifact it
    just discovered.
    """
    raw = tmp_path / "vhost.json"
    raw.write_text('{"results": ['
                   '{"input": {"FUZZ": "zzz"}, "host": "zzz", '
                   '"length": 645, "words": 77, "status": 200},'
                   '{"input": {"FUZZ": "nope"}, "host": "nope", '
                   '"length": 645, "words": 77, "status": 200},'
                   '{"input": {"FUZZ": "admin"}, "host": "admin", '
                   '"length": 2426, "words": 120, "status": 200}'
                   '], "config": {"url": "http://git.vulnshop.test:80", '
                   '"headers": {"Host": "FUZZ.vulnshop.test"}}}')
    out = list(VhostStage().parse(raw))
    names = [getattr(o, "value", "") or getattr(o, "target", "") for o in out]
    assert any("admin.vulnshop.test" in n for n in names), names
    assert not any(n.endswith("//admin") or n == "admin" for n in names), names
