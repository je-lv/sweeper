"""A targets file of URLs must seed HOSTNAMES, not URLs.

Found 2026-08-04 on the first live run. The scope file held three lines of
the form `https://shop.client.example/` -- the ordinary shape of a scope
pasted out of an engagement document -- and every DNS-based stage failed:

    naabu: no valid ipv4 or ipv6 targets were found
    dnsx, cdncheck: complete, 0 artifacts

ScopeGuard.allows() normalises before comparing, so all three were correctly
admitted and the run reported `3 requested, 3 in scope`. But ScopeGuard.filter()
returns the RAW strings it was given, and app.prepare() seeds those as HOST
artifacts -- so `https://shop.client.example/` was handed to naabu as a
hostname, and nothing can resolve that.

The failure is quiet in the way this project keeps finding: scope validation
passes, the manifest says three targets are in scope, two stages report
`complete`, and the run produces nothing. The operator sees a scope problem
where there is none.

Normalising at the seam is the fix rather than teaching each stage to parse
URLs: a HOST artifact is a hostname by definition, and every stage downstream
is entitled to assume it.
"""
from sweeper.app import prepare
from sweeper.artifacts import ArtifactKind
from sweeper.context import RunConfig
from sweeper.scope import ScopeGuard


def hosts_from(tmp_path, lines):
    t = tmp_path / "targets.txt"
    t.write_text("\n".join(lines) + "\n")
    ctx = prepare(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    return sorted(ctx.store.values(ArtifactKind.HOST))


def test_a_scope_file_of_urls_seeds_bare_hostnames(tmp_path):
    assert hosts_from(tmp_path, [
        "https://shop.client.example/",
        "http://api.client.example/v2/orders",
    ]) == ["api.client.example", "shop.client.example"]


def test_a_url_with_a_port_seeds_the_host_without_it(tmp_path):
    """The port belongs to a PORT artifact, which naabu produces. Leaving it
    on the host makes the hostname unresolvable for every DNS stage."""
    assert hosts_from(tmp_path, ["https://shop.client.example:8443/"]) \
        == ["shop.client.example"]


def test_bare_hostnames_are_unchanged(tmp_path):
    assert hosts_from(tmp_path, ["shop.client.example", "api.client.example"]) \
        == ["api.client.example", "shop.client.example"]


def test_a_trailing_dot_is_dropped_so_one_host_is_not_seeded_twice(tmp_path):
    """`client.example.` and `client.example` are the same host. Seeded as
    written they are two artifacts, and every stage scans it twice."""
    assert hosts_from(tmp_path, ["client.example.", "client.example"]) \
        == ["client.example"]


def test_case_is_folded_so_one_host_is_not_seeded_twice(tmp_path):
    assert hosts_from(tmp_path, ["Shop.Client.Example", "shop.client.example"]) \
        == ["shop.client.example"]


def test_an_ip_literal_survives(tmp_path):
    assert hosts_from(tmp_path, ["198.51.100.10"]) == ["198.51.100.10"]


def test_userinfo_cannot_smuggle_a_second_host_into_the_store(tmp_path):
    """`https://real.example@evil.example/` addresses evil.example.

    normalize() routes everything through urlsplit precisely so that the
    stored host is the one the URL actually reaches. Seeding the raw string
    would put an unresolvable value in the store; seeding the wrong half
    would put an out-of-scope host in it.
    """
    t = tmp_path / "targets.txt"
    t.write_text("https://real.example@evil.example/\n")
    ctx = prepare(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    hosts = sorted(ctx.store.values(ArtifactKind.HOST))
    assert "real.example" not in hosts
    assert hosts in ([], ["evil.example"])


def test_the_scope_guard_and_the_store_agree_on_what_was_admitted(tmp_path):
    """Whatever prepare() seeds must be a host the guard would admit.

    Otherwise admission control and the artifact store hold two different
    ideas of the scope, and a stage re-checking its input against the guard
    (they all do) can refuse a target the run was built from.
    """
    t = tmp_path / "targets.txt"
    t.write_text("https://shop.client.example/\n")
    ctx = prepare(RunConfig(targets_file=t, outdir=tmp_path / "out"))
    guard = ScopeGuard(["shop.client.example"])
    for host in ctx.store.values(ArtifactKind.HOST):
        assert guard.allows(host), f"seeded {host!r} would be refused downstream"
