import pytest
from sweeper.artifacts import ArtifactKind, Artifact, Finding, finding_id


def test_artifact_kinds_exist():
    assert {k.name for k in ArtifactKind} == {
        "HOST", "DNS_RECORD", "PORT", "UDP_PORT", "HTTP_SERVICE", "FINDING"
    }


def test_artifact_holds_value_and_meta():
    a = Artifact(kind=ArtifactKind.HOST, value="acc.example", meta={"src": "file"})
    assert a.value == "acc.example"
    assert a.meta["src"] == "file"


def test_finding_id_is_stable_across_calls():
    a = finding_id("dnsx", "ns1.example", "dns-axfr", "matcher-0")
    b = finding_id("dnsx", "ns1.example", "dns-axfr", "matcher-0")
    assert a == b
    assert len(a) == 40


def test_finding_id_differs_on_any_component():
    base = finding_id("dnsx", "ns1.example", "dns-axfr", "m0")
    assert finding_id("naabu", "ns1.example", "dns-axfr", "m0") != base
    assert finding_id("dnsx", "ns2.example", "dns-axfr", "m0") != base
    assert finding_id("dnsx", "ns1.example", "dns-other", "m0") != base
    assert finding_id("dnsx", "ns1.example", "dns-axfr", "m1") != base


def test_finding_rejects_unknown_severity():
    with pytest.raises(ValueError):
        Finding(stage="dnsx", severity="apocalyptic", title="x",
                target="y", template_id="z")


def test_finding_autogenerates_id():
    f = Finding(stage="dnsx", severity="high", title="AXFR permitted",
                target="ns1.example", template_id="dns-axfr")
    assert f.id == finding_id("dnsx", "ns1.example", "dns-axfr", "")


def test_artifact_identity_is_kind_and_value_only():
    """Artifact identity is (kind, value); meta is excluded from eq and hash.

    Locks in `frozen=True` and `compare=False` on `meta`. Dropping either
    breaks value-based deduplication of artifacts discovered by more than
    one source, which later stages rely on.
    """
    a = Artifact(kind=ArtifactKind.HOST, value="acc.example", meta={"src": "file"})
    b = Artifact(kind=ArtifactKind.HOST, value="acc.example",
                 meta={"src": "subfinder"})

    # Same kind+value, different meta: equal, and collapse to one set entry.
    assert a == b
    assert hash(a) == hash(b)
    assert len({a, b}) == 1

    # Usable as a dict key even though meta is an unhashable dict.
    d = {a: "first"}
    d[b] = "second"
    assert len(d) == 1
    assert d[a] == "second"

    # Differing kind or value stays distinct.
    other_kind = Artifact(kind=ArtifactKind.DNS_RECORD, value="acc.example")
    other_value = Artifact(kind=ArtifactKind.HOST, value="other.example")
    assert a != other_kind
    assert a != other_value
    assert len({a, b, other_kind, other_value}) == 3
