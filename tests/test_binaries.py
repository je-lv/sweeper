# tests/test_binaries.py
from pathlib import Path
import pytest
from sweeper import binaries


def test_known_binaries_cover_plan1_tools():
    for name in ("dnsx", "naabu", "httpx"):
        assert name in binaries.KNOWN_BINARIES


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(binaries.KNOWN_BINARIES))
def test_every_known_binary_verifies_against_the_real_tool(name):
    if binaries.resolve(name) is None:
        pytest.skip(f"{name} not installed")
    st = binaries.verify(name)
    assert st.ok, f"{name} failed identity verification: {st.reason}"


def _real_version_output(name):
    """Run the real binary's version flag and return its combined output."""
    import subprocess
    path = binaries.resolve(name)
    if path is None:
        pytest.skip(f"{name} not installed")
    spec = binaries.KNOWN_BINARIES[name]
    try:
        proc = subprocess.run([str(path), spec.version_flag],
                              capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        # Not a defect in version scraping, which is what these tests are
        # about -- it is a slow cold start on a loaded machine. trufflehog is
        # a large Go binary and exceeded 20s during a full-suite run while
        # passing in isolation. Failing here would be a false positive, and a
        # test that fails for reasons unrelated to its subject gets ignored.
        # Skipping keeps it visible instead of silently passing.
        pytest.skip(f"{name} {spec.version_flag} timed out; machine under load")
    return f"{proc.stdout}\n{proc.stderr}"


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(binaries.KNOWN_BINARIES))
def test_recorded_version_comes_from_a_line_that_names_a_version(name):
    """A plausible-but-wrong version is as bad as a failed identity check.

    ok=True was the only thing checked here, so a version scraped from an
    unrelated number went unnoticed: nmap was recorded as liblua's 5.4.8
    (from its "Compiled with:" line) and arjun as "127.0.0" (from the
    127.0.0.1:8080 default in its --help), and both reached the manifest.

    Asserting the string merely appears somewhere in the output would NOT
    catch that — "5.4.8" really is in nmap's output. What made it wrong is the
    line it came from, so this asserts provenance instead. Today's version
    numbers are deliberately not pinned; they change on every upgrade, and a
    pinned assertion only teaches people to edit the test.
    """
    blob = _real_version_output(name)
    st = binaries.verify(name)
    if st.version is None:
        return   # absence is the companion test's subject
    # A spec that sets bare_version has a second legitimate provenance: a
    # line that IS the version and nothing else (checkdmarc prints "5.17.4").
    # Still provenance, not "appears somewhere" — the whole stripped line
    # must be the version, so liblua-5.4.8 and 127.0.0.1:8080 remain
    # unreachable, which is the defect this test exists for.
    bare_ok = binaries.KNOWN_BINARIES[name].bare_version and any(
        line.strip().lstrip("v") == st.version for line in blob.splitlines()
    )
    assert bare_ok or any(
        st.version in line and "version" in line.lower()
        for line in blob.splitlines()
    ), (
        f"{name}: recorded version {st.version!r} appears on no line naming a "
        f"version — it was probably scraped from an unrelated number. "
        f"Output: {' '.join(blob.split())[:200]!r}"
    )


@pytest.mark.slow
@pytest.mark.parametrize("name", sorted(binaries.KNOWN_BINARIES))
def test_version_is_none_only_when_the_tool_reports_none(name):
    """None must mean "reports no version", never "we failed to find it".

    trufflehog prints "trufflehog dev" and arjun has no version flag at all,
    so None is the honest record for them. This pins the converse too: if an
    upgrade starts reporting a version, continuing to record None would be a
    new silent gap in the manifest's audit trail.
    """
    blob = _real_version_output(name)
    st = binaries.verify(name)
    reports_one = any(
        binaries.VERSION_RE.search(line)
        for line in blob.splitlines() if "version" in line.lower()
    )
    if binaries.KNOWN_BINARIES[name].bare_version:
        # See the sibling test: a bare-version tool reports one on a line
        # that is nothing but the version.
        reports_one = reports_one or any(
            binaries.BARE_VERSION_RE.fullmatch(line.strip())
            for line in blob.splitlines()
        )
    if st.version is None:
        assert not reports_one, (
            f"{name} does report a version but None was recorded: "
            f"{' '.join(blob.split())[:200]!r}"
        )
    else:
        assert reports_one


def test_version_is_not_scraped_from_an_unrelated_number(tmp_path, monkeypatch):
    """The nmap defect, reproduced without depending on nmap itself.

    A 2-component version on the version line plus a 3-component number on an
    unrelated line: the old whole-blob 3-part regex could only match the latter.
    """
    fake = tmp_path / "nmapish"
    fake.write_text(
        "#!/bin/sh\n"
        "echo 'Nmapish version 7.98 ( https://example.test )'\n"
        "echo 'Compiled with: liblua-5.4.8 openssl-3.5.5'\n"
    )
    fake.chmod(0o755)
    monkeypatch.setitem(
        binaries.KNOWN_BINARIES, "nmapish",
        binaries.BinarySpec("nmapish", [fake], "--version", r"nmapish", "n/a"),
    )
    st = binaries.verify("nmapish")
    assert st.ok is True
    assert st.version == "7.98", "the version came from the wrong line"


def test_version_is_none_when_no_line_reports_one(tmp_path, monkeypatch):
    """arjun/trufflehog shape: numbers present, but no version reported."""
    fake = tmp_path / "hogish"
    fake.write_text(
        "#!/bin/sh\n"
        "echo 'hogish dev'\n"
        "echo 'Default proxy is 127.0.0.1:8080.'\n"
    )
    fake.chmod(0o755)
    monkeypatch.setitem(
        binaries.KNOWN_BINARIES, "hogish",
        binaries.BinarySpec("hogish", [fake], "--version", r"hogish", "n/a"),
    )
    st = binaries.verify("hogish")
    assert st.ok is True
    assert st.version is None, (
        "a tool reporting no version must record None, not a number scraped "
        "from an IP literal"
    )


def test_every_stage_requirement_has_a_spec():
    """A stage requiring a binary with no BinarySpec is silently disabled."""
    from sweeper import app
    for cls in app.ALL_STAGES:
        for req in cls().requires:
            assert req in binaries.KNOWN_BINARIES, (
                f"stage {cls().name!r} requires {req!r}, which has no "
                "BinarySpec — the stage would be permanently disabled"
            )


def test_httpx_candidates_prefer_pdtm_over_usr_bin():
    spec = binaries.KNOWN_BINARIES["httpx"]
    cands = [str(c) for c in spec.candidates]
    assert any(".pdtm" in c for c in cands)
    assert cands.index(next(c for c in cands if ".pdtm" in c)) == 0, (
        "the ProjectDiscovery httpx must be tried before /usr/bin/httpx"
    )


def test_resolve_returns_none_when_no_candidate_exists(monkeypatch):
    spec = binaries.BinarySpec(
        name="ghost", candidates=[Path("/nonexistent/ghost")],
        version_flag="-version", identity_pattern=r"ghost",
        install_hint="apt install ghost",
    )
    monkeypatch.setitem(binaries.KNOWN_BINARIES, "ghost", spec)
    assert binaries.resolve("ghost") is None


def test_verify_reports_missing_with_install_hint(monkeypatch):
    spec = binaries.BinarySpec(
        name="ghost", candidates=[Path("/nonexistent/ghost")],
        version_flag="-version", identity_pattern=r"ghost",
        install_hint="apt install ghost",
    )
    monkeypatch.setitem(binaries.KNOWN_BINARIES, "ghost", spec)
    st = binaries.verify("ghost")
    assert st.ok is False
    assert "apt install ghost" in st.reason


def test_verify_fails_when_identity_pattern_does_not_match(tmp_path, monkeypatch):
    fake = tmp_path / "fake"
    fake.write_text("#!/bin/sh\necho 'totally different program'\n")
    fake.chmod(0o755)
    spec = binaries.BinarySpec(
        name="fake", candidates=[fake], version_flag="-version",
        identity_pattern=r"projectdiscovery", install_hint="n/a",
    )
    monkeypatch.setitem(binaries.KNOWN_BINARIES, "fake", spec)
    st = binaries.verify("fake")
    assert st.ok is False
    assert "identity" in st.reason.lower()


def test_identity_failure_reason_names_the_pattern_not_the_tool(tmp_path, monkeypatch):
    """The reason must describe the check that actually ran.

    verify() matches spec.identity_pattern, not the tool's own name, so a
    reader debugging a shadowed binary needs to see the pattern that was
    required plus what the binary actually printed.
    """
    fake = tmp_path / "fake"
    fake.write_text("#!/bin/sh\necho 'totally different program'\n")
    fake.chmod(0o755)
    spec = binaries.BinarySpec(
        name="fake", candidates=[fake], version_flag="-version",
        identity_pattern=r"projectdiscovery", install_hint="n/a",
    )
    monkeypatch.setitem(binaries.KNOWN_BINARIES, "fake", spec)
    st = binaries.verify("fake")
    assert st.ok is False
    # the pattern that was actually checked, not the tool name
    assert "projectdiscovery" in st.reason
    # a snippet of what the binary really printed, so the mismatch is visible
    assert "totally different program" in st.reason


def test_identity_failure_snippet_is_truncated_and_collapsed(tmp_path, monkeypatch):
    noisy = tmp_path / "noisy"
    noisy.write_text("#!/bin/sh\nprintf 'aaaa\\n\\n   bbbb\\t\\tcccc\\n'\nfor i in $(seq 60); do printf 'padpadpad '; done\n")
    noisy.chmod(0o755)
    spec = binaries.BinarySpec(
        name="noisy", candidates=[noisy], version_flag="-version",
        identity_pattern=r"projectdiscovery", install_hint="n/a",
    )
    monkeypatch.setitem(binaries.KNOWN_BINARIES, "noisy", spec)
    st = binaries.verify("noisy")
    assert st.ok is False
    # whitespace collapsed: no runs of blank lines or tabs leak into the reason
    assert "aaaa bbbb cccc" in st.reason
    assert "\t" not in st.reason
    assert "\n" not in st.reason
    # snippet bounded so a chatty binary cannot flood the reason
    assert len(st.reason) < 400


def test_resolve_returns_none_for_unregistered_name_without_raising():
    """A stage may declare requires=["typo"]; that must not be a KeyError.

    resolve() indexed KNOWN_BINARIES directly, so an unregistered name
    crashed the caller instead of reporting a configuration problem.
    """
    assert "definitely-not-registered" not in binaries.KNOWN_BINARIES
    assert binaries.resolve("definitely-not-registered") is None


def test_verify_reports_unregistered_name_as_config_error():
    """An unknown binary name degrades the stage; it never kills the run."""
    assert "definitely-not-registered" not in binaries.KNOWN_BINARIES
    st = binaries.verify("definitely-not-registered")
    assert st.ok is False
    assert st.name == "definitely-not-registered"
    # the reason must point at the actual fix: add a spec to KNOWN_BINARIES
    assert "KNOWN_BINARIES" in st.reason
    assert "definitely-not-registered" in st.reason


def test_verify_succeeds_and_captures_version(tmp_path, monkeypatch):
    fake = tmp_path / "dnsx"
    fake.write_text("#!/bin/sh\necho 'dnsx version 1.2.3 projectdiscovery'\n")
    fake.chmod(0o755)
    spec = binaries.BinarySpec(
        name="dnsx", candidates=[fake], version_flag="-version",
        identity_pattern=r"dnsx", install_hint="n/a",
    )
    monkeypatch.setitem(binaries.KNOWN_BINARIES, "dnsx", spec)
    st = binaries.verify("dnsx")
    assert st.ok is True
    assert st.version == "1.2.3"
    assert st.path == fake


def test_a_bare_version_line_is_recorded_when_the_spec_opts_in():
    """Some tools print only the number: `checkdmarc --version` -> "5.17.4",
    no "version" keyword anywhere. VERSION_LINE_RE requires that keyword --
    correctly, because matching numbers anywhere once recorded nmap as
    running liblua's version -- so those tools silently reach run.json with
    no version at all, and run.json is the record of WHICH tool version
    produced a finding.

    Opt-in per spec, never global: the keyword rule stays the default.
    """
    from sweeper import binaries
    assert binaries.extract_version("5.17.4\n", bare=True) == "5.17.4"
    assert binaries.extract_version("5.17.4\n") is None, (
        "the default must still require the keyword")


def test_bare_extraction_still_refuses_a_number_that_is_not_the_version():
    """The bug this whole rule exists for: nmap's output carries
    "Compiled with: liblua-5.4.8", and arjun's --help carries
    127.0.0.1:8080. A bare-version tool prints the version ALONE on a line,
    so anything else on the line disqualifies it."""
    from sweeper import binaries
    assert binaries.extract_version("Compiled with: liblua-5.4.8",
                                    bare=True) is None
    assert binaries.extract_version("listening on 127.0.0.1:8080",
                                    bare=True) is None


def test_checkdmarc_reports_its_version():
    """End to end against the installed tool: an unversioned entry in
    run.json makes a mail finding unreproducible."""
    from sweeper import binaries
    status = binaries.verify("checkdmarc")
    if not status.ok:
        pytest.skip(f"checkdmarc not installed: {status.reason}")
    assert status.version, "checkdmarc ran but recorded no version"
