"""Recovering lazily-loaded chunks from a bundle, without running it.

The Vite assertions here run against an EXCERPT of a real production build
(tests/fixtures/bundle-vite-entry.js), because the point of this module is
matching what bundlers actually emit, and a fixture invented to match the
regex proves only that the regex matches itself.

The measurement that motivated the module, taken against that build in full:

    JS files in dist/assets            66
    referenced by index.html            1   <- what a crawler sees
    recovered from the entry bundle    65   <- all but the entry itself
    candidates that were not real       0

The webpack and Next.js cases below are pattern-based rather than measured
(no bundle on the build machine used a runtime chunk map), and are marked as
such in sweeper/chunks.py.
"""
from pathlib import Path

from sweeper import chunks

FIX = Path(__file__).parent / "fixtures" / "bundle-vite-entry.js"
BASE = "https://acc.example/assets/index-53847554.js"


def test_dynamic_imports_are_recovered():
    """`import("./X.js")` is the canonical code-splitting shape."""
    got = chunks.candidates(FIX.read_text(), BASE)
    assert "https://acc.example/assets/About-840a70b6.js" in got


def test_preload_dependency_paths_are_recovered():
    """Vite lists a chunk's own dependencies as bare `assets/...` paths."""
    got = chunks.candidates(FIX.read_text(), BASE)
    assert any(u.startswith("https://acc.example/assets/") for u in got)


def test_a_base_relative_path_is_not_nested_under_its_own_directory():
    """The bug this module's resolver exists for.

    Plain urljoin turns `assets/X.js`, seen from inside `/assets/index.js`,
    into `/assets/assets/X.js`. Against the real build that mis-resolved 65
    of 91 candidates into a directory that does not exist -- every request
    would have 404'd and the whole capability would have looked like it
    worked.
    """
    got = chunks.candidates('x=["assets/VBtn-1a2b3c4d.js"]', BASE)
    assert got == ["https://acc.example/assets/VBtn-1a2b3c4d.js"]


def test_a_prefixed_deployment_resolves_under_its_prefix():
    """Same rule must hold for a site served under a path, not at the root."""
    got = chunks.candidates('x=["assets/VBtn-1a2b3c4d.js"]',
                            "https://acc.example/app/assets/index-aaaaaaaa.js")
    assert got == ["https://acc.example/app/assets/VBtn-1a2b3c4d.js"]


def test_root_relative_paths_are_left_alone():
    got = chunks.candidates('x=["/static/js/main.4d816da9.chunk.js"]', BASE)
    assert got == ["https://acc.example/static/js/main.4d816da9.chunk.js"]


def test_webpack_runtime_chunk_map_is_reconstructed():
    """PATTERN-BASED: the webpack 4/5 runtime builds URLs by concatenation.

    Nothing else recovers these -- the filenames exist only as the result of
    that expression, so they appear nowhere in the bundle as literals.
    """
    runtime = (
        'r.p="/static/";'
        'r.u=function(e){return"js/"+e+"."+{147:"a1b2c3d4",512:"deadbeef"}[e]+".chunk.js"}'
    )
    got = chunks.candidates(runtime, "https://acc.example/static/js/runtime.js")
    assert "https://acc.example/static/js/147.a1b2c3d4.chunk.js" in got
    assert "https://acc.example/static/js/512.deadbeef.chunk.js" in got


def test_webpack_public_path_is_applied():
    """Without it a reconstructed path resolves against the bundle's dir."""
    runtime = (
        'n.p="/cdn-assets/";'
        'n.u=e=>"js/"+e+"."+{7:"cafebabe"}[e]+".chunk.js"'
    )
    got = chunks.candidates(runtime, "https://acc.example/deep/nested/runtime.js")
    assert "https://acc.example/cdn-assets/js/7.cafebabe.chunk.js" in got


def test_next_build_manifest_is_named():
    """The manifest is itself fetchable; naming it is enough."""
    got = chunks.candidates(
        'a="/_next/static/abc123/_buildManifest.js"',
        "https://acc.example/_next/static/chunks/main-1234abcd.js")
    assert "https://acc.example/_next/static/abc123/_buildManifest.js" in got


def test_the_bundle_never_proposes_itself():
    """Self-reference is an infinite fetch loop dressed as a discovery."""
    got = chunks.candidates('import("./index-53847554.js")', BASE)
    assert BASE not in got


def test_non_javascript_is_not_returned():
    text = 'import("./styles-aabbccdd.css");x=["assets/logo-11223344.png"]'
    assert chunks.candidates(text, BASE) == []


def test_an_unhashed_filename_is_not_treated_as_a_chunk():
    """`assets/index.js` with no content hash is a source path, not a build
    artifact, and matching it would return half the quoted strings in a
    development bundle."""
    assert chunks.candidates('x=["assets/helpers.js"]', BASE) == []


def test_output_is_deduplicated_and_ordered():
    text = 'import("./A-11111111.js");import("./A-11111111.js");import("./B-22222222.js")'
    got = chunks.candidates(text, BASE)
    assert got == ["https://acc.example/assets/A-11111111.js",
                   "https://acc.example/assets/B-22222222.js"]


def test_one_bundle_cannot_produce_unbounded_requests():
    text = ";".join(f'import("./c{i:04d}-abcdef12.js")' for i in range(400))
    assert len(chunks.candidates(text, BASE)) <= chunks.MAX_PER_BUNDLE


def test_garbage_input_degrades_to_no_chunks(tmp_path):
    """A bundle that cannot be parsed must never fail the stage."""
    assert chunks.candidates("", BASE) == []
    assert chunks.candidates("not javascript at all", BASE) == []
    assert chunks.candidates('import("./x-aabbccdd.js")', "") == []


def test_a_malformed_base_does_not_raise():
    assert chunks.candidates('import("./x-aabbccdd.js")', "https://[::1/x") == []
