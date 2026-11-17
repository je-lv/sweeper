from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

import sweeper


ROOT = Path(__file__).parents[1]


def test_package_and_distribution_versions_match():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert metadata["project"]["version"] == sweeper.__version__ == "0.1.0"


def test_public_release_files_exist():
    for name in (
        "README.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "SECURITY.md",
        "MANIFEST.in",
    ):
        assert (ROOT / name).is_file()
