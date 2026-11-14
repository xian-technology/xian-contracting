"""Every test file that CI or the release check names exists, so a deleted or
renamed test fails here instead of as a pytest "file not found" in CI."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = [
    *sorted((ROOT / ".github" / "workflows").glob("*.yml")),
    ROOT / "scripts" / "validate-release.sh",
]
TEST_PATH = re.compile(r"(?<![\w/.-])(tests/[\w/.-]+\.py)")


def named_test_paths() -> dict[str, set[str]]:
    return {source.name: set(TEST_PATH.findall(source.read_text())) for source in SOURCES}


def test_ci_names_test_files():
    assert named_test_paths()["validate.yml"], (
        "the pattern no longer finds validate.yml's test paths"
    )


def test_every_test_file_ci_names_exists():
    missing = {
        source: sorted(path for path in paths if not (ROOT / path).is_file())
        for source, paths in named_test_paths().items()
    }
    assert not any(missing.values()), f"CI names missing test files: {missing}"
