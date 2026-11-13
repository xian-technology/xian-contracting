"""CI and release builds use one pinned Rust toolchain that every crate supports."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
PIN = re.compile(r"(?:dtolnay/rust-toolchain@|rust-toolchain:\s*)(\S+)")
VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?$")


def workflow_pins() -> dict[str, list[str]]:
    pins = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        found = PIN.findall(path.read_text())
        if found:
            pins[path.name] = found
    return pins


def version(text: str) -> tuple[int, int, int]:
    match = VERSION.match(text)
    assert match, f"Rust toolchain {text!r} is not an exact version"
    major, minor, patch = match.groups()
    return int(major), int(minor), int(patch or 0)


def test_every_rust_build_uses_the_same_exact_toolchain():
    pins = workflow_pins()
    assert set(pins) == {"determinism.yml", "release.yml", "validate.yml"}
    used = {pin for found in pins.values() for pin in found}
    assert len(used) == 1, f"Rust toolchain pins differ: {pins}"
    version(used.pop())


def test_the_pinned_toolchain_meets_every_crate_minimum():
    (pin,) = {pin for found in workflow_pins().values() for pin in found}
    for manifest in sorted(ROOT.glob("packages/*/Cargo.toml")):
        declared = re.search(r'^rust-version\s*=\s*"([^"]+)"', manifest.read_text(), re.M)
        assert declared, f"{manifest} declares no rust-version"
        assert version(pin) >= version(declared.group(1)), manifest
