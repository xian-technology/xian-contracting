"""Separate source admission and execution checks against a pinned old runtime."""

import hashlib
import json
from pathlib import Path

import pytest

from tests.compatibility.runner import comparable, encode, run_case

FIXTURES = Path(__file__).absolute().parents[1] / "compatibility"
BASELINE = json.loads((FIXTURES / "legacy_baseline.json").read_text())
CASES = json.loads((FIXTURES / "cases.json").read_text())


def test_baseline_provenance():
    assert BASELINE["revision"] == "3b82001f2d587bbfb51f3d9235a2a8dcd0078a9a"
    for filename in ("cases", "runner"):
        suffix = ".json" if filename == "cases" else ".py"
        assert (
            hashlib.sha256((FIXTURES / (filename + suffix)).read_bytes()).hexdigest()
            == BASELINE[filename + "_sha256"]
        )
    assert set(BASELINE["observations"]) == {case["id"] for case in CASES}


def test_observations_preserve_type_keys_and_order():
    assert encode([1]) != encode((1,))
    assert encode(True) != encode(1) != encode(1.0)
    assert encode({1: "a"}) != encode({"1": "a"})
    assert encode({1: "a", "1": "b"}) != encode({"1": "b", 1: "a"})


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
@pytest.mark.parametrize(
    "native",
    [False, pytest.param(True, marks=pytest.mark.optional_native)],
    ids=["python", "native"],
)
def test_historical_admission_and_execution(tmp_path, case, native):
    expected = BASELINE["observations"][case["id"]]
    actual = run_case(case, tmp_path, native=native)
    assert actual["admission"] == expected["admission"], actual
    if case["id"] == "hashing":
        # The old sha256 alias was removed in favor of sha256_text/sha256_hex.
        # Pin the current failure so an unrelated admission or state regression
        # cannot be hidden by the recorded compatibility gap.
        assert actual["status_code"] == 1
        assert actual["writes"] == ["dict", []]
        assert actual["events"] == ["list", []]
        missing_name = (
            "no native method 'sha256()'" if native else "has no attribute 'sha256'"
        )
        assert missing_name in actual["diagnostic"]
        pytest.xfail("R9: historical hashlib.sha256 alias is absent; policy pending")
    assert comparable(actual) == comparable(expected), actual
