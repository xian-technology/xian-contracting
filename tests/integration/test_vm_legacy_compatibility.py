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
    if case["id"] == "iterator_range_lazy" and not native:
        # The local Python harness retains its range-size guard. Native ranges
        # are lazy and bounded at materialization and by execution metering.
        assert actual["status_code"] == 1, actual
        assert actual["writes"] == encode({})
        assert actual["events"] == encode([])
        assert "too large" in actual["diagnostic"], actual
        return
    if case["id"] == "storage_snapshot":
        # Deliberate safety change since the historical release: storage values
        # are snapshots, never writable aliases. Both current engines agree.
        assert actual["status_code"] == 0, actual
        assert actual["result"] == encode([[1, 2], [1, 3], [1]])
        assert actual["writes"] == encode({"baseline_storage_snapshot.v": [1]})
        assert actual["events"] == encode([])
        return
    assert comparable(actual) == comparable(expected), actual
