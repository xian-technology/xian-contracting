"""Separate source admission and execution checks against a pinned old runtime."""

import ast
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
    for filename, path in (
        ("cases", FIXTURES / "cases.json"),
        ("runner", FIXTURES / "historical/runner.py"),
    ):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == BASELINE[filename + "_sha256"]
    assert set(BASELINE["observations"]) == {case["id"] for case in CASES}


def test_observations_preserve_type_keys_and_order():
    assert encode([1]) != encode((1,))
    assert encode(True) != encode(1) != encode(1.0)
    assert encode({1: "a"}) != encode({"1": "a"})
    assert encode({1: "a", "1": "b"}) != encode({"1": "b", 1: "a"})


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
@pytest.mark.optional_native
def test_historical_admission_and_execution(tmp_path, case):
    expected = BASELINE["observations"][case["id"]]
    actual = run_case(case, tmp_path)
    assert actual["admission"] == expected["admission"], actual
    if case["id"] == "storage_snapshot":
        # Deliberate safety change since the historical release: storage values
        # are snapshots, never writable aliases.
        assert actual["status_code"] == 0, actual
        assert actual["result"] == encode([[1, 2], [1, 3], [1]])
        assert actual["writes"] == encode({"baseline_storage_snapshot.v": [1]})
        assert actual["events"] == encode([])
        return
    if case["id"] == "quantum_storage":
        # Execution 5 makes protocol write-map order stable across processes.
        # Preserve the historical fixture and verify its exact original shape;
        # only these two top-level entries exchange order. Values stay exact.
        assert expected["writes"] == [
            "dict",
            [
                [["str", "baseline_quantum_storage.v"], ["ContractingDecimal", "2"]],
                [["str", "baseline_quantum_storage.h:x"], ["ContractingDecimal", "2"]],
            ],
        ]
        expected = {**expected, "writes": ["dict", list(reversed(expected["writes"][1]))]}
    assert comparable(actual) == comparable(expected), actual


def test_historical_corpus_calls_each_allowed_callable_builtin():
    from contracting.compilation.whitelists import ALLOWED_BUILTINS

    called = {
        node.func.id
        for case in CASES
        for node in ast.walk(ast.parse(case["source"]))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    syntax_and_exception = {"False", "True", "None", "import", "Exception"}
    assert set(ALLOWED_BUILTINS) - called - syntax_and_exception == set()
