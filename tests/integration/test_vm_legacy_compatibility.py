"""The pinned old runtime's compatibility corpus and its provenance.

The corpus is V1 (the historical profile). Current code no longer executes
V1 (single-engine plan, decision 6): its execution against the baseline
replays on the pinned release; these checks keep the corpus intact.
"""

import ast
import hashlib
import json
from pathlib import Path


from tests.compatibility.runner import encode

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
