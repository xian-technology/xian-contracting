"""Both artifact compiler paths must agree on the expanded compatibility grammar."""

import json
from pathlib import Path

import pytest
from scripts.audit_compiler_core_parity import compile_with_python, compile_with_rust

CASES = [
    case
    for case in json.loads((Path(__file__).parents[1] / "compatibility/cases.json").read_text())
    if case["id"].startswith(("module_", "starred_"))
]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_compatibility_grammar_artifacts_match(case):
    args = dict(
        module_name="con_grammar", source=case["source"], lint=True, vm_profile="xian_vm_v1"
    )
    expected = compile_with_python(**args)
    actual = compile_with_rust(**args)
    assert actual.ok == expected.ok, (actual, expected)
    if expected.ok:
        assert actual.artifact == expected.artifact
