"""Authored unbound mutable methods cannot corrupt frozen dictionary keys."""

import pytest

from tests.integration.test_vm_language_conformance import _run_python_case


@pytest.mark.parametrize(
    "call",
    [
        "set.add(value,2)",
        "set.remove(value,1)",
        "set.discard(value,1)",
        "set.discard(value,99)",
        "set.pop(value)",
        "set.clear(value)",
    ],
)
def test_authored_unbound_mutation_of_frozen_keys_is_rejected(tmp_path, call):
    case = {
        "id": "frozen_immutability",
        "source": "@export\ndef probe():\n    value=frozenset([1])\n    mapping={value:7}\n    "
        + call
        + "\n    return [list(value),len(value),mapping.get(frozenset([1,2]),0)]\n",
        "function_name": "probe",
        "kwargs": {},
    }
    result = _run_python_case(case, tmp_path / "python")
    assert result["status_code"] == 1, result
    assert result["result"]["exception"] == "TypeError", result
    assert result["writes"] == {} and result["events"] == []
