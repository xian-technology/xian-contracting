"""Authored float vectors use exact outputs or independent semantic anchors."""

import json

import pytest

from tests.determinism.float_cases import float_cases
from tests.determinism.observer import observe_case


def test_float_vectors_are_fixed_fresh_json_safe_and_cover_key_boundaries():
    first = float_cases()
    second = float_cases()
    assert first == second
    assert 15 <= len(first) <= 40
    assert len({case["id"] for case in first}) == len(first)
    assert all(case["id"].startswith("float_edge_") for case in first)
    json.dumps(first, allow_nan=False)
    assert all("expected_result" in case or case.get("expected_failure") for case in first)
    source = "\n".join(case["source"] for case in first)
    assert "**" in source and "pow(" in source and "divmod(" in source
    assert "p-1074" in source and "nan(123)" in source
    first[0]["source"] = "changed"
    assert float_cases() == second


@pytest.mark.optional_native
@pytest.mark.parametrize("case", float_cases(), ids=lambda case: case["id"])
def test_authored_float_vector_executes_with_meter_and_checked_oracle(tmp_path, case):
    result = observe_case(case, tmp_path, reopen=True)
    execution = result["executions"][0]
    assert execution["chi_used"] > 0
    assert execution["raw_cost"] > 0
    if case.get("records_hex"):
        state = dict(result["final_state"])
        assert f"determinism_{case['id']}.observed" in state


@pytest.mark.optional_native
@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("float.fromhex('0x1.fffffffffffffp+1023') ** float('0.5')", "0x1.fffffffffffffp+511"),
        ("pow(float.fromhex('0x1.fffffffffffffp+1023'), float('0.5'))", "0x1.fffffffffffffp+511"),
        ("float('-0') ** 3", "-0x0.0p+0"),
        ("pow(float('-0'), 3)", "-0x0.0p+0"),
        ("2 ** float('3')", "0x1.0000000000000p+3"),
        ("pow(2, float('3'))", "0x1.0000000000000p+3"),
    ],
)
def test_portable_power_routes_preserve_exact_boundary_values(tmp_path, expression, expected):
    case = {
        "id": "portable_pow",
        "vm_profile": "xian_vm_v1",
        "source": f"@export\ndef probe():\n    return ({expression}).hex()\n",
        "expected_result": expected,
    }
    observe_case(case, tmp_path)


@pytest.mark.optional_native
@pytest.mark.parametrize(
    "expression",
    [
        "float('-nan') ** 1",
        "pow(float('-nan'), 1)",
        "float('-1') ** float('0.5')",
        "pow(float('-1'), float('0.5'))",
    ],
)
def test_power_nan_results_have_canonical_positive_formatting(tmp_path, expression):
    # Exact NaN bits are checked in Rust; the public native result boundary
    # deliberately rejects raw non-finite floats, including inside containers.
    case = {
        "id": "power_nan",
        "vm_profile": "xian_vm_v1",
        "source": f"@export\ndef probe():\n    value = {expression}\n"
        "    return [value != value, value.hex(), format(value, '+')]\n",
        "expected_result": [True, "nan", "+nan"],
    }
    observe_case(case, tmp_path)
