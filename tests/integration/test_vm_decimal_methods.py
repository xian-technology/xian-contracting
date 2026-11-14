"""Sequence method arity (the raw Decimal method tests were V1 only)."""

import pytest

pytestmark = pytest.mark.optional_native


def test_sequence_index_rejects_excess_arguments(tmp_path):
    from tests.integration.pre_retirement_oracle import recorded_python_observation
    from tests.integration.test_vm_language_conformance import _run_native_case

    case = {
        "id": "sequence_index_arity",
        "source": "@export\ndef probe():\n    return [0, 1, 2].index(0,0,3,999)\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert recorded_python_observation(case)["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native")["status_code"] == 1
