"""Python-oracle regressions for admitted builtin boundary cases."""

from pathlib import Path

import pytest

from tests.integration.pre_retirement_oracle import recorded_python_observation
from tests.integration.test_vm_language_conformance import _run_native_case

pytestmark = pytest.mark.optional_native


# float() is V1 only (V1 execution was removed from current code).
@pytest.mark.parametrize("expression", ["bool()", "int()", "str()", "list(zip())"])
def test_empty_builtin_defaults_match_python(tmp_path: Path, expression: str):
    case = {
        "id": "empty_builtin",
        "source": f"@export\ndef probe():\n    return {expression}\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = recorded_python_observation(case)
    assert expected["status_code"] == 0
    assert _run_native_case(case, tmp_path / "native") == expected


@pytest.mark.parametrize(
    "expression",
    [
        "[1, 2, 3][99::-1]",
        "'abc'[99::-1]",
        "b'abc'[99::-1]",
        "[1, 2, 3][1::9223372036854775807]",
        "[1, 2, 3][2:99:-1]",
        "[][99::-1]",
    ],
)
def test_slice_boundaries_match_python(tmp_path: Path, expression: str):
    case = {
        "id": "slice_boundary",
        "source": f"@export\ndef probe():\n    return {expression}\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = recorded_python_observation(case)
    assert expected["status_code"] == 0
    assert _run_native_case(case, tmp_path / "native") == expected
