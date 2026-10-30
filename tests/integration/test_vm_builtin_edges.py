"""Python-oracle regressions for admitted builtin boundary cases."""

from pathlib import Path

import pytest

from tests.integration.test_vm_language_conformance import _run_native_case, _run_python_case

pytestmark = pytest.mark.optional_native


@pytest.mark.parametrize("expression", ["bool()", "int()", "float()", "str()", "list(zip())"])
def test_empty_builtin_defaults_match_python(tmp_path: Path, expression: str):
    case = {
        "id": "empty_builtin",
        "source": f"@export\ndef probe():\n    return {expression}\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = _run_python_case(case, tmp_path / "python")
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
    expected = _run_python_case(case, tmp_path / "python")
    assert expected["status_code"] == 0
    assert _run_native_case(case, tmp_path / "native") == expected


@pytest.mark.parametrize(
    "expression",
    [
        "abs(True)",
        "abs(False)",
        "round(5, None)",
        "round(1.5, None)",
        'float(" 1.25 ")',
        'float(b" 1.25 ")',
    ],
)
def test_numeric_builtin_boundaries_match_python(tmp_path: Path, expression: str):
    case = {
        "id": "numeric_boundary",
        "source": f"@export\ndef probe():\n    return {expression}\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = _run_python_case(case, tmp_path / "python")
    assert expected["status_code"] == 0
    assert _run_native_case(case, tmp_path / "native") == expected


def test_float_bytes_reject_non_ascii_whitespace(tmp_path: Path):
    case = {
        "id": "float_bytes_whitespace",
        "source": '@export\ndef probe():\n    return float(b"\\xc2\\xa01.25\\xc2\\xa0")\n',
        "function_name": "probe",
        "kwargs": {},
    }
    assert _run_python_case(case, tmp_path / "python")["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native")["status_code"] == 1
