"""String classifications use the historical Python 3.12 / Unicode 15 rules."""

import json
from pathlib import Path

import pytest

from tests.integration.test_vm_language_conformance import _run_native_case, _run_python_case

pytestmark = pytest.mark.optional_native


@pytest.mark.parametrize(
    "expression",
    [
        "['¼'.isdigit(), '²'.isdigit(), '١'.isdigit()]",
        "['\\u0345'.isalpha(), '\\u0345'.isalnum(), '中'.isalpha()]",
        "['a中'.islower(), '中'.islower(), 'aǅ'.islower(), '\\u0345'.islower()]",
        "['\\x1c alpha\\x1f beta\\x1e'.strip(), '\\x1c alpha\\x1f beta\\x1e'.split()]",
        "['\\x1c alpha\\x1f beta\\x1e'.split(None, 0), '\\x1c alpha\\x1f beta\\x1e'.split(None, 1)]",
        "'\\x1c alpha\\x1e'.strip(None)",
    ],
)
def test_unicode_string_methods_match_python(tmp_path, expression):
    case = {
        "id": "unicode_strings",
        "source": f"@export\ndef probe():\n    return {expression}\n",
        "function_name": "probe",
        "kwargs": {},
    }
    expected = _run_python_case(case, tmp_path / "python")
    assert expected["status_code"] == 0, expected
    assert _run_native_case(case, tmp_path / "native") == expected


@pytest.mark.parametrize(
    "case",
    json.loads(Path(__file__).with_name("unicode_casing_baseline.json").read_text())["cases"],
    ids=lambda case: ascii(case["text"]),
)
def test_casing_uses_historical_unicode_tables(tmp_path, case):
    # Current host Python may use newer Unicode data; the historical fixture is
    # authoritative for codepoints that were unassigned in Unicode 15.
    observation = _run_native_case(
        {
            "id": "unicode_casing",
            "source": (
                "@export\ndef probe():\n"
                f"    text = {case['text']!r}\n"
                "    return [text.lower(), text.upper()]\n"
            ),
            "function_name": "probe",
            "kwargs": {},
        },
        tmp_path,
    )
    assert observation == {
        "status_code": 0,
        "result": [case["lower"], case["upper"]],
        "writes": {},
        "events": [],
    }
