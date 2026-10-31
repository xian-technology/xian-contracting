"""Value-method regressions discovered by the authored surface inventory."""

import pytest

from tests.compatibility.runner import encode, run_case


@pytest.mark.parametrize("native", [False, pytest.param(True, marks=pytest.mark.optional_native)])
@pytest.mark.parametrize("items", ["[]", "[1, 2]"])
def test_frozenset_copy_preserves_identity(tmp_path, native, items):
    source = (
        f"@export\ndef probe():\n    value=frozenset({items})\n    return value.copy() is value\n"
    )
    actual = run_case({"id": "frozen_copy_identity", "source": source}, tmp_path, native=native)
    assert actual["admission"] == "accepted"
    assert actual["status_code"] == 0
    assert actual["result"] == encode(True)


@pytest.mark.parametrize("native", [False, pytest.param(True, marks=pytest.mark.optional_native)])
@pytest.mark.parametrize("arguments", ["1", "unknown=1"])
def test_frozenset_copy_rejects_arguments(tmp_path, native, arguments):
    source = f"@export\ndef probe():\n    return frozenset([1]).copy({arguments})\n"
    actual = run_case({"id": "frozen_copy_signature", "source": source}, tmp_path, native=native)
    assert actual["admission"] == "accepted"
    assert actual["status_code"] == 1


@pytest.mark.parametrize("native", [False, pytest.param(True, marks=pytest.mark.optional_native)])
@pytest.mark.parametrize("template", ["{} {0}", "{0} {}", "{{}} {} {1}"])
def test_string_format_rejects_mixed_numbering(tmp_path, native, template):
    source = f"@export\ndef probe():\n    return {template!r}.format('x', 'y')\n"
    actual = run_case({"id": "format_mixed_numbering", "source": source}, tmp_path, native=native)
    assert actual["admission"] == "accepted"
    assert actual["status_code"] == 1


@pytest.mark.parametrize("native", [False, pytest.param(True, marks=pytest.mark.optional_native)])
@pytest.mark.parametrize(
    ("template", "expected"),
    [("{} {}", "x y"), ("{1} {0} {1}", "y x y"), ("{{}} {}", "{} x")],
)
def test_string_format_keeps_consistent_numbering(tmp_path, native, template, expected):
    source = f"@export\ndef probe():\n    return {template!r}.format('x', 'y')\n"
    actual = run_case({"id": "format_valid_numbering", "source": source}, tmp_path, native=native)
    assert actual["admission"] == "accepted"
    assert actual["status_code"] == 0
    assert actual["result"] == encode(expected)
