"""Subscript, equality and raise edge rules of the native VM.

These pin paths that the conformance corpus does not reach: a nested
mapping proxy, unsupported subscript receivers, the equality depth limit,
a mapping proxy on the right of ``==``, ``raise ... from ...`` and raising
a value that is not an exception.
"""

from pathlib import Path

import pytest

from tests.integration.test_vm_language_conformance import _run_native_case


def _probe(tmp_path: Path, body: str, *, vm_profile: str = "xian_vm_v2") -> dict:
    case = {
        "id": "subscript_rules",
        "source": "@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines()),
        "function_name": "probe",
        "kwargs": {},
    }
    return _run_native_case(case, tmp_path, vm_profile=vm_profile)


def test_nested_mapping_proxy_reads_through_to_the_dict(tmp_path):
    outcome = _probe(tmp_path, "d={'a':1}\nm=d.keys().mapping\nreturn m.keys().mapping['a']")
    assert (outcome["status_code"], outcome["result"]) == (0, 1)


def test_decimal_tuple_is_indexed_like_a_tuple(tmp_path):
    outcome = _probe(
        tmp_path,
        "t=round(decimal('-1.50'),2).as_tuple()\nreturn [t[0], t[1], t[2], t[-1]]",
        vm_profile="xian_vm_v1",
    )
    assert outcome["status_code"] == 0, outcome
    assert outcome["result"] == [1, [1, 5, 0], -2, -2]


@pytest.mark.parametrize(("value", "type_name"), [("5", "int"), ("None", "none")])
def test_subscript_of_a_scalar_is_refused(tmp_path, value, type_name):
    outcome = _probe(tmp_path, f"x={value}\nreturn x[0]")
    assert outcome["status_code"] == 1
    assert outcome["result"] == f"subscript access is not supported for {type_name}"


def test_mapping_proxy_compares_equal_on_either_side(tmp_path):
    outcome = _probe(
        tmp_path,
        "d={'a':1}\nreturn [{'a':1} == d.keys().mapping, d.keys().mapping == {'a':1}, "
        "{'a':2} == d.keys().mapping]",
    )
    assert (outcome["status_code"], outcome["result"]) == (0, [True, True, False])


@pytest.mark.parametrize(("depth", "status"), [(120, 0), (140, 1)])
def test_equality_of_deeply_nested_lists_is_bounded(tmp_path, depth, status):
    outcome = _probe(
        tmp_path,
        "a=[]\nb=[]\nx=a\ny=b\n"
        f"for i in range({depth}):\n    x.append([])\n    y.append([])\n    x=x[0]\n    y=y[0]\n"
        "return a == b",
    )
    assert outcome["status_code"] == status, outcome
    if status:
        assert outcome["result"] == "maximum equality recursion depth exceeded"
    else:
        assert outcome["result"] is True


def test_raise_from_evaluates_the_cause_and_raises_the_exception(tmp_path):
    outcome = _probe(tmp_path, "raise Exception('a') from Exception('b')")
    assert outcome["status_code"] == 1
    assert outcome["result"] == {"exception": "Exception", "args": ["a"]}


def test_raise_from_a_failing_cause_raises_the_cause_error(tmp_path):
    outcome = _probe(tmp_path, "raise Exception('a') from [][0]")
    assert outcome["status_code"] == 1
    assert outcome["result"] != {"exception": "Exception", "args": ["a"]}


def test_raising_a_non_exception_is_a_type_error(tmp_path):
    outcome = _probe(tmp_path, "raise 5")
    assert outcome["status_code"] == 1
    assert outcome["result"] == {
        "exception": "TypeError",
        "args": ["exceptions must derive from BaseException, got int"],
    }
