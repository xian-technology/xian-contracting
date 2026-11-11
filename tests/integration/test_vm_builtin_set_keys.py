"""Builtin sets use Python key eligibility without widening wrapper serialization."""

import pytest

from tests.integration.pre_retirement_oracle import recorded_python_observation
from tests.integration.test_vm_language_conformance import _run_native_case

pytestmark = pytest.mark.optional_native


def _case(body, dependencies=()):
    return {
        "id": "builtin_set_keys",
        "source": "def helper():\n    return 7\n\n@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines()),
        "function_name": "probe",
        "kwargs": {},
        "dependencies": dependencies,
    }


def _compare(tmp_path, body, dependencies=(), *, vm_profile="xian_vm_v2"):
    case = _case(body, dependencies)
    expected = recorded_python_observation(case)
    assert expected["status_code"] == 0, expected
    assert _run_native_case(case, tmp_path / "native", vm_profile=vm_profile) == expected


def _reject(tmp_path, body):
    case = _case(body)
    expected = recorded_python_observation(case)
    assert expected["status_code"] == 1, expected
    assert expected["result"]["exception"] == "TypeError", expected
    actual = _run_native_case(case, tmp_path / "native")
    assert actual["status_code"] == 1, actual
    assert actual["writes"] == {} and actual["events"] == []


LEGACY_HASHABLE_VALUES = [
    "float('1.25')",
    "float('nan')",
    "round(decimal('1.25'), 2)",
    "round(decimal('1'), 0).from_float(float('nan'))",
]
HASHABLE_VALUES = [
    "None",
    "True",
    "2",
    *LEGACY_HASHABLE_VALUES,
    "'abc'",
    "b'abc'",
    "(1, 'abc')",
    "frozenset([1, 'abc'])",
    "frozenset([decimal('1.25')])",
    "frozenset([datetime.datetime(2024, 1, 2)])",
    "frozenset([datetime.timedelta(seconds=2)])",
    "(frozenset([decimal('1.25')]),)",
]
WRAPPER_ONLY_VALUES = [
    "decimal('1.25')",
    "datetime.datetime(2024, 1, 2)",
    "datetime.timedelta(seconds=2)",
    "(decimal('1.25'),)",
    "(datetime.datetime(2024, 1, 2),)",
    "(datetime.timedelta(seconds=2),)",
]


@pytest.mark.parametrize("expression", HASHABLE_VALUES)
def test_builtin_hashable_scalar_and_frozen_families(tmp_path, expression):
    _compare(
        tmp_path,
        f"value={expression}\nresult={{}}.keys()|[]\nresult.add(value)\n"
        "merged=result.union([value])\n"
        "return [len(result),value in result,len(merged),result.issubset([value])]",
        vm_profile="xian_vm_v1" if expression in LEGACY_HASHABLE_VALUES else "xian_vm_v2",
    )


@pytest.mark.parametrize("expression", WRAPPER_ONLY_VALUES)
@pytest.mark.parametrize(
    "operation",
    [
        "result.add(value)",
        "result.union([value])",
        "result.intersection([value])",
        "result.difference([value])",
        "result.symmetric_difference([value])",
        "result.update([value])",
        "result.intersection_update([value])",
        "result.difference_update([value])",
        "result.symmetric_difference_update([value])",
        "value in result",
        "result.remove(value)",
        "result.discard(value)",
        "result.issubset([value])",
        "result.issuperset([value])",
        "result.isdisjoint([value])",
    ],
)
def test_builtin_rejects_keys_that_only_wrappers_admit(tmp_path, expression, operation):
    _reject(tmp_path, f"value={expression}\nresult={{}}.keys()|[]\n{operation}\nreturn 1")


@pytest.mark.parametrize("expression", WRAPPER_ONLY_VALUES)
def test_wrapper_key_domain_is_preserved(tmp_path, expression):
    _compare(
        tmp_path,
        f"value={expression}\nresult=set()\nresult.add(value)\n"
        "return [len(result),value in result,len(frozenset([value]))]",
    )


LOCAL_KEYS = [
    "receiver.append",
    "helper",
    "int",
    "set",
    "len",
    "datetime.datetime",
    "hashlib.sha3_text",
    "importlib.Func",
    "importlib.Func('f', args=('a',))",
    "importlib.Var('x', Variable)",
]


@pytest.mark.parametrize("expression", LOCAL_KEYS)
def test_view_produced_sets_accept_dictionary_execution_local_keys(tmp_path, expression):
    _compare(
        tmp_path,
        f"receiver=[]\nkey={expression}\nresult={{key:1}}.keys()|[]\n"
        "result.add(key)\ncopy=result.union([key])\n"
        "return [len(result),key in result,len(copy),isinstance(result,set)]",
    )


@pytest.mark.parametrize("expression", LOCAL_KEYS)
def test_callable_bearing_tuples_are_valid_builtin_keys(tmp_path, expression):
    _compare(
        tmp_path,
        f"receiver=[]\nkey={expression}\nvalue=(key,(frozenset([decimal('1')]),2))\n"
        "result={value:1}.keys()|[]\n"
        "return [len(result),value in result,len(result.union([value]))]",
    )


@pytest.mark.parametrize("constructor", ["set", "frozenset"])
@pytest.mark.parametrize("expression", LOCAL_KEYS)
def test_builtin_admission_does_not_make_execution_keys_serializable(
    tmp_path, constructor, expression
):
    _reject(
        tmp_path,
        f"receiver=[]\nkey={expression}\nresult={{key:1}}.keys()|[]\nreturn {constructor}(result)",
    )


@pytest.mark.parametrize(
    "expression",
    [
        "(helper, [])",
        "(helper, {})",
        "(helper, bytearray())",
        "(helper, decimal('1'))",
        "(helper, datetime.datetime(2024,1,2))",
        "(helper, datetime.timedelta(seconds=2))",
    ],
)
def test_callable_prefix_does_not_bypass_invalid_tuple_siblings(tmp_path, expression):
    _reject(tmp_path, f"result={{}}.keys()|[]\nresult.add({expression})\nreturn 1")


def test_bound_method_equality_uses_receiver_identity_and_remains_live(tmp_path):
    _compare(
        tmp_path,
        "left=[]\nright=[]\nfirst=left.append\nresult={first:1}.keys()|[]\n"
        "result.add(left.append)\nresult.add(right.append)\nleft.append(4)\n"
        "before=[len(result),left.append in result,right.append in result]\n"
        "result.remove(left.append)\ncallback=result.pop()\ncallback(9)\n"
        "return [before,left,right,len(result)]",
    )


@pytest.mark.parametrize(
    "left,right",
    [
        ("int.from_bytes", "(7).from_bytes"),
        ("bytes.fromhex", "b'x'.fromhex"),
        ("dict.fromkeys", "{}.fromkeys"),
        ("str.maketrans", "'x'.maketrans"),
        ("'x'.maketrans", "'y'.maketrans"),
        ("bool.from_bytes", "True.from_bytes"),
        ("bool.from_bytes", "int.from_bytes"),
        ("bytearray.fromhex", "bytearray(b'x').fromhex"),
        ("bytes.maketrans", "b'x'.maketrans"),
        ("bytearray.maketrans", "bytearray(b'x').maketrans"),
        ("b'x'.maketrans", "b'y'.maketrans"),
        ("b'x'.fromhex", "b'y'.fromhex"),
    ],
)
def test_class_static_method_dictionary_and_set_identity_agree(tmp_path, left, right):
    _compare(
        tmp_path,
        f"first={left}\nsecond={right}\nkeys={{first:1,second:2}}\n"
        "result=keys.keys()|[]\nreturn [first==second,len(keys),len(result),second in result]",
    )


def test_descriptor_identity_does_not_collapse_equal_fields(tmp_path):
    _compare(
        tmp_path,
        "first=importlib.Func('f',args=('a',))\nsecond=importlib.Func('f',args=('a',))\n"
        "result={first:1,second:2}.keys()|[]\nfirst.name='changed'\n"
        "return [len(result),first in result,second in result,first==second]",
    )


def test_contract_handles_keep_execution_identity_as_builtin_keys(tmp_path):
    dependency = {
        "name": "con_key_target",
        "source": "@export\ndef value():\n    return 1\n",
        "owner": None,
    }
    _compare(
        tmp_path,
        "first=importlib.import_module('con_key_target')\nsecond=importlib.import_module('con_key_target')\n"
        "result={first:1,second:2}.keys()|[]\n"
        "return [len(result),first in result,second in result,first==second]",
        (dependency,),
    )


def test_callable_bucket_has_explicit_stable_encounter_order(tmp_path):
    # This sequence is a VM policy, not an assertion about Python's randomized set order.
    body = (
        "receiver=[]\nfirst=receiver.clear\nsecond=receiver.append\n"
        "result={}.keys()|[]\nresult.update([first,2,second,None,first])\nlabels=[]\n"
        "for key in result:\n"
        "    if key is None:\n        labels.append('none')\n"
        "    elif key==2:\n        labels.append('two')\n"
        "    elif key==first:\n        labels.append('first')\n"
        "    else:\n        labels.append('second')\n"
        "return labels"
    )
    actual = _run_native_case(_case(body), tmp_path / "native")
    assert actual["status_code"] == 0, actual
    assert actual["result"] == ["none", "two", "first", "second"]


def test_callable_tuple_nan_identity_is_preserved(tmp_path):
    _compare(
        tmp_path,
        "nan=float('nan')\nfirst=(helper,nan)\nsecond=(helper,nan)\n"
        "other=(helper,float('nan'))\nresult={first:1,second:2,other:3}.keys()|[]\n"
        "return [len(result),first in result,second in result,other in result]",
        vm_profile="xian_vm_v1",
    )
