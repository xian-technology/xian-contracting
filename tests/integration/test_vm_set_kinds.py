"""Builtin sets from dictionary views retain their execution-time value kind."""

import pytest

from tests.integration.test_vm_language_conformance import (
    _run_native_case,
    _run_python_case,
)

pytestmark = pytest.mark.optional_native


def _case(body, dependencies=()):
    return {
        "id": "set_kinds",
        "source": "".join("import " + item["name"] + "\n" for item in dependencies)
        + "@export\ndef probe():\n"
        + "".join("    " + line + "\n" for line in body.splitlines()),
        "function_name": "probe",
        "kwargs": {},
        "dependencies": dependencies,
    }


def _compare(tmp_path, body, dependencies=(), *, vm_profile="xian_vm_v2"):
    case = _case(body, dependencies)
    _compare_case(tmp_path, case | {"vm_profile": vm_profile})


def _compare_case(tmp_path, case):
    expected = _run_python_case(case, tmp_path / "python")
    assert expected["status_code"] == 0, expected
    assert _run_native_case(case, tmp_path / "native") == expected


def _reject(tmp_path, case, error="TypeError"):
    expected = _run_python_case(case, tmp_path / "python")
    actual = _run_native_case(case, tmp_path / "native")
    assert expected["status_code"] == actual["status_code"] == 1
    assert expected["result"]["exception"] == error
    assert actual["writes"] == {} and actual["events"] == []


def test_views_builtin_sets_and_wrappers_compare_in_both_orders(tmp_path):
    _compare(
        tmp_path,
        "view={'a':1,'b':2}.keys()\nbuiltin=view|[]\nwrapped=set(['a','b'])\n"
        "frozen=frozenset(['a','b'])\nreturn [view==builtin,builtin==view,"
        "builtin==wrapped,wrapped==builtin,builtin!=wrapped,wrapped!=builtin,"
        "builtin==frozen,frozen==builtin,view==wrapped,wrapped==view,"
        "builtin<=view,view<=builtin,builtin<view,view>builtin,"
        "isinstance(builtin,set),isinstance(builtin,frozenset),"
        "isinstance(wrapped,set),isinstance(frozen,frozenset)]",
    )


@pytest.mark.parametrize(
    "expression",
    [
        "view|[]",
        "view&['a','b']",
        "view-[]",
        "view^[]",
        "builtin.copy()",
        "builtin.union(wrapped)",
        "builtin.intersection(wrapped)",
        "builtin.difference([])",
        "builtin.symmetric_difference([])",
        "builtin|builtin.copy()",
        "builtin&builtin.copy()",
        "builtin-({}.keys()|[])",
        "builtin^({}.keys()|[])",
        "builtin|view",
        "view|builtin",
    ],
)
def test_builtin_set_results_preserve_kind(tmp_path, expression):
    _compare(
        tmp_path,
        "view={'a':1,'b':2}.keys()\nbuiltin=view|[]\nwrapped=set(['a','b'])\n"
        + "result="
        + expression
        + "\n"
        "return [sorted(result),result==view,view==result,"
        "result==wrapped,wrapped==result,isinstance(result,set)]",
    )


@pytest.mark.parametrize("method", ["union", "intersection", "difference", "symmetric_difference"])
def test_wrapper_methods_keep_wrapper_kind_with_builtin_iterables(tmp_path, method):
    _compare(
        tmp_path,
        "builtin={'b':2}.keys()|[]\nwrapped=set(['a','b'])\n"
        + "result=wrapped."
        + method
        + "(builtin)\n"
        "return [isinstance(result,set),sorted(result),"
        "result==set(result),result==dict.fromkeys(result).keys()]",
    )


@pytest.mark.parametrize("operator", ["|", "&", "-", "^", "<", "<=", ">", ">="])
@pytest.mark.parametrize("reverse", [False, True])
def test_builtin_and_wrapper_operators_reject_mixed_kinds(tmp_path, operator, reverse):
    left, right = ("wrapped", "builtin") if reverse else ("builtin", "wrapped")
    case = _case("builtin={'a':1}.keys()|[]\nwrapped=set(['a'])\nreturn " + left + operator + right)
    _reject(tmp_path, case)


@pytest.mark.parametrize("operator", ["|=", "&=", "-=", "^="])
@pytest.mark.parametrize("other", ["{'b':2,'c':3}.keys()|[]", "{'b':2,'c':3}.keys()"])
def test_augmented_set_operations_preserve_the_right_alias_policy(tmp_path, operator, other):
    _compare(
        tmp_path,
        "value={'a':1,'b':2}.keys()|[]\nalias=value\nother="
        + other
        + "\n"
        + "value"
        + operator
        + "other\n"
        "return [sorted(value),sorted(alias),value is alias,isinstance(value,set)]",
    )


def test_bound_mutators_keep_builtin_kind_and_original_receiver(tmp_path):
    _compare(
        tmp_path,
        "value={'a':1}.keys()|[]\nalias=value\nadd=value.add\ncopy=value.copy\n"
        "value={'z':0}.keys()|[]\nadd('b')\ncloned=copy()\ncloned.discard('a')\n"
        "alias.update(['c'])\nalias.intersection_update(['a','b'])\n"
        "alias.difference_update(['a'])\nalias.symmetric_difference_update(['d'])\n"
        "return [sorted(value),sorted(alias),sorted(cloned),cloned is alias,"
        "isinstance(alias,set),isinstance(cloned,set)]",
    )


def test_nested_builtin_set_equality_and_explicit_conversion(tmp_path):
    _compare(
        tmp_path,
        "view={'a':1}.keys()\nbuiltin=view|[]\nwrapped=set(['a'])\n"
        "return [[builtin]==[wrapped],{'v':builtin}=={'v':wrapped},"
        "[builtin]==[view],(builtin,)==(builtin.copy(),),"
        "set(builtin)==wrapped,frozenset(builtin)==frozenset(['a']),"
        "isinstance(set(builtin),set),isinstance(frozenset(builtin),frozenset)]",
    )


def test_nan_membership_and_copy_preserve_distinct_objects(tmp_path):
    _compare(
        tmp_path,
        "first=float('nan')\nsecond=float('nan')\nthird=float('nan')\n"
        "values={first:1,second:2}.keys()|[]\ncopy=values.copy()\n"
        "values.add(first)\nvalues.discard(third)\n"
        "return [len(values),len(copy),first in values,second in copy,third in values,"
        "copy==values,copy is values,isinstance(copy,set),"
        "len(values.intersection(copy)),len(values.difference(copy)),"
        "len(values.symmetric_difference(copy))]",
        vm_profile="xian_vm_v1",
    )


def test_builtin_kind_and_shared_mutation_survive_cross_contract_calls(tmp_path):
    dependency = {
        "name": "con_set_kind_target",
        "owner": None,
        "source": "@export\ndef mutate(values: list):\n"
        "    item=values[0]\n    assert not isinstance(item,set)\n"
        "    item.add('b')\n    return {'item':item,'made':{'c':3}.keys()|[]}\n",
    }
    _compare(
        tmp_path,
        "value={'a':1}.keys()|[]\n"
        "result=con_set_kind_target.mutate([value])\n"
        "return [sorted(value),result['item'] is value,"
        "isinstance(result['item'],set),isinstance(result['made'],set),"
        "result['made']=={'c':3}.keys(),set(result['made'])]",
        [dependency],
    )


@pytest.mark.parametrize(
    "boundary",
    [
        "return value",
        "return [value]",
        "state.set(value)\nreturn 1",
        "state.set({'value':value})\nreturn 1",
    ],
)
def test_builtin_sets_require_explicit_conversion_at_external_boundaries(tmp_path, boundary):
    from xian_vm_core import execute_contract

    from contracting.storage.driver import Driver

    source = (
        "state=Variable()\n@export\ndef probe():\n    state.set(99)\n"
        "    value={'a':1}.keys()|[]\n"
        + "".join("    " + line + "\n" for line in boundary.splitlines())
        + "@export\ndef followup():\n    state.set(set({'b':2}.keys()|[]))\n    return state.get()\n"
    )
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_set_boundary", source, owner=None)
        driver.commit()
        context = {"caller": "alice", "signer": "alice", "this": "con_set_boundary"}
        result = execute_contract(
            driver=driver,
            contract_name="con_set_boundary",
            function_name="probe",
            kwargs={},
            context=context,
            meter=False,
        )
        assert result.status_code == 1
        assert "builtin sets cannot cross the VM boundary" in str(result.result)
        assert "set()" in str(result.result)
        assert result.writes == {} and result.events == []
        followup = execute_contract(
            driver=driver,
            contract_name="con_set_boundary",
            function_name="followup",
            kwargs={},
            context=context,
            meter=False,
        )
        assert followup.status_code == 0
        assert list(followup.result) == ["b"]


def test_builtin_sets_use_the_approved_deterministic_iteration_policy(tmp_path):
    result = _run_native_case(
        _case(
            "value={'z':0,'b':1,'a':2}.keys()|['c']\nreturn [list(value),list(value.copy()),value.pop(),list(value)]"
        ),
        tmp_path,
    )
    assert result["status_code"] == 0
    assert result["result"] == [["a", "b", "c", "z"], ["a", "b", "c", "z"], "a", ["b", "c", "z"]]


@pytest.mark.parametrize(
    "expression",
    [
        "builtin.add(value='b')",
        "builtin.remove(value='a')",
        "builtin.discard(value='a')",
        "builtin.issubset(other=['a'])",
        "builtin.issuperset(other=['a'])",
        "builtin.isdisjoint(other=['z'])",
        "builtin.symmetric_difference(other=[])",
        "builtin.copy(value=1)",
        "builtin.update(other=['b'])",
        "builtin.intersection_update(other=['a'])",
        "builtin.difference_update(other=['z'])",
        "builtin.symmetric_difference_update(other=[])",
        "builtin.symmetric_difference_update([],[])",
    ],
)
def test_builtin_set_method_signatures_are_strict(tmp_path, expression):
    case = _case("builtin={'a':1}.keys()|[]\nreturn " + expression)
    _reject(tmp_path, case)


def test_wrapper_methods_keep_their_python_keyword_parameters(tmp_path):
    _compare(
        tmp_path,
        "wrapped=set(['a'])\nwrapped.add(value='b')\nwrapped.remove(value='a')\n"
        "wrapped.discard(value='z')\nreturn [sorted(wrapped),"
        "wrapped.issubset(other=['b']),wrapped.issuperset(other=[]),"
        "wrapped.isdisjoint(other=['z']),sorted(wrapped.symmetric_difference(other=['c']))]",
    )


def test_builtin_update_methods_accept_multiple_iterables_and_return_none(tmp_path):
    _compare(
        tmp_path,
        "value={'a':1}.keys()|[]\nalias=value\n"
        "updated=value.update(['b'],['c'])\n"
        "intersected=value.intersection_update(['a','b','c'],['b','c'])\n"
        "removed=value.difference_update(['b'],['z'])\n"
        "changed=value.symmetric_difference_update(['d'])\n"
        "return [updated,intersected,removed,changed,sorted(value),value is alias,"
        "isinstance(value,set)]",
    )


@pytest.mark.parametrize(
    "method", ["update", "intersection_update", "difference_update", "symmetric_difference_update"]
)
def test_builtin_only_mutators_do_not_appear_on_wrappers(tmp_path, method):
    case = _case("return set(['a'])." + method + "([])")
    _reject(tmp_path, case, "AttributeError")


@pytest.mark.parametrize("needle", ["[]", "{}", "bytearray()", "set()"])
@pytest.mark.parametrize(
    "expression", ["needle in builtin", "builtin.remove(needle)", "builtin.discard(needle)"]
)
def test_builtin_set_lookup_hash_checks_unhashable_needles(tmp_path, needle, expression):
    case = _case("builtin={'a':1}.keys()|[]\nneedle=" + needle + "\nreturn " + expression)
    _reject(tmp_path, case)


def test_builtin_set_needles_autofreeze_only_for_lookup(tmp_path):
    _compare(
        tmp_path,
        "builtin={'a':1}.keys()|[]\nneedle={}.keys()|[]\n"
        "return [needle in builtin,builtin.discard(needle),len(builtin),"
        "frozenset() in builtin,[] in set(['a'])]",
    )


@pytest.mark.parametrize(
    "expression, error",
    [("builtin.remove(needle)", "KeyError"), ("builtin.add(needle)", "TypeError")],
)
def test_builtin_set_needles_still_cannot_be_added_or_removed_when_absent(
    tmp_path, expression, error
):
    case = _case("builtin={'a':1}.keys()|[]\nneedle={}.keys()|[]\nreturn " + expression)
    _reject(tmp_path, case, error)


def test_builtin_iterable_methods_stop_after_a_decisive_match(tmp_path):
    _compare(
        tmp_path,
        "value={'a':1}.keys()|[]\n"
        "intersection=value.intersection(['a',[]])\n"
        "subset=value.issubset(['a',[]])\n"
        "disjoint=value.isdisjoint(['a',[]])\n"
        "updated=value.intersection_update(['a',[]])\n"
        "return [sorted(intersection),subset,disjoint,updated,sorted(value)]",
    )


@pytest.mark.parametrize(
    "expression",
    [
        "builtin.isdisjoint([[],'a'])",
        "builtin.issuperset(['a',[]])",
        "builtin.union(['a',[]])",
        "builtin.difference(['a',[]])",
        "builtin.difference_update(['a',[]])",
        "empty.intersection([[]])",
        "empty.issubset([[]])",
        "empty.isdisjoint([[]])",
        "empty.intersection_update([[]])",
    ],
)
def test_builtin_methods_validate_every_item_they_consume(tmp_path, expression):
    case = _case("builtin={'a':1}.keys()|[]\nempty={}.keys()|[]\nreturn " + expression)
    _reject(tmp_path, case)


def test_autofrozen_builtin_needles_do_not_match_wrapper_frozen_sets(tmp_path):
    _compare(
        tmp_path,
        "outer={frozenset(['a']):1}.keys()|[]\nneedle={'a':1}.keys()|[]\n"
        "return [needle in outer,frozenset(['a']) in outer,"
        "outer.discard(needle),len(outer)]",
    )


BUILTIN_ITERABLE_METHODS = [
    "union",
    "intersection",
    "difference",
    "symmetric_difference",
    "issubset",
    "issuperset",
    "isdisjoint",
    "update",
    "intersection_update",
    "difference_update",
    "symmetric_difference_update",
]


def _callback_case(method, mutation=""):
    result = (
        "sorted(result)"
        if method in ["union", "intersection", "difference", "symmetric_difference"]
        else "result"
    )
    case = _case(
        "value={1:1,2:2}.keys()|[]\nobservations=[]\n"
        "inputs=[(2,value,observations),(1,value,observations),(3,value,observations)]\n"
        "result=value." + method + "(map(observe,inputs))\n"
        "return [" + result + ",observations,sorted(value)]"
    )
    case["source"] = (
        "def observe(payload):\n    item=payload[0]\n    value=payload[1]\n    observations=payload[2]\n"
        + mutation
        + "    observations.append([item,sorted(value)])\n    return item\n"
        + case["source"]
    )
    return case


@pytest.mark.parametrize("method", BUILTIN_ITERABLE_METHODS)
def test_builtin_set_methods_consume_iterators_in_python_order(tmp_path, method):
    _compare_case(tmp_path, _callback_case(method))


@pytest.mark.parametrize("method", BUILTIN_ITERABLE_METHODS)
@pytest.mark.parametrize("action", ["replace", "grow", "shrink"])
def test_builtin_set_methods_observe_live_reentrant_receiver_mutation(tmp_path, method, action):
    mutation = {
        "replace": "    if len(observations)==0:\n        value.clear()\n        value.add(9)\n",
        "grow": "    if len(observations)==0:\n        value.add(3)\n",
        "shrink": "    if len(observations)==0:\n        value.discard(1)\n",
    }[action]
    _compare_case(tmp_path, _callback_case(method, mutation))
