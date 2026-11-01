"""Interface introspection follows reviewed bridge code, independent of call binding."""

import json
from pathlib import Path

import pytest

from contracting.execution.executor import Executor
from contracting.storage.driver import Driver
from tests.integration.test_vm_interface_descriptors import execute

pytestmark = pytest.mark.optional_native
CASES = json.loads(
    (Path(__file__).parents[1] / "fixtures/interface_metadata_cases.json").read_text()
)


def observe(value):
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, list):
        return ["list", [observe(item) for item in value]]
    raise AssertionError(f"unexpected oracle result {value!r}")


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_reviewed_host_code_metadata(tmp_path, case, native):
    with Driver(storage_home=tmp_path) as driver:
        for name, source in case.get("dependencies", {}).items():
            driver.set_contract_from_source(name, source, owner=None)
        driver.set_contract_from_source("con_metadata", case["source"], owner=None)
        driver.commit()
        if native:
            from xian_vm_core import execute_contract

            result = execute_contract(
                driver=driver,
                contract_name="con_metadata",
                function_name="probe",
                kwargs={},
                context={"caller": "alice", "signer": "alice", "this": "con_metadata"},
                meter=False,
            )
            status, value = result.status_code, result.result
        else:
            result = Executor(driver=driver, metering=False).execute(
                sender="alice",
                contract_name="con_metadata",
                function_name="probe",
                kwargs={},
                metering=False,
            )
            status, value = result["status_code"], result["result"]
        expected = case["expected_current"]
        assert status == expected["status_code"], value
        if status == 0:
            assert observe(value) == expected["result"]
        elif native:
            assert "Python code metadata" in str(value), value


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_unbound_descriptor_methods_keep_function_identity_and_keyword_binding(tmp_path, native):
    body = """f = importlib.Func('probe', ())
check = importlib.Func.is_of
v = importlib.Var('state', Variable)
return [check is importlib.Func.is_of,
        check(self=f, f=probe),
        importlib.Var.is_of(v=v.type, self=v),
        importlib.Func('is_of', ('self','f')).is_of(check),
        importlib.Func('is_of', ('self','v')).is_of(importlib.Var.is_of)]"""
    status, value, _ = execute(tmp_path, body, native=native)
    assert status == 0, value
    assert value == [True, True, False, True, True]


@pytest.mark.parametrize(
    "call",
    [
        "check(f, probe, probe)",
        "check(f, probe, f=probe)",
        "check(self=f, wrong=probe)",
        "check(f)",
    ],
)
def test_unbound_descriptor_invalid_signatures(tmp_path, call):
    status, _, writes = execute(
        tmp_path,
        "f=importlib.Func('probe', ())\ncheck=importlib.Func.is_of\nstate.set(9)\nreturn " + call,
    )
    assert status == 1
    assert writes == {}


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_wrapper_unbound_methods_bind_self_and_preserve_function_identity(tmp_path, native):
    body = """values = set([1])
add = set.add
add(self=values, value=2)
set.discard(values, value=1)
frozen = frozenset([3])
combined = frozenset.union(self=frozen)
return [sorted(values), sorted(combined), add is set.add,
        frozenset.union is frozenset.union,
        list.append is list.append, str.upper is str.upper,
        dict.fromkeys is dict.fromkeys]"""
    status, value, _ = execute(tmp_path, body, native=native)
    assert status == 0, value
    assert value == [[2], [3], True, True, True, True, False]


@pytest.mark.parametrize(
    "call",
    [
        "set.add(values, 2, self=values)",
        "set.add(value=2)",
        "set.add(self=values, wrong=2)",
        "set.add([], 2)",
        "set.add(frozenset([1]), 2)",
    ],
)
def test_wrapper_unbound_invalid_binding_rolls_back(tmp_path, call):
    status, _, writes = execute(tmp_path, "values=set([1])\nstate.set(9)\nreturn " + call)
    assert status == 1
    assert writes == {}


@pytest.mark.parametrize("native", [False, True], ids=["python", "native"])
def test_wrapper_inherited_functions_and_overridden_copy(tmp_path, native):
    body = """mutable = set([1])
frozen = frozenset([1])
a = set.union(frozen, [2])
b = frozenset.union(mutable, [2])
c = set.copy(frozen)
d = frozenset.copy(mutable)
plain = []
keys = {set.union: 1, frozenset.union: 2}
return [set.union is frozenset.union,
        set.copy is frozenset.copy,
        isinstance(a,frozenset), sorted(a),
        isinstance(b,set), sorted(b),
        c is frozen, c == frozen, isinstance(c,frozenset),
        d is mutable, frozenset.copy(plain) is plain, len(keys)]"""
    status, value, _ = execute(tmp_path, body, native=native)
    assert status == 0, value
    assert value == [True, False, True, [1, 2], True, [1, 2], False, True, True, True, True, 1]
