"""Callable aliases stay local even when nested calls share mutable heap values."""

from contextlib import contextmanager

import pytest

from contracting.compilation.linter import LintingError
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

CALLABLES = [
    "int",
    "len",
    "set",
    "decimal",
    "datetime.datetime",
    "datetime.timedelta",
    "hashlib.sha3_text",
    "random.random",
    "importlib.Func",
]
DECLARATIONS = (
    "state=Variable(default_value=0)\n"
    "notice=LogEvent(event='CallableBoundary',params={'stage':int})\n"
)
READ_SOURCE = "@export\ndef read():\n    return state.get()\n"
FOLLOWUP_SOURCE = (
    "@export\ndef followup():\n"
    "    assert state.get()==0\n"
    "    assert con_callable_target.read()==0\n"
    "    state.set(7)\n"
    "    notice({'stage':7})\n"
    "    return 7\n"
)


def _export(name, body, arguments=""):
    return (
        "@export\ndef "
        + name
        + "("
        + arguments
        + "):\n"
        + "".join("    " + line + "\n" for line in body.splitlines())
    )


@contextmanager
def _deployed(home, caller_body, callee_body):
    caller = (
        "import con_callable_target\n"
        + DECLARATIONS
        + _export("probe", "state.set(1)\nnotice({'stage':1})\n" + caller_body)
        + FOLLOWUP_SOURCE
    )
    with Driver(storage_home=home) as driver:
        driver.set_contract_from_source(
            "con_callable_target", DECLARATIONS + READ_SOURCE + callee_body, owner=None
        )
        driver.set_contract_from_source("con_callable_caller", caller, owner=None)
        driver.commit()
        yield driver


def _execute(driver, function, meter):
    from xian_vm_core import execute_contract

    return execute_contract(
        driver=driver,
        contract_name="con_callable_caller",
        function_name=function,
        kwargs={},
        context={"caller": "alice", "signer": "alice", "this": "con_callable_caller"},
        meter=meter,
        chi_budget_raw=10_000_000,
    )


def _assert_boundary_and_recovery(driver, meter, fragment="cannot cross"):
    # Deliberately let unexpected native/Python exceptions fail this test: these
    # paths must return a controlled execution failure in both meter modes.
    failure = _execute(driver, "probe", meter)
    assert failure.status_code == 1, failure.result
    assert fragment in str(failure.result), failure.result
    assert failure.writes == {} and failure.events == []
    recovered = _execute(driver, "followup", meter)
    assert recovered.status_code == 0, recovered.result
    assert recovered.result == 7
    assert recovered.writes == {"con_callable_caller.state": 7}
    assert len(recovered.events) == 1


def _assert_input_boundary(home, meter, callable_expression, payload):
    callee = _export("consume", "state.set(2)\nnotice({'stage':2})\nreturn 99", "value: Any")
    caller = (
        "callback=" + callable_expression + "\nreturn con_callable_target.consume(" + payload + ")"
    )
    with _deployed(home, caller, callee) as driver:
        _assert_boundary_and_recovery(driver, meter)


@pytest.mark.parametrize("meter", [False, True], ids=["unmetered", "metered"])
@pytest.mark.parametrize("callable_expression", CALLABLES)
def test_nested_callable_inputs_are_rejected_before_shared_contract_execution(
    tmp_path, meter, callable_expression
):
    _assert_input_boundary(tmp_path, meter, callable_expression, "{'nested':[callback]}")


@pytest.mark.parametrize("meter", [False, True], ids=["unmetered", "metered"])
@pytest.mark.parametrize("callable_expression", CALLABLES)
def test_nested_callable_results_are_rejected_and_both_contracts_roll_back(
    tmp_path, meter, callable_expression
):
    callee = _export(
        "produce",
        "state.set(2)\nnotice({'stage':2})\ncallback="
        + callable_expression
        + "\nreturn {'nested':[callback]}",
    )
    with _deployed(tmp_path, "con_callable_target.produce()\nreturn 99", callee) as driver:
        _assert_boundary_and_recovery(driver, meter)


@pytest.mark.parametrize("meter", [False, True], ids=["unmetered", "metered"])
@pytest.mark.parametrize(
    "callable_expression", ["int", "len", "datetime.timedelta", "hashlib.sha3_text"]
)
def test_callee_cannot_inject_callable_dictionary_keys_into_caller_data(
    tmp_path, meter, callable_expression
):
    callee = _export(
        "inject",
        "state.set(2)\nnotice({'stage':2})\ncallback="
        + callable_expression
        + "\nvalues[callback]=1\nreturn 99",
        "values: dict",
    )
    caller = "values={}\ncon_callable_target.inject(values)\nreturn 99"
    with _deployed(tmp_path, caller, callee) as driver:
        _assert_boundary_and_recovery(driver, meter)


CAPTURED_PAYLOADS = [
    "map(callback, [])",
    "filter(callback, [])",
    "zip(map(callback, []))",
    "reversed([callback])",
    "Exception({'callback': callback})",
]


@pytest.mark.parametrize("meter", [False, True], ids=["unmetered", "metered"])
@pytest.mark.parametrize("payload", CAPTURED_PAYLOADS)
def test_callable_captures_cannot_hide_inside_iterator_inputs(tmp_path, meter, payload):
    _assert_input_boundary(tmp_path, meter, "hashlib.sha3_text", payload)


@pytest.mark.parametrize("meter", [False, True], ids=["unmetered", "metered"])
@pytest.mark.parametrize("payload", CAPTURED_PAYLOADS)
def test_callee_cannot_hide_callable_captures_in_shared_container_mutations(
    tmp_path, meter, payload
):
    callee = _export(
        "inject",
        "state.set(2)\nnotice({'stage':2})\ncallback=hashlib.sha3_text\n"
        "values.append(" + payload + ")\nreturn 99",
        "values: list",
    )
    with _deployed(
        tmp_path, "values=[]\ncon_callable_target.inject(values)\nreturn 99", callee
    ) as driver:
        _assert_boundary_and_recovery(driver, meter)


@pytest.mark.parametrize("meter", [False, True], ids=["unmetered", "metered"])
def test_noncallable_shared_aliases_and_cycles_remain_valid(tmp_path, meter):
    callee = _export(
        "mutate",
        "assert values[0] is values\nvalues.clear()\nvalues.append(9)\nreturn {'same':values}",
        "values: list",
    )
    caller = (
        "values=[]\nvalues.append(values)\nresult=con_callable_target.mutate(values)\n"
        "return [result['same'] is values,values]"
    )
    with _deployed(tmp_path, caller, callee) as driver:
        result = _execute(driver, "probe", meter)
        assert result.status_code == 0, result.result
        assert result.result == [True, [9]]
        assert result.writes == {"con_callable_caller.state": 1}
        assert len(result.events) == 1


@pytest.mark.parametrize(
    "orm_name", ["Variable", "Hash", "ForeignVariable", "ForeignHash", "LogEvent"]
)
def test_orm_constructor_aliases_remain_linter_forbidden(tmp_path, orm_name):
    source = _export("probe", "factory=" + orm_name + "\nreturn 1")
    with Driver(storage_home=tmp_path) as driver:
        with pytest.raises(LintingError, match="E014"):
            driver.set_contract_from_source("con_forbidden_orm_alias", source, owner=None)


@pytest.mark.parametrize("meter", [False, True], ids=["unmetered", "metered"])
@pytest.mark.parametrize("aliased", [False, True], ids=["direct", "alias"])
def test_metadata_owner_changes_remain_submission_only(tmp_path, meter, aliased):
    call = "Contract.set_owner('con_callable_target','mallory')"
    if aliased:
        call = "change=Contract.set_owner\nchange('con_callable_target','mallory')"
    with _deployed(tmp_path, call + "\nreturn 99", "") as driver:
        owner = driver.get_owner("con_callable_target")
        _assert_boundary_and_recovery(driver, meter, "submission")
        assert driver.get_owner("con_callable_target") == owner
