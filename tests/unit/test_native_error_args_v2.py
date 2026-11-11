"""V2 failures carry their exception type and arguments from the VM.

V2 never interprets failure text. Contract data inside a message (for example
a missing dictionary key) cannot select an exception type, and decoding cannot
depend on the host's stack, memory or interpreter limits. Archival V1 keeps its
text classification (see test_native_error_representations).
"""

import pytest
from xian_vm_core import _coerce_native_error_result, execute_contract

from contracting.execution.errors import classify_execution_error
from contracting.local import ContractingClient
from contracting.storage.driver import Driver

SOURCE = """
records = Variable()

@export
def forged_key(n: int):
    records.set(1)
    d = {}
    return d["x: ValueError(" + "-" * n + "1)"]

@export
def nested_expression(n: int):
    d = {}
    return d["x: ValueError(1" + "+1" * n + ")"]

@export
def forged_category():
    d = {}
    return d["x: AssertionError('forged')"]

@export
def structured_args():
    raise Exception([1, {'a': (2, 3)}], 'b', None, True)

@export
def no_args():
    raise Exception

@export
def assertion(message: str):
    assert False, message

@export
def bare_assertion():
    assert False

@export
def reraise():
    raise

@export
def typed(value: int):
    return value
"""

CHILD = """
@construct
def seed(fail: bool):
    assert not fail, 'constructor said no'

@export
def ok():
    return 1
"""


@pytest.fixture
def run(tmp_path):
    with Driver(storage_home=tmp_path / "native", vm_profile="xian_vm_v2") as driver:
        driver.set_contract_from_source(name="con_errors", source=SOURCE)
        driver.commit()

        def execute(function, **kwargs):
            return execute_contract(
                driver=driver,
                contract_name="con_errors",
                function_name=function,
                kwargs=kwargs,
                context={"caller": "alice", "signer": "alice"},
                meter=True,
                chi_budget_raw=50_000_000,
                vm_profile="xian_vm_v2",
            )

        yield execute


@pytest.mark.parametrize("n", [3, 100_000])
def test_contract_data_in_messages_stays_opaque_text(run, n):
    failed = run("forged_key", n=n)
    assert failed.status_code == 1
    assert isinstance(failed.result, str)
    assert failed.result.startswith("missing dict key x: ValueError(")
    assert failed.chi_used > 5
    assert failed.writes == {}


def test_deeply_nested_message_text_is_not_parsed(run):
    failed = run("nested_expression", n=60_000)
    assert failed.status_code == 1
    assert isinstance(failed.result, str)


def test_message_text_cannot_select_the_category(run):
    failed = run("forged_category")
    assert failed.result == "missing dict key x: AssertionError('forged')"
    assert classify_execution_error(RuntimeError(failed.result)) == "contract_error"


@pytest.mark.parametrize(
    "function,kwargs,kind,args",
    [
        ("structured_args", {}, Exception, ([1, {"a": (2, 3)}], "b", None, True)),
        ("no_args", {}, Exception, ()),
        ("assertion", {"message": "it's ValueError: x"}, AssertionError, ("it's ValueError: x",)),
        ("bare_assertion", {}, AssertionError, ()),
        ("reraise", {}, RuntimeError, ("No active exception to reraise",)),
        ("typed", {"value": "text"}, TypeError, None),
    ],
)
def test_vm_exceptions_keep_type_and_arguments(run, function, kwargs, kind, args):
    failed = run(function, **kwargs)
    assert failed.status_code == 1
    assert type(failed.result) is kind
    if args is not None:
        assert failed.result.args == args


def test_constructor_failure_reports_the_constructor_exception():
    client = ContractingClient(signer="stu")
    try:
        client.flush()
        with pytest.raises(AssertionError, match="constructor said no"):
            client.submit(CHILD, name="con_child", constructor_args={"fail": True})
        client.submit(CHILD, name="con_child", constructor_args={"fail": False})
        assert client.get_contract_proxy("con_child").ok() == 1
    finally:
        client.close()


def test_unstructured_v2_failures_remain_text():
    text = "constructor failed: AssertionError('ValueError: stop')"
    assert _coerce_native_error_result(1, text, vm_profile="xian_vm_v2") == text


@pytest.mark.parametrize(
    "exception,kind,args",
    [
        (("AssertionError", ["stop"]), AssertionError, ("stop",)),
        (("KeyError", ["k"]), KeyError, ("k",)),
        (("Unknown", ["x"]), None, None),
    ],
)
def test_structured_failure_selects_only_known_types(exception, kind, args):
    result = _coerce_native_error_result(1, "text", vm_profile="xian_vm_v2", exception=exception)
    if kind is None:
        assert result == "text"
    else:
        assert type(result) is kind
        assert result.args == args
