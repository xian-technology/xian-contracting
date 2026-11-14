"""Native failures remain bounded and keep the VM's error categories."""

import pytest
from xian_vm_core import native_error_result
from tests.vm_calls import execute_contract

from contracting.execution.errors import classify_execution_error
from contracting.storage.driver import Driver


def test_long_native_failure_is_returned_without_writes_and_next_call_succeeds(tmp_path):
    source = """stored = Variable()
@export
def fail():
    stored.set(99)
    assert False, 'ValueError: ' * 1500
@export
def good():
    return 7
"""
    with Driver(storage_home=tmp_path / "native") as driver:
        driver.set_contract_from_source(name="con_error", source=source)
        driver.set_var("con_error", "stored", value=1)
        driver.commit()

        def execute(function):
            return execute_contract(
                driver=driver,
                contract_name="con_error",
                function_name=function,
                kwargs={},
                context={"caller": "alice", "signer": "alice"},
            )

        failed = execute("fail")
        assert failed.status_code == 1
        assert type(failed.result) is AssertionError
        assert classify_execution_error(failed.result) == "contract_assertion"
        assert failed.result.args == ("ValueError: " * 1500,)
        assert failed.writes == {}
        assert failed.events == []
        assert driver.get_var("con_error", "stored") == 1
        followup = execute("good")
        assert followup.status_code == 0
        assert followup.result == 7


@pytest.mark.parametrize(
    "status,value",
    [(0, "AssertionError('ordinary result')"), (1, RuntimeError("typed failure")), (0, None)],
)
def test_failure_coercion_preserves_success_values_and_existing_exception_objects(
    status, value
):
    assert native_error_result(status, value) is value
