"""An execution reads each contract's owner once, and sees owner changes at once.

The VM checks a contract's owner on every call into it. Within one execution
the owner can only change through a host syscall (``submission.change_owner``),
so the VM keeps each owner it read until the next host syscall instead of
asking the host again on every call.
"""

import pytest
from tests.vm_calls import execute_contract
from xian_runtime_types.time import Datetime

from contracting.local import ContractingClient

pytestmark = pytest.mark.optional_native

TARGET = """
@export
def ping():
    return 1
"""

REPEATED_CALLS = """
import con_target

@export
def run():
    total = 0
    for i in range(5):
        total += con_target.ping()
    return total
"""

HAND_OVER_THEN_CALL = """
import con_target
import submission

@export
def run():
    con_target.ping()
    submission.change_owner(contract="con_target", new_owner="bob")
    return con_target.ping()
"""


def _context(this):
    return {
        "signer": "alice",
        "caller": "alice",
        "this": this,
        "owner": None,
        "now": Datetime(2026, 1, 1),
        "block_num": 1,
        "chain_id": "test-chain",
    }


@pytest.fixture
def driver(tmp_path):
    client = ContractingClient(storage_home=tmp_path)
    client.flush()
    client.raw_driver.set_contract_from_source("con_target", TARGET, owner=None)
    client.raw_driver.commit()
    yield client.raw_driver
    client.flush()


def _run(driver, name, source, *, target_owner=None):
    driver.set_contract_from_source(name, source, owner=None)
    driver.set_var("con_target", "__owner__", value=target_owner)
    driver.commit()
    return execute_contract(
        driver=driver,
        contract_name=name,
        function_name="run",
        kwargs={},
        context=_context(name),
        meter=True,
        chi_budget_raw=5_000_000,
    )


def test_repeated_calls_to_an_owned_contract_pass_the_owner_check(driver):
    # The executor reads each owner once per execution (BundleExecutor's owner
    # cache); here the repeated calls only have to succeed.
    output = _run(driver, "con_caller", REPEATED_CALLS)

    assert output.status_code == 0, output.result
    assert output.result == 5


def test_an_owner_change_applies_to_the_next_call_in_the_same_execution(driver):
    output = _run(driver, "con_parent", HAND_OVER_THEN_CALL, target_owner="con_parent")

    assert output.status_code == 1
    assert str(output.result) == "Caller is not the owner!"


def test_the_owner_check_passes_while_the_owner_is_unchanged(driver):
    output = _run(driver, "con_caller", REPEATED_CALLS, target_owner="con_caller")

    assert output.status_code == 0, output.result
    assert output.result == 5
