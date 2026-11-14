"""The local client runs calls with the code a block runs.

``NativeExecutor`` executes through ``xian_vm_core.execute_tx`` over the
driver's environment and pending state; the result dictionary keeps its
shape. A call the Rust executor leaves to Python runs on the Python host.
"""

import pytest
import xian_vm_core

from contracting.local import ContractingClient

COUNTER = """count = Variable()

@construct
def seed():
    count.set(0)

@export
def bump(by: int):
    count.set(count.get() + by)
    return count.get()

@export
def fail():
    count.set(99)
    assert False, "forced"
"""


@pytest.fixture
def client(tmp_path):
    client = ContractingClient(storage_home=tmp_path, vm_profile="xian_vm_v2")
    client.submit(COUNTER, name="con_counter", owner=None)
    try:
        yield client
    finally:
        client.close()


def _execute(client, function, **kwargs):
    return client.executor.execute(
        sender="sys", contract_name="con_counter", function_name=function, kwargs=kwargs
    )


def test_a_call_runs_in_rust_and_stages_its_writes(client, monkeypatch):
    routes = []
    real = xian_vm_core.execute_tx

    def recorded(*args, **kwargs):
        routes.append(run := real(*args, **kwargs))
        return run

    monkeypatch.setattr(xian_vm_core, "execute_tx", recorded)
    output = _execute(client, "bump", by=3)

    assert [type(run) for run in routes] == [xian_vm_core.TxRun]
    assert output["status_code"] == 0
    assert output["result"] == 3
    assert output["writes"] == {"con_counter.count": 3}
    assert output["error_class"] == "success"
    assert output["contract_costs"]["con_counter"] > 0
    assert client.get_var("con_counter", "count") == 3


def test_a_failed_call_raises_its_exception_and_keeps_no_writes(client):
    contract = client.get_contract_proxy("con_counter")

    with pytest.raises(AssertionError, match="forced"):
        contract.fail()
    assert client.get_var("con_counter", "count") == 0
