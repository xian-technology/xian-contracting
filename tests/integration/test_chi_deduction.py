"""Native execution reports deterministic costs; node fee policy owns token fees."""

import pytest

from contracting.local import ContractingClient

SOURCE = """value = Variable(default_value=0)
@export
def transfer(amount: int):
    value.set(value.get() + amount)
    return value.get()
@export
def forever():
    value.set(999)
    while True:
        pass
@export
def text(length: int):
    return 'a' * length
"""


@pytest.fixture
def client(tmp_path):
    with ContractingClient(storage_home=tmp_path, metering=True) as client:
        client.submit(SOURCE, name="con_metering", metering=False)
        client.raw_driver.set("currency.balances:alice", 1000)
        client.raw_driver.commit()
        yield client


def test_success_reports_cost_without_applying_node_currency_fees(client):
    output = client.executor.execute(
        sender="alice",
        contract_name="con_metering",
        function_name="transfer",
        kwargs={"amount": 7},
        auto_commit=True,
    )
    assert output["status_code"] == 0, output
    assert output["result"] == 7
    assert output["chi_used"] > 0
    assert output["contract_costs"]["con_metering"] > 0
    assert output["writes"] == {"con_metering.value": 7}
    assert client.raw_driver.get("currency.balances:alice") == 1000


def test_exhausted_budget_rolls_back_writes_but_retains_cost(client):
    output = client.executor.execute(
        sender="alice",
        contract_name="con_metering",
        function_name="forever",
        kwargs={},
        chi=1,
        auto_commit=True,
    )
    assert output["status_code"] == 1, output
    assert output["chi_used"] == 1
    assert "chi" in str(output["result"]).lower() or "budget" in str(output["result"]).lower()
    assert output["writes"] == {}
    assert output["events"] == []
    assert client.raw_driver.get_var("con_metering", "value") is None
    assert client.raw_driver.get("currency.balances:alice") == 1000


def test_pending_native_writes_are_applied_before_explicit_commit(client):
    output = client.executor.execute(
        sender="alice",
        contract_name="con_metering",
        function_name="transfer",
        kwargs={"amount": 11},
        auto_commit=False,
    )
    assert output["status_code"] == 0, output
    assert client.raw_driver.pending_items() == [("con_metering.value", 11)]
    client.raw_driver.commit()
    assert client.raw_driver.get_var("con_metering", "value") == 11


def test_larger_return_values_cost_more_chi(client):
    outputs = [
        client.executor.execute(
            sender="alice",
            contract_name="con_metering",
            function_name="text",
            kwargs={"length": size},
        )
        for size in (1, 4096)
    ]
    assert [out["status_code"] for out in outputs] == [0, 0]
    assert [len(out["result"]) for out in outputs] == [1, 4096]
    assert outputs[1]["chi_used"] > outputs[0]["chi_used"]


def test_constructor_budget_failure_leaves_no_deployment(client):
    source = """value = Variable()
@construct
def seed():
    value.set(3)
    while True:
        pass
@export
def read():
    return value.get()
"""
    before = client.raw_driver.items()
    output = client.get_contract_proxy("submission").submit_contract(
        name="con_exhausted",
        code=source,
        chi=1,
        return_full_output=True,
    )
    assert output["status_code"] == 1, output
    assert output["chi_used"] > 0
    assert output["writes"] == {}
    assert not client.raw_driver.has_contract("con_exhausted")
    assert client.raw_driver.items() == before
