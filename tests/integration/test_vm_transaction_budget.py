"""Constructors and host work spend the same transaction budget, even on failure."""

import pytest
from xian_runtime_types.time import Datetime
from contracting.local import ContractingClient

pytestmark = pytest.mark.optional_native
BUDGET = 5_000_000
HEAVY = """
total = Variable()
@construct
def seed():
    x = 0
    while x < 8000:
        x = x + 1
    total.set(x)
@export
def get():
    return total.get()
"""
FACTORY = """
import submission
@export
def spawn(code: str):
    submission.submit_contract(name="con_one", code=code)
    submission.submit_contract(name="con_two", code=code)
"""
NESTED = """
import submission
total = Variable()
@construct
def seed(code: str):
    submission.submit_contract(name="con_nested", code=code)
    x = 0
    while x < 8000:
        x = x + 1
    total.set(x)
@export
def get():
    return total.get()
"""


@pytest.fixture
def client(tmp_path):
    client = ContractingClient(storage_home=tmp_path)
    client.flush()
    yield client
    client.flush()


def call(client, contract, function, kwargs, budget=BUDGET):
    from xian_vm_core import execute_contract

    return execute_contract(
        driver=client.raw_driver,
        contract_name=contract,
        function_name=function,
        kwargs=kwargs,
        context={
            "signer": "alice",
            "caller": "alice",
            "this": contract,
            "owner": None,
            "now": Datetime(2026, 1, 1),
            "chain_id": "test",
        },
        meter=True,
        chi_budget_raw=budget,
    )


def assert_out_of_chi(output, budget=BUDGET):
    assert output.status_code == 1, output
    assert "Out of chi" in str(output.result)
    assert output.writes == {}
    assert output.events == []
    assert output.raw_cost >= budget
    assert output.chi_used == budget // 1000
    # Attribution includes the measured failed work, not just its parent.
    assert sum(output.contract_costs.values()) >= budget


def test_serial_constructors_share_one_transaction_budget(client):
    client.raw_driver.set_contract_from_source("con_factory", FACTORY, owner=None)
    client.raw_driver.commit()
    assert_out_of_chi(call(client, "con_factory", "spawn", {"code": HEAVY}))


def test_nested_constructors_share_one_transaction_budget(client):
    assert_out_of_chi(
        call(
            client,
            "submission",
            "submit_contract",
            {"name": "con_outer", "code": NESTED, "constructor_args": {"code": HEAVY}},
        )
    )


def test_failed_constructor_keeps_its_measured_cost(client):
    assert_out_of_chi(
        call(
            client,
            "submission",
            "submit_contract",
            {"name": "con_fail", "code": HEAVY.replace("8000", "2000000")},
        )
    )


def test_host_deployment_cost_cannot_exceed_transaction_budget(client):
    assert_out_of_chi(
        call(
            client,
            "submission",
            "submit_contract",
            {"name": "con_plain", "code": "@export\ndef get():\n    return 1\n"},
            budget=200_000,
        ),
        200_000,
    )


def test_successful_constructor_is_charged_once(client):
    output = call(client, "submission", "submit_contract", {"name": "con_ok", "code": HEAVY})
    assert output.status_code == 0, output.result
    assert output.writes["con_ok.total"] == 8000
    assert 4_000_000 < output.raw_cost < BUDGET
    assert output.chi_used == output.raw_cost // 1000 + 5
