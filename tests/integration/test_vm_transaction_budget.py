"""Constructors and host work spend the same transaction budget, even on failure."""

import time

import pytest
from xian_runtime_types.time import Datetime

from contracting.constants import (
    DEPLOYMENT_BASE_COST,
    DEPLOYMENT_COST_PER_SOURCE_BYTE,
    TRANSACTION_BASE_CHI,
)
from contracting.local import ContractingClient

pytestmark = pytest.mark.optional_native
# Enough for one deployment (15,000 chi charged before compiling) and its
# constructor, not for two.
BUDGET = 30_000_000
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
    client.close()


def call(client, contract, function, kwargs, budget=BUDGET):
    from tests.vm_calls import execute_contract

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
    # The base chi counts against the budget (revision 14): the work runs
    # out once it and the base exceed the budget's chi.
    work_limit = budget - (TRANSACTION_BASE_CHI - 1) * 1000
    assert output.chi_used == budget // 1000
    # Attribution includes the measured failed work, not just its parent.
    assert sum(output.contract_costs.values()) >= work_limit


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
    # 8000 constructor iterations cost over 4,000,000 raw (4000 chi) plus the base.
    assert 4_000 + TRANSACTION_BASE_CHI <= output.chi_used <= BUDGET // 1000


def deployment_charge(code):
    return DEPLOYMENT_BASE_COST + len(code.encode()) * DEPLOYMENT_COST_PER_SOURCE_BYTE


def compile_bomb(factories, links):
    """Factories found one whole-program pass after another, then a long
    local alias chain: minutes of compiler work before the linear inference."""
    parts = ["import con_token\n"]
    for index in range(factories):
        argument = "con_token" if index == 0 else f"F{index - 1}(con_token)"
        parts.append(
            f"def F{index}(p):\n return p\ndef U{index}():\n return F{index}({argument})\n"
        )
    parts.append("def heavy():\n")
    parts.extend(f" a{index}=a{index - 1}\n" for index in range(links, 1, -1))
    parts.append(" a1=con_token\n return 1\n@export\ndef go():\n return 1\n")
    return "".join(parts)


def test_a_source_that_fails_to_compile_pays_for_its_compilation(client):
    client.raw_driver.set_contract_from_source("con_exists", HEAVY, owner=None)
    client.raw_driver.commit()
    code = "x = 1\n" * 4000 + "@export\ndef broken(:\n"

    def charged(name):
        output = call(client, "submission", "submit_contract", {"name": name, "code": code})
        assert output.status_code == 1
        return str(output.result), sum(output.contract_costs.values())

    # An existing name is refused before the charge; the same call to a new
    # name pays the deployment charge, then fails to compile.
    refused, before = charged("con_exists")
    failed, after = charged("con_absent")
    assert "Contract already exists" in refused
    assert "xian.syntax.parse_error" in failed
    assert after - before == deployment_charge(code)


def test_a_compile_bomb_compiles_promptly_and_pays_for_its_bytes(client):
    code = compile_bomb(200, 2000)
    started = time.perf_counter()
    output = call(
        client,
        "submission",
        "submit_contract",
        {"name": "con_bomb", "code": code},
        budget=200_000_000,
    )
    elapsed = time.perf_counter() - started
    assert output.status_code == 0, output.result
    assert elapsed < 5, elapsed
    assert sum(output.contract_costs.values()) > deployment_charge(code)
