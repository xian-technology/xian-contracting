"""Native failure and admission cannot leak token or contract state changes."""

from pathlib import Path

import pytest

from contracting.local import ContractingClient

CONTRACTS = Path(__file__).parent / "contracts"


@pytest.fixture
def client(tmp_path):
    with ContractingClient(storage_home=tmp_path, signer="stu", metering=True) as client:
        client.submit(
            (CONTRACTS / "erc20_clone.s.py").read_text(), name="con_erc20", metering=False
        )
        client.raw_driver.commit()
        yield client


@pytest.mark.parametrize(
    "fixture",
    [
        "hack_tokens.s.py",
        "builtin_hack_token.s.py",
        "import_hash_from_contract.s.py",
        "get_set_driver.py",
        "get_set_driver_2.py",
    ],
)
def test_authored_storage_attacks_cannot_mutate_token_or_partial_deployment(client, fixture):
    before = client.raw_driver.items()
    output = client.get_contract_proxy("submission").submit_contract(
        name="con_token_attack",
        code=(CONTRACTS / fixture).read_text(),
        return_full_output=True,
    )
    assert output["status_code"] == 1, output
    assert output["writes"] == {}
    assert output["events"] == []
    assert not client.raw_driver.has_contract("con_token_attack")
    assert client.raw_driver.items() == before


def test_budget_exhaustion_after_cross_contract_transfer_rolls_back_tokens(client):
    token = client.get_contract_proxy("con_erc20")
    token.approve(amount=10000, to="con_hack", metering=False)
    client.submit(
        (CONTRACTS / "double_spend_gas_attack.s.py").read_text(), name="con_hack", metering=False
    )
    client.raw_driver.commit()
    before = client.raw_driver.items()
    output = client.get_contract_proxy("con_hack").double_spend(
        receiver="colin",
        chi=200,
        return_full_output=True,
    )
    assert output["status_code"] == 1, output
    assert output["chi_used"] > 0
    assert output["writes"] == {}
    assert output["events"] == []
    assert client.raw_driver.items() == before


def test_nested_infinite_loop_cannot_escape_the_transaction_budget(client):
    client.submit(
        (CONTRACTS / "infinate_loop.s.py").read_text(), name="con_infinate_loop", metering=False
    )
    client.submit(
        (CONTRACTS / "call_infinate_loop.s.py").read_text(),
        name="con_call_infinate_loop",
        metering=False,
    )
    client.raw_driver.commit()
    before = client.raw_driver.items()
    output = client.get_contract_proxy("con_call_infinate_loop").call(
        chi=200, return_full_output=True
    )
    assert output["status_code"] == 1, output
    assert output["chi_used"] > 0
    assert output["writes"] == {}
    assert client.raw_driver.items() == before


@pytest.mark.parametrize("fixture", ["constructor_infinate_loop.s.py", "con_inf_writes.s.py"])
def test_failed_constructor_rolls_back_all_writes_and_artifacts(client, fixture):
    before = client.raw_driver.items()
    output = client.get_contract_proxy("submission").submit_contract(
        name="con_constructor_attack",
        code=(CONTRACTS / fixture).read_text(),
        chi=200,
        return_full_output=True,
    )
    assert output["status_code"] == 1, output
    assert output["chi_used"] > 0
    assert output["writes"] == {}
    assert output["events"] == []
    assert not client.raw_driver.has_contract("con_constructor_attack")
    assert client.raw_driver.items() == before
