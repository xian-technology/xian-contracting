"""Repeated native transactions preserve each recipient and the total supply."""

from pathlib import Path

from contracting.local import ContractingClient


def test_repeated_native_transfers_persist_without_losing_balances():
    source = (Path(__file__).parent / "test_contracts/erc20_clone.s.py").read_text()
    recipients = [f"recipient-{index}" for index in range(10_000)]
    with ContractingClient(signer="stu") as client:
        client.submit(source, name="con_erc20_clone")
        token = client.get_contract_proxy("con_erc20_clone")
        supply = token.total_supply()
        initial_balance = token.balance_of(account="stu")

        for recipient in recipients:
            token.transfer(amount=1, to=recipient)

        assert token.balance_of(account="stu") == initial_balance - len(recipients)
        assert token.total_supply() == supply
        assert all(token.balance_of(account=recipient) == 1 for recipient in recipients)
        client.raw_driver.commit()

    with ContractingClient(signer="stu") as reopened:
        token = reopened.get_contract_proxy("con_erc20_clone")
        assert token.balance_of(account="stu") == initial_balance - len(recipients)
        assert token.balance_of(account=recipients[-1]) == 1
        assert token.total_supply() == supply
