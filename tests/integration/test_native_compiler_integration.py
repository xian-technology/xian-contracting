"""Compiler declarations are enforced by native deployment and execution."""

import pytest

from contracting.local import ContractingClient


@pytest.fixture
def client():
    with ContractingClient() as client:
        yield client


def test_native_constructor_and_storage_declarations(client):
    client.submit(
        """
balance = Variable()
balances = Hash(default_value=0)

@construct
def seed():
    balance.set(42)
    balances['alice'] = 17

@export
def inspect():
    return [balance.get(), balances['alice']]
""",
        name="con_source",
    )
    contract = client.get_contract_proxy("con_source")
    assert contract.inspect() == [42, 17]
    assert client.raw_driver.get("con_source.balance") == 42
    assert client.raw_driver.get("con_source.balances:alice") == 17


def test_native_foreign_storage_binds_the_declared_contract(client):
    client.submit(
        """
balance = Variable()
balances = Hash()

@construct
def seed():
    balance.set(42)
    balances['alice'] = 17

@export
def inspect():
    return balance.get()
""",
        name="con_source",
    )
    client.submit(
        """
balance = ForeignVariable(foreign_contract='con_source', foreign_name='balance')
balances = ForeignHash(foreign_contract='con_source', foreign_name='balances')

@export
def inspect():
    return [balance.get(), balances['alice']]
""",
        name="con_reader",
    )
    assert client.get_contract_proxy("con_reader").inspect() == [42, 17]


def test_private_forward_calls_work_without_exporting_the_helper(client):
    client.submit(
        """
@export
def invoke(message: str):
    return first(message)

def first(message: str):
    return second(message)

def second(message: str):
    return message
""",
        name="con_helpers",
    )
    contract = client.get_contract_proxy("con_helpers")
    assert contract.invoke(message="hello") == "hello"
    assert [name for name, _ in contract.functions] == ["invoke"]
    with pytest.raises(AttributeError):
        contract.first(message="no")


def test_native_event_declaration_and_public_typecheck(client):
    client.submit(
        """
approve = LogEvent('Approve', {'owner': indexed(str), 'amount': int})

@export(typecheck=True)
def emit(amount: int):
    approve({'owner': ctx.caller, 'amount': amount})
    return amount
""",
        name="con_events",
    )
    output = client.executor.execute(
        sender="alice", contract_name="con_events", function_name="emit", kwargs={"amount": 5}
    )
    assert output["status_code"] == 0
    assert output["result"] == 5
    assert output["events"][0]["contract"] == "con_events"
    assert output["events"][0]["event"] == "Approve"
    assert output["events"][0]["data"] == {"amount": 5}
    assert output["events"][0]["data_indexed"] == {"owner": "alice"}
    assert output["events"][0]["signer"] == "alice"
    rejected = client.executor.execute(
        sender="alice", contract_name="con_events", function_name="emit", kwargs={"amount": "5"}
    )
    assert rejected["status_code"] == 1
    assert rejected["events"] == []
