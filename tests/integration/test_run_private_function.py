"""Native callers may invoke helpers only through an exported entrypoint."""

from pathlib import Path

import pytest

from contracting.local import ContractingClient


@pytest.fixture
def contract(tmp_path):
    source = (Path(__file__).parent / "test_contracts/private_methods.s.py").read_text()
    with ContractingClient(storage_home=tmp_path) as client:
        client.submit(source, name="con_private_methods")
        yield client.get_contract_proxy("con_private_methods")


def test_exported_entrypoint_can_call_private_helper(contract):
    assert contract.call_private() == "abc"


@pytest.mark.parametrize("name", ["private", "__private", "missing_private"])
def test_private_and_unknown_functions_are_not_entrypoints(contract, name):
    output = contract.executor.execute(
        sender="alice", contract_name="con_private_methods", function_name=name, kwargs={}
    )
    assert output["status_code"] == 1
    assert output["writes"] == {}


def test_local_proxy_exposes_no_python_private_bypass(contract):
    assert not hasattr(contract, "run_private_function")
    assert not hasattr(contract, "private")
    assert not hasattr(contract, "__private")
    assert contract.call_private() == "abc"
