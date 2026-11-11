"""Local authoring and simulation use the selected profile end to end."""

from decimal import Decimal

import pytest
from xian_runtime_types.decimal import ContractingDecimal
from contracting.local import ContractingClient

pytestmark = pytest.mark.optional_native


def con_v2():
    balance = Variable()

    @construct
    def seed():
        balance.set(0.120000000000000000000000000001)

    @export
    def multiply(amount: decimal, numerator: int = 1, denominator: int = 1):
        balance.set(amount * numerator / denominator)
        return balance.get()

    @export
    def inspect():
        return balance.get()


def test_exact_closure_deployment_and_failed_call_preserves_persisted_state(tmp_path):
    with ContractingClient(storage_home=tmp_path, vm_profile="xian_vm_v2") as client:
        client.submit(con_v2)
        contract = client.get_contract_proxy("con_v2")
        assert contract.inspect() == Decimal("0.120000000000000000000000000001")
        total = contract.multiply(amount=9007199254740993, denominator=2)
        assert type(total) is ContractingDecimal
        assert total == Decimal("4503599627370496.5")
        failure = contract.multiply(amount=10, denominator=0, return_full_output=True)
        assert failure["status_code"] == 1
        assert failure["writes"] == {}
        assert contract.inspect() == total
        client.raw_driver.commit()
    with ContractingClient(storage_home=tmp_path, vm_profile="xian_vm_v2") as client:
        assert client.get_contract_proxy("con_v2").inspect() == total


def test_parallel_local_simulation_applies_v2_in_each_worker(tmp_path):
    from contracting.execution.parallel import ExecutionRequest
    from xian_runtime_types.time import Datetime

    with ContractingClient(storage_home=tmp_path, vm_profile="xian_vm_v2") as client:
        client.submit(con_v2)
        client.raw_driver.commit()
        workers = client.build_parallel_executor(workers=2, min_batch_size=2)
        try:
            requests = [
                ExecutionRequest(sender=sender, contract_name="con_v2", function_name="multiply",
                                 kwargs={"amount": value, "denominator": 3},
                                 environment={"now": Datetime(2026, 1, 1)})
                for sender, value in [("alice", 1), ("bob", 2)]
            ]
            results, stats = workers.execute(requests=requests)
            assert [out["result"] for out in results] == [
                Decimal("0." + "3" * 30), Decimal("0." + "6" * 30)
            ]
            assert stats.speculative_wave_count
        finally:
            workers.close()


def test_native_proxy_exposes_compiler_exports_with_explicit_typecheck(tmp_path):
    source = """def helper(x: int):
    return x + 1

@export(typecheck=True)
def checked(x: int):
    return helper(x)

@export(typecheck=False)
def unchecked(x: int):
    return helper(x)
"""
    with ContractingClient(storage_home=tmp_path, vm_profile="xian_vm_v2") as client:
        client.submit(source, name="con_exported")
        contract = client.get_contract_proxy("con_exported")
        assert contract.checked(x=2) == 3
        assert contract.unchecked(x=4) == 5
        assert not hasattr(contract, "helper")
