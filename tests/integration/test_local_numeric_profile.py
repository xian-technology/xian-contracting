"""Local authoring and simulation use the selected profile end to end."""

from decimal import Decimal

import pytest
from xian_runtime_types.decimal import ContractingDecimal

from contracting.local import ContractingClient


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


def test_default_rejects_historical_storage_before_bootstrap(tmp_path):
    from contracting.storage.driver import Driver

    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as historical:
        historical.set_contract_from_source("submission", "@export\ndef old():\n    return 1")
        ir = historical.get_contract_ir("submission")
        historical.set("con_old.amount", Decimal("1.25"))
        historical.commit()
    with pytest.raises(ValueError, match="uses 'xian_vm_v1'.*requested 'xian_vm_v2'"):
        ContractingClient(storage_home=tmp_path)
    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as driver:
        assert driver.get_contract_ir("submission") == ir
        assert driver.get("con_old.amount") == Decimal("1.25")


def test_default_driver_rejects_legacy_deployment_before_staging_writes(tmp_path):
    from contracting.artifacts import compile_contract_source

    with ContractingClient(storage_home=tmp_path) as client:
        source = "@export\ndef ping():\n    return 1"
        legacy = compile_contract_source(
            module_name="con_old", source=source, vm_profile="xian_vm_v1"
        )
        with pytest.raises(ValueError, match="IR must target xian_vm_v2"):
            client.raw_driver.set_contract(
                "con_old", source=source, vm_ir_json=legacy["vm_ir_json"]
            )
        assert not client.raw_driver.pending_items()
        assert not client.raw_driver.has_contract("con_old")


def test_default_driver_rejects_unbootstrapped_legacy_artifacts(tmp_path):
    from contracting.storage.driver import Driver

    source = "@export\ndef old():\n    return 3"
    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as historical:
        historical.set_contract_from_source("con_old", source)
        historical.commit()
    with pytest.raises(ValueError, match="uses 'xian_vm_v1'"):
        ContractingClient(storage_home=tmp_path)
    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as historical:
        assert historical.get_contract_ir("submission") is None


def test_source_only_driver_install_uses_exact_v2_ir(tmp_path):
    from contracting.storage.driver import Driver

    with Driver(storage_home=tmp_path) as driver:
        source = "@export\ndef amount():\n    return 1.000000000000000000000000000001"
        driver.set_contract("con_amount", source=source)
        driver.commit()
    with ContractingClient(storage_home=tmp_path) as client:
        assert client.get_contract_proxy("con_amount").amount() == Decimal(
            "1.000000000000000000000000000001"
        )
