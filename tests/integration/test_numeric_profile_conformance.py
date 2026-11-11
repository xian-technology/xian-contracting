"""Reviewed V2 consensus examples through source, artifact admission and metered VM."""

from decimal import Decimal

import pytest
from xian_runtime_types.decimal import ContractingDecimal

from contracting.artifacts import build_contract_artifacts, validate_contract_artifacts
from contracting.storage.driver import Driver
from tests.compatibility.application_runner import context_for
from tests.determinism.numeric_cases import FAILURES, VECTORS

pytestmark = pytest.mark.optional_native
PROFILE = "xian_vm_v2"
MODULE = "con_numeric_vectors"


@pytest.fixture(scope="module")
def contract(tmp_path_factory):
    source = "scratch = Variable()\n\n"
    for index, (expression, _) in enumerate(VECTORS):
        source += f"@export\ndef vector_{index}():\n    return {expression}\n\n"
    for index, expression in enumerate(FAILURES):
        source += (
            f"@export\ndef invalid_{index}():\n    scratch.set(1)\n    return {expression}\n\n"
        )
    source += "@export\ndef typed(amount: decimal):\n    return amount\n"
    artifact = build_contract_artifacts(module_name=MODULE, source=source, vm_profile=PROFILE)
    validate_contract_artifacts(
        module_name=MODULE, artifacts=artifact, input_source=source, vm_profile=PROFILE
    )
    driver = Driver(storage_home=tmp_path_factory.mktemp("numeric-v2"), vm_profile=PROFILE)
    try:
        driver.set_contract(MODULE, source=artifact["source"], vm_ir_json=artifact["vm_ir_json"])
        driver.commit()
        yield driver
    finally:
        driver._store.close()


def call(driver, function, **kwargs):
    from xian_vm_core import execute_contract

    return execute_contract(
        driver=driver,
        contract_name=MODULE,
        function_name=function,
        context=context_for({"contract": MODULE, "function": function}),
        kwargs=kwargs,
        vm_profile=PROFILE,
        meter=True,
        chi_budget_raw=100_000_000,
    )


@pytest.mark.parametrize("index", range(len(VECTORS)), ids=[expr for expr, _ in VECTORS])
def test_exact_result(contract, index):
    expected = VECTORS[index][1]
    result = call(contract, f"vector_{index}")
    assert result.status_code == 0, str(result.result)
    assert result.raw_cost > 0
    if isinstance(expected, str):
        assert isinstance(result.result, ContractingDecimal)
        assert Decimal(str(result.result)) == Decimal(expected)
    else:
        assert type(result.result) is int
        assert result.result == expected


@pytest.mark.parametrize("index", range(len(FAILURES)), ids=FAILURES)
def test_failed_numeric_operation_discards_effects(contract, index):
    result = call(contract, f"invalid_{index}")
    assert result.status_code != 0
    assert result.writes == {}
    assert result.events == []
    assert contract.get(f"{MODULE}.scratch") is None


def test_decimal_parameter_promotes_whole_amount_exactly(contract):
    result = call(contract, "typed", amount=9007199254740993)
    assert result.status_code == 0, str(result.result)
    assert isinstance(result.result, ContractingDecimal)
    assert str(result.result) == "9007199254740993"
