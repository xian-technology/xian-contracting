"""Public raw Decimal methods retain Python signatures, result types and identity."""

import pytest

from tests.integration.test_vm_raw_decimal import compare

pytestmark = pytest.mark.optional_native


def test_decimal_methods_quantum_and_signatures(tmp_path):
    compare(
        tmp_path,
        "x=round(decimal('2.555'),3)\ny=round(decimal('0.01'),2)\n"
        "return [x.quantize(exp=y,rounding='ROUND_HALF_EVEN',context=None),"
        "x.to_integral_value(rounding='ROUND_UP'),x.fma(other=2,third=1),"
        "x.sqrt(),x.as_integer_ratio(),x.as_tuple()]",
        vm_profile="xian_vm_v1",
    )


def test_decimal_exact_constructors_and_identity(tmp_path):
    compare(
        tmp_path,
        "x=round(decimal('1'),0)\ny=x.from_float(float('5e-324'))\n"
        "return [str(y),y.as_integer_ratio(),y.as_tuple().exponent,"
        "x.canonical() is x,x.conjugate() is x,x.copy_abs() is x,"
        "x.from_float(10**150)]",
        vm_profile="xian_vm_v1",
    )


@pytest.mark.parametrize(
    "call",
    [
        "x.adjusted(1)",
        "x.copy_abs(context=None)",
        "x.quantize(x, exp=x)",
        'x.quantize(x, rounding="INVALID")',
        'x.quantize(decimal("1"))',
        "x.from_float(f=1)",
        "x.sqrt(context=1)",
        "x.fma(other=1)",
    ],
)
def test_decimal_method_invalid_signatures(tmp_path, call):
    from tests.integration.test_vm_language_conformance import _run_native_case, _run_python_case

    case = {
        "id": "decimal_method_invalid",
        "source": '@export\ndef probe():\n    x=round(decimal("2"),1)\n    return ' + call + "\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert _run_python_case(case, tmp_path / "python")["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native", vm_profile="xian_vm_v1")["status_code"] == 1


def test_modular_decimal_power_charges_all_operands_before_work(tmp_path):
    from contracting.storage.driver import Driver
    from xian_vm_core import execute_contract

    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as driver:
        driver.set_contract_from_source(
            "con_modular_budget",
            "v=Variable()\n@export\ndef probe(exponent:int):\n"
            "    v.set(1)\n    return pow(2,exponent,round(decimal('7'),0))\n",
            owner=None,
        )
        driver.commit()
        output = execute_contract(
            driver=driver,
            contract_name="con_modular_budget",
            function_name="probe",
            kwargs={"exponent": 10**100},
            context={"caller": "alice", "signer": "alice", "this": "con_modular_budget"},
            meter=True,
            chi_budget_raw=50_000,
            vm_profile=driver.vm_profile,
        )
        assert output.status_code == 1 and "Out of chi" in str(output.result)
        assert output.writes == {} and output.events == []


@pytest.mark.parametrize("receiver", ["[0, 1, 2]", "round(decimal('2.50'),2).as_tuple()"])
def test_sequence_index_rejects_excess_arguments(tmp_path, receiver):
    from tests.integration.test_vm_language_conformance import _run_native_case, _run_python_case

    case = {
        "id": "sequence_index_arity",
        "source": f"@export\ndef probe():\n    return {receiver}.index(0,0,3,999)\n",
        "function_name": "probe",
        "kwargs": {},
    }
    assert _run_python_case(case, tmp_path / "python")["status_code"] == 1
    assert _run_native_case(case, tmp_path / "native", vm_profile="xian_vm_v1")["status_code"] == 1


def test_quiet_nan_rounding_propagates_outside_finite_context(tmp_path):
    compare(
        tmp_path,
        "x=round(decimal('0'),0).from_float(float('nan'))\n"
        "return [str(round(x,191)),str(round(x,-101)),str(round(x,1000))]",
        vm_profile="xian_vm_v1",
    )
