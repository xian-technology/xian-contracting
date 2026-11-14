"""V2 numeric rules at the VM boundary, in callbacks and across imports."""

import tempfile
from pathlib import Path

import pytest
from xian_runtime_types.decimal import ContractingDecimal

from contracting.artifacts import build_contract_artifacts
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native
PROFILE = "xian_vm_v2"
NAME = "con_numeric_scope"


def compile_ir(source, profile=PROFILE, name=NAME):
    return build_contract_artifacts(module_name=name, source=source, vm_profile=profile)[
        "vm_ir_json"
    ]


def call(source, *, kwargs=None, meter=True, budget=100_000_000, dependencies=()):
    """``probe`` of ``source`` run by the block executor's rules (V2)."""
    from tests.vm_calls import execute_contract

    with tempfile.TemporaryDirectory() as home, Driver(storage_home=Path(home)) as driver:
        for name, ir in dependencies:
            driver.set_contract(name, source="", vm_ir_json=ir)
        driver.set_contract(NAME, source=source, vm_ir_json=compile_ir(source))
        driver.commit()
        return execute_contract(
            driver=driver,
            contract_name=NAME,
            function_name="probe",
            kwargs=kwargs or {},
            context={"caller": "alice", "signer": "alice", "this": NAME},
            meter=meter,
            chi_budget_raw=budget,
        )


def test_integer_only_host_result_and_nested_abi_promotion():
    result = call(
        "@export\ndef probe(amounts: list[decimal]):\n"
        "    random.seed()\n    return [amounts,random.randint(0,1)]",
        kwargs={"amounts": [9007199254740993]},
    )
    assert result.status_code == 0, result.result
    amount = result.result[0][0]
    assert type(amount) is ContractingDecimal and str(amount) == "9007199254740993"
    assert type(result.result[1]) is int


def test_comparison_distinguishes_bool_and_supports_wide_ints():
    source = """@export
def probe():
    keys = {True: 'bool', 1: 'int'}
    return [keys[True], keys[1], [True] == [1], 10**100 > 1.0, isinstance(True, int)]
"""
    output = call(source)
    assert output.status_code == 0, output.result
    assert output.result == ["bool", "int", False, True, False]


def test_v2_numeric_helpers_bind_names_and_charge_exponent_work():
    output = call("""@export
def probe():
    return [quantize(mode='floor', value=-0.101, places=2), sqrt(value=9), mul_div_ceil(d=3, a=4, b=2)]
""")
    assert output.status_code == 0, output.result
    assert [str(item) for item in output.result] == ["-0.11", "3", "3"]
    source = "@export\ndef probe(e: int):\n    return pow(1,e)"
    small = call(source, kwargs={"e": 1})
    # 125 more exponent bits at 96 raw each: exactly 12 chi more.
    wide = call(source, kwargs={"e": 2**125})
    assert small.status_code == wide.status_code == 0
    assert wide.chi_used - small.chi_used == 125 * 96 // 1000


def test_imported_module_must_share_chain_profile(tmp_path):
    # A V1 module can never sit beside V2 contracts: the V2 driver refuses
    # to store its IR (the block host would not load it either).
    child = compile_ir(
        "@export\ndef amount():\n    return 1 / 3", profile="xian_vm_v1", name="con_legacy"
    )
    with Driver(storage_home=tmp_path) as driver:
        with pytest.raises(ValueError, match="must target xian_vm_v2"):
            driver.set_contract("con_legacy", source="", vm_ir_json=child)


def test_numeric_text_never_roundtrips_through_binary_float():
    output = call("""@export
def probe():
    return [str(1e-30), format(9007199254740993,'.2f'), f'{-1.015:.2f}', f'{quantize(-1.015,2,"half_even"):.2f}']
""")
    assert output.status_code == 0, output.result
    assert output.result == ["0." + "0" * 29 + "1", "9007199254740993.00", "-1.01", "-1.02"]


@pytest.mark.parametrize("expression", ["True.real", "True.bit_count()", "format(True, 'd')"])
def test_bool_is_not_an_integer_receiver(expression):
    output = call("@export\ndef probe():\n    return " + expression)
    assert output.status_code == 1


def test_external_dictionary_keys_checked_after_local_execution():
    source = """@export
def probe(use_int: bool):
    key = 3 if use_int else 'ok'
    lookup = {key: 'amount'}
    return [{'nested': lookup}]
"""
    assert call(source, kwargs={"use_int": False}).result == [{"nested": {"ok": "amount"}}]
    assert call(source, kwargs={"use_int": True}).status_code == 1


def test_v2_set_distinguishes_bool_and_int_across_native_boundary():
    source = """@export
def probe():
    pairs = frozenset([(True, 'x'), (1, 'x')])
    return set([True, 1, pairs])
"""
    output = call(source)
    assert output.status_code == 0, output.result
    members = list(output.result)
    assert len(members) == 3
    assert [type(item) for item in members[:2]] == [bool, int]
    nested = list(members[2])
    assert [type(pair[0]) for pair in nested] == [bool, int]
