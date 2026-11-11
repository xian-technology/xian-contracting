import json
from decimal import Decimal

import pytest
from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import decode, encode, encode_wire, loads_wire_json

PROFILE = "xian_vm_v2"


def test_exact_numeric_wire_and_storage_roundtrip():
    data = [True, 2**53 - 1, -(2**512 - 1), Decimal("12.300"), Decimal("-0"), Decimal("1e-30")]
    fixed_min = "0." + "0" * 29 + "1"
    expected = [
        True,
        2**53 - 1,
        {"__big_int__": str(-(2**512 - 1))},
        {"__fixed__": "12.3"},
        {"__fixed__": "0"},
        {"__fixed__": fixed_min},
    ]
    output = encode_wire(data, vm_profile=PROFILE)
    assert json.loads(output) == expected
    decoded = decode(output, vm_profile=PROFILE)
    assert isinstance(decoded[-1], ContractingDecimal)
    assert decoded == data
    assert encode(decoded, vm_profile=PROFILE) == output


@pytest.mark.parametrize(
    "invalid",
    [
        1.1,
        float("inf"),
        2**512,
        {"__big_int__": "4"},
        {"__big_int__": "+99999999999999999"},
        {"__big_int__": str(2**512)},
        {"__fixed__": "-0"},
        {"__fixed__": "1.200"},
        {"__fixed__": "1e-5"},
        {"__fixed__": "0." + "0" * 30 + "1"},
        {"__fixed__": "1", "extra": True},
        {"__fixed__": True},
        Decimal("1e61"),
        Decimal("1e-31"),
    ],
)
def test_rejects_noncanonical_or_unrepresentable_numbers(invalid):
    with pytest.raises((ValueError, TypeError, OverflowError)):
        encode_wire({"nested": [invalid]}, vm_profile=PROFILE)


def test_input_requires_tags_for_unsafe_json_integers():
    with pytest.raises(ValueError):
        decode(str(2**53), vm_profile=PROFILE)
    assert decode('{"__big_int__":"9007199254740992"}', vm_profile=PROFILE) == 2**53


def test_profile_driver_persists_canonical_numbers_and_rejects_bad_batches(tmp_path):
    from contracting.storage.driver import Driver

    with Driver(storage_home=tmp_path, vm_profile=PROFILE) as driver:
        driver.set("ledger.balance", Decimal("1e-29"))
        driver.set("ledger.large", 2**53)
        driver.commit()
        with pytest.raises(TypeError):
            driver.apply_writes({"ledger.good": 1, "ledger.bad": [0.25]})
        assert driver.find("ledger.good") is None
        with driver._store._env.begin() as txn:
            assert txn.get(b"ledger.balance") == b'{"__fixed__":"0.00000000000000000000000000001"}'
            assert txn.get(b"ledger.large") == b'{"__big_int__":"9007199254740992"}'
    with Driver(storage_home=tmp_path, vm_profile=PROFILE) as driver:
        assert driver.get("ledger.balance") == Decimal("1e-29")


def test_python_compiler_entrypoints_preserve_v2_source_and_ir_precision():
    import json

    from contracting.compilation.compiler import ContractingCompiler

    compiler = ContractingCompiler(module_name="con_exact")
    literal = "1.000000000000000000000000000001"
    source = f"@export\ndef price(amount: decimal):\n    return amount * {literal}"
    assert compiler.check_vm_compatibility(source, PROFILE).compatible
    assert not compiler.check_vm_compatibility(
        source.replace("decimal", "float"), PROFILE
    ).compatible
    assert literal in compiler.normalize_source(source, vm_profile=PROFILE)
    assert literal in compiler.parse_to_code(source, vm_profile=PROFILE)
    lowered = compiler.lower_to_ir(source, vm_profile=PROFILE)
    assert literal in json.dumps(lowered)
    assert lowered["vm_profile"] == PROFILE


@pytest.mark.parametrize("token", ["-0", "1e-400", "1.0", "1.0000000000000001", "Infinity", "NaN"])
def test_v2_wire_json_rejects_noncanonical_numeric_tokens(token):
    with pytest.raises(ValueError):
        loads_wire_json(f'{{"arg": [{token}]}}')
    with pytest.raises(ValueError):
        decode(token, vm_profile=PROFILE)
    assert loads_wire_json('{"arg":"-0"}') == {"arg": "-0"}


def test_v2_sets_preserve_boolean_identity_through_nested_storage():
    nested = ContractingFrozenSet._from_v2_members([True, 1, ContractingDecimal("1")])
    value = ContractingSet._from_v2_members([(True,), (1,), nested])
    decoded = decode(encode(value, vm_profile=PROFILE), vm_profile=PROFILE)
    assert list(decoded) == [(True,), (1,), nested]
    assert [type(x[0]) for x in list(decoded)[:2]] == [bool, int]
    frozen = list(decoded)[-1]
    assert [type(x) for x in frozen] == [bool, int]
    value = decoded.copy()
    value.remove((1,))
    assert (True,) in value and (1,) not in value
    value.add((1,))
    assert encode(value, vm_profile=PROFILE) == encode(decoded, vm_profile=PROFILE)
    assert len(ContractingSet([True, 1])) == 1
