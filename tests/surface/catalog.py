"""Discover public surface drift without mistaking names for correctness proof."""

import json
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime, Timedelta

from contracting.compilation.conformance import CONTRACT_LANGUAGE_MANIFEST

DIRECTORY = Path(__file__).parent
# Native subjects are opaque outside the VM. Their reviewed contract-visible
# fields are enforced by interface_subjects.rs and the native boundary cases;
# introspecting a Python stand-in would not inventory the native implementation.
NATIVE_INTERFACE_SUBJECT_FIELDS = ("kind", "name", "args", "storage_type")


def value_examples():
    return {
        "str": "a",
        "bytes": b"a",
        "bytearray": bytearray(b"a"),
        "list": [1],
        "tuple": (1,),
        "dict": {"a": 1},
        "set": ContractingSet([1]),
        "builtin_set": {"a": 1}.keys() | [],
        "frozenset": ContractingFrozenSet([1]),
        "range": range(3),
        "iterator.map": map(str, [1]),
        "iterator.filter": filter(bool, [1]),
        "iterator.zip": zip([1]),
        "iterator.reversed": reversed([1]),
        "dict_keys": {"a": 1}.keys(),
        "dict_values": {"a": 1}.values(),
        "dict_items": {"a": 1}.items(),
        "mappingproxy": {"a": 1}.keys().mapping,
        "bound_method": [].append,
        "bool": True,
        "int": 2,
        "float": 1.5,
        "fixed_decimal": ContractingDecimal("1.5"),
        "Decimal": Decimal("1.5"),
        "DecimalTuple": Decimal("1.5").as_tuple(),
        "datetime": Datetime(2026, 1, 1),
        "timedelta": Timedelta(seconds=90),
        "None": None,
        "Exception": Exception("sample"),
    }


def public_members(value):
    return {
        name: "method" if callable(getattr(value, name)) else "attribute"
        for name in dir(value)
        if not name.startswith("_") and not name.endswith("_")
    }


def discover():
    manifest = CONTRACT_LANGUAGE_MANIFEST
    value_members = {name: public_members(value) for name, value in value_examples().items()}
    value_members["InterfaceSubject"] = dict.fromkeys(NATIVE_INTERFACE_SUBJECT_FIELDS, "attribute")
    return {
        "builtins": manifest["python_contracting"]["allowed_builtins"],
        "environment": {
            name: {key: value for key, value in entry.items() if key != "type"}
            for name, entry in manifest["python_contracting"]["public_env_surface"].items()
        },
        "host_bindings": manifest["xian_vm_v1"]["host_bindings"],
        "annotations": manifest["python_contracting"]["allowed_annotations"],
        "value_members": value_members,
    }


def load_cases():
    return [
        case
        for path in sorted(DIRECTORY.glob("*-cases.json"))
        for case in json.loads(path.read_text())
    ]


# Cases whose expectations are the historical V1 profile's: binary floats, raw
# Decimal methods and tuples, bool as an int, decimal powers with fractional
# exponents. Current code executes V2 only (V1 replays on its pinned release);
# V2's own numeric rules have separate compiler and execution tests.
V1_ONLY_CASES = frozenset(
    {
        "builtin_float_boundary",
        "builtin_float_invalid",
        "builtin_float_nominal",
        "builtin_frozenset_boundary",
        "builtin_isinstance_boundary",
        "builtin_issubclass_nominal",
        "builtin_round_boundary",
        "builtin_round_invalid",
        "builtin_round_nominal",
        "builtin_set_boundary",
        "builtin_set_nan_identity",
        "builtin_sum_boundary",
        "expansion_bool_as_integer_ratio_nominal",
        "expansion_bool_bit_count_nominal",
        "expansion_bool_bit_length_nominal",
        "expansion_bool_conjugate_nominal",
        "expansion_bool_denominator_nominal",
        "expansion_bool_from_bytes_nominal",
        "expansion_bool_imag_nominal",
        "expansion_bool_is_integer_nominal",
        "expansion_bool_numerator_nominal",
        "expansion_bool_real_nominal",
        "expansion_bool_to_bytes_nominal",
        "expansion_decimal_from_number_policy",
        "expansion_float_as_integer_ratio_invalid",
        "expansion_float_as_integer_ratio_nominal",
        "expansion_float_conjugate_nominal",
        "expansion_float_from_number_policy",
        "expansion_float_fromhex_invalid",
        "expansion_float_fromhex_nominal",
        "expansion_float_hex_boundary",
        "expansion_float_hex_nominal",
        "expansion_float_imag_nominal",
        "expansion_float_is_integer_nominal",
        "expansion_float_real_nominal",
        "value_bool_numeric_nominal",
        "value_decimal_adjusted_nominal",
        "value_decimal_as_integer_ratio_nominal",
        "value_decimal_as_tuple_nominal",
        "value_decimal_canonical_nominal",
        "value_decimal_compare_nominal",
        "value_decimal_compare_signal_nominal",
        "value_decimal_compare_total_mag_nominal",
        "value_decimal_compare_total_nominal",
        "value_decimal_conjugate_nominal",
        "value_decimal_copy_abs_nominal",
        "value_decimal_copy_negate_nominal",
        "value_decimal_copy_sign_nominal",
        "value_decimal_exp_nominal",
        "value_decimal_fields_nominal",
        "value_decimal_fma_nominal",
        "value_decimal_from_float_invalid",
        "value_decimal_from_float_nominal",
        "value_decimal_is_canonical_nominal",
        "value_decimal_is_finite_nominal",
        "value_decimal_is_infinite_nominal",
        "value_decimal_is_nan_nominal",
        "value_decimal_is_normal_nominal",
        "value_decimal_is_qnan_nominal",
        "value_decimal_is_signed_nominal",
        "value_decimal_is_snan_nominal",
        "value_decimal_is_subnormal_nominal",
        "value_decimal_is_zero_nominal",
        "value_decimal_ln_nominal",
        "value_decimal_log10_nominal",
        "value_decimal_logb_nominal",
        "value_decimal_logical_and_nominal",
        "value_decimal_logical_invert_nominal",
        "value_decimal_logical_or_nominal",
        "value_decimal_logical_xor_nominal",
        "value_decimal_max_mag_nominal",
        "value_decimal_max_nominal",
        "value_decimal_min_mag_nominal",
        "value_decimal_min_nominal",
        "value_decimal_next_minus_nominal",
        "value_decimal_next_plus_nominal",
        "value_decimal_next_toward_nominal",
        "value_decimal_normalize_nominal",
        "value_decimal_number_class_nominal",
        "value_decimal_quantize_boundary",
        "value_decimal_quantize_invalid",
        "value_decimal_quantize_nominal",
        "value_decimal_radix_nominal",
        "value_decimal_remainder_near_nominal",
        "value_decimal_rotate_nominal",
        "value_decimal_same_quantum_nominal",
        "value_decimal_scaleb_nominal",
        "value_decimal_shift_nominal",
        "value_decimal_sqrt_invalid",
        "value_decimal_sqrt_nominal",
        "value_decimal_to_eng_string_nominal",
        "value_decimal_to_integral_exact_nominal",
        "value_decimal_to_integral_nominal",
        "value_decimal_to_integral_value_nominal",
        "value_decimaltuple_count_nominal",
        "value_decimaltuple_fields_nominal",
        "value_decimaltuple_index_invalid",
        "value_decimaltuple_index_nominal",
        "value_fixed_decimal_quantum_nominal",
        "value_float_binary_nominal",
    }
)


def load_v2_cases():
    """The cases current code executes (V2): all but ``V1_ONLY_CASES``."""
    return [case for case in load_cases() if case["id"] not in V1_ONLY_CASES]


def coverage_report():
    catalog = json.loads((DIRECTORY / "catalog.json").read_text())
    cases = load_cases()
    dimensions = defaultdict(lambda: defaultdict(list))
    for case in cases:
        for name in case["covers"]:
            dimensions[name][case["dimension"]].append(case["id"])
    rows = []
    for item in catalog["items"]:
        rows.append({**item, "direct_cases": dict(dimensions[item["id"]])})
    return {
        "schema_version": 1,
        "discovery_matches": discover() == catalog["discovery"],
        "counts": {
            "inventory_items": len(rows),
            "authored_cases": len(cases),
            "native_only_policy_cases": sum(bool(case.get("native_only")) for case in cases),
            "shared_compatibility_cases": sum(not case.get("native_only") for case in cases),
            "items_with_direct_cases": sum(bool(row["direct_cases"]) for row in rows),
            "implementation_status": dict(Counter(row["implementation"] for row in rows)),
            "policy_disposition": dict(
                Counter(row["disposition"] for row in rows if row.get("disposition"))
            ),
            "unresolved_missing_items": sum(
                row["implementation"] == "missing" and not row.get("disposition") for row in rows
            ),
        },
        "interpretation": "Direct cases verify only their explicit assertions; source references and dispatch presence are not behavioral coverage or full parity.",
        "items": rows,
    }
