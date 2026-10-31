"""Discover public surface drift without mistaking names for correctness proof."""

import json
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

from contracting.compilation.conformance import CONTRACT_LANGUAGE_MANIFEST
from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime, Timedelta

DIRECTORY = Path(__file__).parent


def value_examples():
    return {
        "str": "a",
        "bytes": b"a",
        "bytearray": bytearray(b"a"),
        "list": [1],
        "tuple": (1,),
        "dict": {"a": 1},
        "set": ContractingSet([1]),
        "frozenset": ContractingFrozenSet([1]),
        "range": range(3),
        "iterator.map": map(str, [1]),
        "iterator.filter": filter(bool, [1]),
        "iterator.zip": zip([1]),
        "iterator.reversed": reversed([1]),
        "dict_keys": {"a": 1}.keys(),
        "dict_values": {"a": 1}.values(),
        "dict_items": {"a": 1}.items(),
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
    return {
        "builtins": manifest["python_contracting"]["allowed_builtins"],
        "environment": {
            name: {key: value for key, value in entry.items() if key != "type"}
            for name, entry in manifest["python_contracting"]["public_env_surface"].items()
        },
        "host_bindings": manifest["xian_vm_v1"]["host_bindings"],
        "annotations": manifest["python_contracting"]["allowed_annotations"],
        "value_members": {name: public_members(value) for name, value in value_examples().items()},
    }


def load_cases():
    return [
        case
        for path in sorted(DIRECTORY.glob("*-cases.json"))
        for case in json.loads(path.read_text())
    ]


def coverage_report():
    catalog = json.loads((DIRECTORY / "catalog.json").read_text())
    dimensions = defaultdict(lambda: defaultdict(list))
    for case in load_cases():
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
            "authored_cases": len(load_cases()),
            "items_with_direct_cases": sum(bool(row["direct_cases"]) for row in rows),
            "implementation_status": dict(Counter(row["implementation"] for row in rows)),
        },
        "interpretation": "Direct cases verify only their explicit assertions; source references and dispatch presence are not behavioral coverage or full parity.",
        "items": rows,
    }
