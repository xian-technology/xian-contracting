"""Immutable observations from the retired Python engine, never VM-generated.

The fixture pins fixed language inputs and preserves the previous normalized
result, writes, events and failure observation. Generated stateful tests use an
independent model instead; this module cannot execute a Python contract.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from functools import lru_cache
from pathlib import Path

from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime, Timedelta

_SCALARS = (type(None), bool, int, str)
_TEXT_VALUES = {
    ContractingDecimal: "contracting-decimal",
    Decimal: "decimal",
    Datetime: "datetime",
    Timedelta: "timedelta",
}
_SEQUENCE_VALUES = {
    list: "list",
    tuple: "tuple",
    set: "set",
    frozenset: "frozenset",
    ContractingSet: "contracting-set",
    ContractingFrozenSet: "contracting-frozenset",
}


def encode_oracle_value(value):
    """Keep input types/order and exact floats when addressing frozen cases."""
    kind = type(value)
    if kind in _SCALARS:
        return [kind.__name__, value]
    if kind in _TEXT_VALUES:
        return [_TEXT_VALUES[kind], str(value)]
    if kind is dict:
        return [
            "dict",
            [[encode_oracle_value(k), encode_oracle_value(v)] for k, v in value.items()],
        ]
    if kind in _SEQUENCE_VALUES:
        items = [encode_oracle_value(item) for item in value]
        if kind in (set, frozenset):
            items.sort(key=lambda item: json.dumps(item, sort_keys=True))
        return [_SEQUENCE_VALUES[kind], items]
    if kind in (bytes, bytearray):
        return [kind.__name__, value.hex()]
    if kind is float:
        return ["float", value.hex()]
    raise TypeError(f"Unsupported oracle value type: {kind.__name__}")


def _decode_items(value):
    return [decode_oracle_value(item) for item in value]


_DECODERS = {
    "NoneType": lambda value: None,
    "bool": bool,
    "int": int,
    "str": str,
    "float": float.fromhex,
    "bytes": bytes.fromhex,
    "bytearray": bytearray.fromhex,
    "list": _decode_items,
    "tuple": lambda value: tuple(_decode_items(value)),
    "set": lambda value: set(_decode_items(value)),
    "frozenset": lambda value: frozenset(_decode_items(value)),
    "dict": lambda value: {decode_oracle_value(k): decode_oracle_value(v) for k, v in value},
}


def decode_oracle_value(value):
    kind, data = value
    return _DECODERS[kind](data)


def oracle_case_key(case):
    encoded = json.dumps(encode_oracle_value(case), ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


@lru_cache(maxsize=1)
def _observations():
    path = Path(__file__).parents[1] / "fixtures/pre_retirement_python/observations.json"
    return json.loads(path.read_text())["cases"]


def recorded_python_observation(case):
    observations = _observations()
    key = oracle_case_key(case)
    if key not in observations:
        raise AssertionError(
            f"No pre-retirement observation for {case['id']} ({key}). "
            "Add independent native expectations or an explicitly reviewed historical capture."
        )
    return decode_oracle_value(observations[key]["observation"])
