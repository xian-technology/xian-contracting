"""The Driver stages V2 stored bytes written by Rust (``BlockState.write_value``).

The bytes must be the ones ``xian_runtime_types.encoding.encode`` writes for
every value it stores, and a value it refuses must be refused (nothing
staged). ``apply_writes`` stays all or nothing.
"""

from __future__ import annotations

import math
from decimal import Decimal
from enum import IntEnum

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import encode
from xian_runtime_types.time import Datetime, Timedelta
from xian_vm_core import BlockState

from contracting.storage.driver import Driver
from tests.integration.test_stored_value_encoder import REFUSED, python_writes
from tests.integration.test_stored_value_reader import SAMPLE_VALUES, values


def rust_writes(value) -> bytes | str:
    state = BlockState()
    try:
        state.write_value("con_x.v", value)
    except ValueError:
        assert state.lookup("con_x.v") == (False, None)
        return REFUSED
    held, stored = state.lookup("con_x.v")
    assert held
    return stored


def _nested(depth):
    value = []
    for _ in range(depth):
        value = [value]
    return value


EDGES = [
    1.5,
    math.nan,
    Decimal("NaN"),
    {1: "int key"},
    {True: "bool key"},
    {None: "none key"},
    {(1, 2): "tuple key"},
    {"__fixed__": "1"},
    {"__set__": []},
    {"a": {"__big_int__": "1"}},
    [ContractingSet(range(1700))] * 2,
    [ContractingSet(range(1700))] * 3,
    [ContractingSet(range(300))] * 100,
    2**512,
    2**512 - 1,
    -(2**512) + 1,
    _nested(127),
    _nested(128),
    _nested(129),
    "\x00\x1f\x7f \U0010ffff",
    (1, (2, "x")),
    [(1, 2), {"t": (3,)}],
    {1, 2},
    frozenset({"a"}),
    ContractingSet._from_v2_members([]),
    ContractingFrozenSet._from_v2_members([ContractingFrozenSet._from_v2_members([])]),
    object(),
    ContractingDecimal("-0.000000000000000000000000000001"),
    Datetime(1, 1, 1),
    Timedelta(days=999999999, seconds=86399),
    b"",
    bytearray(),
    "",
    0,
    -0,
    False,
    [],
    {},
]


# Python's encoder also wrote these, but no V2 value is one: the VM's own
# reader refuses text with a lone surrogate (a key holding it could not be
# read again), and the VM boundary takes exact ints and ContractingDecimal,
# never int subclasses or the standard library's Decimal. Rust refuses them
# where they are written.
NOT_V2_VALUES = [
    "\ud800",
    {"a": "x\udfff"},
    {"\ud800": 1},
    IntEnum("Choice", "A").A,
    Decimal("1.5"),
    [Decimal("2"), {"k": Decimal("-0.000000000000000000000000000001")}],
    Decimal("1e-29"),
    Decimal("-0"),
]


@settings(max_examples=600, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(values.filter(lambda value: value is not None))
def test_every_storable_value_is_staged_as_python_encodes_it(value):
    expected = python_writes(value)
    assert expected != REFUSED
    assert rust_writes(value) == expected


CASES = [value for value in SAMPLE_VALUES if value is not None] + EDGES


@pytest.mark.parametrize("value", CASES, ids=range(len(CASES)))
def test_samples_edges_and_refusals_match_python(value):
    assert rust_writes(value) == python_writes(value)


@settings(max_examples=100, deadline=None)
@given(st.decimals(allow_nan=False, allow_infinity=False, places=None))
def test_no_standard_library_decimal_is_stored(value):
    assert rust_writes(value) == REFUSED


@pytest.mark.parametrize("value", NOT_V2_VALUES, ids=range(len(NOT_V2_VALUES)))
def test_values_that_are_no_v2_value_are_refused(value):
    assert python_writes(value) != REFUSED
    assert rust_writes(value) == REFUSED


def test_none_stages_a_deletion():
    state = BlockState()
    state.write_value("con_x.v", 5)
    state.write_value("con_x.v", None)
    assert state.lookup("con_x.v") == (True, None)


def test_write_values_stages_all_or_nothing():
    state = BlockState()
    state.write_values([("con_x.a", 1), ("con_x.b", {"k": [1, 2]})])
    assert state.items() == [("con_x.a", b"1"), ("con_x.b", b'{"k":[1,2]}')]
    with pytest.raises(ValueError):
        state.write_values([("con_x.c", 3), ("con_x.d", 1.5), ("con_x.e", 4)])
    assert [key for key, _ in state.items()] == ["con_x.a", "con_x.b"]


def test_the_v2_driver_stages_the_bytes_python_encodes(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        written = {
            "con_x.a": ContractingDecimal("1.5"),
            "con_x.b": {"n": 2**80, "t": Datetime(2026, 1, 1)},
            "con_x.c": ContractingSet._from_v2_members([3, "x"]),
        }
        driver.apply_writes(written)
        driver.set("con_x.d", [b"\x00", Timedelta(seconds=5)])
        written["con_x.d"] = [b"\x00", Timedelta(seconds=5)]
        assert driver.pending_stored_items() == [
            (key, encode(value, vm_profile="xian_vm_v2").encode())
            for key, value in sorted(written.items())
        ]
        with pytest.raises(ValueError):
            driver.apply_writes({"con_x.e": 1, "con_x.f": 1.5})
        assert [key for key, _ in driver.pending_stored_items()] == sorted(written)
