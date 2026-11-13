"""The Rust stored-value writer matches Python's ``encode`` byte for byte.

A VM write stored from Rust (step B) must be the bytes the node stores today
for the same value, and a value Python refuses to store must be refused.
``_stored_value_encode_debug`` writes the value a Python value becomes at the
VM boundary; ``_stored_value_reencode_debug`` writes a decoded stored value.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import decode, encode
from xian_vm_core._native import _stored_value_encode_debug, _stored_value_reencode_debug

from tests.integration.test_stored_value_reader import (
    REJECTED,
    SAMPLE_VALUES,
    SPELLINGS,
    python_reads,
    values,
)

REFUSED = "refused"


def python_writes(value) -> bytes | str:
    try:
        return encode(value, vm_profile="xian_vm_v2").encode()
    except Exception:  # noqa: BLE001 - any failure is a refusal to store
        return REFUSED


def rust_writes(value) -> bytes | str:
    try:
        return _stored_value_encode_debug(value)
    except ValueError:
        return REFUSED


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(values)
def test_every_storable_value_is_written_the_same(value):
    expected = python_writes(value)
    assert expected != REFUSED
    assert rust_writes(value) == expected


@pytest.mark.parametrize("value", SAMPLE_VALUES, ids=range(len(SAMPLE_VALUES)))
def test_sample_values_are_written_the_same(value):
    assert rust_writes(value) == python_writes(value)


def _nested(depth):
    value = []
    for _ in range(depth):
        value = [value]
    return value


@pytest.mark.parametrize(
    "value",
    [
        1.5,
        {1: "int key"},
        {"__fixed__": "1"},
        {"a": {"__set__": 1}},
        2**512,
        -(2**512),
        2**512 - 1,
        _nested(128),
        _nested(129),
        {"k": _nested(127)},
        {"k": _nested(128)},
        "\x00\x1f\x7f ퟿\U0010ffff",
        ContractingDecimal("-0.000000000000000000000000000001"),
    ],
    ids=range(13),
)
def test_limits_and_refusals_match(value):
    assert rust_writes(value) == python_writes(value)


@pytest.mark.parametrize("text", SPELLINGS)
def test_every_readable_stored_value_is_written_back_canonically(text):
    data = text.encode("utf-8", "surrogatepass")
    if python_reads(data) == REJECTED:
        pytest.skip("the VM cannot read it (reader parity covers this)")
    expected = encode(decode(data, vm_profile="xian_vm_v2"), vm_profile="xian_vm_v2").encode()
    assert _stored_value_reencode_debug(data) == expected
