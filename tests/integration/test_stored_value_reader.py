"""The Rust stored-value reader matches Python decode + VM boundary conversion.

Committed V2 state is read by the VM without Python: ``_stored_value_debug``
shows the value the Rust reader yields, ``_vm_value_debug`` the value Python's
``decode`` hands the VM. Both must agree on every value and every rejection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import decode, encode
from xian_runtime_types.time import Datetime, Timedelta
from xian_vm_core._native import _stored_value_debug, _vm_value_debug

REJECTED = "rejected"


def python_reads(data: bytes) -> str:
    try:
        return _vm_value_debug(decode(data, vm_profile="xian_vm_v2"))
    except Exception:  # noqa: BLE001 - any failure is a rejection of the stored value
        return REJECTED


def rust_reads(data: bytes) -> str:
    try:
        return _stored_value_debug(data)
    except ValueError:
        return REJECTED


def assert_same_reading(data: bytes) -> str:
    expected = python_reads(data)
    assert rust_reads(data) == expected, data
    return expected


SAFE = 2**53 - 1
integers = st.one_of(
    st.integers(-SAFE, SAFE),
    st.integers(-(2**511), 2**511),
    st.sampled_from([SAFE, SAFE + 1, -SAFE - 1, 2**512 - 1, -(2**512) + 1, 0]),
)
decimals = st.decimals(
    min_value=-(10**30), max_value=10**30, places=30, allow_nan=False
).map(lambda value: ContractingDecimal(str(value)))
datetimes = st.datetimes().map(
    lambda value: Datetime(
        value.year, value.month, value.day, value.hour, value.minute, value.second, value.microsecond
    )
)
timedeltas = st.integers(-(10**12), 10**12).map(lambda seconds: Timedelta(seconds=seconds))
texts = st.text()
scalars = st.one_of(
    st.none(), st.booleans(), integers, decimals, texts, datetimes, timedeltas, st.binary(max_size=40)
)
# Set normalization compares ints with decimals, so members stay in decimal range.
member_integers = st.integers(-(10**50), 10**50)
hashable_members = st.recursive(
    st.one_of(st.none(), st.booleans(), member_integers, decimals, texts, datetimes, timedeltas, st.binary()),
    lambda inner: st.one_of(
        st.lists(inner, max_size=4).map(tuple),
        st.lists(inner, max_size=4).map(ContractingFrozenSet._from_v2_members),
    ),
    max_leaves=12,
)
sets = st.one_of(
    st.lists(hashable_members, max_size=6).map(ContractingSet._from_v2_members),
    st.lists(hashable_members, max_size=6).map(ContractingFrozenSet._from_v2_members),
)
values = st.recursive(
    st.one_of(scalars, sets, st.binary(max_size=20).map(bytearray)),
    lambda inner: st.one_of(
        st.lists(inner, max_size=5),
        st.dictionaries(st.text().filter(lambda key: not key.startswith("__")), inner, max_size=5),
    ),
    max_leaves=25,
)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(values)
def test_every_encoded_value_reads_the_same(value):
    data = encode(value, vm_profile="xian_vm_v2").encode()
    assert assert_same_reading(data) != REJECTED


def _set_doc(items, tag="__set__", codec="xian-set-1"):
    return json.dumps({tag: {"codec": codec, "items": items}})


SPELLINGS = [
    # JSON grammar
    "",
    " ",
    "﻿1",
    "1 ",
    " \t\n\r[1, 2]\r\n",
    "[1,]",
    "{,}",
    '{"a":1,}',
    '{"a" 1}',
    "[1 2]",
    "01",
    "-",
    "-0",
    "0",
    "1.0",
    "1.",
    "1e5",
    "1E-5",
    "1e",
    "NaN",
    "Infinity",
    "-Infinity",
    "true",
    "tru",
    "nul",
    "9007199254740991",
    "9007199254740992",
    "-9007199254740992",
    "00000000000000001",
    "12345678901234567",
    '"\\ud83d\\ude00"',
    '"\\ud83d"',
    '"\\ud83d\\u0041"',
    '"\\ude00\\ud83d"',
    '"\\ud83d\\uzzzz"',
    '"\\u00"',
    '"\\a"',
    '"\x01"',
    '"\x7fé\U0001f600"',
    '{"a":"\\ud800","a":1}',
    '{"\\ud800":1}',
    '{"\\ud800":1,"\\ud801":2}',
    '{"b":1,"a":2,"b":3}',
    "[" * 128 + "]" * 128,
    "[" * 129 + "]" * 129,
    "[" * 2000 + "]" * 2000,
    '{"a":' * 64 + "1" + "}" * 64,
    '{"a":' * 65 + "1" + "}" * 65,
    # tags
    '{"__fixed__":"1.5"}',
    '{"__fixed__":"1.50"}',
    '{"__fixed__":"01.5"}',
    '{"__fixed__":"-0"}',
    '{"__fixed__":"0"}',
    '{"__fixed__":"1e3"}',
    '{"__fixed__":"0.' + "0" * 29 + '1"}',
    '{"__fixed__":"0.' + "0" * 30 + '1"}',
    '{"__fixed__":"' + "9" * 61 + '"}',
    '{"__fixed__":"' + "9" * 60 + '"}',
    '{"__fixed__":1}',
    '{"__fixed__":"1","b":1}',
    '{"__fixed__":"1","__fixed__":"2"}',
    '{"__big_int__":"9007199254740992"}',
    '{"__big_int__":"9007199254740991"}',
    '{"__big_int__":"-9007199254740992"}',
    '{"__big_int__":"+9007199254740992"}',
    '{"__big_int__":"09007199254740992"}',
    '{"__big_int__":"9_007199254740992"}',
    '{"__big_int__":" 9007199254740992"}',
    '{"__big_int__":"' + str(2**512 - 1) + '"}',
    '{"__big_int__":"' + str(2**512) + '"}',
    '{"__big_int__":9007199254740992}',
    '{"__time__":[2024,2,29]}',
    '{"__time__":[2023,2,29]}',
    '{"__time__":[2024,1,1,23,59,59,999999]}',
    '{"__time__":[2024,1,1,24,0,0,0]}',
    '{"__time__":[2024,1]}',
    '{"__time__":[2024,1,1,0,0,0,0,0]}',
    '{"__time__":[2024,true,1]}',
    '{"__time__":[0,1,1]}',
    '{"__time__":[10000,1,1]}',
    '{"__time__":"2024"}',
    '{"__time__":{"a":1,"b":2,"c":3}}',
    '{"__time__":null}',
    '{"__delta__":[1,5]}',
    '{"__delta__":[-1,0]}',
    '{"__delta__":[999999999,86399]}',
    '{"__delta__":[999999999,86400]}',
    '{"__delta__":[-999999999,0]}',
    '{"__delta__":[-999999999,-1]}',
    '{"__delta__":[1]}',
    '{"__delta__":[1,2,3]}',
    '{"__delta__":[1,false]}',
    '{"__delta__":"1"}',
    '{"__delta__":5}',
    '{"__bytes__":""}',
    '{"__bytes__":"00ff"}',
    '{"__bytes__":"00FF"}',
    '{"__bytes__":" 00 ff\\n"}',
    '{"__bytes__":"0 0"}',
    '{"__bytes__":"0"}',
    '{"__bytes__":"zz"}',
    '{"__bytes__":"\\u0660\\u0661"}',
    '{"__bytes__":[]}',
    '{"__bytes__":[1,2]}',
    '{"__bytearray__":"abcd"}',
    '{"__bytearray__":5}',
    '{"plain":{"__bytes__":"ab"}}',
    # sets
    '{"__set__":[1,2]}',
    _set_doc([]),
    _set_doc([], tag="__frozenset__"),
    _set_doc([["int", "1"], ["str", "a"]]),
    _set_doc([["str", "a"], ["int", "1"]]),
    _set_doc([["int", "1"], ["int", "1"]]),
    _set_doc([["int", "1"], ["fixed", "1000000000000000000000000000000"]]),
    _set_doc([["fixed", "1500000000000000000000000000000"]]),
    _set_doc([["fixed", "15"]]),
    _set_doc([["bool", True], ["int", "0"]]),
    _set_doc([["int", "0"], ["bool", True]]),
    _set_doc([["bool", 1]]),
    _set_doc([["none"]]),
    _set_doc([["none", None]]),
    _set_doc([["int", "-0"]]),
    _set_doc([["int", "01"]]),
    _set_doc([["int", str(2**512)]]),
    _set_doc([["int", "1" * 157]]),
    _set_doc([["float", "3ff0000000000000"]]),
    _set_doc([["raw_decimal", 0, "1", 0]]),
    _set_doc([["bytes", "ab"]]),
    _set_doc([["bytes", "AB"]]),
    _set_doc([["bytes", "a"]]),
    _set_doc([["str", "\ud800"]]),
    _set_doc([["timedelta", "86400"]]),
    _set_doc([["timedelta", "86400000000000000"]]),
    _set_doc([["datetime", [2024, 1, 1, 0, 0, 0, 0]]]),
    _set_doc([["datetime", [2024, 1, 1, 0, 0, 0]]]),
    _set_doc([["datetime", [2024, 13, 1, 0, 0, 0, 0]]]),
    _set_doc([["tuple", [["int", "1"], ["none"]]]]),
    _set_doc([["tuple", []]]),
    _set_doc([["frozenset", [["int", "2"], ["int", "1"]]]]),
    _set_doc([["frozenset", [["int", "1"], ["int", "2"]]]]),
    _set_doc([["frozenset", [["int", "1"]]], ["tuple", [["int", "1"]]]]),
    _set_doc([["tuple", [["int", "1"]]], ["frozenset", [["int", "1"]]]]),
    _set_doc([["unknown", "1"]]),
    _set_doc([["int"]]),
    _set_doc([[1, "1"]]),
    _set_doc(["int"]),
    _set_doc([["int", "1"]], codec="xian-set-2"),
    _set_doc([["tuple", [["tuple", []]]]]),
    json.dumps({"__set__": {"items": [], "codec": "xian-set-1"}}),
    json.dumps({"__set__": {"codec": "xian-set-1", "items": [], "x": 1}}),
    json.dumps({"__set__": {"codec": "xian-set-1"}}),
    json.dumps({"__set__": {"codec": "xian-set-1", "items": {}}}),
    json.dumps({"__set__": {"codec": "xian-set-1", "items": []}, "x": 1}),
    json.dumps({"a": [{"__set__": {"codec": "xian-set-1", "items": [["int", "1"]]}}]}),
]


def _nested_tuple(depth):
    member = ["none"]
    for _ in range(depth):
        member = ["tuple", [member]]
    return member


SPELLINGS += [_set_doc([_nested_tuple(63)]), _set_doc([_nested_tuple(64)])]


@pytest.mark.parametrize("text", SPELLINGS)
def test_noncanonical_and_limit_spellings_read_the_same(text):
    assert_same_reading(text.encode("utf-8", "surrogatepass"))


@pytest.mark.parametrize(
    "data", [b"\xff", b'"\xed\xa0\x80"', b'"\xc0\xaf"', b"[1]\x00", b'"a\xe9"']
)
def test_invalid_utf8_is_rejected_by_both(data):
    assert assert_same_reading(data) == REJECTED


@pytest.mark.parametrize(
    "text",
    ['{"__delta__":"12"}', '{"__delta__":{"1":null,"2":null}}', '{"__delta__":"١٢"}'],
)
def test_delta_tuple_unpacking_spellings_are_rejected_only_in_rust(text):
    # Python feeds a 2-character string or a 2-key object to int() through
    # tuple unpacking. The encoder never writes these; the reader rejects them.
    assert python_reads(text.encode()) != REJECTED
    assert rust_reads(text.encode()) == REJECTED


_alphabet = st.sampled_from(list('{}[]",:0123456789-.eE ntrufalsx\\') + ["__fixed__", "__set__"])


@settings(max_examples=600, deadline=None)
@given(st.lists(_alphabet, max_size=30).map("".join))
def test_random_json_like_text_reads_the_same(text):
    assert_same_reading(text.encode())


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(values, st.data())
def test_mutated_encodings_read_the_same(value, data):
    encoded = encode(value, vm_profile="xian_vm_v2")
    position = data.draw(st.integers(0, len(encoded)))
    replacement = data.draw(st.sampled_from(list('{}[]",:0123456789-. aZ\\_')))
    mutated = encoded[:position] + replacement + encoded[position + 1 :]
    if '__delta__":"' in mutated or '__delta__":{' in mutated:
        return
    assert_same_reading(mutated.encode())


# A Python-derived reading corpus for the Rust reader's own tests (so they can
# run, and be mutation-tested, without Python). Regenerate with
# `python tests/integration/test_stored_value_reader.py` after changing it.
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "stored_value_readings.json"
SAMPLE_VALUES = [
    None,
    True,
    -SAFE,
    SAFE + 1,
    -(2**511),
    ContractingDecimal("-12.000000000000000000000000000001"),
    ContractingDecimal("0"),
    "snow 雪 \U0001f600 \n\t\x00 \\ \"",
    b"\x00\xff",
    bytearray(b"\x01"),
    Datetime(2024, 2, 29, 23, 59, 59, 999999),
    Timedelta(days=-3, seconds=5),
    [1, [2, [3, {}]], {"k": None}],
    {"b": 1, "a": {"nested": [True, False]}, "": "empty"},
    ContractingSet._from_v2_members(
        [1, ContractingDecimal("1.5"), "a", b"b", None, False, Datetime(2020, 1, 1)]
    ),
    ContractingFrozenSet._from_v2_members(
        [(1, (2, None)), ContractingFrozenSet._from_v2_members([3, 4]), Timedelta(seconds=7)]
    ),
    {"sets": [ContractingSet._from_v2_members([ContractingFrozenSet._from_v2_members(["x"])])]},
]


def current_readings() -> list[dict]:
    documents = [encode(value, vm_profile="xian_vm_v2") for value in SAMPLE_VALUES] + SPELLINGS
    readings = []
    for document in documents:
        data = document.encode("utf-8", "surrogatepass")
        reading = python_reads(data)
        readings.append({"hex": data.hex(), "reading": None if reading == REJECTED else reading})
    return readings


def test_rust_reader_fixture_matches_python():
    assert json.loads(FIXTURE.read_text()) == current_readings()


if __name__ == "__main__":
    FIXTURE.write_text(json.dumps(current_readings(), indent=1, ensure_ascii=True) + "\n")
