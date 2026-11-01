"""Wire documents retain tags while persistent values reject tag impersonation."""

import json
from decimal import Decimal

import pytest
from xian_runtime_types import encoding
from xian_runtime_types.collections import ContractingSet
from xian_runtime_types.time import Datetime


@pytest.mark.parametrize("tag", sorted(encoding.TYPES))
def test_wire_preserves_opaque_tag_payloads_and_siblings(tag):
    value = {"nested": [{tag: ["opaque", {"__fixed__": "1.2300"}], "sibling": "雪"}]}
    assert encoding.encode_wire(value) == json.dumps(value, separators=(",", ":"))
    with pytest.raises(ValueError, match="reserved"):
        encoding.encode(value)
    with pytest.raises(ValueError, match="reserved"):
        encoding.Encoder().encode(value)


def test_wire_mixes_raw_tags_and_typed_runtime_values_without_decoding():
    value = {
        "raw": {"__time__": [2026, 1, 2, 3, 4, 5, 6]},
        "typed": Datetime(2026, 1, 2, 3, 4, 5, 6),
        "integer": 2**90,
        "raw_decimal": {"__fixed__": "1.2300"},
        "set": ContractingSet([(1, 2)]),
    }
    assert encoding.encode_wire(value) == (
        '{"raw":{"__time__":[2026,1,2,3,4,5,6]},'
        '"typed":{"__time__":[2026,1,2,3,4,5,6]},'
        '"integer":{"__big_int__":"1237940039285380274899124224"},'
        '"raw_decimal":{"__fixed__":"1.2300"},'
        '"set":{"__set__":{"codec":"xian-set-1",'
        '"items":[["tuple",[["int","1"],["int","2"]]]]}}}'
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), Decimal("NaN")])
def test_wire_rejects_actual_nonfinite_numbers_even_inside_raw_tags(value):
    with pytest.raises(ValueError, match="finite"):
        encoding.encode_wire({"__set__": [value]})


def test_wire_bounds_depth_and_rejects_cycles_and_unsupported_objects():
    value = 0
    for _ in range(128):
        value = [value]
    assert encoding.encode_wire(value) == "[" * 128 + "0" + "]" * 128
    with pytest.raises(ValueError, match="traversal"):
        encoding.encode_wire([value])
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="cyclic"):
        encoding.encode_wire(cycle)
    with pytest.raises(TypeError, match="unsupported"):
        encoding.encode_wire({"object": object()})


def test_wire_shares_normalization_work_across_actual_wrapper_roots(monkeypatch):
    import xian_runtime_types.set_codec as codec

    members = ContractingSet([1, 2])
    monkeypatch.setattr(codec, "MAX_NORMALIZATION_WORK", 7)
    with pytest.raises(ValueError, match="aggregate normalization"):
        encoding.encode_wire({"__set__": "opaque", "values": [members, members]})


def test_wire_keeps_persistence_bytes_for_ordinary_and_typed_values():
    value = {"text": "雪😀", "items": [True, None, 2**90, Decimal("1.2300"), b"\x00\xff"]}
    assert encoding.encode_wire(value) == encoding.encode(value)


@pytest.mark.parametrize("key", [1, None, True, 1.5])
def test_wire_requires_string_object_keys_without_changing_persistence(key):
    value = {"nested": {key: "value"}}
    with pytest.raises(TypeError, match="keys must be strings"):
        encoding.encode_wire(value)
    assert encoding.encode(value)
