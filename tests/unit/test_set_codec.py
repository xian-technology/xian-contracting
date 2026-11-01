"""Lossless, bounded wrapper-set storage; legacy non-set encodings stay fixed."""

import json
from decimal import Decimal

import pytest
from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import TYPES, Encoder, convert_dict, decode, encode
from xian_runtime_types.time import Datetime, Timedelta


def signature(value):
    if isinstance(value, Decimal):
        return ("raw", value.as_tuple())
    if isinstance(value, ContractingDecimal):
        return ("fixed", value._scaled)
    if isinstance(value, (ContractingSet, ContractingFrozenSet, tuple)):
        return (type(value).__name__, tuple(signature(item) for item in value))
    if type(value) is float:
        return ("float", value.hex())
    if isinstance(value, Datetime):
        return ("datetime", str(value))
    if isinstance(value, Timedelta):
        return ("timedelta", value.seconds)
    return (type(value).__name__, value)


@pytest.mark.parametrize("wrapper", [ContractingSet, ContractingFrozenSet])
@pytest.mark.parametrize(
    "member",
    [
        None,
        True,
        2**90,
        -0.0,
        1.25,
        "雪",
        b"\x00\xff",
        ContractingDecimal("1.25"),
        Decimal("1.2300"),
        Decimal("-0.00"),
        Decimal("1234567890" * 15 + ".000100"),
        Datetime(2026, 1, 2, 3, 4, 5, 123456),
        Timedelta(seconds=-90001),
        (1, "a", (Decimal("2.00"),)),
        ContractingFrozenSet([(1, 2)]),
    ],
)
def test_set_members_roundtrip_without_losing_type_or_quantum(wrapper, member):
    value = wrapper([member])
    assert signature(decode(encode(value))) == signature(value)
    assert signature(convert_dict(json.loads(encode(value)))) == signature(value)
    assert signature(decode(json.dumps(value, cls=Encoder))) == signature(value)


@pytest.mark.parametrize("tag", ["__set__", "__frozenset__"])
def test_legacy_set_arrays_recover_only_member_tuples(tag):
    value = decode(json.dumps({tag: [[1, [2, 3]]]}))
    assert list(value) == [(1, (2, 3))]
    assert decode("[1,[2,3]]") == [1, [2, 3]]


@pytest.mark.parametrize("tag", sorted(TYPES))
def test_ordinary_reserved_tag_dictionaries_are_rejected_recursively(tag):
    for value in ({tag: 1}, {"nested": [{tag: 1, "ordinary": 2}]}):
        with pytest.raises((ValueError, TypeError), match="reserved"):
            encode(value)
        with pytest.raises((ValueError, TypeError), match="reserved"):
            json.dumps(value, cls=Encoder)


@pytest.mark.parametrize(
    "member", [float("nan"), float("inf"), float("-inf"), Decimal("NaN"), Decimal("Infinity")]
)
def test_nonfinite_set_members_never_persist(member):
    for value in [ContractingSet([member]), ContractingFrozenSet([(member,)])]:
        with pytest.raises((ValueError, TypeError), match="finite"):
            encode(value)


@pytest.mark.parametrize(
    "value,wire",
    [
        (2**70, '{"__big_int__":"1180591620717411303424"}'),
        (b"\x00\xff", '{"__bytes__":"00ff"}'),
        (ContractingDecimal("1.25"), '{"__fixed__":"1.25"}'),
        (Datetime(2026, 1, 2, 3, 4, 5, 6), '{"__time__":[2026,1,2,3,4,5,6]}'),
        (Timedelta(seconds=-90001), '{"__delta__":[-2,82799]}'),
    ],
)
def test_existing_nonset_encoding_bytes_do_not_change(value, wire):
    assert encode(value) == wire


@pytest.mark.parametrize(
    "node",
    [
        ["none", 1],
        ["bool", 1],
        ["int", "+1"],
        ["int", "01"],
        ["int", "-0"],
        ["float", "fff0000000000000"],
        ["float", "0000"],
        ["bytes", "FF"],
        ["raw_decimal", True, "1", 0],
        ["raw_decimal", 0, "01", 0],
        ["raw_decimal", 0, "1", 131073],
        ["datetime", [2026] * 100],
        ["unknown", "value"],
        ["int", {"unsafe": []}],
        ["tuple", {}],
    ],
)
def test_malformed_typed_nodes_are_rejected(node):
    from xian_runtime_types.encoding import decode_set_value

    with pytest.raises((ValueError, TypeError, OverflowError)):
        decode_set_value("__set__", {"codec": "xian-set-1", "items": [node]})


def test_set_codec_depth_limit_accounts_for_typed_json_layers():
    from xian_runtime_types.encoding import encode_set_value

    member = None
    for _ in range(63):
        member = (member,)
    value = ContractingSet([member])
    assert signature(decode(encode(value))) == signature(value)
    assert encode_set_value(value)["__set__"]["codec"] == "xian-set-1"
    with pytest.raises(ValueError, match="depth"):
        encode(ContractingSet([(member,)]))


def test_normalization_work_is_checked_before_decoding_members():
    from xian_runtime_types.encoding import decode_set_value, encode_set_value
    from xian_runtime_types.set_codec import MAX_NORMALIZATION_WORK

    maximum = 2896
    assert maximum**2 <= MAX_NORMALIZATION_WORK < (maximum + 1) ** 2
    value = ContractingSet(range(maximum))
    assert len(decode(encode(value))) == maximum
    too_large = ContractingSet(range(maximum + 1))
    with pytest.raises(ValueError, match="normalization work"):
        encode_set_value(too_large)
    with pytest.raises(ValueError, match="normalization work"):
        decode_set_value("__set__", {"codec": "xian-set-1", "items": [["bad"]] * (maximum + 1)})


def test_nested_frozen_sets_share_the_normalization_work_budget(monkeypatch):
    import xian_runtime_types.set_codec as codec

    value = ContractingSet([(ContractingFrozenSet([1, 2]), ContractingFrozenSet([3, 4]))])
    monkeypatch.setattr(codec, "MAX_NORMALIZATION_WORK", 8)
    with pytest.raises(ValueError, match="normalization work"):
        codec.encode_set_value(value)


def test_node_and_byte_limits_are_applied_during_traversal(monkeypatch):
    import xian_runtime_types.set_codec as codec

    value = ContractingSet([(1, 2, 3)])
    monkeypatch.setattr(codec, "MAX_SET_NODES", 4)
    assert codec.encode_set_value(value)
    monkeypatch.setattr(codec, "MAX_SET_NODES", 3)
    with pytest.raises(ValueError, match="node"):
        codec.encode_set_value(value)
    monkeypatch.setattr(codec, "MAX_SET_NODES", 131072)
    monkeypatch.setattr(codec, "MAX_SET_BYTES", 80)
    with pytest.raises(ValueError, match="byte"):
        codec.encode_set_value(ContractingSet(["雪" * 20]))


def test_noncanonical_sets_are_not_silently_rewritten():
    from xian_runtime_types.encoding import decode_set_value

    for items in [
        [["int", "2"], ["int", "1"]],
        [["int", "1"], ["int", "1"]],
        [["bool", True], ["int", "1"]],
    ]:
        with pytest.raises(ValueError, match="noncanonical"):
            decode_set_value("__set__", {"codec": "xian-set-1", "items": items})


def test_wide_integer_roundtrip_does_not_depend_on_python_digit_limit():
    value = ContractingSet([2**20000])
    assert list(decode(encode(value))) == list(value)


def test_legacy_nested_frozen_and_fixed_members_keep_historical_kind():
    value = decode('{"__set__":[{"__frozenset__":[[1,2]]},{"__fixed__":"1.2300"}]}')
    assert any(isinstance(item, ContractingFrozenSet) and list(item) == [(1, 2)] for item in value)
    assert any(isinstance(item, ContractingDecimal) for item in value)


def test_plain_cycles_and_raw_builtin_sets_are_not_persistable():
    from xian_runtime_types.encoding import validate_persistent_value

    cyclic = []
    cyclic.append(cyclic)
    for value in [cyclic, {"a": 1}.keys() | []]:
        with pytest.raises((ValueError, TypeError)):
            validate_persistent_value(value)


def test_python_and_rust_share_independent_structural_wire_goldens():
    from pathlib import Path

    from xian_runtime_types.encoding import encode_set_value

    members = {
        "none": None,
        "bool": True,
        "int": 2**90,
        "negative_zero": -0.0,
        "fixed": ContractingDecimal("1.25"),
        "raw": Decimal("1.2300"),
        "raw_negative_zero": Decimal("-0.00"),
        "unicode": "雪😀\n",
        "bytes": b"\0\xff",
        "datetime": Datetime(2026, 1, 2, 3, 4, 5, 123456),
        "timedelta": Timedelta(seconds=-90001),
        "tuple": (1, "a", Decimal("2.00")),
        "nested_frozen": ContractingFrozenSet([(1, 2)]),
    }
    fixtures = json.loads(
        (Path(__file__).parents[1] / "fixtures/set_member_codec.json").read_text()
    )
    for case in fixtures:
        if case["id"] == "empty_set":
            value = ContractingSet()
        elif case["id"] == "empty_frozen":
            value = ContractingFrozenSet()
        else:
            value = ContractingSet([members[case["id"]]])
        assert encode_set_value(value) == case["wire"], case["id"]
        assert signature(decode(json.dumps(case["wire"]))) == signature(value)


def test_ascii_escape_cap_counts_astral_pairs_and_control_escapes(monkeypatch):
    import xian_runtime_types.set_codec as codec

    value = ContractingSet(["雪😀\n\x01"])
    wire = codec.encode_set_value(value)
    size = len(json.dumps(wire, separators=(",", ":"), ensure_ascii=True).encode())
    assert codec._json_string_size("😀") == 14
    assert codec._json_string_size("\n\x01") == 10
    monkeypatch.setattr(codec, "MAX_SET_BYTES", size)
    assert codec.encode_set_value(value) == wire
    monkeypatch.setattr(codec, "MAX_SET_BYTES", size - 1)
    with pytest.raises(ValueError, match="byte"):
        codec.encode_set_value(value)


def test_integer_and_normalization_limit_equality_is_admitted(monkeypatch):
    import xian_runtime_types.set_codec as codec

    monkeypatch.setattr(codec, "MAX_INTEGER_BITS", 8)
    assert list(
        codec.decode_set_value("__set__", {"codec": "xian-set-1", "items": [["int", "255"]]})
    ) == [255]
    with pytest.raises(ValueError, match="bit"):
        codec.encode_set_value(ContractingSet([256]))
    monkeypatch.setattr(codec, "MAX_NORMALIZATION_WORK", 9)
    assert len(codec.encode_set_value(ContractingSet([1, 2, 3]))["__set__"]["items"]) == 3
    with pytest.raises(ValueError, match="normalization work"):
        codec.encode_set_value(ContractingSet([1, 2, 3, 4]))


def test_lossless_set_members_survive_lmdb_close_and_reopen(tmp_path):
    from contracting.storage.driver import Driver

    value = ContractingSet(
        [(1, Decimal("1.2300")), ContractingFrozenSet([(2, 3)]), Decimal("-0.00")]
    )
    with Driver(storage_home=tmp_path) as driver:
        driver.set("con_codec.value", value)
        driver.commit()
    with Driver(storage_home=tmp_path) as driver:
        assert signature(driver.get("con_codec.value")) == signature(value)


def test_raw_decimal_text_bound_keeps_persisted_members_native_reloadable():
    from xian_runtime_types.encoding import encode_set_value

    digits = "9" * 131072
    assert encode_set_value(ContractingSet([Decimal(digits)]))
    for value in [Decimal("-" + digits), Decimal(digits + "E-1")]:
        with pytest.raises(ValueError, match="raw decimal text"):
            encode_set_value(ContractingSet([value]))


def test_many_wrapper_roots_share_one_persistence_work_budget(monkeypatch):
    import xian_runtime_types.set_codec as codec

    value = ContractingSet([1, 2])
    monkeypatch.setattr(codec, "MAX_NORMALIZATION_WORK", 7)
    with pytest.raises(ValueError, match="aggregate normalization"):
        encode([value, value])
    legacy = '[{"__set__":[1,2]},{"__set__":[1,2]}]'
    with pytest.raises(ValueError, match="aggregate normalization"):
        decode(legacy)
    with pytest.raises(ValueError, match="aggregate normalization"):
        convert_dict(json.loads(legacy))
    wire = codec.encode_set_value(value)
    with pytest.raises(ValueError, match="aggregate normalization"):
        decode(json.dumps([wire, wire]))


def test_legacy_nested_sets_count_each_constructor_once(monkeypatch):
    import xian_runtime_types.set_codec as codec

    monkeypatch.setattr(codec, "MAX_NORMALIZATION_WORK", 5)
    wire = '{"__set__":[{"__frozenset__":[1,2]}]}'
    value = decode(wire)
    assert signature(convert_dict(json.loads(wire))) == signature(value)
    assert encode(value)


@pytest.mark.parametrize(
    "values,hex_value", [([-0.0, 0.0], "-0x0.0p+0"), ([0.0, -0.0], "0x0.0p+0")]
)
def test_equal_float_zero_members_keep_the_first_retained_bits(values, hex_value):
    original = ContractingSet(values)
    assert list(decode(encode(original)))[0].hex() == hex_value


def test_python_storage_rejects_aggregate_wrapper_work_then_accepts_followup(tmp_path):
    from contracting.storage.driver import Driver

    members = ContractingSet(range(1700))
    with Driver(storage_home=tmp_path) as driver:
        driver.set("con_codec.single", members)
        driver.commit()
        with pytest.raises(ValueError, match="aggregate normalization work"):
            driver.set("con_codec.aggregate", [members, members, members])
        assert driver.get("con_codec.aggregate") is None
        driver.set("con_codec.followup", 7)
        driver.commit()
    with Driver(storage_home=tmp_path) as driver:
        assert len(driver.get("con_codec.single")) == 1700
        assert driver.get("con_codec.aggregate") is None
        assert driver.get("con_codec.followup") == 7
