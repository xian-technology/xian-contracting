from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
import pytest


def test_contracting_set_normalizes_and_deduplicates():
    value = ContractingSet([5, 1, 5, 3])

    assert list(value) == [1, 3, 5]
    assert repr(value) == "{1, 3, 5}"


def test_contracting_set_methods_are_deterministic():
    value = ContractingSet([5, 1, 3])

    value.add(7)
    value.discard(99)
    popped = value.pop()
    value.add(popped)

    assert popped == 1
    assert list(value) == [1, 3, 5, 7]
    assert list(value.union((9, 3))) == [1, 3, 5, 7, 9]
    assert list(value.intersection((3, 7, 11))) == [3, 7]
    assert list(value.difference((3,))) == [1, 5, 7]
    assert list(value.symmetric_difference((7, 11))) == [1, 3, 5, 11]


def test_contracting_frozenset_is_hashable_and_immutable():
    value = ContractingFrozenSet([5, 1, 3])

    assert hash(value) == hash(ContractingFrozenSet([3, 1, 5]))
    assert repr(value) == "frozenset({1, 3, 5})"
    assert value.copy() is value


def test_contracting_set_rejects_unhashable_members():
    try:
        ContractingSet([[1, 2]])
    except TypeError as exc:
        assert "unhashable type" in str(exc)
    else:
        raise AssertionError("expected unhashable values to be rejected")


@pytest.mark.parametrize(
    "left,right",
    [
        (True, 1),
        (1, 1.0),
        (1, ContractingDecimal("1")),
        ((True,), (1,)),
        (ContractingFrozenSet([True]), ContractingFrozenSet([1])),
    ],
)
def test_equal_frozen_sets_are_interchangeable_dictionary_keys(left, right):
    first, second = ContractingFrozenSet([left]), ContractingFrozenSet([right])
    assert first == second
    assert hash(first) == hash(second)
    values = {first: "old", second: "new"}
    assert len(values) == 1
    assert values[first] == "new"


def test_raw_decimal_special_keys_use_numeric_payload_order_and_identity():
    from decimal import Decimal

    first = Decimal("NaN2")
    second = Decimal("NaN2")
    values = ContractingSet(
        [Decimal("NaN10"), first, Decimal("Infinity"), Decimal("-Infinity"), second, first]
    )
    assert [str(value) for value in values] == ["-Infinity", "Infinity", "NaN2", "NaN2", "NaN10"]
    assert list(values)[2] is first and list(values)[3] is second
    with pytest.raises(TypeError, match="signaling NaN"):
        ContractingSet([Decimal("sNaN")])
