"""Frozen wrappers keep equality/hash invariants through every mutation entry."""

import pickle
from copy import copy, deepcopy

import pytest
from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.encoding import decode, encode
from xian_runtime_types.time import Datetime

MUTATORS = [
    ("add", (2,)),
    ("add", (1,)),
    ("remove", (1,)),
    ("remove", (99,)),
    ("discard", (1,)),
    ("discard", (99,)),
    ("pop", ()),
    ("clear", ()),
]


@pytest.mark.parametrize("method,args", MUTATORS)
@pytest.mark.parametrize("members", [[1], []])
def test_unbound_mutators_reject_frozen_receivers_before_any_effect(method, args, members):
    value = ContractingFrozenSet(members)
    fresh = ContractingFrozenSet(members)
    mapping = {value: "original"}
    original_hash = hash(value)
    with pytest.raises(TypeError, match="mutable set"):
        getattr(ContractingSet, method)(value, *args)
    assert value == fresh
    assert hash(value) == original_hash == hash(fresh)
    assert mapping[fresh] == "original"
    assert list(value) == members


@pytest.mark.parametrize("attribute,replacement", [("_values", (2,)), ("_hash", 999)])
def test_private_attributes_cannot_change_or_be_deleted(attribute, replacement):
    value = ContractingFrozenSet([1])
    mapping = {value: "original"}
    with pytest.raises(AttributeError, match="immutable"):
        setattr(value, attribute, replacement)
    with pytest.raises(AttributeError, match="immutable"):
        delattr(value, attribute)
    assert list(value) == [1]
    assert mapping[ContractingFrozenSet([1])] == "original"


@pytest.mark.parametrize(
    "reconstruct",
    [
        copy,
        deepcopy,
        lambda value: pickle.loads(pickle.dumps(value)),
        lambda value: decode(encode(value)),
    ],
)
def test_host_reconstruction_preserves_frozen_values_hashes_and_guards(reconstruct):
    original = ContractingFrozenSet([3, (1, 2), ContractingFrozenSet([7])])
    restored = reconstruct(original)
    assert restored == original
    assert hash(restored) == hash(original)
    assert {original: "ok"}[restored] == "ok"
    assert restored.copy() is restored
    with pytest.raises(AttributeError, match="immutable"):
        restored._values = ()


def test_host_deepcopy_still_copies_member_objects_and_dictionary_keys():
    member = Datetime(2024, 1, 2)
    original = ContractingFrozenSet([member])
    cloned = deepcopy({original: [original]})
    cloned_key = next(iter(cloned))
    assert next(iter(cloned_key)) is not member
    assert cloned[ContractingFrozenSet([Datetime(2024, 1, 2)])][0] is cloned_key
    assert cloned_key.copy() is cloned_key


def test_mutable_set_methods_remain_usable():
    value = ContractingSet()
    ContractingSet.add(value, 1)
    ContractingSet.add(value, 2)
    ContractingSet.discard(value, 99)
    ContractingSet.remove(value, 2)
    assert ContractingSet.pop(value) == 1
    ContractingSet.clear(value)
    assert list(value) == []
    with pytest.raises(KeyError):
        ContractingSet.remove(value, 1)
    with pytest.raises(KeyError):
        ContractingSet.pop(value)
