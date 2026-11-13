"""xian_vm_core.StateRootTree as xian-abci's state root uses it.

Roots are pinned from xian-abci's Python reference
(``tests/unit/state_root_reference.py``), which also compares whole corpora.
A leaf commits to the key and the value's stored bytes.
"""

import hashlib

import pytest
from xian_vm_core import LmdbEnvironment, StateRootTree, state_root_leaf_hash

EMPTY = hashlib.sha256(b"xian-state-root-v3:empty").digest()
ALICE_BOB_ROOT = "94e06b178389fe7d582eb734169201a5bf0779ba498c0e68c248f6557175452b"
NODE_KEYS = ["__fee_policy", "__execution_policy"]
NODE_PREFIXES = ["__n:", "__runtime_features."]


def leaf(key, stored_text):
    return state_root_leaf_hash(key, stored_text.encode())


def test_the_leaf_hash_frames_the_key_and_the_stored_bytes():
    key, value = b"con.a", b'{"x":1}'
    framed = len(key).to_bytes(8, "big") + key + len(value).to_bytes(8, "big") + value
    expected = hashlib.sha256(b"xian-state-root-v3:leaf:" + framed).digest()
    assert state_root_leaf_hash("con.a", value) == expected


def test_a_tree_tracks_leaves_and_the_root():
    tree = StateRootTree()
    assert tree.root_hash == EMPTY
    assert len(tree) == 0
    tree.set_leaf("currency.balances:bob", leaf("currency.balances:bob", "2"))
    tree.set_leaf("currency.balances:alice", leaf("currency.balances:alice", "1"))
    assert tree.root_hash.hex() == ALICE_BOB_ROOT
    assert len(tree) == 2
    assert tree.leaf_hash("currency.balances:alice") == leaf("currency.balances:alice", "1")
    assert tree.leaf_hash("currency.balances:carol") is None
    assert tree.remove("currency.balances:bob") is True
    assert tree.remove("currency.balances:bob") is False
    assert (
        tree.root_hash
        == StateRootTree.from_leaves(
            [("currency.balances:alice", leaf("currency.balances:alice", "1"))]
        ).root_hash
    )


def test_from_leaves_takes_any_order_and_refuses_duplicates():
    leaves = [
        ("currency.balances:bob", leaf("currency.balances:bob", "2")),
        ("currency.balances:alice", leaf("currency.balances:alice", "1")),
    ]
    assert StateRootTree.from_leaves(leaves).root_hash.hex() == ALICE_BOB_ROOT
    with pytest.raises(ValueError, match="duplicate consensus state key: currency.balances:bob"):
        StateRootTree.from_leaves(leaves + leaves[:1])


@pytest.mark.parametrize("size", [0, 31, 33])
def test_a_leaf_hash_has_32_bytes(size):
    with pytest.raises(ValueError, match="32 bytes"):
        StateRootTree().set_leaf("con.a", b"x" * size)
    with pytest.raises(ValueError, match="32 bytes"):
        StateRootTree.from_leaves([("con.a", b"x" * size)])


def test_from_storage_hashes_the_stored_bytes_of_hashed_keys(tmp_path):
    env = LmdbEnvironment(str(tmp_path), 1 << 24)
    env.write(
        [
            (b"currency.balances:alice", b"1"),
            (b"currency.balances:bob", b"2"),
            (b"__local.cache", b"3"),
            (b"con.gone", b"null"),
        ]
    )
    tree = StateRootTree.from_storage(env, NODE_KEYS, NODE_PREFIXES)
    assert tree.root_hash.hex() == ALICE_BOB_ROOT
    assert len(tree) == 2
    env.write([(b"con.raw", b'{"__bytes__":"ff"}')])
    tree = StateRootTree.from_storage(env, NODE_KEYS, NODE_PREFIXES)
    assert tree.leaf_hash("con.raw") == leaf("con.raw", '{"__bytes__":"ff"}')
    env.close()


def test_from_storage_refuses_a_key_that_is_not_text(tmp_path):
    env = LmdbEnvironment(str(tmp_path), 1 << 24)
    env.write([(b"con.\xff", b"1")])
    with pytest.raises(ValueError, match="not UTF-8"):
        StateRootTree.from_storage(env, NODE_KEYS, NODE_PREFIXES)
    env.close()
