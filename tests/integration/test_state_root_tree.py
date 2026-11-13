"""xian_vm_core.StateRootTree as xian-abci's state root uses it.

The roots are the ones the pre-Rust Python treap computed (xian-abci
``tests/unit/state_root_reference.py``); xian-abci compares whole corpora.
"""

import hashlib

import pytest
from xian_vm_core import LmdbEnvironment, StateRootTree, state_root_leaf_hash

EMPTY = hashlib.sha256(b"xian-state-root-v2:empty").digest()
ALICE_BOB_ROOT = "7e3c87527d71b6fdf2c2bc2512147371b94e43ec3ca4cdc33feabe94936ba654"
NODE_KEYS = ["__fee_policy", "__execution_policy"]
NODE_PREFIXES = ["__n:", "__runtime_features."]


def leaf(key, json_text):
    return state_root_leaf_hash(key, json_text.encode())


def test_the_leaf_hash_frames_the_key_and_the_value_json():
    key, value = b"con.a", b'{"x":1}'
    framed = len(key).to_bytes(8, "big") + key + len(value).to_bytes(8, "big") + value
    expected = hashlib.sha256(b"xian-state-root-v2:leaf:" + framed).digest()
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


def test_from_storage_hashes_committed_entries_and_hands_back_the_rest(tmp_path):
    env = LmdbEnvironment(str(tmp_path), 1 << 24)
    env.write(
        [
            (b"currency.balances:alice", b"1"),
            (b"currency.balances:bob", b"2"),
            (b"__local.cache", b"3"),
            (b"con.gone", b"null"),
            (b"con.raw", b'{"__bytes__":"ff"}'),
        ]
    )
    tree, handed_back = StateRootTree.from_storage(env, NODE_KEYS, NODE_PREFIXES)
    assert tree.root_hash.hex() == ALICE_BOB_ROOT
    assert len(tree) == 2
    assert handed_back == [(b"con.raw", b'{"__bytes__":"ff"}')]
    env.close()
