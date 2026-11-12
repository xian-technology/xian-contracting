"""Large stored texts (contract IR, source) are decoded once per stored content.

Every contract call reads its IR text, hundreds of kilobytes of wire JSON.
Decoding it dominated the read. The store reuses the decoded text while the
stored bytes are byte-for-byte unchanged, whoever wrote them.
"""

import pytest

from contracting.storage.lmdb_store import LMDBStore

KEY = "con_big.__xian_ir_v1__"


def _text(tag):
    return '{"module": "' + tag + '", "body": "' + "x" * 20_000 + '"}'


@pytest.fixture
def store(tmp_path):
    with LMDBStore(tmp_path) as store:
        yield store


def test_unchanged_large_text_is_decoded_once(store):
    store.batch_set({KEY: _text("v1")})

    first = store.get(KEY)

    assert first == _text("v1")
    assert store.get(KEY) is first


def test_a_rewritten_text_is_read_fresh(store):
    store.batch_set({KEY: _text("v1")})
    store.get(KEY)

    store.batch_set({KEY: _text("v2")})

    assert store.get(KEY) == _text("v2")


def test_a_write_through_another_store_on_the_same_files_is_seen(store, tmp_path):
    store.batch_set({KEY: _text("v1")})
    store.get(KEY)

    with LMDBStore(tmp_path) as other:
        other.batch_set({KEY: _text("v3")})

    assert store.get(KEY) == _text("v3")


@pytest.mark.parametrize(
    "remove",
    [
        lambda store: store.delete(KEY),
        lambda store: store.delete_prefix("con_big."),
        lambda store: store.flush(),
        lambda store: store.batch_set({KEY: None}),
    ],
)
def test_a_removed_text_reads_as_missing(store, remove):
    store.batch_set({KEY: _text("v1")})
    store.get(KEY)

    remove(store)

    assert store.get(KEY) is None


@pytest.mark.parametrize(
    "value",
    [
        {"items": ["x" * 20_000]},
        ["x" * 20_000],
        "short text",
        12,
    ],
)
def test_other_values_are_decoded_fresh_every_read(store, value):
    store.batch_set({KEY: value})

    first = store.get(KEY)

    assert first == value
    if not isinstance(value, (str, int)):
        assert store.get(KEY) is not first
    assert store.get(KEY) == value
