"""The Rust-owned LMDB environment reads and writes py-lmdb's files unchanged.

Existing node state was written by py-lmdb (LMDB 0.9.36). The storage layer
now opens the same files through xian_vm_core's pinned LMDB 0.9.37 without a
migration, and py-lmdb must still read whatever it writes.
"""

import os
import random

import lmdb
import pytest
from xian_vm_core import LmdbEnvironment, LmdbMapFullError

MAP_SIZE = 64 * 1024 * 1024


def _entries(seed=7, count=600):
    rng = random.Random(seed)
    entries = {}
    for index in range(count):
        key = f"con_{rng.randrange(40)}.balances:{index:05d}".encode()
        size = rng.choice([0, 1, 30, 600, 5000, 70000])  # includes overflow pages
        entries[key] = os.urandom(size)
    return entries


def _write_py(path, changes, map_size=MAP_SIZE):
    with lmdb.open(str(path), map_size=map_size) as env:
        with env.begin(write=True) as txn:
            for key, value in changes.items():
                if value is None:
                    txn.delete(key)
                else:
                    txn.put(key, value)


def _read_py(path):
    with lmdb.open(str(path), map_size=MAP_SIZE) as env:
        with env.begin() as txn:
            return list(txn.cursor())


def _write_rust(path, changes, map_size=MAP_SIZE):
    env = LmdbEnvironment(str(path), map_size)
    try:
        env.write(list(changes.items()))
    finally:
        env.close()


def _read_rust(path):
    env = LmdbEnvironment(str(path), MAP_SIZE)
    try:
        return env.items(b"")
    finally:
        env.close()


def test_rust_reads_state_written_by_py_lmdb(tmp_path):
    entries = _entries()
    _write_py(tmp_path, entries)

    assert _read_rust(tmp_path) == sorted(entries.items())


def test_py_lmdb_reads_state_written_by_rust(tmp_path):
    entries = _entries(seed=11)
    _write_rust(tmp_path, entries)

    assert _read_py(tmp_path) == sorted(entries.items())


def test_alternating_writers_keep_one_consistent_database(tmp_path):
    expected = {}
    rng = random.Random(3)
    for round_number in range(6):
        changes = {}
        for _ in range(80):
            key = f"k{rng.randrange(200):03d}".encode()
            changes[key] = (
                None
                if key in expected and rng.random() < 0.3
                else os.urandom(rng.choice([1, 100, 5000]))
            )
        (_write_py if round_number % 2 else _write_rust)(tmp_path, changes)
        for key, value in changes.items():
            if value is None:
                expected.pop(key, None)
            else:
                expected[key] = value
        reader = _read_rust if round_number % 2 else _read_py
        assert reader(tmp_path) == sorted(expected.items())


def test_same_transactions_write_byte_identical_files(tmp_path):
    batches = [_entries(seed=seed, count=150) for seed in range(4)]
    batches.append({key: None for key in list(batches[0])[::3]})
    for writer, home in ((_write_py, tmp_path / "py"), (_write_rust, tmp_path / "rust")):
        home.mkdir()
        for batch in batches:
            writer(home, batch)

    assert (tmp_path / "py" / "data.mdb").read_bytes() == (
        tmp_path / "rust" / "data.mdb"
    ).read_bytes()


@pytest.mark.parametrize("requested", [MAP_SIZE // 4, MAP_SIZE, 2 * MAP_SIZE])
def test_map_size_on_reopen_matches_py_lmdb(tmp_path, requested):
    _write_py(tmp_path, _entries(count=200), map_size=MAP_SIZE)
    with lmdb.open(str(tmp_path), map_size=requested) as env:
        py_size = env.info()["map_size"]
    env = LmdbEnvironment(str(tmp_path), requested)
    try:
        assert env.map_size() == py_size
    finally:
        env.close()


def test_a_write_beyond_the_map_fails_whole_and_succeeds_after_growth(tmp_path):
    env = LmdbEnvironment(str(tmp_path), 64 * 1024)
    try:
        with pytest.raises(LmdbMapFullError):
            env.write([(b"small", b"1"), (b"big", os.urandom(256 * 1024))])
        assert env.get(b"small") is None
        env.set_map_size(MAP_SIZE)
        env.write([(b"small", b"1"), (b"big", b"2")])
        assert env.get_with_entries(b"small") == (b"1", 2)
    finally:
        env.close()


def test_read_only_unlocked_reader_sees_committed_state(tmp_path):
    _write_py(tmp_path, {b"policy": b"{}"})
    env = LmdbEnvironment(str(tmp_path), MAP_SIZE, readonly=True, lock=False)
    try:
        assert env.get_with_entries(b"policy") == (b"{}", 1)
    finally:
        env.close()


def test_store_grows_its_map_until_a_large_write_fits(tmp_path):
    from contracting.storage.lmdb_store import LMDBStore

    with LMDBStore(tmp_path, map_size=64 * 1024) as store:
        store.batch_set({"con_big.blob": "x" * (512 * 1024), "con_big.flag": True})
        assert store.get("con_big.flag") is True
        assert len(store.get("con_big.blob")) == 512 * 1024
        assert store._lease.env.map_size() >= 512 * 1024


def test_standalone_environment_closes_and_releases_the_directory(tmp_path):
    from contracting.storage.lmdb_environment import standalone_environment

    with standalone_environment(tmp_path) as env:
        assert env.write_if_empty([(b"policy", b"1")]) is True
        assert env.write_if_empty([(b"other", b"2")]) is False
    assert env.closed
    with standalone_environment(tmp_path, readonly=True, lock=False) as reader:
        assert reader.get_with_entries(b"policy") == (b"1", 1)
