"""The driver keeps the block's pending writes in a Rust ``BlockState``.

Pending values are held as the bytes LMDB will store, so every read decodes a
fresh copy equal to what was written, a commit writes them unchanged, and the
VM reads them in Rust like committed state.
"""

import pickle

import pytest
from xian_runtime_types.collections import ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.encoding import encode
from xian_runtime_types.time import Datetime, Timedelta

from contracting.storage.driver import Driver

VALUES = {
    "con_a.decimal": ContractingDecimal("12.5"),
    "con_a.big": 2**80,
    "con_a.when": Datetime(2026, 1, 2, 3, 4, 5),
    "con_a.delta": Timedelta(days=2, seconds=7),
    "con_a.bytes": b"\x00\xff",
    "con_a.set": ContractingSet({3, 1, 2}),
    "con_a.nested": {"z": [1, {"y": "ü"}], "a": None},
}


@pytest.fixture
def driver(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        yield driver


def test_pending_values_read_back_equal_and_in_their_dict_order(driver):
    for key, value in VALUES.items():
        driver.set(key, value)

    for key, value in VALUES.items():
        assert driver.get(key) == value
    assert list(driver.get("con_a.nested")) == ["z", "a"]


def test_committed_values_equal_the_pending_ones(driver):
    for key, value in VALUES.items():
        driver.set(key, value)
    pending = dict(driver.pending_items())

    driver.commit()

    assert driver.pending_items() == []
    assert {key: driver.get(key) for key in VALUES} == pending == VALUES


def test_pending_items_are_in_key_order_with_deletions_as_none(driver):
    driver.set("con_b.x", 1)
    driver.set("con_a.y", 2)
    driver.delete("con_a.x")

    assert driver.pending_items() == [("con_a.x", None), ("con_a.y", 2), ("con_b.x", 1)]


def test_pending_stored_items_are_the_bytes_the_commit_writes(driver):
    # The state root hashes these bytes before Commit; LMDB must end up with
    # exactly them.
    for key, value in VALUES.items():
        driver.set(key, value)
    driver.delete("con_a.gone")
    pending = driver.pending_stored_items()
    assert [key for key, _ in pending] == sorted([*VALUES, "con_a.gone"])
    assert dict(pending)["con_a.gone"] is None
    assert {key: raw for key, raw in pending if raw is not None} == {
        key: encode(value).encode() for key, value in VALUES.items()
    }

    driver.commit()

    environment = driver.committed_storage()[0]
    for key, raw in pending:
        assert environment.get(key.encode()) == raw
    assert driver.pending_stored_items() == []


def test_a_failed_commit_keeps_the_block_for_a_retry(driver, monkeypatch):
    driver.set("con_a.x", 1)
    store = driver._store
    original = store._run_write

    def fail_once(operation):
        monkeypatch.setattr(store, "_run_write", original)
        raise OSError("disk unavailable")

    monkeypatch.setattr(store, "_run_write", fail_once)
    with pytest.raises(OSError):
        driver.commit()
    assert driver.pending_items() == [("con_a.x", 1)]
    assert driver.value_from_disk("con_a.x") is None

    driver.commit()
    assert driver.pending_items() == []
    assert driver.value_from_disk("con_a.x") == 1


def test_transaction_access_tracks_reads_writes_and_prefixes(driver):
    driver.set_transaction_read_tracking(True)
    driver.get("con_a.read")
    driver.set("con_a.written", 1)
    driver.keys_from_disk("con_b.")
    driver.get("con_a.unmarked", save=False)

    assert driver.transaction_access() == (
        frozenset({"con_a.read", "con_a.written"}),
        frozenset({"con_b."}),
    )


def test_tracking_off_records_nothing(driver):
    driver.set_transaction_read_tracking(False)
    driver.get("con_a.read")
    driver.set("con_a.written", 1)

    assert driver.transaction_access() == (frozenset(), frozenset())
    assert not driver.track_transaction_reads


def test_a_discarding_scope_undoes_writes_and_tracked_reads(driver):
    driver.set("con_a.kept", 1)
    driver.get("con_a.read_before")
    before = (driver.pending_items(), driver.transaction_access())

    with driver.discarding_changes():
        driver.set("con_a.kept", 2)
        driver.set("con_a.new", 3)
        driver.delete("con_a.kept")
        driver.get("con_a.read_inside")
        driver.keys_from_disk("con_c.")

    assert (driver.pending_items(), driver.transaction_access()) == before


def test_a_snapshot_is_plain_data_restorable_more_than_once(driver):
    driver.set("con_a.x", [1, 2])
    driver.get("con_a.read")
    snapshot = pickle.loads(pickle.dumps(driver.snapshot_state()))
    expected = (driver.pending_items(), driver.transaction_access())

    for _ in range(2):
        driver.set("con_a.x", "junk")
        driver.set("con_a.y", 1)
        driver.restore_state(snapshot)
        assert (driver.pending_items(), driver.transaction_access()) == expected


def test_detached_state_comes_back_and_interim_writes_are_dropped(driver):
    driver.set("con_a.x", 1)
    detached = driver.detach_pending_state()
    assert driver.pending_items() == []

    driver.set("con_a.interim", 2)
    driver.attach_pending_state(detached)

    assert driver.pending_items() == [("con_a.x", 1)]


def test_deleting_a_contract_forgets_its_pending_writes(driver):
    driver.set("con_a.x", 1)
    driver.set("con_ab.x", 2)

    driver.delete_contract("con_a")

    assert driver.pending_items() == [("con_ab.x", 2)]
