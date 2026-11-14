"""A store or lease left to the garbage collector never deadlocks the pool.

The cycle collector runs finalizers at any allocation, also while this thread
holds the pool lock inside a pool operation (``acquire`` opens an environment
there). A finalizer that took the lock itself would wait on its own thread for
ever: CI hung for hours this way. Finalizers hand their release to the pool,
which completes it under the lock.
"""

from __future__ import annotations

import gc
import threading

import pytest

import contracting.storage.lmdb_environment as environments
from contracting.storage.lmdb_environment import LMDBEnvironmentOptions, LMDBEnvironmentPool
from contracting.storage.lmdb_store import LMDBStore

OPTIONS = LMDBEnvironmentOptions(map_size=1 << 20)


class _Cycle:
    """Something only the cycle collector frees."""

    def __init__(self, held):
        self.held = held
        self.self = self


def _collect_while_opening(monkeypatch):
    """Run a full collection inside ``acquire``, where the pool lock is held."""
    opening = environments.LmdbEnvironment

    def open_and_collect(*args, **kwargs):
        gc.collect()
        return opening(*args, **kwargs)

    monkeypatch.setattr(environments, "LmdbEnvironment", open_and_collect)


def _finishes(operation) -> bool:
    done = threading.Event()

    def run():
        operation()
        done.set()

    threading.Thread(target=run, daemon=True).start()
    return done.wait(timeout=10)


def test_a_lease_finalized_during_acquire_does_not_deadlock(tmp_path, monkeypatch):
    pool = LMDBEnvironmentPool()
    _Cycle(pool.acquire(tmp_path / "leaked", OPTIONS))
    _collect_while_opening(monkeypatch)

    assert _finishes(lambda: pool.acquire(tmp_path / "next", OPTIONS))
    # The leaked environment is closed once the pool next runs.
    assert pool.ref_count(tmp_path / "leaked") == 0


def test_a_store_finalized_during_acquire_does_not_deadlock(tmp_path, monkeypatch):
    _Cycle(LMDBStore(tmp_path / "leaked"))
    _collect_while_opening(monkeypatch)

    assert _finishes(lambda: LMDBStore(tmp_path / "next").close())
    assert environments.DEFAULT_ENVIRONMENT_POOL.ref_count(tmp_path / "leaked") == 0


def test_a_finalized_lease_releases_only_its_own_reference(tmp_path):
    pool = LMDBEnvironmentPool()
    kept = pool.acquire(tmp_path / "shared", OPTIONS)
    _Cycle(pool.acquire(tmp_path / "shared", OPTIONS))
    gc.collect()

    assert pool.ref_count(tmp_path / "shared") == 1
    assert kept.env.get(b"missing") is None
    kept.close()
    assert pool.ref_count(tmp_path / "shared") == 0


def test_the_leaked_environment_can_be_opened_again(tmp_path):
    pool = LMDBEnvironmentPool()
    _Cycle(pool.acquire(tmp_path / "again", OPTIONS))
    gc.collect()

    lease = pool.acquire(tmp_path / "again", OPTIONS)
    assert pool.ref_count(tmp_path / "again") == 1
    lease.close()


@pytest.fixture(autouse=True)
def _no_garbage_left_behind():
    yield
    gc.collect()
