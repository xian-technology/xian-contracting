"""One pinned committed view for every read of a detached simulation."""

from concurrent.futures import ThreadPoolExecutor

import pytest
from xian_vm_core import LmdbEnvironment, LmdbMapFullError, LmdbStorageError


def test_a_snapshot_pins_point_reads_and_scans_across_commits_and_threads(tmp_path):
    env = LmdbEnvironment(str(tmp_path), 1 << 24)
    try:
        env.write([(b"h:a", b"100"), (b"h:b", b"200")])
        snapshot = env.snapshot()
        env.write([(b"h:a", b"7"), (b"h:b", None), (b"h:c", b"300")])

        with ThreadPoolExecutor(max_workers=1) as pool:
            assert pool.submit(snapshot.get, b"h:a").result() == b"100"
            assert pool.submit(snapshot.items, b"h:").result() == [
                (b"h:a", b"100"),
                (b"h:b", b"200"),
            ]
        assert env.get(b"h:a") == b"7"
        assert env.items(b"h:") == [(b"h:a", b"7"), (b"h:c", b"300")]
    finally:
        env.close()


def test_closing_the_environment_invalidates_a_snapshot_safely(tmp_path):
    env = LmdbEnvironment(str(tmp_path), 1 << 24)
    snapshot = env.snapshot()
    env.close()
    with pytest.raises(LmdbStorageError, match="closed"):
        snapshot.get(b"key")
    with pytest.raises(LmdbStorageError, match="closed"):
        snapshot.items(b"")


def test_map_growth_expires_readers_and_the_writer_keeps_working(tmp_path):
    env = LmdbEnvironment(str(tmp_path), 1 << 20)
    try:
        env.write([(b"a", b"old")])
        snapshot = env.snapshot()
        cursor = env.iter_items(b"")
        assert next(cursor) == (b"a", b"old")
        large = b"x" * (2 << 20)
        with pytest.raises(LmdbMapFullError):
            env.write([(b"large", large)])

        def grow_and_write():
            env.set_map_size(4 << 20)
            env.write([(b"large", large)])

        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(grow_and_write).result(timeout=10)
        with pytest.raises(LmdbStorageError, match="invalidated.*map resize"):
            snapshot.get(b"a")
        with pytest.raises(LmdbStorageError, match="invalidated.*map resize"):
            next(cursor)
        assert env.snapshot().get(b"large") == large
    finally:
        env.close()


def test_pinned_queries_leave_reader_capacity_for_ordinary_execution(tmp_path):
    env = LmdbEnvironment(str(tmp_path), 1 << 24)
    try:
        env.write([(b"a", b"100")])
        capacity = env.max_pinned_readers()
        assert 0 < capacity < env.max_readers()
        snapshots = []
        with pytest.raises(LmdbStorageError, match="capacity exhausted"):
            for _ in range(512):
                snapshots.append(env.snapshot())
        assert len(snapshots) == capacity
        assert env.get(b"a") == b"100"
        snapshots[-1].close()
        fresh = env.snapshot()
        with pytest.raises(LmdbStorageError, match="capacity exhausted"):
            env.iter_items(b"")
        fresh.close()
        cursor = env.iter_items(b"")
        cursor.close()
        env.write([(b"a", b"7")])
        assert env.get(b"a") == b"7"
        snapshots.clear()
        assert env.snapshot().get(b"a") == b"7"
    finally:
        env.close()


def test_explicit_close_releases_a_retained_snapshot_idempotently(tmp_path):
    env = LmdbEnvironment(str(tmp_path), 1 << 24)
    try:
        env.write([(b"a", b"100")])
        snapshot = env.snapshot()
        assert snapshot.get(b"a") == b"100"
        snapshot.close()
        snapshot.close()
        with pytest.raises(LmdbStorageError, match="closed"):
            snapshot.get(b"a")
        env.write([(b"a", b"7")])
        fresh = env.snapshot()
        snapshot.close()
        assert fresh.get(b"a") == b"7"
        env.set_map_size(2 << 24)
        fresh.close()
        fresh.close()
        env.close()
        fresh.close()
    finally:
        env.close()
