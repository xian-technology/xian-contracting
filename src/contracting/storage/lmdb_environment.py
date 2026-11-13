"""Process-local LMDB environment pooling.

Environments are xian_vm_core's Rust-owned LMDB (the pinned release that wrote
existing state), so the VM and this storage layer share one environment per
state directory.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from threading import Lock

from xian_vm_core import (
    MAX_STORAGE_KEY_BYTES,  # noqa: F401 - re-exported: the longest key this store holds
    LmdbEnvironment,
    LmdbMapFullError,
    LmdbStorageError,
    validate_storage_key,  # noqa: F401 - re-exported: refuses a longer key
)

# Storage failures (a host fault, never a transaction outcome) and their
# map-full subclass, which callers handle by growing the map.
LMDBError = LmdbStorageError
LMDBMapFullError = LmdbMapFullError
# Map size of a short-lived environment opened outside the pool.
STANDALONE_MAP_SIZE = 10 * 1024 * 1024


@dataclass(frozen=True)
class LMDBEnvironmentOptions:
    map_size: int
    max_dbs: int = 1
    readahead: bool = True
    writemap: bool = False
    sync: bool = True
    metasync: bool = True

    def compatibility_key(self) -> tuple[object, ...]:
        return (
            self.max_dbs,
            self.readahead,
            self.writemap,
            self.sync,
            self.metasync,
        )


@dataclass
class _EnvironmentEntry:
    env: LmdbEnvironment
    ref_count: int
    path_signature: tuple[int, int]
    options: LMDBEnvironmentOptions


class LMDBEnvironmentLease:
    """Reference-counted lease for a pooled LMDB environment."""

    def __init__(
        self,
        pool: LMDBEnvironmentPool,
        key: Path,
        env: LmdbEnvironment,
    ) -> None:
        self._pool = pool
        self._key = key
        self.env = env
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._pool.release(self._key, self.env)

    def resize(self, map_size: int) -> None:
        if self._closed:
            raise RuntimeError("LMDB environment lease is closed")
        self._pool.resize(self._key, self.env, map_size)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


class LMDBEnvironmentPool:
    """Share one LMDB environment per canonical path in this process."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._entries: dict[Path, _EnvironmentEntry] = {}

    def acquire(
        self,
        path: str | Path,
        options: LMDBEnvironmentOptions,
    ) -> LMDBEnvironmentLease:
        storage_path = Path(path)
        storage_path.mkdir(parents=True, exist_ok=True)
        key = storage_path.resolve()
        path_signature = self._path_signature(key)

        with self._lock:
            existing = self._entries.get(key)
            if existing is not None:
                if existing.path_signature == path_signature:
                    self._assert_compatible(existing.options, options, key)
                    self._resize_entry(existing, options.map_size)
                    existing.ref_count += 1
                    return LMDBEnvironmentLease(self, key, existing.env)

                self._entries.pop(key, None)
                self._close_environment(existing.env)

            env = LmdbEnvironment(
                str(key),
                options.map_size,
                max_dbs=options.max_dbs,
                readahead=options.readahead,
                writemap=options.writemap,
                sync=options.sync,
                metasync=options.metasync,
            )
            self._entries[key] = _EnvironmentEntry(
                env=env,
                ref_count=1,
                path_signature=path_signature,
                options=options,
            )
            return LMDBEnvironmentLease(self, key, env)

    def read_existing_value(self, path: str | Path, key: bytes) -> tuple[bytes | None, int] | None:
        """Read a pooled environment without opening, creating, or resizing storage."""
        storage_path = Path(path).resolve()
        with self._lock:
            entry = self._entries.get(storage_path)
            if entry is None or not storage_path.exists():
                return None
            if entry.path_signature != self._path_signature(storage_path):
                return None
            entry.ref_count += 1
            lease = LMDBEnvironmentLease(self, storage_path, entry.env)
        try:
            return lease.env.get_with_entries(key)
        finally:
            lease.close()

    def release(self, key: Path, env: LmdbEnvironment) -> None:
        with self._lock:
            existing = self._entries.get(key)
            if existing is None or existing.env is not env:
                self._close_environment(env)
                return

            existing.ref_count -= 1
            if existing.ref_count > 0:
                return

            self._entries.pop(key, None)
            self._close_environment(env)

    def resize(
        self,
        key: Path,
        env: LmdbEnvironment,
        map_size: int,
    ) -> None:
        with self._lock:
            existing = self._entries.get(key)
            if existing is None or existing.env is not env:
                env.set_map_size(map_size)
                return
            self._resize_entry(existing, map_size)

    def ref_count(self, path: str | Path) -> int:
        key = Path(path).resolve()
        with self._lock:
            existing = self._entries.get(key)
            return 0 if existing is None else existing.ref_count

    @staticmethod
    def _path_signature(path: Path) -> tuple[int, int]:
        stat = path.stat()
        return (stat.st_dev, stat.st_ino)

    @staticmethod
    def _assert_compatible(
        existing: LMDBEnvironmentOptions,
        requested: LMDBEnvironmentOptions,
        path: Path,
    ) -> None:
        if existing.compatibility_key() == requested.compatibility_key():
            return
        raise ValueError(f"LMDB environment already open with incompatible options for {path}")

    @staticmethod
    def _close_environment(env: LmdbEnvironment) -> None:
        try:
            env.close()
        except LMDBError:
            pass

    @staticmethod
    def _resize_entry(
        entry: _EnvironmentEntry,
        requested_map_size: int,
    ) -> None:
        current_map_size = entry.env.map_size()
        if requested_map_size > current_map_size:
            entry.env.set_map_size(requested_map_size)
        if requested_map_size > entry.options.map_size:
            entry.options = replace(
                entry.options,
                map_size=requested_map_size,
            )


DEFAULT_ENVIRONMENT_POOL = LMDBEnvironmentPool()


@contextmanager
def standalone_environment(
    path: str | Path, *, readonly: bool = False, lock: bool = True
) -> Iterator[LmdbEnvironment]:
    """Open an existing state directory outside the pool, closed on exit.

    For startup checks that run before (or instead of) the pooled storage.
    """
    env = LmdbEnvironment(str(path), STANDALONE_MAP_SIZE, readonly=readonly, lock=lock)
    try:
        yield env
    finally:
        env.close()
