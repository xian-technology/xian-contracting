"""Process-local LMDB environment pooling."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from threading import Lock

import lmdb


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
    env: lmdb.Environment
    ref_count: int
    path_signature: tuple[int, int]
    options: LMDBEnvironmentOptions


class LMDBEnvironmentLease:
    """Reference-counted lease for a pooled LMDB environment."""

    def __init__(
        self,
        pool: LMDBEnvironmentPool,
        key: Path,
        env: lmdb.Environment,
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

            env = lmdb.open(
                str(key),
                map_size=options.map_size,
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

    def release(self, key: Path, env: lmdb.Environment) -> None:
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
        env: lmdb.Environment,
        map_size: int,
    ) -> None:
        with self._lock:
            existing = self._entries.get(key)
            if existing is None or existing.env is not env:
                env.set_mapsize(map_size)
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
        raise ValueError(
            "LMDB environment already open with incompatible options for "
            f"{path}"
        )

    @staticmethod
    def _close_environment(env: lmdb.Environment) -> None:
        try:
            env.close()
        except lmdb.Error:
            pass

    @staticmethod
    def _resize_entry(
        entry: _EnvironmentEntry,
        requested_map_size: int,
    ) -> None:
        current_map_size = entry.env.info()["map_size"]
        if requested_map_size > current_map_size:
            entry.env.set_mapsize(requested_map_size)
        if requested_map_size > entry.options.map_size:
            entry.options = replace(
                entry.options,
                map_size=requested_map_size,
            )


DEFAULT_ENVIRONMENT_POOL = LMDBEnvironmentPool()
