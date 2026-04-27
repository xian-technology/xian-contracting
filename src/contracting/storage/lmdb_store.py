"""LMDB-backed contract state store."""

from __future__ import annotations

import os
from pathlib import Path

import lmdb
from xian_runtime_types.encoding import decode, encode

from contracting.storage.lmdb_environment import (
    DEFAULT_ENVIRONMENT_POOL,
    LMDBEnvironmentOptions,
)

DEFAULT_MAP_SIZE = int(
    os.environ.get(
        "XIAN_CONTRACTING_LMDB_MAP_SIZE",
        str(4 * 1024 * 1024 * 1024),
    )
)


class LMDBStore:
    """Thin wrapper around a single LMDB environment."""

    def __init__(self, path: str | Path, map_size: int = DEFAULT_MAP_SIZE):
        self._path = Path(path)
        self._map_size = map_size
        self._lease = DEFAULT_ENVIRONMENT_POOL.acquire(
            self._path,
            LMDBEnvironmentOptions(map_size=map_size),
        )
        self._env = self._lease.env
        self._db = self._env.open_db()

    def _require_open(self):
        if self._env is None or self._db is None or self._lease is None:
            raise RuntimeError("LMDBStore is closed")
        return self._env

    def close(self):
        if self._env is not None:
            self._lease.close()
            self._env = None
            self._db = None
            self._lease = None

    def __enter__(self):
        self._require_open()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _grow_map(self):
        self._map_size *= 2
        self._require_open()
        self._lease.resize(self._map_size)

    def _run_write_transaction(self, operation):
        while True:
            try:
                with self._require_open().begin(write=True) as txn:
                    operation(txn)
                return
            except lmdb.MapFullError:
                self._grow_map()

    def get(self, key: str):
        with self._require_open().begin() as txn:
            value = txn.get(key.encode("utf-8"))
        if value is None:
            return None
        return decode(value)

    def batch_set(self, writes: dict[str, object]):
        def operation(txn):
            for key, value in writes.items():
                encoded_key = key.encode("utf-8")
                if value is None:
                    txn.delete(encoded_key)
                else:
                    txn.put(encoded_key, encode(value).encode("utf-8"))

        self._run_write_transaction(operation)

    def keys(self, prefix: str = ""):
        prefix_bytes = prefix.encode("utf-8")
        keys = []
        with self._require_open().begin() as txn:
            cursor = txn.cursor()
            if prefix_bytes:
                if not cursor.set_range(prefix_bytes):
                    return keys
            elif not cursor.first():
                return keys

            for key_bytes in cursor.iternext(values=False):
                if prefix_bytes and not key_bytes.startswith(prefix_bytes):
                    break
                keys.append(key_bytes.decode("utf-8"))
        return keys

    def scan_keys(
        self,
        prefix: str = "",
        *,
        limit: int = 100,
        after_key: str | None = None,
    ) -> tuple[list[str], bool]:
        prefix_bytes = prefix.encode("utf-8")
        after_key_bytes = (
            after_key.encode("utf-8") if after_key is not None else None
        )
        normalized_limit = max(int(limit), 0)
        if normalized_limit == 0:
            return [], False

        keys: list[str] = []
        has_more = False
        start_bytes = (
            after_key_bytes if after_key_bytes is not None else prefix_bytes
        )

        with self._require_open().begin() as txn:
            cursor = txn.cursor()
            if start_bytes:
                if not cursor.set_range(start_bytes):
                    return keys, False
            elif not cursor.first():
                return keys, False

            for key_bytes in cursor.iternext(values=False):
                if prefix_bytes and not key_bytes.startswith(prefix_bytes):
                    break
                if after_key_bytes is not None and key_bytes <= after_key_bytes:
                    continue
                if len(keys) >= normalized_limit:
                    has_more = True
                    break
                keys.append(key_bytes.decode("utf-8"))

        return keys, has_more

    def items(self, prefix: str = ""):
        prefix_bytes = prefix.encode("utf-8")
        items = {}
        with self._require_open().begin() as txn:
            cursor = txn.cursor()
            if prefix_bytes:
                if not cursor.set_range(prefix_bytes):
                    return items
            elif not cursor.first():
                return items

            for key_bytes, value_bytes in cursor:
                if prefix_bytes and not key_bytes.startswith(prefix_bytes):
                    break
                items[key_bytes.decode("utf-8")] = decode(value_bytes)
        return items

    def delete(self, key: str):
        self._run_write_transaction(lambda txn: txn.delete(key.encode("utf-8")))

    def delete_prefix(self, prefix: str):
        prefix_bytes = prefix.encode("utf-8")

        def operation(txn):
            cursor = txn.cursor()
            if not cursor.set_range(prefix_bytes):
                return
            to_delete = []
            for key_bytes in cursor.iternext(values=False):
                if not key_bytes.startswith(prefix_bytes):
                    break
                to_delete.append(key_bytes)
            for key_bytes in to_delete:
                txn.delete(key_bytes)

        self._run_write_transaction(operation)

    def flush(self):
        self._run_write_transaction(
            lambda txn: txn.drop(self._db, delete=False)
        )

    def exists(self, key: str) -> bool:
        with self._require_open().begin() as txn:
            return txn.get(key.encode("utf-8")) is not None
