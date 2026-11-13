"""LMDB-backed contract state store."""

from __future__ import annotations

import os
from pathlib import Path

from xian_runtime_types.encoding import decode, encode

from contracting.storage.content_cache import ContentKeyedCache
from contracting.storage.lmdb_environment import (
    DEFAULT_ENVIRONMENT_POOL,
    LMDBEnvironmentOptions,
    LMDBMapFullError,
)

# Stored texts at least this large (contract IR, source) are decoded once per
# stored content: decoding them costs far more than reading them.
REUSED_TEXT_MIN_BYTES = 4096

DEFAULT_MAP_SIZE = int(
    os.environ.get(
        "XIAN_CONTRACTING_LMDB_MAP_SIZE",
        str(4 * 1024 * 1024 * 1024),
    )
)


class LMDBStore:
    """Thin wrapper around a single LMDB environment."""

    def __init__(
        self, path: str | Path, map_size: int = DEFAULT_MAP_SIZE, *, vm_profile="xian_vm_v2"
    ):
        self.vm_profile = vm_profile
        self._path = Path(path)
        self._map_size = map_size
        self._lease = DEFAULT_ENVIRONMENT_POOL.acquire(
            self._path,
            LMDBEnvironmentOptions(map_size=map_size),
        )
        self._env = self._lease.env
        # Texts are immutable, so readers can share one decoded copy.
        self._texts = ContentKeyedCache(max_entries=256)

    def _require_open(self):
        if self._env is None or self._lease is None:
            raise RuntimeError("LMDBStore is closed")
        return self._env

    @property
    def environment(self):
        """The open LMDB environment (the VM reads committed state from it)."""
        return self._require_open()

    def close(self):
        if self._env is not None:
            self._lease.close()
            self._env = None
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

    def _run_write(self, operation):
        """Run one atomic write, growing the map until it fits."""
        while True:
            try:
                operation(self._require_open())
                return
            except LMDBMapFullError:
                self._grow_map()

    def get(self, key: str):
        encoded_key = key.encode("utf-8")
        value = self._require_open().get(encoded_key)
        if value is None:
            return None
        if len(value) < REUSED_TEXT_MIN_BYTES:
            return decode(value, vm_profile=self.vm_profile)
        return self._decode_text(encoded_key, value)

    def _decode_text(self, encoded_key: bytes, value: bytes):
        decoded = self._texts.get(encoded_key, value)
        if decoded is None:
            decoded = decode(value, vm_profile=self.vm_profile)
            if isinstance(decoded, str):
                self._texts.put(encoded_key, value, decoded)
        return decoded

    def batch_set(self, writes: dict[str, object]):
        if not writes:
            return
        changes = [
            (
                key.encode("utf-8"),
                None
                if value is None
                else encode(value, vm_profile=self.vm_profile).encode("utf-8"),
            )
            for key, value in writes.items()
        ]
        self._run_write(lambda env: env.write(changes))

    def keys(self, prefix: str = ""):
        return [key.decode("utf-8") for key in self._require_open().keys(prefix.encode("utf-8"))]

    def first_key_with_suffix(self, suffixes: tuple[str, ...]) -> str | None:
        key = self._require_open().first_key_with_suffix(
            [suffix.encode("utf-8") for suffix in suffixes]
        )
        return None if key is None else key.decode("utf-8")

    def scan_keys(
        self,
        prefix: str = "",
        *,
        limit: int = 100,
        after_key: str | None = None,
    ) -> tuple[list[str], bool]:
        prefix_bytes = prefix.encode("utf-8")
        after_key_bytes = after_key.encode("utf-8") if after_key is not None else None
        normalized_limit = max(int(limit), 0)
        if normalized_limit == 0:
            return [], False

        start_bytes = max(prefix_bytes, after_key_bytes or b"")
        keys, more = self._require_open().key_page(
            prefix_bytes, start_bytes, after_key_bytes, normalized_limit
        )
        return [key.decode("utf-8") for key in keys], more

    def iter_items(self, prefix: str = ""):
        """Yield decoded entries in UTF-8 key order from one read snapshot."""
        entries = self._require_open().iter_items(prefix.encode("utf-8"))
        try:
            for key_bytes, value_bytes in entries:
                yield key_bytes.decode("utf-8"), decode(value_bytes, vm_profile=self.vm_profile)
        finally:
            entries.close()

    def items(self, prefix: str = ""):
        return {
            key_bytes.decode("utf-8"): decode(value_bytes, vm_profile=self.vm_profile)
            for key_bytes, value_bytes in self._require_open().items(prefix.encode("utf-8"))
        }

    def delete(self, key: str):
        self._run_write(lambda env: env.write([(key.encode("utf-8"), None)]))

    def delete_prefix(self, prefix: str):
        self._run_write(lambda env: env.delete_prefix(prefix.encode("utf-8")))

    def flush(self):
        self._run_write(lambda env: env.clear())

    def exists(self, key: str) -> bool:
        return self._require_open().exists(key.encode("utf-8"))
