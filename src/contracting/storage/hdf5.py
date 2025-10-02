"""SQLite-backed storage adapter used by :mod:`contracting.storage.driver`.

This module replaces the legacy HDF5 implementation with a lightweight,
pure-Python dependency that offers the same high level primitives
(`get`, `set`, `delete`, and key iteration).  The public functions retain
their original signatures so that the rest of the codebase continues to
interact with the storage layer transparently.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from pathlib import Path
from threading import Lock
from typing import Iterable, Optional

from contextlib import contextmanager

from contracting.storage.encoder import decode, encode
from contracting import constants

# Constants
ATTR_LEN_MAX = 64000
ATTR_VALUE = "value"
ATTR_BLOCK = "block"

# A dictionary to maintain file-specific locks (mirrors the old behaviour)
file_locks = defaultdict(Lock)

# SQL fragments used throughout the module
SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    group_name TEXT PRIMARY KEY,
    value BLOB,
    block INTEGER
)
"""


def get_file_lock(file_path: str) -> Lock:
    """Retrieve a lock for a specific file path."""

    normalized = _normalize_path(file_path)
    return file_locks[normalized]


def get_value(file_path: str, group_name: str):
    return get_attr(file_path, group_name, ATTR_VALUE)


def get_block(file_path: str, group_name: str):
    return get_attr(file_path, group_name, ATTR_BLOCK)


def get_attr(file_path: str, group_name: str, attr_name: str):
    """Fetch a single attribute (value or block) for ``group_name``."""

    path = _normalize_path(file_path)
    if not Path(path).exists():
        return None

    with _connect(path) as conn:
        cursor = conn.execute(
            "SELECT value, block FROM kv WHERE group_name = ?", (group_name,)
        )
        row = cursor.fetchone()

    if row is None:
        return None

    if attr_name == ATTR_VALUE:
        return row[0]
    if attr_name == ATTR_BLOCK:
        return row[1]

    return None


def get_groups(file_path: str) -> Iterable[str]:
    """Return the stored group names for the SQLite file."""

    path = _normalize_path(file_path)
    if not Path(path).exists():
        return []

    with _connect(path) as conn:
        cursor = conn.execute("SELECT group_name FROM kv")
        return [row[0] for row in cursor.fetchall()]


def set(
    file_path: str,
    group_name: str,
    value,
    blocknum: Optional[int],
    timeout: int = 20,
):
    """Persist ``value`` and ``blocknum`` for ``group_name``."""

    path = _normalize_path(file_path)
    lock = get_file_lock(path)

    if not lock.acquire(timeout=timeout):
        raise TimeoutError("Lock acquisition timed out")

    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with _connect(path, timeout=timeout) as conn:
            conn.execute(
                """
                INSERT INTO kv (group_name, value, block)
                VALUES (?, ?, ?)
                ON CONFLICT(group_name) DO UPDATE SET
                    value = excluded.value,
                    block = excluded.block
                """,
                (group_name, value, blocknum if blocknum is not None else -1),
            )
            conn.commit()
    finally:
        lock.release()


def delete(file_path: str, group_name: str, timeout: int = 20):
    path = _normalize_path(file_path)
    lock = get_file_lock(path)

    if not lock.acquire(timeout=timeout):
        raise TimeoutError("Lock acquisition timed out")

    try:
        if not Path(path).exists():
            return

        with _connect(path, timeout=timeout) as conn:
            conn.execute("DELETE FROM kv WHERE group_name = ?", (group_name,))
            conn.commit()
    finally:
        lock.release()


def set_value_to_disk(
    file_path: str,
    group_name: str,
    value,
    block_num: Optional[int] = None,
    timeout: int = 20,
):
    """Save ``value`` to disk with an optional ``block_num``."""

    encoded_value = encode(value) if value is not None else None
    set(file_path, group_name, encoded_value, block_num, timeout)


def delete_key_from_disk(file_path: str, group_name: str, timeout: int = 20):
    delete(file_path, group_name, timeout)


def get_value_from_disk(file_path: str, group_name: str):
    return decode(get_value(file_path, group_name))


def get_all_keys_from_file(file_path: str):
    """Return all keys from ``file_path`` replacing '/' with ``constants.DELIMITER``."""

    path = _normalize_path(file_path)
    if not Path(path).exists():
        return []

    with _connect(path) as conn:
        cursor = conn.execute("SELECT group_name FROM kv")
        raw_keys = [row[0] for row in cursor.fetchall()]

    return [
        key.replace(constants.HDF5_GROUP_SEPARATOR, constants.DELIMITER)
        for key in raw_keys
    ]


@contextmanager
def _connect(path: str, timeout: int = 5):
    """Create a SQLite connection initialised with the storage schema."""

    conn = sqlite3.connect(path, timeout=timeout)
    try:
        conn.execute(SCHEMA)
        yield conn
    finally:
        conn.close()


def _normalize_path(file_path) -> str:
    """Normalise ``file_path`` values that may be ``Path`` objects."""

    if hasattr(file_path, "filename"):
        return str(file_path.filename)
    return str(file_path)

