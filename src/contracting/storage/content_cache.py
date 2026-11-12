"""Values derived from large content, reused while that content is identical."""

from __future__ import annotations

from typing import Any


class ContentKeyedCache:
    """Remember a value derived from content, per key, for identical content only.

    Contract IR is read and interpreted on every call although it rarely
    changes. A lookup succeeds only when the content equals, byte for byte,
    the content the value was derived from, so a deploy, update or rollback
    is never served a stale value and nothing has to be invalidated. Comparing
    is far cheaper than deriving (identical objects compare instantly).

    The cache is bounded by entries and by total content size; the least
    recently used entry goes first. What it holds never changes a result.
    """

    def __init__(self, *, max_entries: int = 512, max_size: int = 64 << 20) -> None:
        self._entries: dict[Any, tuple[str | bytes, Any]] = {}
        self._max_entries = max_entries
        self._max_size = max_size
        self._size = 0

    def get(self, key, content: str | bytes):
        """The value kept for ``key`` if it was derived from ``content``, else None."""
        entry = self._entries.get(key)
        if entry is None or entry[0] != content:
            return None
        # Insertion order is recency: move the entry to the most recent end.
        del self._entries[key]
        self._entries[key] = entry
        return entry[1]

    def put(self, key, content: str | bytes, value) -> None:
        self._forget(key)
        if len(content) > self._max_size:
            return
        while self._entries and (
            len(self._entries) >= self._max_entries or self._size + len(content) > self._max_size
        ):
            self._forget(next(iter(self._entries)))
        self._entries[key] = (content, value)
        self._size += len(content)

    def clear(self) -> None:
        self._entries.clear()
        self._size = 0

    def _forget(self, key) -> None:
        entry = self._entries.pop(key, None)
        if entry is not None:
            self._size -= len(entry[0])
