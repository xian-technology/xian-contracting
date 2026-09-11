"""Ordered storage overlays; values are consumed lazily and tombstones win."""

from heapq import merge
from itertools import groupby


def iter_overlay_items(overlay, base, prefix=""):
    """Merge a mapping over a sorted iterator without materializing disk values."""
    keys = sorted(key for key in overlay if key.startswith(prefix))
    local = ((key, 0, overlay[key]) for key in keys)
    remote = ((key, 1, value) for key, value in base)
    for key, entries in groupby(
        merge(local, remote, key=lambda item: item[:2]), key=lambda item: item[0]
    ):
        _, _, value = next(entries)
        if value is not None:
            yield key, value
