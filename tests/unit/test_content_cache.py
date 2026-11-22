import sys
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from contracting.storage.content_cache import ContentKeyedCache


def test_a_value_is_returned_only_for_identical_content():
    cache = ContentKeyedCache()
    value = object()
    cache.put("con_a", "ir-1", value)

    assert cache.get("con_a", "ir-1") is value
    assert cache.get("con_a", "".join(["ir-", "1"])) is value
    assert cache.get("con_a", "ir-2") is None
    assert cache.get("con_b", "ir-1") is None


def test_new_content_replaces_the_value_for_its_key():
    cache = ContentKeyedCache()
    cache.put("con_a", "ir-1", "one")
    cache.put("con_a", "ir-22", "two")

    assert cache.get("con_a", "ir-1") is None
    assert cache.get("con_a", "ir-22") == "two"
    assert cache._size == len("ir-22")


def test_bytes_content_is_compared_like_text():
    cache = ContentKeyedCache()
    cache.put(b"k", b"raw-1", "decoded")

    assert cache.get(b"k", bytes(bytearray(b"raw-1"))) == "decoded"
    assert cache.get(b"k", b"raw-2") is None


def test_the_least_recently_used_entry_goes_first_at_the_entry_limit():
    cache = ContentKeyedCache(max_entries=2)
    cache.put("a", "1", "A")
    cache.put("b", "1", "B")
    assert cache.get("a", "1") == "A"

    cache.put("c", "1", "C")

    assert cache.get("a", "1") == "A"
    assert cache.get("b", "1") is None
    assert cache.get("c", "1") == "C"


def test_the_size_limit_bounds_the_kept_content():
    cache = ContentKeyedCache(max_size=10)
    cache.put("a", "aaaa", "A")
    cache.put("b", "bbbb", "B")
    cache.put("c", "cccc", "C")

    assert cache.get("a", "aaaa") is None
    assert (cache.get("b", "bbbb"), cache.get("c", "cccc")) == ("B", "C")
    assert cache._size == 8

    cache.put("d", "d" * 10, "D")
    assert cache.get("d", "d" * 10) == "D"
    assert cache._size == 10

    cache.put("e", "e" * 11, "E")
    assert cache.get("e", "e" * 11) is None
    assert cache.get("d", "d" * 10) == "D"


def test_several_entries_can_exactly_fill_the_size_limit():
    cache = ContentKeyedCache(max_size=6)
    cache.put("a", "aa", "A")
    cache.put("b", "bbbb", "B")

    assert cache.get("a", "aa") == "A"
    assert cache.get("b", "bbbb") == "B"


def test_one_entry_limit_keeps_the_latest_entry():
    cache = ContentKeyedCache(max_entries=1)
    cache.put("a", "content", "A")
    cache.put("b", "content", "B")

    assert cache.get("a", "content") is None
    assert cache.get("b", "content") == "B"


def test_clear_forgets_everything():
    cache = ContentKeyedCache()
    cache.put("a", "1", "A")

    cache.clear()

    assert cache.get("a", "1") is None
    assert cache._size == 0


def test_zero_entry_limit_disables_caching():
    cache = ContentKeyedCache(max_entries=0)
    cache.put("a", "content", "decoded")

    assert cache.get("a", "content") is None


def test_threads_can_refresh_the_same_cached_content():
    cache = ContentKeyedCache()
    ready = Barrier(4, timeout=10)

    def refresh():
        ready.wait()
        for _ in range(20_000):
            cache.put("a", "content", "decoded")
            assert cache.get("a", "content") == "decoded"

    original_interval = sys.getswitchinterval()
    try:
        sys.setswitchinterval(1e-6)
        with ThreadPoolExecutor(max_workers=4) as workers:
            for result in [workers.submit(refresh) for _ in range(4)]:
                result.result()
    finally:
        sys.setswitchinterval(original_interval)
