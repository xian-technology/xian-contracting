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


def test_clear_forgets_everything():
    cache = ContentKeyedCache()
    cache.put("a", "1", "A")

    cache.clear()

    assert cache.get("a", "1") is None
    assert cache._size == 0
