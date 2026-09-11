from contracting.storage.driver import Driver
from contracting.storage.ordered import iter_overlay_items


def test_merge_is_lazy_sorted_and_honors_tombstones():
    consumed = []

    def base():
        for key, value in [("a", 1), ("c", 3), ("z", 26)]:
            consumed.append(key)
            yield key, value

    merged = iter_overlay_items({"b": 2, "c": None, "a": 10}, base())
    assert next(merged) == ("a", 10)
    assert len(consumed) < 3
    assert list(merged) == [("b", 2), ("z", 26)]


def test_driver_merges_disk_cache_and_pending_in_key_order(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        for key in ["z", "é", "a", "c"]:
            driver.set("con.h:" + key, [key])
        driver.commit()
        driver.get("con.h:z")
        driver.get("con.h:a")
        driver.set("con.h:c", None)
        driver.set("con.h:b", ["new"])
        items = list(driver.iter_items("con.h:"))
        assert [key for key, _ in items] == ["con.h:a", "con.h:b", "con.h:z", "con.h:é"]
        items[0][1].append("mutation")
        assert driver.get("con.h:a") == ["a"]
