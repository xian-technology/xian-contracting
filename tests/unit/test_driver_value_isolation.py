from contracting.storage.driver import Driver


def _mutate(value):
    if isinstance(value, list):
        value.append("leaked")
    else:
        value["leaked"] = True


def test_pending_values_returned_by_get_are_isolated(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        driver.set("con_a.items", ["kept"])
        driver.set("con_a.meta", {"kept": True})

        _mutate(driver.get("con_a.items"))
        _mutate(driver.find("con_a.meta"))
        driver.commit()

        assert driver.get("con_a.items") == ["kept"]
        assert driver.get("con_a.meta") == {"kept": True}


def test_applied_values_returned_by_get_are_isolated(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        driver.set("con_a.items", ["kept"])
        driver.commit()

        _mutate(driver.get("con_a.items"))

        assert driver.get("con_a.items") == ["kept"]
        assert driver.value_from_disk("con_a.items") == ["kept"]
