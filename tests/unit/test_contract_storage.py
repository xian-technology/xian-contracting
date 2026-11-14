"""Storage and host metadata behavior remain independent of Python execution."""

from xian_runtime_types.time import Datetime

from contracting.storage.contract import Contract
from contracting.storage.driver import Driver


def test_driver_reads_pending_none_without_falling_back_to_disk():
    with Driver() as driver:
        key = driver.make_key("con_probe", "left_at", ["alice"])
        driver.set(key, "stale")
        driver.commit()
        driver.set(key, None)
        assert driver.get(key) is None
        assert driver.find(key) is None


def test_host_metadata_reads_and_updates_native_contracts():
    submitted = Datetime(2026, 1, 1)
    with Driver() as driver:
        driver.set_contract_from_source(
            "con_meta",
            "@export\ndef read():\n    return 1",
            owner="alice",
            developer="developer",
            deployer="deployer",
            initiator="initiator",
            timestamp=submitted,
        )
        Contract.set_owner("con_meta", "bob", driver=driver)
        Contract.set_developer("con_meta", "carol", driver=driver)
        assert Contract.get_info("con_meta", driver=driver) == {
            "name": "con_meta",
            "owner": "bob",
            "developer": "carol",
            "deployer": "deployer",
            "initiator": "initiator",
            "submitted": submitted,
        }


def test_metadata_changes_go_to_the_given_driver():
    with Driver() as driver:
        driver.set_contract_from_source(
            "con_meta", "@export\ndef read():\n    return 1", owner="alice"
        )
        Contract.set_owner("con_meta", "bob", driver=driver)
        Contract.set_developer("con_meta", "dev", driver=driver)
        info = Contract.get_info("con_meta", driver=driver)
        assert (info["owner"], info["developer"]) == ("bob", "dev")
