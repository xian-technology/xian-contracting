"""Storage and host metadata behavior remain independent of Python execution."""

import pytest
from xian_runtime_types.time import Datetime

from contracting.execution.runtime import rt
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


def test_active_contract_cannot_rewrite_another_contracts_metadata(monkeypatch):
    with Driver() as driver:
        driver.set_contract_from_source(
            "con_meta", "@export\ndef read():\n    return 1", owner="alice"
        )
        monkeypatch.setitem(rt.context._base_state, "this", "con_intruder")
        with pytest.raises(AssertionError, match="restricted to submission"):
            Contract.set_owner("con_meta", "attacker", driver=driver)
        assert Contract.get_info("con_meta", driver=driver)["owner"] == "alice"


def test_submission_metadata_uses_the_active_driver_and_tracks_transaction_writes(monkeypatch):
    with Driver() as driver:
        driver.set_contract_from_source(
            "con_meta", "@export\ndef read():\n    return 1", owner="alice"
        )
        monkeypatch.setitem(rt.env, "__Driver", driver)
        monkeypatch.setitem(rt.context._base_state, "this", "submission")
        Contract.set_owner("con_meta", "bob")
        assert Contract.get_info("con_meta")["owner"] == "bob"
        assert driver.transaction_writes["con_meta.__owner__"] == "bob"


def test_empty_host_context_is_not_an_active_contract(monkeypatch):
    with Driver() as driver:
        driver.set_contract_from_source(
            "con_meta", "@export\ndef read():\n    return 1", owner="alice"
        )
        monkeypatch.setitem(rt.context._base_state, "this", "")
        Contract.set_owner("con_meta", "bob", driver=driver)
        assert Contract.get_info("con_meta", driver=driver)["owner"] == "bob"
