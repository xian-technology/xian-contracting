"""Explicit execution drivers own the transaction's reads, writes and rollback."""

from contracting.local.native_executor import NativeExecutor
from contracting.storage.driver import Driver

SOURCE = """value = Variable()
@export
def write(fail: bool):
    value.set(9)
    assert not fail, 'deliberate failure'
    return value.get()
"""


def test_override_driver_rolls_back_its_own_pending_state(tmp_path):
    with (
        Driver(storage_home=tmp_path / "primary", vm_profile="xian_vm_v2") as primary,
        Driver(storage_home=tmp_path / "override", vm_profile="xian_vm_v2") as override,
    ):
        override.set_contract_from_source("con_probe", SOURCE)
        override.commit()
        primary.set("con_primary.value", 1)
        override.set("con_existing.value", 2)

        output = NativeExecutor(driver=primary, metering=False).execute(
            sender="alice",
            contract_name="con_probe",
            function_name="write",
            kwargs={"fail": True},
            driver=override,
        )

        assert output["status_code"] == 1
        assert isinstance(output["result"], AssertionError)
        assert output["writes"] == {}
        assert override.pending_items() == [("con_existing.value", 2)]
        assert primary.pending_items() == [("con_primary.value", 1)]


def test_override_driver_resets_its_own_transaction_tracking(tmp_path):
    with (
        Driver(storage_home=tmp_path / "primary", vm_profile="xian_vm_v2") as primary,
        Driver(storage_home=tmp_path / "override", vm_profile="xian_vm_v2") as override,
    ):
        override.set_contract_from_source("con_probe", SOURCE)
        override.commit()
        override.set("con_existing.value", 2, is_txn_write=True)
        override.get("con_old_read.value")
        override.set_event({"event": "old"})
        primary.set("con_primary.value", 1, is_txn_write=True)

        output = NativeExecutor(driver=primary, metering=False).execute(
            sender="alice",
            contract_name="con_probe",
            function_name="write",
            kwargs={"fail": False},
            driver=override,
        )

        assert output["status_code"] == 0, output["result"]
        assert output["result"] == 9
        assert output["writes"] == {"con_probe.value": 9}
        assert output["events"] == []
        assert "con_old_read.value" not in output["reads"]
        assert primary.transaction_writes == {"con_primary.value": 1}
