"""Storage boundaries remain usable after cursors and initialization errors."""

import pytest
from xian_compiler_core import CompilerError

from contracting.local import ContractingClient
from contracting.storage.driver import Driver
from contracting.storage.lmdb_environment import DEFAULT_ENVIRONMENT_POOL
from contracting.storage.lmdb_store import LMDBStore


@pytest.mark.parametrize("after", ["", "a.before", "con_alpha.value", "con_balances"])
def test_scan_cursor_before_prefix_still_returns_matching_keys(tmp_path, after):
    with LMDBStore(tmp_path / "store") as store:
        store.batch_set(
            {
                "a.before": 1,
                "con_alpha.value": 2,
                "con_balances:alice": 3,
                "con_balances:bob": 4,
                "con_balances:carol": 5,
                "z.after": 6,
            }
        )
        first, more = store.scan_keys("con_balances:", limit=2, after_key=after)
        assert first == ["con_balances:alice", "con_balances:bob"]
        assert more is True
        assert store.scan_keys("con_balances:", after_key=first[-1]) == (
            ["con_balances:carol"],
            False,
        )


@pytest.mark.parametrize("invalid_source", [False, True], ids=["missing", "invalid"])
def test_failed_client_initialization_closes_owned_storage(tmp_path, invalid_source):
    home = tmp_path / "owned"
    source = tmp_path / "submission.py"
    if invalid_source:
        source.write_text("def invalid(\n")
    # Keep the exception alive: construction must release resources itself.
    expected_error = CompilerError if invalid_source else FileNotFoundError
    with pytest.raises(expected_error) as failure:
        ContractingClient(storage_home=home, submission_filename=source)
    assert failure.value is not None
    assert DEFAULT_ENVIRONMENT_POOL.ref_count(home / "lmdb") == 0
    with Driver(storage_home=home) as driver:
        driver.set("con_state.value", 12)
        driver.commit()
        assert driver.get("con_state.value") == 12


def test_failed_client_initialization_keeps_borrowed_storage_open(tmp_path):
    home = tmp_path / "borrowed"
    with Driver(storage_home=home) as driver:
        with pytest.raises(FileNotFoundError):
            ContractingClient(driver=driver, submission_filename=tmp_path / "missing.py")
        assert DEFAULT_ENVIRONMENT_POOL.ref_count(home / "lmdb") == 1
        driver.set("con_state.value", 12)
        driver.commit()
        assert driver.get("con_state.value") == 12


@pytest.mark.parametrize("prefix", ["", "con_balances:", "con_missing:", "é"])
@pytest.mark.parametrize("after", [None, "", "a.before", "con_balances:bob", "z.after", "zz", "🚀"])
@pytest.mark.parametrize("limit", [-1, 0, 1, 2, 20])
def test_key_pages_match_independent_prefix_and_cursor_filter(tmp_path, prefix, after, limit):
    entries = {
        "a.before": 1,
        "con_balances:alice": 2,
        "con_balances:bob": 3,
        "con_balances:carol": 4,
        "z.after": 5,
        "é.state": 6,
    }
    matches = [
        key for key in sorted(entries) if key.startswith(prefix) and (after is None or key > after)
    ]
    expected = (matches[:limit], len(matches) > limit) if limit > 0 else ([], False)
    with LMDBStore(tmp_path / "store") as store:
        store.batch_set(entries)
        assert store.scan_keys(prefix, after_key=after, limit=limit) == expected


def test_explicit_profile_with_borrowed_storage_preserves_environment_and_lifetime(tmp_path):
    environment = {"chain_id": "private-client-test"}
    with Driver(storage_home=tmp_path) as driver:
        with ContractingClient(
            driver=driver,
            vm_profile="xian_vm_v2",
            environment=environment,
            submission_filename=None,
        ) as client:
            assert client.raw_driver is driver
            assert client.environment == environment
            assert client.submission_contract is None
        driver.set("con_state.value", 12)
        driver.commit()
        assert driver.get("con_state.value") == 12


def test_explicit_profile_mismatch_preserves_borrowed_driver_state(tmp_path):
    with Driver(storage_home=tmp_path, vm_profile="xian_vm_v1") as driver:
        driver.set("con_state.value", 12)
        with pytest.raises(ValueError, match="client and storage driver profiles must match"):
            ContractingClient(driver=driver, vm_profile="xian_vm_v2")
        assert driver.get("con_state.value") == 12
        assert driver.pending_items() == [("con_state.value", 12)]
