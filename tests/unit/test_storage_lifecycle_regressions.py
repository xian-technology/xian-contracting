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


def test_single_process_parallel_executors_own_and_release_their_workers(tmp_path):
    from contracting.execution.parallel import ExecutionRequest

    home = tmp_path / "parallel"
    path = home / "lmdb"
    with ContractingClient(storage_home=home) as client:
        client.submit("@export\ndef ping():\n    return 42", name="con_ping")
        client.raw_driver.commit()
        first = client.build_parallel_executor(workers=1, min_batch_size=2)
        second = client.build_parallel_executor(workers=1, min_batch_size=2)
        requests = [
            ExecutionRequest(sender=sender, contract_name="con_ping", function_name="ping")
            for sender in ("alice", "bob")
        ]
        try:
            results, stats = first.execute(requests=requests)
            assert [result["result"] for result in results] == [42, 42]
            assert stats.speculative_accepted == 2
            first.close()
            assert DEFAULT_ENVIRONMENT_POOL.ref_count(path) == 1
            for executor in (first, second):
                results, stats = executor.execute(requests=requests)
                assert [result["result"] for result in results] == [42, 42]
                assert stats.speculative_accepted == 2
            assert DEFAULT_ENVIRONMENT_POOL.ref_count(path) == 3
            first.close()
            first.close()
            assert DEFAULT_ENVIRONMENT_POOL.ref_count(path) == 2
            results, stats = second.execute(requests=requests)
            assert [result["result"] for result in results] == [42, 42]
            assert stats.speculative_accepted == 2
            second.close()
            assert DEFAULT_ENVIRONMENT_POOL.ref_count(path) == 1
        finally:
            first.close()
            second.close()
    assert DEFAULT_ENVIRONMENT_POOL.ref_count(path) == 0


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
        assert driver.pending_writes == {"con_state.value": 12}


def test_parallel_close_releases_storage_while_failed_results_are_retained(tmp_path):
    from contracting.execution.parallel import ExecutionRequest

    with ContractingClient(storage_home=tmp_path) as client:
        client.submit("@export\ndef echo(value: int):\n    return value", name="con_echo")
        client.raw_driver.commit()
        executor = client.build_parallel_executor(workers=1, min_batch_size=2)
        try:
            results, stats = executor.execute(
                requests=[
                    ExecutionRequest(
                        sender=sender,
                        contract_name="con_echo",
                        function_name="echo",
                        kwargs={"value": object()},
                    )
                    for sender in ("alice", "bob")
                ]
            )
            assert [result["status_code"] for result in results] == [1, 1]
            errors = [result["result"] for result in results]
            assert all(isinstance(error, TypeError) for error in errors)
            assert all(error.__traceback__ is not None for error in errors)
            executor.close()
            assert DEFAULT_ENVIRONMENT_POOL.ref_count(tmp_path / "lmdb") == 1
        finally:
            executor.close()


def test_parallel_local_worker_tracks_default_metering_changes(tmp_path):
    from contracting.execution.parallel import ExecutionRequest

    with ContractingClient(storage_home=tmp_path, metering=False) as client:
        client.submit("@export\ndef ping():\n    return 42", name="con_ping")
        client.raw_driver.commit()
        executor = client.build_parallel_executor(workers=1, min_batch_size=2)
        requests = [
            ExecutionRequest(sender=sender, contract_name="con_ping", function_name="ping", chi=1)
            for sender in ("alice", "bob")
        ]
        try:
            results, _ = executor.execute(requests=requests)
            assert [result["status_code"] for result in results] == [0, 0]
            client.executor.metering = True
            results, _ = executor.execute(requests=requests)
            assert [result["status_code"] for result in results] == [1, 1]
        finally:
            executor.close()


def test_parallel_local_worker_tracks_driver_replacement(tmp_path):
    from contracting.execution.parallel import ExecutionRequest

    with (
        ContractingClient(storage_home=tmp_path / "first") as first,
        ContractingClient(storage_home=tmp_path / "second") as second,
    ):
        for value, client in [(1, first), (2, second)]:
            client.submit(f"@export\ndef ping():\n    return {value}", name="con_ping")
            client.raw_driver.commit()
        executor = first.build_parallel_executor(workers=1, min_batch_size=2)
        requests = [
            ExecutionRequest(sender=sender, contract_name="con_ping", function_name="ping")
            for sender in ("alice", "bob")
        ]
        try:
            results, _ = executor.execute(requests=requests)
            assert [result["result"] for result in results] == [1, 1]
            first.executor.driver = second.raw_driver
            results, _ = executor.execute(requests=requests)
            assert [result["result"] for result in results] == [2, 2]
            assert DEFAULT_ENVIRONMENT_POOL.ref_count(tmp_path / "first" / "lmdb") == 1
            assert DEFAULT_ENVIRONMENT_POOL.ref_count(tmp_path / "second" / "lmdb") == 2
        finally:
            executor.close()
