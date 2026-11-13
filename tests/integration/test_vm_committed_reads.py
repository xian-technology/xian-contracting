"""The VM reads V2 state in Rust: the block overlay, then LMDB.

Contract variable and hash reads of pending or committed state do not call the
Python host (only keys the host staged itself during the execution do). The
reads are tracked as the transaction's access exactly as Python reads are, and
a stored value the reader rejects is a host fault, never a transaction outcome.
"""

import pytest
import xian_vm_core
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime

from contracting.local import ContractingClient
from contracting.storage.lmdb_environment import LMDBError

pytestmark = pytest.mark.optional_native

READER = """
balances = Hash(default_value=0)
total = Variable()

@export
def run(account: str):
    return [balances[account], balances["nobody"], total.get()]
"""


def _context():
    return {
        "signer": "alice",
        "caller": "alice",
        "this": "con_reader",
        "owner": None,
        "now": Datetime(2026, 1, 1),
        "block_num": 1,
        "chain_id": "test-chain",
    }


@pytest.fixture
def driver(tmp_path):
    client = ContractingClient(storage_home=tmp_path)
    client.flush()
    driver = client.raw_driver
    driver.set_contract_from_source("con_reader", READER, owner=None)
    driver.set("con_reader.balances:alice", ContractingDecimal("12.5"))
    driver.set("con_reader.total", {"n": [1, 2], "when": Datetime(2025, 5, 6)})
    driver.commit()
    yield driver
    client.flush()


@pytest.fixture
def host_reads(monkeypatch):
    reads = []
    for name in ("read_hash", "read_variable"):
        original = getattr(xian_vm_core.NativeVmHost, name)

        def counting(self, *args, _original=original, _name=name):
            reads.append((_name, args[1]))
            return _original(self, *args)

        monkeypatch.setattr(xian_vm_core.NativeVmHost, name, counting)
    return reads


def _run(driver):
    return xian_vm_core.execute_contract(
        driver=driver,
        contract_name="con_reader",
        function_name="run",
        kwargs={"account": "alice"},
        context=_context(),
        meter=True,
        chi_budget_raw=5_000_000,
    )


EXPECTED = [ContractingDecimal("12.5"), 0, {"n": [1, 2], "when": Datetime(2025, 5, 6)}]


def test_committed_reads_do_not_call_the_python_host(driver, host_reads):
    result = _run(driver)

    assert result.status_code == 0, result.result
    assert result.result == EXPECTED
    assert host_reads == []


def test_pending_writes_are_read_in_rust_too(driver, host_reads):
    driver.set("con_reader.balances:alice", ContractingDecimal("7"))
    driver.delete("con_reader.total")

    result = _run(driver)

    assert result.result == [ContractingDecimal("7"), 0, None]
    assert host_reads == []


def test_vm_reads_are_tracked_as_transaction_access(driver):
    driver.set_transaction_read_tracking(True)
    _run(driver)

    reads, _ = driver.transaction_access()
    assert {
        "con_reader.balances:alice",
        "con_reader.balances:nobody",
        "con_reader.total",
    } <= reads


def test_reads_tracked_inside_a_discarding_scope_are_undone(driver):
    with driver.discarding_changes():
        _run(driver)
        assert "con_reader.total" in driver.transaction_access()[0]

    assert "con_reader.total" not in driver.transaction_access()[0]


def test_a_corrupt_stored_value_is_a_host_fault(driver):
    driver._store.environment.write([(b"con_reader.balances:alice", b'{"__fixed__":"1.50"}')])

    with pytest.raises(LMDBError, match="con_reader.balances:alice"):
        _run(driver)
