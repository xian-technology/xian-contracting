"""The VM reads V2 state in Rust: the block overlay, then LMDB.

Contract variable and hash reads see pending and committed state, and a
stored value the reader rejects is a host fault, never a transaction outcome.
"""

import pytest
from tests.vm_calls import execute_contract
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
    client.close()


def _run(driver):
    return execute_contract(
        driver=driver,
        contract_name="con_reader",
        function_name="run",
        kwargs={"account": "alice"},
        context=_context(),
        meter=True,
        chi_budget_raw=5_000_000,
    )


EXPECTED = [ContractingDecimal("12.5"), 0, {"n": [1, 2], "when": Datetime(2025, 5, 6)}]


def test_committed_reads(driver):
    result = _run(driver)

    assert result.status_code == 0, result.result
    assert result.result == EXPECTED


def test_pending_writes_are_read_too(driver):
    driver.set("con_reader.balances:alice", ContractingDecimal("7"))
    driver.delete("con_reader.total")

    result = _run(driver)

    assert result.result == [ContractingDecimal("7"), 0, None]


def test_a_corrupt_stored_value_is_a_host_fault(driver):
    driver._store.environment.write([(b"con_reader.balances:alice", b'{"__fixed__":"1.50"}')])

    with pytest.raises(LMDBError, match="con_reader.balances:alice"):
        _run(driver)
