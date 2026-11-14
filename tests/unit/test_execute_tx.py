"""One call run by the block executor's rules (``xian_vm_core.execute_tx``).

The simulator, contract views, genesis deploys and the local client run a
single call with the code a block runs. What differs is only how the fee is
settled (a block transaction reserves its budget, a dry run does not) and
which overlay receives the effects (the caller's own, or a fork it drops).
"""

from pathlib import Path

import pytest
from xian_runtime_types.decimal import ContractingDecimal
from xian_vm_core import TxRun, execute_tx

from contracting.local import ContractingClient
from contracting.runtime_features import set_driver_runtime_features

PROBE = """values = Hash()

@export
def put(key: str, value: int):
    values[key] = value
    return value

@export
def zap(key: str):
    values[key] = 1
    assert False, "forced"
"""

ZK_PROBE = """@export
def get():
    return zk.is_available()
"""

OWNED = """@export
def ping():
    return 1
"""

RATE = 20
BALANCE_KEY = "currency.balances:alice"


@pytest.fixture
def driver(tmp_path: Path):
    client = ContractingClient(storage_home=tmp_path, vm_profile="xian_vm_v2")
    driver = client.raw_driver
    driver.set_contract_from_source("con_probe", PROBE)
    driver.set_contract_from_source("con_zk", ZK_PROBE)
    driver.set_contract_from_source("con_owned", OWNED, owner="bob")
    # A contract whose keys sort after the sender's balance.
    driver.set_contract_from_source("zz_probe", PROBE)
    driver.set("chi_cost.S:value", RATE)
    driver.set(BALANCE_KEY, ContractingDecimal("1"))
    driver.commit()
    try:
        yield driver
    finally:
        client.close()


def _run(driver, overlay=None, *, contract="con_probe", function="put", kwargs=None, **options):
    storage, pending = driver.committed_storage()
    kwargs = {"key": "a", "value": 2} if kwargs is None else kwargs
    settings = {"meter": True, "charge_fees": True, "chi_budget": 1_000, **options}
    return execute_tx(
        storage,
        pending if overlay is None else overlay,
        sender="alice",
        contract_name=contract,
        function_name=function,
        kwargs=kwargs,
        context={
            "signer": "alice",
            "caller": "alice",
            "this": contract,
            "entry": (contract, function),
            "submission_name": None,
            "now": None,
            "block_num": 1,
            "block_hash": "00",
            "chain_id": "test",
            "__input_hash": "11",
        },
        **settings,
    )


def test_a_block_transaction_reserves_its_budget(driver):
    # 1 token pays 20 chi, below the 1,000 chi budget.
    run = _run(driver)

    assert run.status_code == 1
    assert isinstance(run.result, AssertionError)
    assert str(run.result) == "Sender does not have enough chi for the submitted budget."


def test_an_estimate_reports_the_chi_without_reserving_the_budget(driver):
    run = _run(driver, estimate=True)

    assert run.status_code == 0
    assert run.result == 2
    fee = ContractingDecimal(run.chi_used) / ContractingDecimal(RATE)
    assert run.writes[BALANCE_KEY] == ContractingDecimal("1") - fee
    # The fee write comes after the run's own writes, as in the Python receipt.
    assert list(run.writes) == ["con_probe.values:a", BALANCE_KEY]
    assert run.contract_costs["con_probe"] > 0


def test_only_an_estimate_lists_a_fee_write_its_run_did_not_make_last(driver):
    driver.set(BALANCE_KEY, ContractingDecimal("1000"))

    estimate = _run(
        driver, driver.committed_storage()[1].snapshot(), contract="zz_probe", estimate=True
    )
    block = _run(driver, driver.committed_storage()[1].snapshot(), contract="zz_probe")

    assert list(estimate.writes) == ["zz_probe.values:a", BALANCE_KEY]
    assert list(block.writes) == [BALANCE_KEY, "zz_probe.values:a"]
    assert estimate.writes[BALANCE_KEY] == block.writes[BALANCE_KEY]


def test_an_estimated_failure_pays_its_fee_and_keeps_no_effects(driver):
    run = _run(driver, function="zap", kwargs={"key": "a"}, estimate=True)

    assert run.status_code == 1
    assert isinstance(run.result, AssertionError)
    fee = ContractingDecimal(run.chi_used) / ContractingDecimal(RATE)
    assert run.writes == {BALANCE_KEY: ContractingDecimal("1") - fee}


def test_a_fork_takes_the_effects_and_the_overlay_stays_untouched(driver):
    storage, pending = driver.committed_storage()
    fork = pending.snapshot()

    run = _run(driver, fork, meter=False, charge_fees=False)

    assert run.status_code == 0
    assert dict(fork.items()).keys() == {"con_probe.values:a"}
    assert len(pending) == 0
    assert driver.get("con_probe.values:a") is None


def test_the_callers_overlay_receives_the_effects_as_a_block_stages_them(driver):
    run = _run(driver, meter=False, charge_fees=False)

    assert run.status_code == 0
    assert run.writes == {"con_probe.values:a": 2}
    assert driver.get("con_probe.values:a") == 2


def test_a_contract_the_chain_does_not_let_run_is_unprepared(driver):
    set_driver_runtime_features(driver, {"zk": False})

    run = _run(
        driver,
        contract="con_zk",
        function="get",
        kwargs={},
        zk_enabled_without_state=False,
        estimate=True,
    )

    assert (run.status_code, run.unprepared) == (1, True)
    assert isinstance(run.result, ValueError)
    assert "zk runtime feature is disabled" in str(run.result)


def test_a_submission_without_source_fails_but_is_prepared(driver):
    run = _run(
        driver,
        contract="submission",
        function="submit_contract",
        kwargs={"name": "con_x"},
        estimate=True,
    )

    assert isinstance(run, TxRun)
    assert (run.status_code, run.unprepared) == (1, False)
    assert str(run.result) == "xian_vm_v2 requires source code for submission.submit_contract"


def test_an_owner_rejection_is_a_failed_run_with_the_base_chi(driver):
    run = _run(driver, contract="con_owned", function="ping", kwargs={}, estimate=True)

    assert (run.status_code, run.chi_used, run.unprepared) == (1, 5, False)
    assert str(run.result) == "Caller is not the owner!"
    assert not any(key.startswith("con_owned.") for key in run.writes)


def test_arguments_the_vm_boundary_refuses_fail_before_execution(driver):
    run = _run(driver, kwargs={"key": "a", "value": 1.5})

    assert (run.status_code, run.chi_used, run.writes, run.events) == (1, 0, {}, [])
    assert isinstance(run.result, Exception)
    assert len(driver.committed_storage()[1]) == 0
