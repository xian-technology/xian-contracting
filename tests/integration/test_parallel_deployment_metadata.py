"""Accepted speculative deployments retain artifacts and all metadata writes."""

import pytest
from xian_runtime_types.time import Datetime

from contracting.execution.executor import Executor
from contracting.execution.parallel import ExecutionRequest, ParallelBatchExecutor
from contracting.storage.driver import Driver

CHILD = "@export\ndef read():\n    return 1\n"
SUBMISSION = f"""@export
def deploy(name: str, fail: bool = False):
    Contract.deploy(name=name, code={CHILD!r})
    assert not fail, 'rollback'
    return Contract.get_info(name)['deployer']
@export
def update(name: str, new_value: str, fail: bool = False):
    Contract.set_owner(name, new_value)
    Contract.set_developer(name, new_value)
    assert not fail, 'rollback'
    return Contract.get_info(name)['developer']
"""


def run_batch(driver, function, kwargs):
    executor = Executor(driver=driver, metering=False)
    batch = ParallelBatchExecutor(executor=executor, workers=2, min_batch_size=2)
    try:
        return batch.execute(
            requests=[
                ExecutionRequest(
                    sender=sender,
                    contract_name="submission",
                    function_name=function,
                    kwargs=arguments,
                    environment={"now": Datetime(2026, 11, 1)},
                    metering=False,
                )
                for sender, arguments in zip(("alice", "bob"), kwargs)
            ],
            auto_commit=True,
        )
    finally:
        batch.close()


@pytest.mark.parametrize("operation", ["deploy", "update"])
@pytest.mark.parametrize("same_name", [False, True])
def test_parallel_metadata_writes_commit_and_conflict(tmp_path, operation, same_name):
    with Driver(storage_home=tmp_path) as driver:
        names = ["con_one", "con_one" if same_name else "con_two"]
        driver.set_contract_from_source("submission", SUBMISSION, owner=None)
        if operation == "update":
            for name in set(names):
                driver.set_contract_from_source(name, CHILD, owner="original", developer="original")
        driver.commit()
        arguments = [
            {"name": name, **({"new_value": sender} if operation == "update" else {})}
            for name, sender in zip(names, ("alice", "bob"))
        ]
        outputs, stats = run_batch(driver, operation, arguments)
        assert stats.parallel_attempted
        if same_name and operation == "deploy":
            assert [output["status_code"] for output in outputs] == [0, 1]
            assert "already exists" in str(outputs[1]["result"])
        else:
            assert [output["status_code"] for output in outputs] == [0, 0]
        for index, (name, sender) in enumerate(zip(names, ("alice", "bob"))):
            assert driver.has_contract(name)
            expected = "bob" if same_name and operation == "update" else sender
            if same_name and operation == "deploy":
                expected = "alice"
            assert driver.get_contract_developer(name) == expected
            if operation == "deploy":
                assert driver.get_contract_deployer(name) == expected
                assert driver.get_contract_initiator(name) == expected
                if outputs[index]["status_code"] == 0:
                    assert f"{name}.__source__" in outputs[index]["writes"]
                    assert f"{name}.__xian_ir_v1__" in outputs[index]["writes"]
            else:
                assert driver.get_owner(name) == expected
                assert set(outputs[index]["writes"]) == {
                    f"{name}.__owner__",
                    f"{name}.__developer__",
                }


@pytest.mark.parametrize("operation", ["deploy", "update"])
def test_failed_parallel_metadata_mutation_rolls_back(tmp_path, operation):
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("submission", SUBMISSION, owner=None)
        if operation == "update":
            for name in ("con_one", "con_two"):
                driver.set_contract_from_source(name, CHILD, owner="original", developer="original")
        driver.commit()
        kwargs = [
            {
                "name": name,
                "fail": True,
                **({"new_value": "changed"} if operation == "update" else {}),
            }
            for name in ("con_one", "con_two")
        ]
        outputs, _ = run_batch(driver, operation, kwargs)
        assert [output["status_code"] for output in outputs] == [1, 1]
        assert all(output["writes"] == {} for output in outputs)
        for name in ("con_one", "con_two"):
            assert driver.has_contract(name) == (operation == "update")
            if operation == "update":
                assert driver.get_owner(name) == "original"
                assert driver.get_contract_developer(name) == "original"


def test_host_contract_setup_does_not_mark_transaction_writes(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_host", CHILD, owner=None)
        driver.set_var("con_host", "arbitrary", value=1)
        assert driver.transaction_writes == {}


def test_trusted_host_deployment_and_metadata_setup_stay_unmarked(tmp_path):
    from contracting.storage.contract import Contract

    with Driver(storage_home=tmp_path) as driver:
        Contract.deploy(name="con_host", code=CHILD, driver=driver)
        Contract.set_owner("con_host", "host", driver=driver)
        Contract.set_developer("con_host", "host", driver=driver)
        assert driver.transaction_writes == {}
        assert driver.get_owner("con_host") == "host"
        assert driver.get_contract_developer("con_host") == "host"
