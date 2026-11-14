"""Executions reuse parsed contract IR only while the stored IR is unchanged.

The Rust VM keeps modules parsed from a contract's IR text
for later executions in the same process. A contract whose stored IR changes
(redeployed, overwritten, rolled back) must run its current code at once, and a
failed deployment must leave nothing behind for a later one.
"""

import pytest
from tests.vm_calls import execute_contract

from contracting.artifacts import compile_contract_source
from contracting.storage.driver import Driver

PROFILE = "xian_vm_v2"


def _source(answer):
    return f"@export\ndef answer():\n    return {answer}\n"


def _ir(name, source):
    return compile_contract_source(module_name=name, source=source, vm_profile=PROFILE)[
        "vm_ir_json"
    ]


def _call(driver, name, function="answer", kwargs=None, caller="alice"):
    return execute_contract(
        driver=driver,
        contract_name=name,
        function_name=function,
        kwargs=kwargs or {},
        context={"caller": caller, "signer": caller, "now": None},
    )


@pytest.fixture
def driver(tmp_path):
    with Driver(storage_home=tmp_path, vm_profile=PROFILE) as driver:
        yield driver


def test_overwritten_ir_runs_the_new_code(driver):
    driver.set_contract_from_source("con_answer", _source(1))
    assert _call(driver, "con_answer").result == 1

    driver.set_contract_from_source("con_answer", _source(2), overwrite=True)

    assert _call(driver, "con_answer").result == 2


def test_rolled_back_ir_runs_the_committed_code(driver):
    driver.set_contract_from_source("con_answer", _source(1))
    driver.commit()
    driver.set_contract_from_source("con_answer", _source(2), overwrite=True)
    assert _call(driver, "con_answer").result == 2

    driver.rollback()

    assert _call(driver, "con_answer").result == 1


def test_importer_sees_the_current_ir_of_its_import(driver):
    driver.set_contract_from_source("con_answer", _source(1))
    driver.set_contract_from_source(
        "con_caller", "import con_answer\n@export\ndef answer():\n    return con_answer.answer()\n"
    )
    assert _call(driver, "con_caller").result == 1

    driver.set_contract_from_source("con_answer", _source(3), overwrite=True)

    assert _call(driver, "con_caller").result == 3


def test_export_checks_follow_the_current_ir(driver):
    driver.set_contract_from_source("con_answer", _source(1))
    assert _call(driver, "con_answer").status_code == 0

    driver.set_contract_from_source(
        "con_answer", "@export\ndef other():\n    return 0\n", overwrite=True
    )

    rejected = _call(driver, "con_answer")
    assert rejected.status_code == 1
    assert "not exported" in str(rejected.result)
