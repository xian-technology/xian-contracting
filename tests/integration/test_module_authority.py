"""Module initialization and transaction entry retain their own authority."""

import pytest

from contracting.execution.executor import Executor
from contracting.storage.driver import Driver


ENGINES = [False, pytest.param(True, marks=pytest.mark.optional_native)]


def execute(driver, contract, function, kwargs, native):
    if native:
        from xian_vm_core import execute_contract

        output = execute_contract(
            driver=driver,
            contract_name=contract,
            function_name=function,
            kwargs=kwargs,
            context={"caller": "alice", "signer": "alice", "this": contract},
            meter=False,
        )
        return {"status_code": output.status_code, "result": output.result, "writes": output.writes}
    return Executor(driver=driver, metering=False).execute(
        sender="alice",
        contract_name=contract,
        function_name=function,
        kwargs=kwargs,
        metering=False,
    )


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize("name", ["public_alias", "private_alias", "helper_alias"])
def test_transaction_entry_requires_the_canonical_export(tmp_path, name, native):
    source = """state = Variable()
@export
def run():
    state.set(7)
    return 1
def hidden():
    state.set(9)
    return 2
public_alias = run
private_alias = hidden
helper_alias = hashlib.sha3_text
"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_entry", source, owner=None)
        driver.commit()
        output = execute(
            driver, "con_entry", name, {"value": "abc"} if name == "helper_alias" else {}, native
        )
        assert output["status_code"] == 1, output
        if not native:
            assert "exported" in str(output["result"])
        assert output["writes"] == {}
        assert driver.get_var("con_entry", "state") is None


@pytest.mark.parametrize("native", ENGINES)
@pytest.mark.parametrize("dynamic", [False, True])
def test_import_initializes_under_target_context_and_restores_requester(tmp_path, dynamic, native):
    target = """initial = [ctx.this, ctx.caller, ctx.owner, ctx.signer]
@export
def read():
    return initial
"""
    statement = (
        "target = importlib.import_module('con_target')"
        if dynamic
        else "import con_target as target"
    )
    source = f"""{statement}
@export
def probe():
    result = target.read()
    return [result, ctx.this, ctx.caller, ctx.signer]
"""
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_target", target, owner="con_probe")
        driver.set_contract_from_source("con_probe", source, owner=None)
        driver.commit()
        output = execute(driver, "con_probe", "probe", {}, native)
        assert output["status_code"] == 0, output["result"]
        assert output["result"] == [
            ["con_target", "con_probe", "con_probe", "alice"],
            "con_probe",
            "alice",
            "alice",
        ]
