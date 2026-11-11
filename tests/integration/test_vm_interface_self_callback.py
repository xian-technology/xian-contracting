"""A local export selected through its own module keeps inspector authority."""

import pytest

from contracting.execution.executor import Executor
from contracting.storage.driver import Driver


@pytest.mark.parametrize(
    "native,meter",
    [
        (False, False),
        pytest.param(True, False, marks=pytest.mark.optional_native),
        pytest.param(True, True, marks=pytest.mark.optional_native),
    ],
)
@pytest.mark.parametrize("selection", ["check", "module.check"])
def test_same_module_callback_preserves_local_export_context(tmp_path, native, meter, selection):
    source = """state = Variable()
@export
def check(subject: Any):
    state.set([subject.kind, subject.name, ctx.this, ctx.caller, ctx.owner, ctx.signer])
    return subject.name == 'target'
@export
def target():
    return 1
@export
def probe():
    module = importlib.import_module(ctx.this)
    descriptor = importlib.Func('target')
    descriptor.is_of = CALLBACK
    result = importlib.enforce_interface(module, [descriptor])
    return [result, state.get()]
""".replace("CALLBACK", selection)
    with Driver(
        storage_home=tmp_path, vm_profile="xian_vm_v2" if native else "xian_vm_v1"
    ) as driver:
        driver.set_contract_from_source("con_self_subject", source, owner="alice")
        driver.commit()
        if native:
            from xian_vm_core import execute_contract

            output = execute_contract(
                driver=driver,
                contract_name="con_self_subject",
                function_name="probe",
                kwargs={},
                context={"caller": "alice", "signer": "alice", "this": "con_self_subject"},
                meter=meter,
                chi_budget_raw=1_000_000,
            )
            status, result = output.status_code, output.result
        else:
            output = Executor(driver=driver, metering=False).execute(
                sender="alice",
                contract_name="con_self_subject",
                function_name="probe",
                kwargs={},
                metering=False,
            )
            status, result = output["status_code"], output["result"]
        assert status == 0, result
        assert result == [
            True,
            ["function", "target", "con_self_subject", "alice", "alice", "alice"],
        ]
