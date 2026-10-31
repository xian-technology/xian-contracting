"""Unpacking obeys execution/allocation limits and transaction rollback."""

import pytest
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


@pytest.mark.parametrize(
    "operation", ["a,*b=range(1000000)", "min(*range(1000000))", "a=[*range(1000000)]"]
)
@pytest.mark.parametrize("meter", [False, True])
def test_expansion_bounds_and_rollback(tmp_path, operation, meter):
    from xian_vm_core import execute_contract

    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source(
            "con_unpack",
            "v=Variable()\n@export\ndef probe():\n    v.set(1)\n    " + operation + "\n",
            owner=None,
        )
        driver.commit()
        output = execute_contract(
            driver=driver,
            contract_name="con_unpack",
            function_name="probe",
            kwargs={},
            context={"caller": "alice", "signer": "alice", "this": "con_unpack"},
            meter=meter,
            chi_budget_raw=50_000,
        )
        assert output.status_code == 1
        assert ("Out of chi" if meter else "allocation limit") in str(output.result)
        assert output.writes == {} and output.events == []
