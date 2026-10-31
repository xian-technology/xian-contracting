"""Collection method resource and rollback boundaries beyond the legacy corpus."""

import pytest
from contracting.storage.driver import Driver
from contracting.stdlib.builtins import safe_bytes
from contracting.constants import MAX_BINARY_ALLOCATION_BYTES


def test_safe_fromhex_bounds_before_allocation():
    assert (
        safe_bytes.fromhex("ab " * MAX_BINARY_ALLOCATION_BYTES)
        == b"\xab" * MAX_BINARY_ALLOCATION_BYTES
    )
    with pytest.raises(AssertionError, match="allocation"):
        safe_bytes.fromhex("ab " * (MAX_BINARY_ALLOCATION_BYTES + 1))


@pytest.mark.optional_native
@pytest.mark.parametrize(
    "operation", ["d.update(zip(range(1000),range(1000)))", "bytes.fromhex('41' * 50000)"]
)
def test_collection_work_is_metered_and_rolls_back(tmp_path, operation):
    from xian_vm_core import execute_contract

    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source(
            "con_methods",
            "v=Variable()\n@export\ndef probe():\n    v.set(1)\n    d={}\n    " + operation + "\n",
            owner=None,
        )
        driver.commit()
        output = execute_contract(
            driver=driver,
            contract_name="con_methods",
            function_name="probe",
            kwargs={},
            context={"caller": "alice", "signer": "alice", "this": "con_methods"},
            meter=True,
            chi_budget_raw=50_000,
        )
        assert output.status_code == 1 and "Out of chi" in str(output.result)
        assert output.writes == {} and output.events == []
