"""Collection method resource and rollback boundaries beyond the legacy corpus."""

import pytest

from contracting.constants import MAX_BINARY_ALLOCATION_BYTES
from contracting.storage.driver import Driver


@pytest.mark.optional_native
@pytest.mark.parametrize(
    "size,accepted", [(MAX_BINARY_ALLOCATION_BYTES, True), (MAX_BINARY_ALLOCATION_BYTES + 1, False)]
)
def test_native_fromhex_bounds_external_text_before_output_allocation(tmp_path, size, accepted):
    from tests.integration.test_vm_language_conformance import _run_native_case

    actual = _run_native_case(
        {
            "id": "fromhex_limit",
            "function_name": "probe",
            "source": "@export\ndef probe(text: str):\n    return len(bytes.fromhex(text))\n",
            "kwargs": {"text": "ab " * size},
        },
        tmp_path,
    )
    assert actual["status_code"] == (0 if accepted else 1), actual
    if accepted:
        assert actual["result"] == MAX_BINARY_ALLOCATION_BYTES
    else:
        assert "allocation" in str(actual["result"]), actual
    assert actual["writes"] == {} and actual["events"] == []


@pytest.mark.optional_native
@pytest.mark.parametrize(
    "operation", ["d.update(zip(range(1000),range(1000)))", "bytes.fromhex('41' * 50000)"]
)
def test_collection_work_is_metered_and_rolls_back(tmp_path, operation):
    from tests.vm_calls import execute_contract

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
