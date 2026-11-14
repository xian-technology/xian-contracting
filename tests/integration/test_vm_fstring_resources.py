"""F-string aggregation enforces the native formatting allocation boundary."""

import pytest

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native


@pytest.mark.parametrize("character", ["a", "é"])
@pytest.mark.parametrize("overflow", [False, True])
def test_fstring_aggregate_limit_and_rollback(tmp_path, character, overflow):
    from tests.vm_calls import execute_contract

    limit = 128 * 1024
    count = limit // (2 * len(character.encode("utf-8")))
    source = (
        "value = Variable()\n@export\ndef probe(extra: str):\n"
        f"    part = {character!r} * {count}\n"
        "    value.set(1)\n"
        "    return len(f'{part}{part}{extra}')\n"
    )
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_fstring_bounds", source, owner=None)
        driver.commit()
        output = execute_contract(
            driver=driver,
            contract_name="con_fstring_bounds",
            function_name="probe",
            kwargs={"extra": "x" if overflow else ""},
            context={"caller": "alice", "signer": "alice", "this": "con_fstring_bounds"},
            meter=True,
            chi_budget_raw=100_000_000,
        )
    if overflow:
        assert output.status_code == 1
        assert "allocation limit" in str(output.result)
        assert output.writes == {}
        assert output.events == []
    else:
        assert output.status_code == 0, output.result
        assert output.result == count * 2
        assert output.writes == {"con_fstring_bounds.value": 1}
