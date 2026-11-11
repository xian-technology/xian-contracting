"""Original execution fingerprints with explicitly audited execution-3 chi.

Fixtures are observations of commit 005a1048, not a second interpreter. Changing
these values requires explaining a semantic or metering change, not regenerating
snapshots to make a refactor pass.
Explicit later metering adjustments are recorded with their derivation in the
fixture metadata; all result, write and event fingerprints remain unchanged.
Execution 3 adds bounded public-callable metadata/lookup and event validation.
The fixture records each source-derived component, contract attribution and
out-of-chi stopping point; expected costs must not be copied from observations.
"""

import json
from pathlib import Path

import pytest

from contracting.storage.driver import Driver
from tests.integration.test_vm_language_conformance import (
    _deploy_case_contracts,
    _execution_context,
    _normalize,
)

pytestmark = pytest.mark.optional_native
BASELINE_PATH = Path(__file__).with_name("vm_dispatch_baseline.json")
CASES = {
    case["id"]: case
    for case in json.loads((Path(__file__).parents[1] / "compatibility/cases.json").read_text())
}
BASELINE = json.loads(BASELINE_PATH.read_text())


@pytest.fixture(scope="module", autouse=True)
def pinned_execution_revision():
    from xian_vm_core import runtime_info

    info = runtime_info("xian_vm_v1")
    assert info["execution_revision"] == BASELINE["execution_revision"]
    assert BASELINE["gas_schedule"] in info["supported_gas_schedules"]


def observe_dispatch(case, storage_home, chi_budget_raw):
    from xian_vm_core import execute_contract

    name = f"conformance_{case['id']}"
    with Driver(storage_home=storage_home, vm_profile="xian_vm_v1") as driver:
        _deploy_case_contracts(
            driver,
            {
                **case,
                "dependencies": [
                    {"name": dependency, "source": source, "owner": None}
                    for dependency, source in case.get("dependencies", {}).items()
                ],
            },
            name,
        )
        result = execute_contract(
            driver=driver,
            vm_profile=driver.vm_profile,
            contract_name=name,
            function_name=case.get("function", "probe"),
            kwargs=case.get("kwargs", {}),
            context=_execution_context(name, case.get("function", "probe"), "alice"),
            meter=True,
            chi_budget_raw=chi_budget_raw,
        )
        return {
            "status_code": result.status_code,
            "result_repr": repr(result.result),
            "writes": {key: repr(value) for key, value in sorted(result.writes.items())},
            "events": _normalize(result.events),
            "raw_cost": result.raw_cost,
            "chi_used": result.chi_used,
            "contract_costs": result.contract_costs,
        }


@pytest.mark.parametrize("case_id", BASELINE["cases"])
def test_dispatch_observables_and_execution3_chi(tmp_path, case_id):
    expected = BASELINE["cases"][case_id]
    case = CASES[expected["source_case"]]
    assert observe_dispatch(case, tmp_path, expected["chi_budget_raw"]) == expected["output"]
