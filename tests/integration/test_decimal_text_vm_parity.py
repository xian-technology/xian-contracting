"""Host-side ContractingDecimal text matches what a V2 contract sees for the same value."""

import json

import pytest
from xian_runtime_types.decimal import ContractingDecimal

from contracting.artifacts import build_contract_artifacts

pytestmark = pytest.mark.optional_native
PROFILE = "xian_vm_v2"
NAME = "con_decimal_text"
LITERALS = [
    "1000",
    "10000",
    "50000000",
    "1234500",
    "0.0001",
    "0.0000001",
    "-0.0000001",
    "1234.5",
    "-1000",
    "0",
    "0.10",
    "1e-30",
    "9" * 61,
]
SPECS = ["", ">12", ".4f", ",", ",.2f", "e", "%", "f", "g", "012", "+"]
SOURCE = """@export
def probe(texts: list, specs: list):
    rows = []
    for text in texts:
        value = decimal(text)
        row = [str(value), f'{value!r}', str([value])]
        for spec in specs:
            row.append(format(value, spec))
        rows.append(row)
    return rows
"""


class Host:
    def get_owner(self, contract):
        return None


def vm_rows():
    from xian_vm_core import execute_bundle

    ir = build_contract_artifacts(module_name=NAME, source=SOURCE, vm_profile=PROFILE)["vm_ir_json"]
    output = execute_bundle(
        json.dumps({NAME: json.loads(ir)}),
        NAME,
        "probe",
        [],
        {"texts": LITERALS, "specs": SPECS},
        {"caller": "alice", "this": NAME},
        Host(),
        vm_profile=PROFILE,
        meter=True,
        chi_budget_raw=100_000_000,
    )
    assert output["status_code"] == 0, output["result"]
    return output["result"]


def host_row(text):
    value = ContractingDecimal(text)
    return [str(value), repr(value), str([value]), *(format(value, spec) for spec in SPECS)]


def test_contracting_decimal_text_matches_v2_vm_rendering():
    assert [host_row(text) for text in LITERALS] == vm_rows()
