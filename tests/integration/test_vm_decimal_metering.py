"""Wide exact Decimal comparisons are paid before container or numeric work."""

from decimal import Decimal

import pytest

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

OPERATIONS = [
    ("x < y", True),
    ("x == y", False),
    ("[x] == [y]", False),
    ("x in [y]", False),
    ("x in map(identity, [y])", False),
    ("mapping.get(x, 0)", 0),
    ("mapping[y]", 1),
    ("items.count(x)", 2),
    ("items.index(y)", 2),
    ("len(set(items))", 2),
    ("len(set(map(identity, items)))", 2),
    ("len(set().union(map(identity, items)))", 2),
    ("len(dict([(x, 1), (y, 2)]))", 2),
    ("min(items) == x", True),
    ("sorted(items)[-1] == y", True),
]


# Captured from the native extension before adding extended-value metering.
ORDINARY_RAW_COSTS = {
    "x < y": 22128,
    "x == y": 22129,
    "[x] == [y]": 22897,
    "x in [y]": 22513,
    "x in map(identity, [y])": 38185,
    "mapping.get(x, 0)": 36933,
    "mapping[y]": 22125,
    "items.count(x)": 36837,
    "items.index(y)": 36837,
    "len(set(items))": 52029,
    "len(set(map(identity, items)))": 68277,
    "len(set().union(map(identity, items)))": 83277,
    "len(dict([(x, 1), (y, 2)]))": 53565,
    "min(items) == x": 37896,
    "sorted(items)[-1] == y": 38760,
}


# The module's interface metadata initialization adds 132 raw chi under gas2.
# Source-derived work: global v=2; identity(value)=15; probe(x,y,mapping,items)=24;
# declaration v=2; base=1. Total 44, times tree-depth bucket 3 for five entries.
# Keep the pre-existing execution costs separate so wide-Decimal comparisons
# still have an exact control independent of this one-time module setup fee.
INTERFACE_METADATA_INIT_RAW_COST = 132


def run_case(home, expression, digits, budget=500_000):
    from xian_vm_core import execute_contract

    x = Decimal("1" + "0" * (digits - 1))
    y = Decimal("1" + "0" * (digits - 2) + "1")
    source = (
        "v = Variable()\n"
        "def identity(value):\n    return value\n"
        "@export\ndef probe(x: Any, y: Any, mapping: dict, items: list):\n"
        "    v.set(7)\n"
        "    for i in range(3):\n"
        f"        answer = {expression}\n"
        "    return answer\n"
    )
    with Driver(storage_home=home) as driver:
        driver.set_contract_from_source("con_decimal_meter", source, owner=None)
        driver.commit()
        return execute_contract(
            driver=driver,
            contract_name="con_decimal_meter",
            function_name="probe",
            kwargs={"x": x, "y": y, "mapping": {y: 1}, "items": [x, x, y]},
            context={"caller": "alice", "signer": "alice", "this": "con_decimal_meter"},
            meter=True,
            chi_budget_raw=budget,
        )


@pytest.mark.parametrize(("expression", "expected"), OPERATIONS)
def test_extended_comparison_work_exhausts_budget_before_results(tmp_path, expression, expected):
    # Inputs are supplied as kwargs: constructor work cannot account for failure.
    # The same program/input shape succeeds for the historical <=91-digit domain.
    ordinary = run_case(tmp_path / "ordinary", expression, 91)
    assert ordinary.status_code == 0, ordinary.result
    assert ordinary.result == expected
    assert ordinary.raw_cost == ORDINARY_RAW_COSTS[expression] + INTERFACE_METADATA_INIT_RAW_COST
    wide = run_case(tmp_path / "wide", expression, 2000)
    assert wide.status_code == 1 and "Out of chi" in str(wide.result), wide.result
    assert wide.writes == {} and wide.events == []


def test_wide_comparisons_still_execute_with_sufficient_chi(tmp_path):
    result = run_case(tmp_path, "x < y", 1000, budget=50_000_000)
    assert result.status_code == 0 and result.result is True
    assert result.writes["con_decimal_meter.v"] == 7
