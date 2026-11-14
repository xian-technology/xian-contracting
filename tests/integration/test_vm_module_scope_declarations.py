"""Module-level declarations and defaults see the module's earlier globals.

Storage options, event parameters, constant bindings and function defaults
are evaluated while a module is instantiated. Names in them resolve to the
globals bound before them, also inside comprehensions and nested calls.
"""

import pytest
from tests.vm_calls import execute_contract

from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

SOURCE = """
LIMIT = 5
SCALED = [i * LIMIT for i in range(3)]
balances = Hash(default_value=LIMIT)
seen = Variable(default_value=SCALED)
Moved = LogEvent(event="Moved", params={"amount": {"type": int, "idx": LIMIT == 5}})

def double(x: int):
    return x * 2

@export
def total(n: int = LIMIT, m: int = SCALED[2]):
    Moved({"amount": n})
    return balances["nobody"] + n + m + seen.get()[1] + double(LIMIT)
"""


@pytest.fixture
def driver(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        driver.set_contract_from_source("con_scope", SOURCE, owner=None)
        driver.commit()
        yield driver


def _total(driver, **kwargs):
    return execute_contract(
        driver=driver,
        contract_name="con_scope",
        function_name="total",
        kwargs=kwargs,
        context={"caller": "alice", "signer": "alice", "now": None},
        meter=True,
        chi_budget_raw=5_000_000,
    )


def test_declarations_and_defaults_resolve_earlier_globals(driver):
    output = _total(driver)

    assert output.status_code == 0, output.result
    assert output.result == 5 + 5 + 10 + 5 + 10
    assert output.events[0]["data_indexed"] == {"amount": 5}
    # Instantiation work is metered: the exact charge (48,201 raw, measured when
    # the Python host reported raw cost) pins how it is evaluated.
    assert output.chi_used == 48_201 // 1000 + 5


def test_explicit_arguments_override_global_defaults(driver):
    output = _total(driver, n=1, m=2)

    assert output.status_code == 0, output.result
    assert output.result == 5 + 1 + 2 + 5 + 10
