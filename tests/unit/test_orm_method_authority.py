"""Trusted host ORM base methods preserve read-only foreign receivers."""

import pytest

from contracting.storage.driver import Driver
from contracting.storage.orm import ForeignHash, ForeignVariable, Hash, LogEvent, Variable


def test_trusted_host_base_functions_read_and_write_with_the_supplied_driver(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        value = Variable(contract="owner", name="value", driver=driver)
        Variable.set(value, 7)
        assert Variable.get(value) == 7
        Variable.set(value, 9)
        assert value.get() == 9
        assert driver.get_var("owner", "value") == 9


def test_trusted_host_hash_and_event_base_functions_remain_usable(tmp_path):
    with Driver(storage_home=tmp_path) as driver:
        source = Hash(contract="owner", name="source", driver=driver)
        target = Hash(contract="owner", name="target", driver=driver)
        source["alice"] = 8
        Hash.clone_from(target, source)
        assert Hash.all(target) == [8]
        Hash.clear(target)
        assert Hash.all(target) == []
        event = LogEvent("Changed", {"value": int}, contract="owner", driver=driver)
        LogEvent.write_event(event, {"value": 8})
        assert len(driver.log_events) == 1
        assert driver.log_events[0]["data"] == {"value": 8}


@pytest.mark.parametrize(
    "operation",
    [
        lambda value, ledger: Variable.set(value, 99),
        lambda value, ledger: Variable.append(value, 99),
        lambda value, ledger: Variable.clear(value),
        lambda value, ledger: Hash.clear(ledger),
        lambda value, ledger: Hash.clone_from(ledger, ledger),
    ],
)
def test_foreign_receiver_readonly_even_for_base_functions(tmp_path, operation):
    with Driver(storage_home=tmp_path) as driver:
        driver.set_var("target", "value", value=[1, 2])
        driver.set_var("target", "ledger", value=8, arguments=["alice"])
        value = ForeignVariable("owner", "value", "target", "value", driver=driver)
        ledger = ForeignHash("owner", "ledger", "target", "ledger", driver=driver)
        before = driver.items()
        with pytest.raises(ReferenceError):
            operation(value, ledger)
        assert value.get() == [1, 2]
        assert ledger["alice"] == 8
        assert driver.items() == before
