"""ORM base functions cannot bypass receiver authority through unbound calls."""

import pytest

from contracting.execution.runtime import contract_execution_scope, rt
from contracting.storage.driver import Driver
from contracting.storage.orm import ForeignHash, ForeignVariable, Hash, LogEvent, Variable


@pytest.mark.parametrize(
    "operation",
    [
        lambda value, ledger, event: Variable.get(value),
        lambda value, ledger, event: Variable.set(value, 99),
        lambda value, ledger, event: Hash.all(ledger),
        lambda value, ledger, event: Hash.clear(ledger),
        lambda value, ledger, event: Hash.clone_from(ledger, ledger),
        lambda value, ledger, event: LogEvent.write_event(event, {"value": 99}),
    ],
)
def test_unbound_methods_require_declaring_contract(tmp_path, monkeypatch, operation):
    driver = Driver(storage_home=tmp_path)
    value = Variable(contract="owner", name="value", driver=driver)
    ledger = Hash(contract="owner", name="ledger", driver=driver)
    event = LogEvent("Changed", {"value": int}, contract="owner", driver=driver)
    value.set(7)
    ledger["alice"] = 8
    driver.commit()
    monkeypatch.setattr(rt.context, "_base_state", {**rt.context._base_state, "this": "other"})
    with contract_execution_scope(), pytest.raises(ReferenceError, match="declaring contract"):
        operation(value, ledger, event)
    assert value.get() == 7
    assert ledger["alice"] == 8
    assert driver.log_events == []


def test_host_and_owner_access_remain_valid(tmp_path, monkeypatch):
    driver = Driver(storage_home=tmp_path)
    value = Variable(contract="owner", name="value", driver=driver)
    value.set(7)
    monkeypatch.setattr(rt.context, "_base_state", {**rt.context._base_state, "this": "owner"})
    with contract_execution_scope():
        Variable.set(value, 9)
        assert Variable.get(value) == 9
    assert value.get() == 9


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
    driver = Driver(storage_home=tmp_path)
    driver.set_var("target", "value", value=[1, 2])
    driver.set_var("target", "ledger", value=8, arguments=["alice"])
    value = ForeignVariable("owner", "value", "target", "value", driver=driver)
    ledger = ForeignHash("owner", "ledger", "target", "ledger", driver=driver)
    with pytest.raises(ReferenceError):
        operation(value, ledger)
    assert value.get() == [1, 2]
    assert ledger["alice"] == 8
