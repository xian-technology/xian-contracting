from __future__ import annotations

import decimal
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime

from contracting.storage.driver import XIAN_VM_V1_IR_KEY, Driver

pytestmark = pytest.mark.optional_native


PARITY_FUZZ_SOURCE = """
counter = Variable(default_value=0)
items = Hash(default_value=0)
claims = Hash(default_value=False)

ProbeEvent = LogEvent(
    "Probe",
    {
        "kind": indexed(str),
        "key": indexed(str),
        "value": int,
        "counter": int,
    },
)

@export
def put(key: str, value: int):
    assert isinstance(key, str) and key != "", "key must be non-empty."
    assert -50 <= value <= 50, "value out of range."
    items[key] = value
    counter.set(counter.get() + 1)
    ProbeEvent(
        {
            "kind": "put",
            "key": key,
            "value": value,
            "counter": counter.get(),
        }
    )
    return {"counter": counter.get(), "value": items[key]}


@export
def add(key: str, delta: int):
    updated = items[key] + delta
    assert -100 <= updated <= 100, "updated value out of range."
    items[key] = updated
    counter.set(counter.get() + 1)
    ProbeEvent(
        {
            "kind": "add",
            "key": key,
            "value": updated,
            "counter": counter.get(),
        }
    )
    return updated


@export
def claim(slot: str, amount: int):
    assert isinstance(slot, str) and slot != "", "slot must be non-empty."
    assert amount >= 0, "amount must be non-negative."
    assert not claims[slot], "slot already claimed."
    claims[slot] = True
    counter.set(counter.get() + amount)
    ProbeEvent(
        {
            "kind": "claim",
            "key": slot,
            "value": amount,
            "counter": counter.get(),
        }
    )
    return counter.get()


@export
def fail_after_write(key: str, value: int):
    items[key] = value
    ProbeEvent(
        {
            "kind": "fail",
            "key": key,
            "value": value,
            "counter": counter.get(),
        }
    )
    assert False, "forced failure"
""".strip()

FIXED_TIMESTAMP = Datetime(2026, 4, 23, 12, 0, 0)


def _execution_context(
    contract_name: str,
    function_name: str,
    owner: str,
    *,
    block_num: int,
) -> dict[str, Any]:
    now = Datetime(2026, 4, 23, 12, 0, block_num)
    return {
        "signer": "alice",
        "caller": "alice",
        "this": contract_name,
        "entry": (contract_name, function_name),
        "owner": owner,
        "submission_name": None,
        "now": now,
        "block_num": block_num,
        "block_hash": f"block-{block_num:04d}",
        "chain_id": "xian-test",
    }


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseException):
        return {
            "exception": type(value).__name__,
            "args": [_normalize(item) for item in value.args],
        }
    if isinstance(value, ContractingDecimal | decimal.Decimal):
        return {"__decimal__": str(value)}
    if isinstance(value, Datetime):
        return {"__datetime__": str(value)}
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value


def _normalize_state(state: dict[str, Any]) -> dict[str, Any]:
    return {key: _normalize(value) for key, value in sorted(state.items())}


def _deploy_probe(driver: Driver, contract_name: str) -> None:
    driver.set_contract_from_source(
        contract_name,
        PARITY_FUZZ_SOURCE,
        owner="alice",
        overwrite=True,
        timestamp=FIXED_TIMESTAMP,
    )
    driver.commit()
    artifact = json.loads(driver.get(f"{contract_name}.{XIAN_VM_V1_IR_KEY}"))
    assert artifact["vm_profile"] == driver.vm_profile


class ReferenceState:
    """Independent state machine for the four authored operations above."""

    def __init__(self, contract_name):
        self.contract_name = contract_name
        self.counter = 0
        self.items = {}
        self.claims = set()

    @staticmethod
    def failure(message):
        return {
            "status_code": 1,
            "result": {"exception": "AssertionError", "args": [message]},
            "writes": {},
            "events": [],
        }

    def _success(self, kind, key, value, result, variable):
        return {
            "status_code": 0,
            "result": result,
            "writes": {
                f"{self.contract_name}.{variable}:{key}": True if kind == "claim" else value,
                f"{self.contract_name}.counter": self.counter,
            },
            "events": [
                {
                    "caller": "alice",
                    "signer": "alice",
                    "contract": self.contract_name,
                    "event": "Probe",
                    "data_indexed": {"kind": kind, "key": key},
                    "data": {"counter": self.counter, "value": value},
                }
            ],
        }

    def put(self, key, value):
        if not key:
            return self.failure("key must be non-empty.")
        if not -50 <= value <= 50:
            return self.failure("value out of range.")
        self.items[key] = value
        self.counter += 1
        result = {"counter": self.counter, "value": value}
        return self._success("put", key, value, result, "items")

    def add(self, key, delta):
        value = self.items.get(key, 0) + delta
        if not -100 <= value <= 100:
            return self.failure("updated value out of range.")
        self.items[key] = value
        self.counter += 1
        return self._success("add", key, value, value, "items")

    def claim(self, slot, amount):
        if not slot:
            return self.failure("slot must be non-empty.")
        if amount < 0:
            return self.failure("amount must be non-negative.")
        if slot in self.claims:
            return self.failure("slot already claimed.")
        self.claims.add(slot)
        self.counter += amount
        return self._success("claim", slot, amount, self.counter, "claims")

    def fail_after_write(self, key, value):
        return self.failure("forced failure")

    def execute(self, operation):
        # Explicit dispatch keeps the model independent of VM calls and storage.
        methods = {
            "put": self.put,
            "add": self.add,
            "claim": self.claim,
            "fail_after_write": self.fail_after_write,
        }
        return methods[operation["function"]](**operation["kwargs"])


def _run_native_step(
    driver: Driver,
    *,
    contract_name: str,
    function_name: str,
    kwargs: dict[str, Any],
    block_num: int,
) -> dict[str, Any]:
    from tests.vm_calls import execute_contract

    output = execute_contract(
        driver=driver,
        contract_name=contract_name,
        function_name=function_name,
        kwargs=dict(kwargs),
        context=_execution_context(
            contract_name,
            function_name,
            "alice",
            block_num=block_num,
        ),
        meter=False,
    )
    if output.status_code == 0:
        driver.apply_writes(output.writes)
        driver.commit()
    return {
        "status_code": output.status_code,
        "result": _normalize(output.result),
        "writes": _normalize(output.writes),
        "events": _normalize(output.events),
    }


def test_native_nested_callback_sees_parent_pending_storage_writes(tmp_path: Path):
    from tests.vm_calls import execute_contract

    controller_name = "con_vm_pending_controller"
    adapter_name = "con_vm_pending_adapter"
    controller_source = """
active = Variable(default_value=0)
values = Hash(default_value=0)

@export
def execute(adapter: str):
    active.set(5)
    values["direct"] = 7
    adapter_module = importlib.import_module(adapter)
    return adapter_module.check()

@export
def get_active():
    return active.get()

@export
def scan_values():
    return values.all()

@export
def store_from_child():
    values["child"] = active.get()
    return values["child"]
""".strip()
    adapter_source = f"""
def controller_module():
    return importlib.import_module("{controller_name}")

@export
def check():
    controller = controller_module()
    assert controller.get_active() == 5, "pending variable not visible"
    assert 7 in controller.scan_values(), "pending hash entry not visible"
    return controller.store_from_child()
""".strip()

    driver = Driver(storage_home=tmp_path)
    driver.flush_full()
    driver.set_contract_from_source(
        controller_name,
        controller_source,
        owner=None,
        overwrite=True,
        timestamp=FIXED_TIMESTAMP,
    )
    driver.set_contract_from_source(
        adapter_name,
        adapter_source,
        owner=None,
        overwrite=True,
        timestamp=FIXED_TIMESTAMP,
    )
    driver.commit()

    output = execute_contract(
        driver=driver,
        contract_name=controller_name,
        function_name="execute",
        kwargs={"adapter": adapter_name},
        context=_execution_context(
            controller_name,
            "execute",
            None,
            block_num=1,
        ),
        meter=False,
    )

    assert output.status_code == 0, output.result
    assert output.result == 5
    assert output.writes[f"{controller_name}.active"] == 5
    assert output.writes[f"{controller_name}.values:direct"] == 7
    assert output.writes[f"{controller_name}.values:child"] == 5


FUZZ_OPERATION = st.one_of(
    st.builds(
        lambda key, value: {
            "function": "put",
            "kwargs": {"key": key, "value": value},
        },
        key=st.sampled_from(["alpha", "beta", "gamma", "delta"]),
        value=st.integers(min_value=-20, max_value=20),
    ),
    st.builds(
        lambda key, delta: {
            "function": "add",
            "kwargs": {"key": key, "delta": delta},
        },
        key=st.sampled_from(["alpha", "beta", "gamma", "delta"]),
        delta=st.integers(min_value=-6, max_value=8),
    ),
    st.builds(
        lambda slot, amount: {
            "function": "claim",
            "kwargs": {"slot": slot, "amount": amount},
        },
        slot=st.sampled_from(["slot-a", "slot-b", "slot-c", "slot-d"]),
        amount=st.integers(min_value=0, max_value=6),
    ),
    st.builds(
        lambda key, value: {
            "function": "fail_after_write",
            "kwargs": {"key": key, "value": value},
        },
        key=st.sampled_from(["alpha", "beta", "gamma", "delta"]),
        value=st.integers(min_value=-20, max_value=20),
    ),
)


@example(
    operations=[
        {"function": "put", "kwargs": {"key": "", "value": 0}},
        {"function": "put", "kwargs": {"key": "alpha", "value": 51}},
        {"function": "put", "kwargs": {"key": "alpha", "value": -51}},
        {"function": "add", "kwargs": {"key": "alpha", "delta": 101}},
        {"function": "claim", "kwargs": {"slot": "", "amount": 0}},
        {"function": "claim", "kwargs": {"slot": "slot-a", "amount": -1}},
        {"function": "put", "kwargs": {"key": "alpha", "value": 50}},
        {"function": "add", "kwargs": {"key": "alpha", "delta": 51}},
        {"function": "claim", "kwargs": {"slot": "slot-a", "amount": 0}},
        {"function": "claim", "kwargs": {"slot": "slot-a", "amount": 1}},
        {"function": "fail_after_write", "kwargs": {"key": "alpha", "value": 7}},
        {"function": "add", "kwargs": {"key": "alpha", "delta": -100}},
    ]
)
@settings(max_examples=24, deadline=None)
@given(operations=st.lists(FUZZ_OPERATION, min_size=1, max_size=12))
def test_native_vm_matches_independent_state_machine(operations: list[dict[str, Any]]):
    with tempfile.TemporaryDirectory(prefix="xian-vm-stateful-fuzz-") as tmpdir:
        contract_name = "con_vm_fuzz_probe"
        model = ReferenceState(contract_name)
        with Driver(storage_home=Path(tmpdir) / "native") as driver:
            _deploy_probe(driver, contract_name)
            expected_state = _normalize_state(driver.get_all_contract_state())
            for block_num, operation in enumerate(operations, start=1):
                before_state = dict(expected_state)
                expected = model.execute(operation)
                actual = _run_native_step(
                    driver,
                    contract_name=contract_name,
                    function_name=operation["function"],
                    kwargs=operation["kwargs"],
                    block_num=block_num,
                )
                assert actual == expected
                expected_state.update(expected["writes"])
                assert _normalize_state(driver.get_all_contract_state()) == expected_state
                if expected["status_code"] != 0:
                    assert expected_state == before_state


def test_native_vm_rolls_back_post_write_failures() -> None:
    contract_name = "con_vm_fuzz_probe"
    with tempfile.TemporaryDirectory(prefix="xian-vm-stateful-failure-") as tmpdir:
        with Driver(storage_home=Path(tmpdir)) as driver:
            _deploy_probe(driver, contract_name)
            before_state = _normalize_state(driver.get_all_contract_state())
            actual = _run_native_step(
                driver,
                contract_name=contract_name,
                function_name="fail_after_write",
                kwargs={"key": "alpha", "value": 7},
                block_num=1,
            )
            assert actual == ReferenceState.failure("forced failure")
            assert _normalize_state(driver.get_all_contract_state()) == before_state
