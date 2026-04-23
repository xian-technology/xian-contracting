from __future__ import annotations

import decimal
import tempfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime

from contracting.execution.executor import Executor
from contracting.storage.driver import Driver

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
        return {
            str(key): _normalize(item) for key, item in sorted(value.items())
        }
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value


def _normalize_state(state: dict[str, Any]) -> dict[str, Any]:
    normalized = {
        key: _normalize(value) for key, value in sorted(state.items())
    }
    normalized.pop("submission.__submitted__", None)
    return normalized


def _deploy_probe(driver: Driver, contract_name: str) -> None:
    driver.set_contract_from_source(
        contract_name,
        PARITY_FUZZ_SOURCE,
        owner="alice",
        overwrite=True,
        timestamp=FIXED_TIMESTAMP,
    )
    driver.commit()


def _run_python_step(
    driver: Driver,
    *,
    contract_name: str,
    function_name: str,
    kwargs: dict[str, Any],
    block_num: int,
) -> dict[str, Any]:
    executor = Executor(driver=driver, metering=False)
    output = executor.execute(
        sender="alice",
        contract_name=contract_name,
        function_name=function_name,
        kwargs=dict(kwargs),
        environment=_execution_context(
            contract_name,
            function_name,
            "alice",
            block_num=block_num,
        ),
        metering=False,
        chi=10_000,
        auto_commit=False,
    )
    if output["status_code"] == 0:
        driver.commit()
    return {
        "status_code": output["status_code"],
        "result": _normalize(output["result"]),
        "writes": _normalize(output["writes"]),
        "events": _normalize(output["events"]),
    }


def _run_native_step(
    driver: Driver,
    *,
    contract_name: str,
    function_name: str,
    kwargs: dict[str, Any],
    block_num: int,
) -> dict[str, Any]:
    import xian_vm_core

    output = xian_vm_core.execute_contract(
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


@settings(max_examples=24, deadline=None)
@given(operations=st.lists(FUZZ_OPERATION, min_size=1, max_size=12))
def test_python_and_native_vm_match_for_stateful_sequences(
    operations: list[dict[str, Any]],
):
    with tempfile.TemporaryDirectory(prefix="xian-vm-stateful-fuzz-") as tmpdir:
        contract_name = "con_vm_fuzz_probe"
        python_driver = Driver(storage_home=Path(tmpdir) / "python")
        native_driver = Driver(storage_home=Path(tmpdir) / "native")
        _deploy_probe(python_driver, contract_name)
        _deploy_probe(native_driver, contract_name)

        for block_num, operation in enumerate(operations, start=1):
            before_python_state = _normalize_state(
                python_driver.get_all_contract_state()
            )
            before_native_state = _normalize_state(
                native_driver.get_all_contract_state()
            )
            assert before_python_state == before_native_state

            python_output = _run_python_step(
                python_driver,
                contract_name=contract_name,
                function_name=operation["function"],
                kwargs=operation["kwargs"],
                block_num=block_num,
            )
            native_output = _run_native_step(
                native_driver,
                contract_name=contract_name,
                function_name=operation["function"],
                kwargs=operation["kwargs"],
                block_num=block_num,
            )

            assert native_output == python_output

            after_python_state = _normalize_state(
                python_driver.get_all_contract_state()
            )
            after_native_state = _normalize_state(
                native_driver.get_all_contract_state()
            )
            assert after_native_state == after_python_state

            if python_output["status_code"] != 0:
                assert after_python_state == before_python_state


def test_python_and_native_vm_roll_back_post_write_failures() -> None:
    contract_name = "con_vm_fuzz_probe"
    with tempfile.TemporaryDirectory(prefix="xian-vm-stateful-failure-") as tmpdir:
        python_driver = Driver(storage_home=Path(tmpdir) / "python")
        native_driver = Driver(storage_home=Path(tmpdir) / "native")
        _deploy_probe(python_driver, contract_name)
        _deploy_probe(native_driver, contract_name)
        before_state = _normalize_state(python_driver.get_all_contract_state())

        kwargs = {"key": "alpha", "value": 7}
        python_output = _run_python_step(
            python_driver,
            contract_name=contract_name,
            function_name="fail_after_write",
            kwargs=kwargs,
            block_num=1,
        )
        native_output = _run_native_step(
            native_driver,
            contract_name=contract_name,
            function_name="fail_after_write",
            kwargs=kwargs,
            block_num=1,
        )

        assert python_output["status_code"] == 1
        assert python_output["writes"] == {}
        assert python_output["events"] == []
        assert native_output == python_output
        assert _normalize_state(python_driver.get_all_contract_state()) == before_state
        assert _normalize_state(native_driver.get_all_contract_state()) == before_state
