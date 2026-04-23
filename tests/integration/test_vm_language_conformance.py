from __future__ import annotations

import decimal
from pathlib import Path

import pytest
from xian_runtime_types.collections import ContractingFrozenSet, ContractingSet
from xian_runtime_types.decimal import ContractingDecimal
from xian_runtime_types.time import Datetime, Timedelta

from contracting.compilation.conformance import (
    CONTRACT_LANGUAGE_CONFORMANCE_CASES,
)
from contracting.execution.executor import Executor
from contracting.storage.driver import Driver

pytestmark = pytest.mark.optional_native

NATIVE_VM_XFAIL_REASONS = {
    "contract_metadata_owner_protected": (
        "native VM reports metadata authorization errors with a different "
        "exception shape than the Python VM"
    ),
    "contract_metadata_developer_protected": (
        "native VM reports metadata authorization errors with a different "
        "exception shape than the Python VM"
    ),
    "binary_values": (
        "native VM and Python VM currently diverge on binary value helper "
        "semantics"
    ),
    "dynamic_private_call_rejected": (
        "native VM reports private dynamic call rejection with a different "
        "error message than the Python VM"
    ),
    "token_allowance_event_flow": (
        "native VM reports this token assertion path with a different error "
        "shape than the Python VM"
    ),
    "replay_submission_deploy_flow": (
        "native VM reports metadata authorization errors with a different "
        "exception shape than the Python VM"
    ),
}


def _case_param(case: dict):
    reason = NATIVE_VM_XFAIL_REASONS.get(case["id"])
    if reason is None:
        return pytest.param(case, id=case["id"])
    return pytest.param(
        case,
        id=case["id"],
        marks=pytest.mark.xfail(strict=True, reason=reason),
    )


def _execution_context(
    contract_name: str, function_name: str, owner: str
) -> dict:
    now = Datetime(2026, 4, 13, 12, 0, 0)
    return {
        "signer": "alice",
        "caller": "alice",
        "this": contract_name,
        "entry": (contract_name, function_name),
        "owner": owner,
        "submission_name": None,
        "now": now,
        "block_num": 7,
        "block_hash": "abcd1234",
        "chain_id": "xian-test",
    }


def _normalize(value):
    if isinstance(value, BaseException):
        return {
            "exception": type(value).__name__,
            "args": [_normalize(item) for item in value.args],
        }
    if isinstance(value, ContractingDecimal | decimal.Decimal):
        return {"__decimal__": str(value)}
    if isinstance(value, Datetime):
        return {"__datetime__": str(value)}
    if isinstance(value, Timedelta):
        return {"__timedelta__": str(value)}
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    if isinstance(value, bytearray):
        return {"__bytearray__": value.hex()}
    if isinstance(value, ContractingSet):
        return {"__set__": [_normalize(item) for item in value]}
    if isinstance(value, ContractingFrozenSet):
        return {"__frozenset__": [_normalize(item) for item in value]}
    if isinstance(value, dict):
        return {
            str(key): _normalize(item) for key, item in sorted(value.items())
        }
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value


def _filter_case_writes(writes, case: dict):
    ignore_suffixes = tuple(case.get("ignore_write_suffixes", ()))
    if not ignore_suffixes:
        return writes
    if isinstance(writes, dict):
        return {
            key: value
            for key, value in writes.items()
            if not any(str(key).endswith(suffix) for suffix in ignore_suffixes)
        }
    if isinstance(writes, list):
        filtered = []
        for item in writes:
            if isinstance(item, dict) and "key" in item:
                if any(
                    str(item["key"]).endswith(suffix)
                    for suffix in ignore_suffixes
                ):
                    continue
            filtered.append(item)
        return filtered
    return writes


def _deploy_case_contracts(
    driver: Driver, case: dict, contract_name: str
) -> None:
    for dependency in case.get("dependencies", ()):
        driver.set_contract_from_source(
            dependency["name"],
            dependency["source"],
            owner=dependency.get("owner", "alice"),
            overwrite=True,
        )
    driver.set_contract_from_source(
        contract_name,
        case["source"],
        owner="alice",
        overwrite=True,
    )
    driver.commit()


def _run_python_case(case: dict, storage_home: Path) -> dict:
    driver = Driver(storage_home=storage_home)
    contract_name = f"conformance_{case['id']}"
    driver.flush_full()
    _deploy_case_contracts(driver, case, contract_name)
    executor = Executor(driver=driver, metering=False)
    context = _execution_context(contract_name, case["function_name"], "alice")
    output = executor.execute(
        sender="alice",
        contract_name=contract_name,
        function_name=case["function_name"],
        kwargs=dict(case["kwargs"]),
        environment=context,
        metering=False,
        chi=10_000,
    )
    return {
        "status_code": output["status_code"],
        "result": _normalize(output["result"]),
        "writes": _normalize(_filter_case_writes(output["writes"], case)),
        "events": _normalize(output["events"]),
    }


def _run_native_case(case: dict, storage_home: Path) -> dict:
    import xian_vm_core

    driver = Driver(storage_home=storage_home)
    contract_name = f"conformance_{case['id']}"
    driver.flush_full()
    _deploy_case_contracts(driver, case, contract_name)
    context = _execution_context(contract_name, case["function_name"], "alice")
    output = xian_vm_core.execute_contract(
        driver=driver,
        contract_name=contract_name,
        function_name=case["function_name"],
        kwargs=dict(case["kwargs"]),
        context=context,
        meter=False,
    )
    return {
        "status_code": output.status_code,
        "result": _normalize(output.result),
        "writes": _normalize(_filter_case_writes(output.writes, case)),
        "events": _normalize(output.events),
    }


@pytest.mark.parametrize(
    "case",
    [_case_param(case) for case in CONTRACT_LANGUAGE_CONFORMANCE_CASES],
)
def test_python_and_xian_vm_match_for_conformance_cases(
    tmp_path: Path, case: dict
):
    python_output = _run_python_case(case, tmp_path / "python")
    native_output = _run_native_case(case, tmp_path / "native")

    assert native_output == python_output, case["description"]
