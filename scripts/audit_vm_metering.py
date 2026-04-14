from __future__ import annotations

import argparse
import importlib
import json
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from contracting.client import ContractingClient
from contracting.execution.tracer import create_tracer

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

generate_vm_parity_fixtures = importlib.import_module(
    "generate_vm_parity_fixtures"
)
FIXTURES = generate_vm_parity_fixtures.FIXTURES
_execute_call = generate_vm_parity_fixtures._execute_call
_json_value = generate_vm_parity_fixtures._json_value
_module_source = generate_vm_parity_fixtures._module_source
_set_seed_state = generate_vm_parity_fixtures._set_seed_state


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(slots=True)
class MeteringObservation:
    name: str
    python_raw_cost: int
    vm_raw_cost: int
    python_chi_used: int
    vm_chi_used: int
    raw_cost_delta: int
    ratio_vs_native: float
    status_code_match: bool
    result_match: bool


def _require_native_instruction_tracer() -> None:
    if sys.version_info < (3, 12):
        raise RuntimeError("native_instruction_v1 requires Python 3.12+")
    tracer = create_tracer("native_instruction_v1")
    tracer.reset()


def _require_native_vm() -> Any:
    try:
        from xian_vm_core import execute_contract
    except ImportError as exc:  # pragma: no cover - exercised by test skip path
        raise RuntimeError(
            "xian_vm_core is not installed. Build it with "
            "`uvx maturin develop --manifest-path packages/xian-vm-core/Cargo.toml`."
        ) from exc
    return execute_contract


def _resolved_call_module(spec: dict[str, Any]) -> str:
    if "modules" in spec:
        return spec["call"]["module"]
    return spec["module_name"]


def _transaction_size_bytes(spec: dict[str, Any]) -> int:
    payload = {
        "contract_name": _resolved_call_module(spec),
        "function_name": spec["call"]["function"],
        "args": [_json_value(value) for value in spec["call"].get("args", [])],
        "kwargs": {
            key: _json_value(value)
            for key, value in spec["call"].get("kwargs", {}).items()
        },
        "context": {
            key: _json_value(value) for key, value in spec["context"].items()
        },
    }
    return len(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    )


def _normalised_result(value: Any) -> Any:
    return _json_value(value)


def _prepare_client(
    spec: dict[str, Any],
    *,
    tracer_mode: str | None,
) -> tuple[tempfile.TemporaryDirectory[str], ContractingClient]:
    tempdir = tempfile.TemporaryDirectory(prefix="xian-vm-metering-")
    client = ContractingClient(
        signer=spec["context"]["signer"],
        storage_home=Path(tempdir.name),
        metering=False,
        tracer_mode=tracer_mode,
    )
    client.executor.bypass_balance_amount = True

    if "modules" in spec:
        modules = spec["modules"]
    else:
        modules = [spec]

    for module in modules:
        client.submit(
            _module_source(module),
            name=module["module_name"],
            owner=module.get("owner"),
            constructor_args=module.get("constructor_args", {}),
            signer=spec["context"]["signer"],
        )

    for module in modules:
        _set_seed_state(client, module["module_name"], module.get("seed", {}))

    default_module_name = _resolved_call_module(spec)
    for setup_call in spec.get("setup_calls", []):
        _execute_call(client, default_module_name, spec["context"], setup_call)

    return tempdir, client


def _python_meter_run(spec: dict[str, Any]) -> dict[str, Any]:
    tempdir, client = _prepare_client(spec, tracer_mode="native_instruction_v1")
    try:
        output = client.executor.execute(
            sender=spec["context"]["signer"],
            contract_name=_resolved_call_module(spec),
            function_name=spec["call"]["function"],
            kwargs=spec["call"].get("kwargs", {}),
            environment={
                "now": spec["context"]["now"],
                "block_num": spec["context"]["block_num"],
                "block_hash": spec["context"]["block_hash"],
                "chain_id": spec["context"]["chain_id"],
            },
            metering=True,
            auto_commit=False,
            transaction_size_bytes=_transaction_size_bytes(spec),
        )
        return {
            "status_code": int(output["status_code"]),
            "result": _normalised_result(output["result"]),
            "chi_used": int(output["chi_used"]),
            "raw_cost": int(sum(output["contract_costs"].values())),
            "contract_costs": dict(output["contract_costs"]),
        }
    finally:
        client.flush()
        tempdir.cleanup()


def _native_vm_meter_run(spec: dict[str, Any]) -> dict[str, Any]:
    execute_contract = _require_native_vm()
    tempdir, client = _prepare_client(spec, tracer_mode=None)
    try:
        output = execute_contract(
            driver=client.raw_driver,
            contract_name=_resolved_call_module(spec),
            function_name=spec["call"]["function"],
            args=spec["call"].get("args", []),
            kwargs=spec["call"].get("kwargs", {}),
            context=spec["context"],
            meter=True,
            chi_budget_raw=50_000_000_000,
            transaction_size_bytes=_transaction_size_bytes(spec),
        )
        return {
            "status_code": int(output.status_code),
            "result": _normalised_result(output.result),
            "chi_used": int(output.chi_used),
            "raw_cost": int(sum(output.contract_costs.values())),
            "contract_costs": dict(output.contract_costs),
        }
    finally:
        client.flush()
        tempdir.cleanup()


def audit_metering(
    fixture_names: list[str] | None = None,
) -> dict[str, Any]:
    _require_native_instruction_tracer()
    selected = {
        spec["name"]: spec
        for spec in FIXTURES
        if fixture_names is None or spec["name"] in fixture_names
    }
    if fixture_names is not None:
        missing = sorted(set(fixture_names) - set(selected))
        if missing:
            raise RuntimeError(f"unknown metering fixtures: {missing}")

    observations: list[MeteringObservation] = []
    under_metered: list[str] = []
    for spec in selected.values():
        python_run = _python_meter_run(spec)
        native_run = _native_vm_meter_run(spec)
        observation = MeteringObservation(
            name=spec["name"],
            python_raw_cost=python_run["raw_cost"],
            vm_raw_cost=native_run["raw_cost"],
            python_chi_used=python_run["chi_used"],
            vm_chi_used=native_run["chi_used"],
            raw_cost_delta=native_run["raw_cost"] - python_run["raw_cost"],
            ratio_vs_native=(
                native_run["raw_cost"] / python_run["raw_cost"]
                if python_run["raw_cost"] > 0
                else 0.0
            ),
            status_code_match=python_run["status_code"]
            == native_run["status_code"],
            result_match=python_run["result"] == native_run["result"],
        )
        if observation.vm_raw_cost < observation.python_raw_cost:
            under_metered.append(observation.name)
        observations.append(observation)

    observations.sort(key=lambda item: item.name)
    ratios = [
        item.ratio_vs_native
        for item in observations
        if item.python_raw_cost > 0
    ]
    authored = [
        item for item in observations if item.name.startswith("authored_")
    ]
    authored_ratios = [
        item.ratio_vs_native for item in authored if item.python_raw_cost > 0
    ]
    authored_under_metered = [
        item.name
        for item in authored
        if item.vm_raw_cost < item.python_raw_cost
    ]
    return {
        "fixtures_scanned": len(observations),
        "under_metered": under_metered,
        "max_ratio_vs_native": max(ratios) if ratios else 0.0,
        "min_ratio_vs_native": min(ratios) if ratios else 0.0,
        "authored_fixtures_scanned": len(authored),
        "authored_under_metered": authored_under_metered,
        "authored_max_ratio_vs_native": max(authored_ratios)
        if authored_ratios
        else 0.0,
        "authored_min_ratio_vs_native": min(authored_ratios)
        if authored_ratios
        else 0.0,
        "observations": [asdict(item) for item in observations],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit xian_vm_v1 metering against native_instruction_v1."
    )
    parser.add_argument(
        "fixtures",
        nargs="*",
        help="Optional fixture names to audit. Defaults to the full authored corpus.",
    )
    args = parser.parse_args()
    report = audit_metering(args.fixtures or None)
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["under_metered"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
