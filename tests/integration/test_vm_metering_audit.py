from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "audit_vm_metering.py"
pytestmark = pytest.mark.optional_native

# CPython 3.14's interpreter dispatch lowers the Python tracer's raw
# instruction count for several workloads, so ratio ceilings are calibrated by
# interpreter family while still requiring the VM to never under-meter.
AUTHORED_MAX_RATIO_LIMIT = 2.5 if sys.version_info >= (3, 14) else 2.4
MAX_RATIO_LIMIT = 2.7 if sys.version_info >= (3, 14) else 2.55


def _load_audit_vm_metering():
    spec = importlib.util.spec_from_file_location(
        "audit_vm_metering", SCRIPT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("audit_vm_metering", module)
    spec.loader.exec_module(module)
    return module


def _max_observation(report: dict, *, authored: bool = False) -> dict:
    observations = report["observations"]
    if authored:
        observations = [
            item
            for item in observations
            if item["name"].startswith("authored_")
        ]
    return max(observations, key=lambda item: item["ratio_vs_native"])


def test_vm_metering_is_not_lower_than_native_instruction():
    audit_vm_metering = _load_audit_vm_metering()

    audit_vm_metering._require_native_instruction_tracer()
    report = audit_vm_metering.audit_metering()
    authored_max = _max_observation(report, authored=True)
    overall_max = _max_observation(report)

    assert all(item["status_code_match"] for item in report["observations"])
    assert all(item["result_match"] for item in report["observations"])
    assert report["under_metered"] == []
    assert report["authored_under_metered"] == []
    assert report["authored_min_ratio_vs_native"] >= 1.0
    assert authored_max["ratio_vs_native"] <= AUTHORED_MAX_RATIO_LIMIT, (
        authored_max
    )
    assert overall_max["ratio_vs_native"] <= MAX_RATIO_LIMIT, overall_max
