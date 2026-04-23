from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "audit_vm_metering.py"
pytestmark = pytest.mark.optional_native


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


def test_vm_metering_is_not_lower_than_native_instruction():
    audit_vm_metering = _load_audit_vm_metering()

    audit_vm_metering._require_native_instruction_tracer()
    report = audit_vm_metering.audit_metering()

    assert all(item["status_code_match"] for item in report["observations"])
    assert all(item["result_match"] for item in report["observations"])
    assert report["under_metered"] == []
    assert report["authored_under_metered"] == []
    assert report["authored_min_ratio_vs_native"] >= 1.0
    assert report["authored_max_ratio_vs_native"] <= 2.4
    assert report["max_ratio_vs_native"] <= 2.55
