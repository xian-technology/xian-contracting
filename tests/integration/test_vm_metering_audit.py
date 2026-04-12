from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "audit_vm_metering.py"


def _load_audit_vm_metering():
    spec = importlib.util.spec_from_file_location("audit_vm_metering", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("audit_vm_metering", module)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(
    sys.version_info < (3, 12), reason="native_instruction_v1 requires Python 3.12+"
)
def test_vm_metering_is_not_lower_than_native_instruction():
    pytest.importorskip("xian_vm_core")
    audit_vm_metering = _load_audit_vm_metering()

    try:
        audit_vm_metering._require_native_instruction_tracer()
    except RuntimeError as exc:
        pytest.skip(str(exc))

    report = audit_vm_metering.audit_metering()

    assert all(item["status_code_match"] for item in report["observations"])
    assert all(item["result_match"] for item in report["observations"])
    assert report["under_metered"] == []
    assert report["authored_under_metered"] == []
    assert report["authored_min_ratio_vs_native"] >= 1.0
    assert report["authored_max_ratio_vs_native"] <= 2.4
    assert report["max_ratio_vs_native"] <= 2.55
