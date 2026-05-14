from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from contracting.artifacts import build_contract_artifacts
from contracting.compilation.vm import XIAN_VM_V1_PROFILE

COMPILER_FIXTURE_SCHEMA_V1 = "xian.compiler_fixture.v1"
COMPILER_FIXTURE_GENERATOR = "python-contracting"


def infer_module_name(path: Path) -> str:
    filename = path.name
    if filename.endswith(".s.py"):
        return filename[: -len(".s.py")]
    return path.stem


def fixture_name_for_module(module_name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_]+", "_", module_name).strip("_")
    return slug or "contract"


def build_compiler_fixture(
    *,
    module_name: str,
    source: str,
    name: str | None = None,
    source_path: str | None = None,
    vm_profile: str = XIAN_VM_V1_PROFILE,
    lint: bool = True,
) -> dict[str, Any]:
    fixture: dict[str, Any] = {
        "schema": COMPILER_FIXTURE_SCHEMA_V1,
        "name": name or fixture_name_for_module(module_name),
        "generator": {
            "name": COMPILER_FIXTURE_GENERATOR,
            "artifact_format": "xian_contract_artifact_v1",
        },
        "module_name": module_name,
        "vm_profile": vm_profile,
        "input_source": source,
        "expected": {"accepted": True},
        "diagnostics": [],
    }
    if source_path is not None:
        fixture["source_path"] = source_path

    try:
        artifacts = build_contract_artifacts(
            module_name=module_name,
            source=source,
            lint=lint,
            vm_profile=vm_profile,
        )
    except Exception as exc:
        fixture["expected"] = {"accepted": False}
        fixture["diagnostics"] = [
            {
                "severity": "error",
                "code": f"python_contracting.{type(exc).__name__}",
                "message": str(exc),
            }
        ]
        return fixture

    fixture["normalized_source"] = artifacts["source"]
    fixture["artifact"] = artifacts
    fixture["vm_ir"] = json.loads(str(artifacts["vm_ir_json"]))
    return fixture


def build_compiler_fixture_from_path(
    path: Path,
    *,
    vm_profile: str = XIAN_VM_V1_PROFILE,
    lint: bool = True,
) -> dict[str, Any]:
    path = path.resolve()
    try:
        display_path = str(path.relative_to(Path.cwd().resolve()))
    except ValueError:
        display_path = str(path)
    module_name = infer_module_name(path)
    return build_compiler_fixture(
        module_name=module_name,
        source=path.read_text(encoding="utf-8"),
        name=fixture_name_for_module(module_name),
        source_path=display_path,
        vm_profile=vm_profile,
        lint=lint,
    )


def write_compiler_fixture(path: Path, fixture: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(fixture, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


__all__ = [
    "COMPILER_FIXTURE_GENERATOR",
    "COMPILER_FIXTURE_SCHEMA_V1",
    "build_compiler_fixture",
    "build_compiler_fixture_from_path",
    "fixture_name_for_module",
    "infer_module_name",
    "write_compiler_fixture",
]
