from __future__ import annotations

import json
from typing import Any

from ._native import (
    CONTRACT_ARTIFACT_FORMAT_V1,
    DEFAULT_VM_PROFILE,
    SUPPORTED_VM_PROFILES,
    XIAN_VM_V1_PROFILE,
    XIAN_VM_V2_PROFILE,
    CompilerError,
    compile_contract_artifact_json,
    compile_contract_source_json,
    compiler_version_json,
    diagnose_contract_json,
    host_surface_json,
    validate_contract_artifact_json,
)
from ._native import (
    lower_source_to_ir_json as _lower_source_to_ir_json,
)
from ._native import (
    normalize_source as _normalize_source,
)


def _options_json(
    *,
    vm_profile: str | None = None,
    lint: bool = True,
) -> str:
    options: dict[str, Any] = {"lint": lint}
    if vm_profile is not None:
        options["vm_profile"] = vm_profile
    return json.dumps(
        options,
        separators=(",", ":"),
        sort_keys=True,
    )


def compiler_version() -> dict[str, Any]:
    return json.loads(compiler_version_json())


def describe_vm_host_surface() -> dict[str, Any]:
    return json.loads(host_surface_json())


def diagnose_contract(
    module_name: str,
    source: str,
    *,
    vm_profile: str | None = None,
    lint: bool = True,
) -> list[dict[str, Any]]:
    return json.loads(
        diagnose_contract_json(
            module_name,
            source,
            options_json=_options_json(vm_profile=vm_profile, lint=lint),
        )
    )


def normalize_source(
    module_name: str,
    source: str,
    *,
    vm_profile: str | None = None,
    lint: bool = True,
) -> str:
    return _normalize_source(
        module_name,
        source,
        options_json=_options_json(vm_profile=vm_profile, lint=lint),
    )


def lower_source_to_ir_json(
    module_name: str,
    source: str,
    *,
    vm_profile: str | None = None,
    lint: bool = True,
) -> str:
    return _lower_source_to_ir_json(
        module_name,
        source,
        options_json=_options_json(vm_profile=vm_profile, lint=lint),
    )


def lower_source_to_ir(
    module_name: str,
    source: str,
    *,
    vm_profile: str | None = None,
    lint: bool = True,
) -> dict[str, Any]:
    return json.loads(
        lower_source_to_ir_json(
            module_name,
            source,
            vm_profile=vm_profile,
            lint=lint,
        )
    )


def compile_contract_artifact(
    module_name: str,
    source: str,
    *,
    vm_profile: str | None = None,
    lint: bool = True,
) -> dict[str, Any]:
    return json.loads(
        compile_contract_artifact_json(
            module_name,
            source,
            options_json=_options_json(vm_profile=vm_profile, lint=lint),
        )
    )


def compile_contract_source(
    module_name: str,
    source: str,
    *,
    vm_profile: str | None = None,
    lint: bool = True,
) -> dict[str, str]:
    """Return the normalized source and canonical IR a node deploys for ``source``."""
    return json.loads(
        compile_contract_source_json(
            module_name,
            source,
            options_json=_options_json(vm_profile=vm_profile, lint=lint),
        )
    )


def validate_contract_artifact(
    module_name: str,
    artifact: dict[str, Any],
    *,
    input_source: str | None = None,
) -> dict[str, str]:
    return json.loads(
        validate_contract_artifact_json(
            module_name,
            json.dumps(artifact, separators=(",", ":"), sort_keys=True),
            input_source=input_source,
        )
    )


__all__ = [
    "CONTRACT_ARTIFACT_FORMAT_V1",
    "DEFAULT_VM_PROFILE",
    "SUPPORTED_VM_PROFILES",
    "XIAN_VM_V1_PROFILE",
    "XIAN_VM_V2_PROFILE",
    "CompilerError",
    "compile_contract_artifact",
    "compile_contract_source",
    "compiler_version",
    "describe_vm_host_surface",
    "diagnose_contract",
    "lower_source_to_ir",
    "lower_source_to_ir_json",
    "normalize_source",
    "validate_contract_artifact",
]
