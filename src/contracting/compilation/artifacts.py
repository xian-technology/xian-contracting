from __future__ import annotations

import hashlib
import json
from functools import lru_cache

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.vm import XIAN_VM_V1_PROFILE

CONTRACT_ARTIFACT_FORMAT_V1 = "xian_contract_artifact_v1"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_structural_artifacts_with_native_core(
    *,
    module_name: str,
    artifacts: dict[str, object],
    input_source: str | None,
    vm_profile: str,
) -> dict[str, str | None] | None:
    try:
        from xian_vm_core import validate_deployment_artifacts_json
    except Exception:
        return None

    try:
        return validate_deployment_artifacts_json(
            module_name,
            json.dumps(artifacts, separators=(",", ":"), sort_keys=True),
            input_source=input_source,
            vm_profile=vm_profile,
        )
    except Exception as exc:
        raise ValueError(str(exc)) from exc


@lru_cache(maxsize=256)
def _compile_canonical_outputs(
    *,
    module_name: str,
    source: str,
    vm_profile: str,
) -> tuple[str, str]:
    compiler = ContractingCompiler(module_name=module_name)
    runtime_code = compiler.parse_to_code(
        source,
        lint=False,
        vm_profile=vm_profile,
    )
    vm_ir_json = compiler.lower_to_ir_json(
        source,
        lint=False,
        vm_profile=vm_profile,
        indent=None,
        sort_keys=True,
    )
    return runtime_code, vm_ir_json


def build_contract_artifacts(
    *,
    module_name: str,
    source: str,
    lint: bool = True,
    vm_profile: str = XIAN_VM_V1_PROFILE,
    compact: bool = False,
    include_runtime_code: bool = False,
) -> dict[str, object]:
    compiler = ContractingCompiler(module_name=module_name)
    normalized_source = compiler.normalize_source(
        source,
        lint=lint,
        vm_profile=vm_profile,
    )
    artifacts = {
        "format": CONTRACT_ARTIFACT_FORMAT_V1,
        "module_name": module_name,
        "vm_profile": vm_profile,
        "source": normalized_source,
        "hashes": {
            "input_source_sha256": _sha256_text(source),
            "source_sha256": _sha256_text(normalized_source),
        },
    }
    _, vm_ir_json = _compile_canonical_outputs(
        module_name=module_name,
        source=normalized_source,
        vm_profile=vm_profile,
    )
    artifacts["vm_ir_json"] = vm_ir_json
    artifacts["hashes"]["vm_ir_sha256"] = _sha256_text(vm_ir_json)
    if compact:
        return artifacts
    if include_runtime_code:
        runtime_code, _ = _compile_canonical_outputs(
            module_name=module_name,
            source=normalized_source,
            vm_profile=vm_profile,
        )
        artifacts["runtime_code"] = runtime_code
        artifacts["hashes"]["runtime_code_sha256"] = _sha256_text(runtime_code)
    return artifacts


def validate_contract_artifacts(
    *,
    module_name: str,
    artifacts: dict[str, object],
    input_source: str | None = None,
    vm_profile: str = XIAN_VM_V1_PROFILE,
) -> dict[str, str]:
    if not isinstance(artifacts, dict):
        raise TypeError("deployment_artifacts must be a dictionary.")

    if artifacts.get("format") != CONTRACT_ARTIFACT_FORMAT_V1:
        raise ValueError("deployment_artifacts has an unsupported format.")
    if artifacts.get("module_name") != module_name:
        raise ValueError(
            "deployment_artifacts module_name does not match the target contract."
        )
    if artifacts.get("vm_profile") != vm_profile:
        raise ValueError(
            "deployment_artifacts vm_profile does not match the execution profile."
        )

    source = artifacts.get("source")
    runtime_code = artifacts.get("runtime_code")
    vm_ir_json = artifacts.get("vm_ir_json")
    hashes = artifacts.get("hashes")

    if not isinstance(source, str) or source == "":
        raise ValueError(
            "deployment_artifacts must include a non-empty 'source' string."
        )
    if not isinstance(hashes, dict):
        raise ValueError(
            "deployment_artifacts must include a 'hashes' dictionary."
        )

    native_validated = _validate_structural_artifacts_with_native_core(
        module_name=module_name,
        artifacts=artifacts,
        input_source=input_source,
        vm_profile=vm_profile,
    )
    if native_validated is not None:
        source = native_validated["source"]
        runtime_code = native_validated["runtime_code"]
        vm_ir_json = native_validated["vm_ir_json"]

    has_runtime_code = isinstance(runtime_code, str) and runtime_code != ""
    has_vm_ir_json = isinstance(vm_ir_json, str) and vm_ir_json != ""
    if not has_vm_ir_json:
        raise ValueError(
            "deployment_artifacts must include a non-empty 'vm_ir_json' string."
        )

    required_hashes = {
        "source_sha256": _sha256_text(source),
        "vm_ir_sha256": _sha256_text(vm_ir_json),
    }
    if has_runtime_code:
        required_hashes["runtime_code_sha256"] = _sha256_text(runtime_code)
    if input_source is not None:
        required_hashes["input_source_sha256"] = _sha256_text(input_source)

    for hash_name, expected in required_hashes.items():
        actual = hashes.get(hash_name)
        if actual != expected:
            raise ValueError(
                f"deployment_artifacts hash mismatch for '{hash_name}'."
            )

    compiler = ContractingCompiler(module_name=module_name)
    canonical_source = compiler.normalize_source(
        source,
        lint=False,
        vm_profile=vm_profile,
    )
    if canonical_source != source:
        raise ValueError(
            "deployment_artifacts source does not match canonical normalized source."
        )

    _, canonical_vm_ir_json = _compile_canonical_outputs(
        module_name=module_name,
        source=source,
        vm_profile=vm_profile,
    )
    if canonical_vm_ir_json != vm_ir_json:
        raise ValueError(
            "deployment_artifacts vm_ir_json does not match canonical compiler output."
        )

    return {
        "source": source,
        "runtime_code": runtime_code if has_runtime_code else None,
        "vm_ir_json": vm_ir_json,
    }
