from __future__ import annotations

import hashlib
from functools import lru_cache

from contracting.compilation.compiler import ContractingCompiler
from contracting.compilation.vm import XIAN_VM_V1_PROFILE

CONTRACT_ARTIFACT_FORMAT_V1 = "xian_contract_artifact_v1"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
) -> dict[str, object]:
    compiler = ContractingCompiler(module_name=module_name)
    normalized_source = compiler.normalize_source(
        source,
        lint=lint,
        vm_profile=vm_profile,
    )
    runtime_code, vm_ir_json = _compile_canonical_outputs(
        module_name=module_name,
        source=normalized_source,
        vm_profile=vm_profile,
    )
    return {
        "format": CONTRACT_ARTIFACT_FORMAT_V1,
        "module_name": module_name,
        "vm_profile": vm_profile,
        "source": normalized_source,
        "runtime_code": runtime_code,
        "vm_ir_json": vm_ir_json,
        "hashes": {
            "input_source_sha256": _sha256_text(source),
            "source_sha256": _sha256_text(normalized_source),
            "runtime_code_sha256": _sha256_text(runtime_code),
            "vm_ir_sha256": _sha256_text(vm_ir_json),
        },
    }


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
        raise ValueError(
            "deployment_artifacts has an unsupported format."
        )
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
    if not isinstance(runtime_code, str) or runtime_code == "":
        raise ValueError(
            "deployment_artifacts must include a non-empty 'runtime_code' string."
        )
    if not isinstance(vm_ir_json, str) or vm_ir_json == "":
        raise ValueError(
            "deployment_artifacts must include a non-empty 'vm_ir_json' string."
        )
    if not isinstance(hashes, dict):
        raise ValueError(
            "deployment_artifacts must include a 'hashes' dictionary."
        )

    required_hashes = {
        "source_sha256": _sha256_text(source),
        "runtime_code_sha256": _sha256_text(runtime_code),
        "vm_ir_sha256": _sha256_text(vm_ir_json),
    }
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

    canonical_runtime_code, canonical_vm_ir_json = _compile_canonical_outputs(
        module_name=module_name,
        source=source,
        vm_profile=vm_profile,
    )
    if canonical_runtime_code != runtime_code:
        raise ValueError(
            "deployment_artifacts runtime_code does not match canonical compiler output."
        )

    if canonical_vm_ir_json != vm_ir_json:
        raise ValueError(
            "deployment_artifacts vm_ir_json does not match canonical compiler output."
        )

    return {
        "source": source,
        "runtime_code": runtime_code,
        "vm_ir_json": vm_ir_json,
    }
