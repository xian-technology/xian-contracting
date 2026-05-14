from __future__ import annotations

import hashlib
from functools import lru_cache

import xian_compiler_core

from contracting.compilation.vm import XIAN_VM_V1_PROFILE

CONTRACT_ARTIFACT_FORMAT_V1 = "xian_contract_artifact_v1"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@lru_cache(maxsize=256)
def _compile_canonical_ir(
    *,
    module_name: str,
    source: str,
    vm_profile: str,
) -> str:
    return xian_compiler_core.lower_source_to_ir_json(
        module_name,
        source,
        lint=False,
        vm_profile=vm_profile,
    )


def build_contract_artifacts(
    *,
    module_name: str,
    source: str,
    lint: bool = True,
    vm_profile: str = XIAN_VM_V1_PROFILE,
    compact: bool = False,
) -> dict[str, object]:
    return xian_compiler_core.compile_contract_artifact(
        module_name,
        source,
        lint=lint,
        vm_profile=vm_profile,
    )


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
    vm_ir_json = artifacts.get("vm_ir_json")
    hashes = artifacts.get("hashes")
    if "runtime_code" in artifacts:
        raise ValueError("deployment_artifacts must not include runtime_code.")

    if not isinstance(source, str) or source == "":
        raise ValueError(
            "deployment_artifacts must include a non-empty 'source' string."
        )
    if not isinstance(hashes, dict):
        raise ValueError(
            "deployment_artifacts must include a 'hashes' dictionary."
        )

    try:
        native_validated = xian_compiler_core.validate_contract_artifact(
            module_name,
            artifacts,
            input_source=input_source,
        )
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    source = native_validated["source"]
    vm_ir_json = native_validated["vm_ir_json"]

    has_vm_ir_json = isinstance(vm_ir_json, str) and vm_ir_json != ""
    if not has_vm_ir_json:
        raise ValueError(
            "deployment_artifacts must include a non-empty 'vm_ir_json' string."
        )

    required_hashes = {
        "source_sha256": _sha256_text(source),
        "vm_ir_sha256": _sha256_text(vm_ir_json),
    }
    if "runtime_code_sha256" in hashes:
        raise ValueError(
            "deployment_artifacts hashes must not include runtime_code_sha256."
        )
    if input_source is not None:
        required_hashes["input_source_sha256"] = _sha256_text(input_source)

    for hash_name, expected in required_hashes.items():
        actual = hashes.get(hash_name)
        if actual != expected:
            raise ValueError(
                f"deployment_artifacts hash mismatch for '{hash_name}'."
            )

    canonical_source = xian_compiler_core.normalize_source(
        module_name,
        source,
        lint=False,
        vm_profile=vm_profile,
    )
    if canonical_source != source:
        raise ValueError(
            "deployment_artifacts source does not match canonical normalized source."
        )

    canonical_vm_ir_json = _compile_canonical_ir(
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
        "vm_ir_json": vm_ir_json,
    }
