import json

import pytest

from contracting.artifacts import (
    build_contract_artifacts,
    validate_contract_artifacts,
)
from contracting.compilation import artifacts as artifacts_module


def test_validate_contract_artifacts_accepts_canonical_bundle() -> None:
    source = "@export\ndef ping():\n    return 'pong'\n"
    artifacts = build_contract_artifacts(
        module_name="con_probe",
        source=source,
        vm_profile="xian_vm_v1",
    )

    validated = validate_contract_artifacts(
        module_name="con_probe",
        artifacts=artifacts,
        vm_profile="xian_vm_v1",
    )

    assert validated["source"] == artifacts["source"]
    assert validated["vm_ir_json"] == artifacts["vm_ir_json"]


def test_validate_contract_artifacts_accepts_compact_bundle() -> None:
    source = "@export\ndef ping():\n    return 'pong'\n"
    artifacts = build_contract_artifacts(
        module_name="con_probe",
        source=source,
        vm_profile="xian_vm_v1",
        compact=True,
    )

    validated = validate_contract_artifacts(
        module_name="con_probe",
        artifacts=artifacts,
        vm_profile="xian_vm_v1",
    )

    assert validated["source"] == artifacts["source"]
    assert validated["vm_ir_json"] == artifacts["vm_ir_json"]


def test_validate_contract_artifacts_rejects_mixed_source_and_runtime() -> None:
    source_a = "@export\ndef ping():\n    return 'A'\n"
    source_b = "@export\ndef ping():\n    return 'B'\n"
    artifacts_a = build_contract_artifacts(
        module_name="con_probe",
        source=source_a,
        vm_profile="xian_vm_v1",
    )
    artifacts_b = build_contract_artifacts(
        module_name="con_probe",
        source=source_b,
        vm_profile="xian_vm_v1",
    )

    forged = dict(artifacts_b)
    forged["source"] = artifacts_a["source"]
    forged["hashes"] = dict(artifacts_b["hashes"])
    forged["hashes"]["source_sha256"] = artifacts_a["hashes"][
        "source_sha256"
    ]

    with pytest.raises(
        ValueError,
        match=(
            "vm_ir_json does not match canonical compiler output"
            "|artifact.vm_ir.source_hash"
        ),
    ):
        validate_contract_artifacts(
            module_name="con_probe",
            artifacts=forged,
            vm_profile="xian_vm_v1",
        )


def test_build_contract_artifacts_records_explicit_hash_syscall() -> None:
    source = (
        "@export\n"
        "def digest(value: str):\n"
        "    return hashlib.sha3_text(value)\n"
    )

    artifacts = build_contract_artifacts(
        module_name="con_hash_probe",
        source=source,
        vm_profile="xian_vm_v1",
    )
    vm_ir = json.loads(artifacts["vm_ir_json"])

    assert "hash.sha3_256_text" in artifacts["vm_ir_json"]
    call = vm_ir["functions"][0]["body"][0]["value"]
    assert call["syscall_id"] == "hash.sha3_256_text"
    assert call["func"]["host_binding_id"] == "hash.sha3_256_text"


def test_build_contract_artifacts_rejects_stale_native_host_surface(
    monkeypatch,
) -> None:
    native_surface = artifacts_module.xian_compiler_core.describe_vm_host_surface()
    stale_surface = {
        "catalog_version": native_surface["catalog_version"],
        "bindings": [
            binding
            for binding in native_surface["bindings"]
            if binding["binding"] != "hashlib.sha3_text"
        ],
    }

    monkeypatch.setattr(
        artifacts_module.xian_compiler_core,
        "describe_vm_host_surface",
        lambda: stale_surface,
    )
    artifacts_module._assert_native_compiler_host_surface_current.cache_clear()
    try:
        with pytest.raises(
            RuntimeError,
            match=(
                "xian_compiler_core host catalog is stale.*"
                "hashlib\\.sha3_text"
            ),
        ):
            build_contract_artifacts(
                module_name="con_hash_probe",
                source=(
                    "@export\n"
                    "def digest(value: str):\n"
                    "    return hashlib.sha3_text(value)\n"
                ),
                vm_profile="xian_vm_v1",
            )
    finally:
        artifacts_module._assert_native_compiler_host_surface_current.cache_clear()
