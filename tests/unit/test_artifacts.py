import json

import pytest

from contracting.artifacts import (
    build_contract_artifacts,
    compile_contract_source,
    diagnose_contract_source,
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


def test_build_contract_artifacts_accepts_the_compatibility_compact_flag() -> None:
    source = "@export\ndef ping():\n    return 'pong'\n"
    for compact in (False, True):
        assert build_contract_artifacts(
            module_name="con_probe", source=source, vm_profile="xian_vm_v1", compact=compact
        ) == build_contract_artifacts(module_name="con_probe", source=source, vm_profile="xian_vm_v1")


def _probe_artifacts(vm_profile: str = "xian_vm_v1") -> dict:
    return build_contract_artifacts(
        module_name="con_probe",
        source="@export\ndef ping():\n    return 'pong'\n",
        vm_profile=vm_profile,
    )


def test_validate_contract_artifacts_rejects_another_execution_profile() -> None:
    with pytest.raises(ValueError, match="vm_profile"):
        validate_contract_artifacts(
            module_name="con_probe",
            artifacts=_probe_artifacts("xian_vm_v1"),
            vm_profile="xian_vm_v2",
        )


def test_validate_contract_artifacts_rejects_a_non_dictionary() -> None:
    with pytest.raises(TypeError, match="must be a dictionary"):
        validate_contract_artifacts(module_name="con_probe", artifacts=[], vm_profile="xian_vm_v1")


def test_validate_contract_artifacts_rejects_runtime_code() -> None:
    artifacts = dict(_probe_artifacts(), runtime_code="pass\n")
    with pytest.raises(ValueError, match="runtime_code"):
        validate_contract_artifacts(
            module_name="con_probe", artifacts=artifacts, vm_profile="xian_vm_v1"
        )


def test_validate_contract_artifacts_checks_the_input_source_hash() -> None:
    with pytest.raises(ValueError, match="input_source_sha256"):
        validate_contract_artifacts(
            module_name="con_probe",
            artifacts=_probe_artifacts(),
            input_source="@export\ndef ping():\n    return 'other'\n",
            vm_profile="xian_vm_v1",
        )


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

    with pytest.raises(ValueError, match="artifact.vm_ir.source_hash"):
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


def test_compile_contract_source_returns_the_artifact_source_and_ir() -> None:
    source = "@export\ndef ping():\n    return 'pong'\n"
    artifacts = _probe_artifacts("xian_vm_v2")

    compiled = compile_contract_source(module_name="con_probe", source=source)

    assert compiled == {"source": artifacts["source"], "vm_ir_json": artifacts["vm_ir_json"]}


def test_compile_contract_source_rejects_empty_source() -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        compile_contract_source(module_name="con_probe", source="")


def test_compile_contract_source_reports_compiler_errors() -> None:
    with pytest.raises(ValueError, match="xian.syntax.unsupported_expression.lambda"):
        compile_contract_source(module_name="con_probe", source="f = lambda: 1\n")


def test_diagnose_contract_source_returns_compiler_diagnostics() -> None:
    diagnostics = diagnose_contract_source(module_name="con_probe", source="f = lambda: 1\n")

    assert [diagnostic["code"] for diagnostic in diagnostics] == [
        "xian.syntax.unsupported_expression.lambda"
    ]
    accepted = "@export\ndef ping():\n    return 'pong'\n"
    assert diagnose_contract_source(module_name="con_probe", source=accepted) == []


def _stale_surface_error(monkeypatch, surface: dict) -> str:
    monkeypatch.setattr(
        artifacts_module.xian_compiler_core, "describe_vm_host_surface", lambda: surface
    )
    artifacts_module._assert_native_compiler_host_surface_current.cache_clear()
    try:
        with pytest.raises(RuntimeError) as error:
            diagnose_contract_source(module_name="con_probe", source="x = 1\n")
    finally:
        artifacts_module._assert_native_compiler_host_surface_current.cache_clear()
    return str(error.value)


def test_host_surface_guard_names_a_stale_catalog_version(monkeypatch) -> None:
    surface = artifacts_module.xian_compiler_core.describe_vm_host_surface()
    message = _stale_surface_error(monkeypatch, dict(surface, catalog_version="old_catalog"))

    assert message == (
        "xian_compiler_core host catalog is stale relative to "
        "contracting.compilation.ir; rebuild xian-tech-compiler-core. "
        "Expected catalog_version='xian_vm_v1_host_v1', got 'old_catalog'."
    )


def test_host_surface_guard_lists_missing_and_mismatched_bindings(monkeypatch) -> None:
    surface = artifacts_module.xian_compiler_core.describe_vm_host_surface()
    bindings = []
    for binding in surface["bindings"]:
        if binding["binding"] == "hashlib.sha3_text":
            continue
        if binding["binding"] == "hashlib.sha256_text":
            binding = dict(binding, kind="value", category="other")
        bindings.append(binding)
    message = _stale_surface_error(monkeypatch, dict(surface, bindings=bindings))

    assert message.endswith(
        "missing bindings: hashlib.sha3_text "
        "mismatched bindings: hashlib.sha256_text.kind: expected 'syscall', got 'value'; "
        "hashlib.sha256_text.category: expected 'hashing', got 'other'"
    )
