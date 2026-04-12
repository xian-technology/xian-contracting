import pytest

from contracting.compilation.artifacts import (
    build_contract_artifacts,
    validate_contract_artifacts,
)


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
    assert validated["runtime_code"] == artifacts["runtime_code"]
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
        match="runtime_code does not match canonical compiler output",
    ):
        validate_contract_artifacts(
            module_name="con_probe",
            artifacts=forged,
            vm_profile="xian_vm_v1",
        )
