use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::constants::{CONTRACT_ARTIFACT_FORMAT_V1, XIAN_IR_V1, XIAN_VM_V1_PROFILE};
use crate::error::{ensure_eq, ensure_non_empty, ensure_sha256_hex, ValidationError};
use crate::hashing::sha256_hex;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactHashes {
    pub input_source_sha256: String,
    pub source_sha256: String,
    pub vm_ir_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractArtifact {
    pub format: String,
    pub module_name: String,
    pub vm_profile: String,
    pub source: String,
    pub vm_ir_json: String,
    pub hashes: ArtifactHashes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedArtifact {
    pub module_name: String,
    pub source: String,
    pub vm_ir: Value,
}

pub fn build_contract_artifact(
    module_name: &str,
    input_source: &str,
    normalized_source: &str,
    vm_ir_json: &str,
) -> Result<ContractArtifact, ValidationError> {
    ensure_non_empty("module_name", module_name)?;
    ensure_non_empty("input_source", input_source)?;
    ensure_non_empty("normalized_source", normalized_source)?;
    ensure_non_empty("vm_ir_json", vm_ir_json)?;
    let artifact = ContractArtifact {
        format: CONTRACT_ARTIFACT_FORMAT_V1.to_string(),
        module_name: module_name.to_string(),
        vm_profile: XIAN_VM_V1_PROFILE.to_string(),
        source: normalized_source.to_string(),
        vm_ir_json: vm_ir_json.to_string(),
        hashes: ArtifactHashes {
            input_source_sha256: sha256_hex(input_source),
            source_sha256: sha256_hex(normalized_source),
            vm_ir_sha256: sha256_hex(vm_ir_json),
        },
    };
    let vm_ir = parse_vm_ir_json(vm_ir_json)?;
    validate_ir_identity(&vm_ir, &artifact)?;
    Ok(artifact)
}

pub fn validate_contract_artifact(
    artifact: &ContractArtifact,
    expected_module_name: &str,
    input_source: Option<&str>,
) -> Result<ValidatedArtifact, ValidationError> {
    ensure_eq(
        "artifact.format",
        &artifact.format,
        CONTRACT_ARTIFACT_FORMAT_V1,
    )?;
    ensure_eq(
        "artifact.vm_profile",
        &artifact.vm_profile,
        XIAN_VM_V1_PROFILE,
    )?;
    ensure_eq(
        "artifact.module_name",
        &artifact.module_name,
        expected_module_name,
    )?;
    ensure_non_empty("artifact.source", &artifact.source)?;
    ensure_non_empty("artifact.vm_ir_json", &artifact.vm_ir_json)?;

    ensure_eq(
        "artifact.hashes.source_sha256",
        &artifact.hashes.source_sha256,
        &sha256_hex(&artifact.source),
    )?;
    ensure_eq(
        "artifact.hashes.vm_ir_sha256",
        &artifact.hashes.vm_ir_sha256,
        &sha256_hex(&artifact.vm_ir_json),
    )?;
    if let Some(input_source) = input_source {
        ensure_eq(
            "artifact.hashes.input_source_sha256",
            &artifact.hashes.input_source_sha256,
            &sha256_hex(input_source),
        )?;
    } else {
        ensure_sha256_hex(
            "artifact.hashes.input_source_sha256",
            &artifact.hashes.input_source_sha256,
        )?;
    }

    let vm_ir = parse_vm_ir_json(&artifact.vm_ir_json)?;
    validate_ir_identity(&vm_ir, artifact)?;

    Ok(ValidatedArtifact {
        module_name: artifact.module_name.clone(),
        source: artifact.source.clone(),
        vm_ir,
    })
}

fn parse_vm_ir_json(raw: &str) -> Result<Value, ValidationError> {
    serde_json::from_str(raw).map_err(|error| {
        ValidationError::field("artifact.vm_ir_json", format!("invalid JSON: {error}"))
    })
}

fn validate_ir_identity(vm_ir: &Value, artifact: &ContractArtifact) -> Result<(), ValidationError> {
    ensure_eq(
        "artifact.vm_ir.ir_version",
        required_ir_str(vm_ir, "ir_version")?,
        XIAN_IR_V1,
    )?;
    ensure_eq(
        "artifact.vm_ir.module_name",
        required_ir_str(vm_ir, "module_name")?,
        &artifact.module_name,
    )?;
    ensure_eq(
        "artifact.vm_ir.vm_profile",
        required_ir_str(vm_ir, "vm_profile")?,
        XIAN_VM_V1_PROFILE,
    )?;
    let source_hash = required_ir_str(vm_ir, "source_hash")?;
    ensure_sha256_hex("artifact.vm_ir.source_hash", source_hash)?;
    ensure_eq(
        "artifact.vm_ir.source_hash",
        source_hash,
        &artifact.hashes.source_sha256,
    )?;
    Ok(())
}

fn required_ir_str<'a>(vm_ir: &'a Value, field: &str) -> Result<&'a str, ValidationError> {
    vm_ir.get(field).and_then(Value::as_str).ok_or_else(|| {
        let field_name = format!("artifact.vm_ir.{field}");
        ValidationError::field(&field_name, "is required")
    })
}

#[cfg(test)]
mod tests {
    use super::{build_contract_artifact, validate_contract_artifact};

    #[test]
    fn build_contract_artifact_records_stable_hashes() {
        let source_hash = crate::hashing::sha256_hex("value = 1");
        let vm_ir_json = format!(
            r#"{{"ir_version":"xian_ir_v1","module_name":"con_counter","vm_profile":"xian_vm_v1","source_hash":"{source_hash}"}}"#
        );
        let artifact =
            build_contract_artifact("con_counter", "value = 1\n", "value = 1", &vm_ir_json)
                .expect("artifact should build");

        assert_eq!(artifact.format, "xian_contract_artifact_v1");
        assert_eq!(artifact.vm_profile, "xian_vm_v1");
        assert_ne!(
            artifact.hashes.input_source_sha256,
            artifact.hashes.source_sha256
        );
    }

    #[test]
    fn validate_contract_artifact_rejects_hash_mismatch() {
        let source_hash = crate::hashing::sha256_hex("value = 1");
        let vm_ir_json = format!(
            r#"{{"ir_version":"xian_ir_v1","module_name":"con_counter","vm_profile":"xian_vm_v1","source_hash":"{source_hash}"}}"#
        );
        let mut artifact =
            build_contract_artifact("con_counter", "value = 1", "value = 1", &vm_ir_json)
                .expect("artifact should build");
        artifact.hashes.source_sha256 = "bad".to_string();

        let error = validate_contract_artifact(&artifact, "con_counter", Some("value = 1"))
            .expect_err("artifact should fail validation");
        assert!(error.to_string().contains("artifact.hashes.source_sha256"));
    }
}
