use crate::parse_module_ir;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CONTRACT_ARTIFACT_FORMAT_V1: &str = "xian_contract_artifact_v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedArtifactBundle {
    pub source: String,
    pub runtime_code: Option<String>,
    pub vm_ir_json: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactValidationError {
    message: String,
}

impl ArtifactValidationError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ArtifactValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ArtifactValidationError {}

pub fn validate_contract_artifacts_json(
    module_name: &str,
    artifacts_json: &str,
    input_source: Option<&str>,
    vm_profile: &str,
) -> Result<ValidatedArtifactBundle, ArtifactValidationError> {
    let payload: Value = serde_json::from_str(artifacts_json)
        .map_err(|error| ArtifactValidationError::new(error.to_string()))?;
    let object = payload.as_object().ok_or_else(|| {
        ArtifactValidationError::new("deployment_artifacts must be a dictionary.")
    })?;

    let format = required_string_field(object, "format")?;
    if format != CONTRACT_ARTIFACT_FORMAT_V1 {
        return Err(ArtifactValidationError::new(
            "deployment_artifacts has an unsupported format.",
        ));
    }

    let artifact_module_name = required_string_field(object, "module_name")?;
    if artifact_module_name != module_name {
        return Err(ArtifactValidationError::new(
            "deployment_artifacts module_name does not match the target contract.",
        ));
    }

    let artifact_vm_profile = required_string_field(object, "vm_profile")?;
    if artifact_vm_profile != vm_profile {
        return Err(ArtifactValidationError::new(
            "deployment_artifacts vm_profile does not match the execution profile.",
        ));
    }

    let source = required_non_empty_string_field(object, "source")?;
    let runtime_code = optional_non_empty_string_field(object, "runtime_code")?;
    let vm_ir_json = optional_non_empty_string_field(object, "vm_ir_json")?;
    let hashes = object
        .get("hashes")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ArtifactValidationError::new("deployment_artifacts must include a 'hashes' dictionary.")
        })?;

    if runtime_code.is_some() != vm_ir_json.is_some() {
        return Err(ArtifactValidationError::new(
            "deployment_artifacts must include both 'runtime_code' and 'vm_ir_json', or neither.",
        ));
    }

    validate_hash_field(hashes, "source_sha256", &sha256_hex(source))?;
    if let Some(input_source) = input_source {
        validate_hash_field(hashes, "input_source_sha256", &sha256_hex(input_source))?;
    }
    if let (Some(runtime_code), Some(vm_ir_json)) = (runtime_code, vm_ir_json) {
        validate_hash_field(hashes, "runtime_code_sha256", &sha256_hex(runtime_code))?;
        validate_hash_field(hashes, "vm_ir_sha256", &sha256_hex(vm_ir_json))?;
        let module_ir = parse_module_ir(vm_ir_json)
            .map_err(|error| ArtifactValidationError::new(error.to_string()))?;
        if module_ir.module_name != module_name {
            return Err(ArtifactValidationError::new(
                "deployment_artifacts vm_ir_json module_name does not match the target contract.",
            ));
        }
        if module_ir.vm_profile != vm_profile {
            return Err(ArtifactValidationError::new(
                "deployment_artifacts vm_ir_json vm_profile does not match the execution profile.",
            ));
        }
        if module_ir.source_hash != sha256_hex(source) {
            return Err(ArtifactValidationError::new(
                "deployment_artifacts vm_ir_json source_hash does not match source.",
            ));
        }

        return Ok(ValidatedArtifactBundle {
            source: source.to_owned(),
            runtime_code: Some(runtime_code.to_owned()),
            vm_ir_json: Some(vm_ir_json.to_owned()),
        });
    }

    Ok(ValidatedArtifactBundle {
        source: source.to_owned(),
        runtime_code: None,
        vm_ir_json: None,
    })
}

fn required_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, ArtifactValidationError> {
    object.get(field).and_then(Value::as_str).ok_or_else(|| {
        ArtifactValidationError::new(format!(
            "deployment_artifacts must include a string field '{field}'."
        ))
    })
}

fn required_non_empty_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, ArtifactValidationError> {
    let value = required_string_field(object, field)?;
    if value.is_empty() {
        return Err(ArtifactValidationError::new(format!(
            "deployment_artifacts must include a non-empty '{field}' string."
        )));
    }
    Ok(value)
}

fn optional_non_empty_string_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, ArtifactValidationError> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        Some(Value::String(_)) => Err(ArtifactValidationError::new(format!(
            "deployment_artifacts must include a non-empty '{field}' string."
        ))),
        Some(_) => Err(ArtifactValidationError::new(format!(
            "deployment_artifacts must include a string field '{field}'."
        ))),
    }
}

fn validate_hash_field(
    hashes: &serde_json::Map<String, Value>,
    field: &str,
    expected: &str,
) -> Result<(), ArtifactValidationError> {
    let actual = hashes.get(field).and_then(Value::as_str).ok_or_else(|| {
        ArtifactValidationError::new(format!("deployment_artifacts hash mismatch for '{field}'."))
    })?;
    if actual != expected {
        return Err(ArtifactValidationError::new(format!(
            "deployment_artifacts hash mismatch for '{field}'."
        )));
    }
    Ok(())
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::{sha256_hex, validate_contract_artifacts_json, CONTRACT_ARTIFACT_FORMAT_V1};
    use crate::{XIAN_IR_V1, XIAN_VM_HOST_CATALOG_V1, XIAN_VM_V1_PROFILE};
    use serde_json::{json, Value};

    fn make_artifact(module_name: &str, source: &str) -> String {
        let source_hash = sha256_hex(source);
        let vm_ir_json = json!({
            "ir_version": XIAN_IR_V1,
            "vm_profile": XIAN_VM_V1_PROFILE,
            "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
            "module_name": module_name,
            "source_hash": source_hash,
            "docstring": null,
            "imports": [],
            "global_declarations": [],
            "functions": [],
            "module_body": [],
            "host_dependencies": [],
        })
        .to_string();
        let runtime_code = "pass\n".to_owned();
        json!({
            "format": CONTRACT_ARTIFACT_FORMAT_V1,
            "module_name": module_name,
            "vm_profile": XIAN_VM_V1_PROFILE,
            "source": source,
            "runtime_code": runtime_code,
            "vm_ir_json": vm_ir_json,
            "hashes": {
                "source_sha256": sha256_hex(source),
                "runtime_code_sha256": sha256_hex("pass\n"),
                "vm_ir_sha256": sha256_hex(&json!({
                    "ir_version": XIAN_IR_V1,
                    "vm_profile": XIAN_VM_V1_PROFILE,
                    "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                    "module_name": module_name,
                    "source_hash": sha256_hex(source),
                    "docstring": null,
                    "imports": [],
                    "global_declarations": [],
                    "functions": [],
                    "module_body": [],
                    "host_dependencies": [],
                }).to_string()),
            }
        })
        .to_string()
    }

    #[test]
    fn validates_minimal_bundle() {
        let artifacts_json = make_artifact("con_probe", "x = 1\n");
        let validated = validate_contract_artifacts_json(
            "con_probe",
            &artifacts_json,
            None,
            XIAN_VM_V1_PROFILE,
        )
        .expect("bundle should validate");

        assert_eq!(validated.source, "x = 1\n");
        assert_eq!(validated.runtime_code.as_deref(), Some("pass\n"));
    }

    #[test]
    fn validates_compact_bundle() {
        let payload = json!({
            "format": CONTRACT_ARTIFACT_FORMAT_V1,
            "module_name": "con_probe",
            "vm_profile": XIAN_VM_V1_PROFILE,
            "source": "x = 1\n",
            "hashes": {
                "source_sha256": sha256_hex("x = 1\n"),
            }
        })
        .to_string();
        let validated =
            validate_contract_artifacts_json("con_probe", &payload, None, XIAN_VM_V1_PROFILE)
                .expect("compact bundle should validate");

        assert_eq!(validated.source, "x = 1\n");
        assert_eq!(validated.runtime_code, None);
        assert_eq!(validated.vm_ir_json, None);
    }

    #[test]
    fn rejects_source_hash_mismatch() {
        let mut payload: Value = serde_json::from_str(&make_artifact("con_probe", "x = 1\n"))
            .expect("artifact json should parse");
        payload["source"] = Value::String("x = 2\n".to_owned());

        let error = validate_contract_artifacts_json(
            "con_probe",
            &payload.to_string(),
            None,
            XIAN_VM_V1_PROFILE,
        )
        .expect_err("bundle should fail");

        assert_eq!(
            error.to_string(),
            "deployment_artifacts hash mismatch for 'source_sha256'."
        );
    }

    #[test]
    fn rejects_ir_module_name_mismatch() {
        let mut payload: Value = serde_json::from_str(&make_artifact("con_probe", "x = 1\n"))
            .expect("artifact json should parse");
        let mut module_ir: Value = serde_json::from_str(
            payload["vm_ir_json"]
                .as_str()
                .expect("vm_ir_json should exist"),
        )
        .expect("vm ir should parse");
        module_ir["module_name"] = Value::String("con_other".to_owned());
        payload["vm_ir_json"] = Value::String(module_ir.to_string());
        let runtime_code = payload["runtime_code"]
            .as_str()
            .expect("runtime_code should exist")
            .to_owned();
        payload["hashes"]["vm_ir_sha256"] =
            Value::String(sha256_hex(payload["vm_ir_json"].as_str().expect("vm ir")));
        payload["hashes"]["runtime_code_sha256"] = Value::String(sha256_hex(&runtime_code));

        let error = validate_contract_artifacts_json(
            "con_probe",
            &payload.to_string(),
            None,
            XIAN_VM_V1_PROFILE,
        )
        .expect_err("bundle should fail");

        assert_eq!(
            error.to_string(),
            "deployment_artifacts vm_ir_json module_name does not match the target contract."
        );
    }
}
