use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::artifact::{validate_contract_artifact, ContractArtifact};
use crate::constants::{
    COMPILER_FIXTURE_SCHEMA_V1, CONTRACT_ARTIFACT_FORMAT_V1, XIAN_VM_V1_PROFILE,
};
use crate::diagnostic::{CompilerDiagnostic, DiagnosticSeverity};
use crate::error::{ensure_eq, ensure_non_empty, ValidationError};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureGenerator {
    pub name: String,
    pub artifact_format: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureExpectation {
    pub accepted: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerFixture {
    pub schema: String,
    pub name: String,
    pub generator: FixtureGenerator,
    pub source_path: Option<String>,
    pub module_name: String,
    pub vm_profile: String,
    pub input_source: String,
    pub normalized_source: Option<String>,
    pub artifact: Option<ContractArtifact>,
    pub vm_ir: Option<Value>,
    pub expected: FixtureExpectation,
    pub diagnostics: Vec<CompilerDiagnostic>,
}

pub fn parse_compiler_fixture_json(raw: &str) -> Result<CompilerFixture, ValidationError> {
    serde_json::from_str(raw).map_err(|error| ValidationError::new(error.to_string()))
}

impl CompilerFixture {
    pub fn validate_basic(&self) -> Result<(), ValidationError> {
        self.validate_common_fields()?;
        if self.expected.accepted {
            self.validate_accepted()
        } else {
            self.validate_rejected()
        }
    }

    fn validate_common_fields(&self) -> Result<(), ValidationError> {
        ensure_eq("schema", &self.schema, COMPILER_FIXTURE_SCHEMA_V1)?;
        ensure_non_empty("name", &self.name)?;
        ensure_non_empty("generator.name", &self.generator.name)?;
        ensure_eq(
            "generator.artifact_format",
            &self.generator.artifact_format,
            CONTRACT_ARTIFACT_FORMAT_V1,
        )?;
        ensure_non_empty("module_name", &self.module_name)?;
        ensure_eq("vm_profile", &self.vm_profile, XIAN_VM_V1_PROFILE)?;
        ensure_non_empty("input_source", &self.input_source)?;
        Ok(())
    }

    fn validate_accepted(&self) -> Result<(), ValidationError> {
        if !self.diagnostics.is_empty() {
            return Err(ValidationError::field(
                "diagnostics",
                "accepted fixtures must not contain diagnostics",
            ));
        }

        let normalized_source = self.normalized_source.as_ref().ok_or_else(|| {
            ValidationError::field("normalized_source", "accepted fixture requires source")
        })?;
        ensure_non_empty("normalized_source", normalized_source)?;

        let artifact = self.artifact.as_ref().ok_or_else(|| {
            ValidationError::field("artifact", "accepted fixture requires artifact")
        })?;
        ensure_eq("artifact.source", &artifact.source, normalized_source)?;

        let expected_vm_ir = self
            .vm_ir
            .as_ref()
            .ok_or_else(|| ValidationError::field("vm_ir", "accepted fixture requires IR"))?;
        let validated =
            validate_contract_artifact(artifact, &self.module_name, Some(&self.input_source))?;
        if &validated.vm_ir != expected_vm_ir {
            return Err(ValidationError::field(
                "vm_ir",
                "fixture IR does not match artifact vm_ir_json",
            ));
        }
        Ok(())
    }

    fn validate_rejected(&self) -> Result<(), ValidationError> {
        if self.artifact.is_some() {
            return Err(ValidationError::field(
                "artifact",
                "rejected fixture must not contain artifact",
            ));
        }
        if self.diagnostics.is_empty() {
            return Err(ValidationError::field(
                "diagnostics",
                "rejected fixture requires diagnostics",
            ));
        }
        if self
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.severity != DiagnosticSeverity::Error)
        {
            return Err(ValidationError::field(
                "diagnostics",
                "rejected fixture requires at least one error",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_compiler_fixture_json, CompilerFixture};
    use crate::diagnostic::{CompilerDiagnostic, DiagnosticSeverity};
    use crate::fixture::{FixtureExpectation, FixtureGenerator};

    #[test]
    fn rejected_fixture_requires_error_diagnostic() {
        let fixture = CompilerFixture {
            schema: "xian.compiler_fixture.v1".to_string(),
            name: "bad".to_string(),
            generator: FixtureGenerator {
                name: "test".to_string(),
                artifact_format: "xian_contract_artifact_v1".to_string(),
            },
            source_path: None,
            module_name: "con_bad".to_string(),
            vm_profile: "xian_vm_v1".to_string(),
            input_source: "def broken(:\n".to_string(),
            normalized_source: None,
            artifact: None,
            vm_ir: None,
            expected: FixtureExpectation { accepted: false },
            diagnostics: vec![CompilerDiagnostic {
                severity: DiagnosticSeverity::Warning,
                code: "test.warning".to_string(),
                message: "warning".to_string(),
                range: None,
            }],
        };

        let error = fixture
            .validate_basic()
            .expect_err("fixture should fail validation");
        assert!(error.to_string().contains("at least one error"));
    }

    #[test]
    fn fixture_json_parser_reports_json_errors() {
        let error = parse_compiler_fixture_json("{").expect_err("JSON should fail");
        assert!(error.to_string().contains("EOF"));
    }
}
