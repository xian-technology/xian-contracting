use serde::{Deserialize, Serialize};

use crate::constants::{
    COMPILER_FIXTURE_SCHEMA_V1, CONTRACT_ARTIFACT_FORMAT_V1, XIAN_VM_HOST_CATALOG_V1,
    XIAN_VM_V1_PROFILE,
};
use crate::diagnostic::CompilerDiagnostic;
use crate::frontend::parse_source;
use crate::ir::compile_contract_artifact;
use crate::limits::{compiler_limits, CompilerLimits};
use crate::source::SourceUnit;
use crate::syntax::build_syntax_tree;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompileOptions {
    pub vm_profile: String,
    pub lint: bool,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            vm_profile: XIAN_VM_V1_PROFILE.to_string(),
            lint: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerVersion {
    pub package: String,
    pub version: String,
    pub artifact_format: String,
    pub fixture_schema: String,
    pub vm_profile: String,
    pub host_catalog_version: String,
    pub limits: CompilerLimits,
}

pub fn diagnose_contract(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Vec<CompilerDiagnostic> {
    if !options.lint {
        let unit = match SourceUnit::with_profile(module_name, source, &options.vm_profile) {
            Ok(unit) => unit,
            Err(error) => {
                return vec![CompilerDiagnostic::error(
                    "xian.source.invalid",
                    error.to_string(),
                )]
            }
        };
        let parsed = match parse_source(&unit) {
            Ok(parsed) => parsed,
            Err(diagnostics) => return diagnostics,
        };
        return match build_syntax_tree(&parsed) {
            Ok(_) => Vec::new(),
            Err(diagnostics) => diagnostics,
        };
    }
    match compile_contract_artifact(module_name, source, options) {
        Ok(_) => Vec::new(),
        Err(diagnostics) => diagnostics,
    }
}

pub fn compiler_version() -> CompilerVersion {
    CompilerVersion {
        package: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        artifact_format: CONTRACT_ARTIFACT_FORMAT_V1.to_string(),
        fixture_schema: COMPILER_FIXTURE_SCHEMA_V1.to_string(),
        vm_profile: XIAN_VM_V1_PROFILE.to_string(),
        host_catalog_version: XIAN_VM_HOST_CATALOG_V1.to_string(),
        limits: compiler_limits(),
    }
}

#[cfg(test)]
mod tests {
    use super::{compiler_version, diagnose_contract, CompileOptions};

    #[test]
    fn diagnose_contract_reports_invalid_source_unit() {
        let diagnostics = diagnose_contract("con_empty", "", &CompileOptions::default());

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "xian.source.invalid");
    }

    #[test]
    fn diagnose_contract_reports_syntax_errors() {
        let diagnostics =
            diagnose_contract("con_bad", "def broken(:\n", &CompileOptions::default());

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "xian.syntax.parse_error");
    }

    #[test]
    fn diagnose_contract_reports_unsupported_syntax_tree_nodes() {
        let diagnostics = diagnose_contract(
            "con_bad",
            "class Bad:\n    pass\n",
            &CompileOptions::default(),
        );

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code,
            "xian.syntax.unsupported_statement.class_def"
        );
    }

    #[test]
    fn compiler_version_reports_stable_contracts() {
        let version = compiler_version();

        assert_eq!(version.artifact_format, "xian_contract_artifact_v1");
        assert_eq!(version.fixture_schema, "xian.compiler_fixture.v1");
        assert_eq!(version.vm_profile, "xian_vm_v1");
        assert_eq!(version.host_catalog_version, "xian_vm_v1_host_v1");
        assert_eq!(version.limits.max_source_bytes, 131_072);
        assert_eq!(version.limits.max_syntax_nodes, 50_000);
        assert_eq!(version.limits.max_syntax_depth, 64);
        assert_eq!(version.limits.max_tokens, 100_000);
        assert_eq!(version.limits.max_logical_line_tokens, 4_096);
    }
}
