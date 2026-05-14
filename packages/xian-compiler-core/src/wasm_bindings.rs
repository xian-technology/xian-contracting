use wasm_bindgen::prelude::*;

use crate::artifact::{validate_contract_artifact, ContractArtifact};
use crate::compiler::{compiler_version, diagnose_contract, CompileOptions};
use crate::ir::{compile_contract_artifact, describe_vm_host_surface, lower_source_to_ir_json};
use crate::normalize::normalize_source;

#[wasm_bindgen(js_name = diagnoseContractJson)]
pub fn diagnose_contract_json(
    module_name: &str,
    source: &str,
    options_json: Option<String>,
) -> Result<String, JsValue> {
    let options = parse_options(options_json)?;
    serde_json::to_string(&diagnose_contract(module_name, source, &options))
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen(js_name = normalizeSource)]
pub fn normalize_source_text(
    module_name: &str,
    source: &str,
    options_json: Option<String>,
) -> Result<String, JsValue> {
    let options = parse_options(options_json)?;
    normalize_source(module_name, source, &options).map_err(diagnostics_error)
}

#[wasm_bindgen(js_name = lowerSourceToIrJson)]
pub fn lower_source_to_ir_json_js(
    module_name: &str,
    source: &str,
    options_json: Option<String>,
) -> Result<String, JsValue> {
    let options = parse_options(options_json)?;
    lower_source_to_ir_json(module_name, source, &options).map_err(diagnostics_error)
}

#[wasm_bindgen(js_name = compileContractArtifactJson)]
pub fn compile_contract_artifact_json(
    module_name: &str,
    source: &str,
    options_json: Option<String>,
) -> Result<String, JsValue> {
    let options = parse_options(options_json)?;
    let artifact =
        compile_contract_artifact(module_name, source, &options).map_err(diagnostics_error)?;
    serde_json::to_string(&artifact).map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen(js_name = validateContractArtifactJson)]
pub fn validate_contract_artifact_json(
    expected_module_name: &str,
    artifact_json: &str,
    input_source: Option<String>,
) -> Result<String, JsValue> {
    let artifact: ContractArtifact = serde_json::from_str(artifact_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    validate_contract_artifact(&artifact, expected_module_name, input_source.as_deref())
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_json::to_string(&serde_json::json!({
        "source": artifact.source,
        "vm_ir_json": artifact.vm_ir_json,
    }))
    .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen(js_name = compilerVersionJson)]
pub fn compiler_version_json() -> Result<String, JsValue> {
    serde_json::to_string(&compiler_version())
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen(js_name = hostSurfaceJson)]
pub fn host_surface_json() -> Result<String, JsValue> {
    serde_json::to_string(&describe_vm_host_surface())
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

fn parse_options(options_json: Option<String>) -> Result<CompileOptions, JsValue> {
    match options_json {
        Some(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw)
            .map_err(|error| JsValue::from_str(&format!("invalid options_json: {error}"))),
        _ => Ok(CompileOptions::default()),
    }
}

fn diagnostics_error(diagnostics: Vec<crate::diagnostic::CompilerDiagnostic>) -> JsValue {
    let message = diagnostics
        .first()
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .unwrap_or_else(|| "compiler failed".to_string());
    let payload = serde_json::to_string(&diagnostics).unwrap_or_else(|_| message.clone());
    JsValue::from_str(&format!("{message}\n{payload}"))
}
