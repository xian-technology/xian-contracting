use wasm_bindgen::prelude::*;

use crate::artifact::{validate_contract_artifact, ContractArtifact};
use crate::compiler::{compiler_version, diagnose_contract, CompileOptions};
use crate::diagnostic::{compiler_error_message, CompilerDiagnostic};
use crate::ir::{
    compile_contract_artifact, compile_contract_source, describe_vm_host_surface,
    lower_source_to_ir_json,
};
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

/// One export per compile entrypoint whose result is returned as JSON.
macro_rules! compile_json_exports {
    ($($js_name:literal => $name:ident($compile:path);)+) => {$(
        #[wasm_bindgen(js_name = $js_name)]
        pub fn $name(
            module_name: &str,
            source: &str,
            options_json: Option<String>,
        ) -> Result<String, JsValue> {
            compiled_json(module_name, source, options_json, $compile)
        }
    )+};
}

compile_json_exports! {
    "compileContractArtifactJson" => compile_contract_artifact_json(compile_contract_artifact);
    "compileContractSourceJson" => compile_contract_source_json(compile_contract_source);
}

#[wasm_bindgen(js_name = validateContractArtifactJson)]
pub fn validate_contract_artifact_json(
    expected_module_name: &str,
    artifact_json: &str,
    input_source: Option<String>,
    vm_profile: Option<String>,
) -> Result<String, JsValue> {
    let artifact: ContractArtifact = serde_json::from_str(artifact_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    validate_contract_artifact(
        &artifact,
        expected_module_name,
        input_source.as_deref(),
        vm_profile.as_deref(),
    )
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

/// Run one compile entrypoint and return its result as JSON.
fn compiled_json<T: serde::Serialize>(
    module_name: &str,
    source: &str,
    options_json: Option<String>,
    compile: fn(&str, &str, &CompileOptions) -> Result<T, Vec<CompilerDiagnostic>>,
) -> Result<String, JsValue> {
    let options = parse_options(options_json)?;
    let value = compile(module_name, source, &options).map_err(diagnostics_error)?;
    serde_json::to_string(&value).map_err(|error| JsValue::from_str(&error.to_string()))
}

fn parse_options(options_json: Option<String>) -> Result<CompileOptions, JsValue> {
    match options_json {
        Some(raw) if !raw.trim().is_empty() => serde_json::from_str(&raw)
            .map_err(|error| JsValue::from_str(&format!("invalid options_json: {error}"))),
        _ => Ok(CompileOptions::default()),
    }
}

fn diagnostics_error(diagnostics: Vec<CompilerDiagnostic>) -> JsValue {
    JsValue::from_str(&compiler_error_message(&diagnostics))
}
