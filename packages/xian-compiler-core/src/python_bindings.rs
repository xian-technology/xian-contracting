use pyo3::create_exception;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde_json::json;

use crate::artifact::{validate_contract_artifact, ContractArtifact};
use crate::compiler::{compiler_version, diagnose_contract, CompileOptions};
use crate::ir::{compile_contract_artifact, describe_vm_host_surface, lower_source_to_ir_json};
use crate::normalize::normalize_source;

create_exception!(xian_compiler_core, CompilerError, PyValueError);

#[pyfunction(signature=(module_name, source, *, options_json=None))]
fn diagnose_contract_json(
    module_name: &str,
    source: &str,
    options_json: Option<&str>,
) -> PyResult<String> {
    let options = parse_options(options_json)?;
    serde_json::to_string(&diagnose_contract(module_name, source, &options))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction(name = "normalize_source", signature=(module_name, source, *, options_json=None))]
fn normalize_source_text(
    module_name: &str,
    source: &str,
    options_json: Option<&str>,
) -> PyResult<String> {
    let options = parse_options(options_json)?;
    normalize_source(module_name, source, &options).map_err(compiler_error)
}

#[pyfunction(name = "lower_source_to_ir_json", signature=(module_name, source, *, options_json=None))]
fn lower_source_to_ir_json_py(
    module_name: &str,
    source: &str,
    options_json: Option<&str>,
) -> PyResult<String> {
    let options = parse_options(options_json)?;
    lower_source_to_ir_json(module_name, source, &options).map_err(compiler_error)
}

#[pyfunction(signature=(module_name, source, *, options_json=None))]
fn compile_contract_artifact_json(
    module_name: &str,
    source: &str,
    options_json: Option<&str>,
) -> PyResult<String> {
    let options = parse_options(options_json)?;
    let artifact =
        compile_contract_artifact(module_name, source, &options).map_err(compiler_error)?;
    serde_json::to_string(&artifact).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction(signature=(expected_module_name, artifact_json, *, input_source=None))]
fn validate_contract_artifact_json(
    expected_module_name: &str,
    artifact_json: &str,
    input_source: Option<&str>,
) -> PyResult<String> {
    let artifact: ContractArtifact = serde_json::from_str(artifact_json)
        .map_err(|error| CompilerError::new_err(error.to_string()))?;
    validate_contract_artifact(&artifact, expected_module_name, input_source)
        .map_err(|error| CompilerError::new_err(error.to_string()))?;
    serde_json::to_string(&json!({
        "source": artifact.source,
        "vm_ir_json": artifact.vm_ir_json,
    }))
    .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn compiler_version_json() -> PyResult<String> {
    serde_json::to_string(&compiler_version())
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pyfunction]
fn host_surface_json() -> PyResult<String> {
    serde_json::to_string(&describe_vm_host_surface())
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pymodule]
fn _native(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("CompilerError", py.get_type::<CompilerError>())?;
    module.add_function(wrap_pyfunction!(diagnose_contract_json, module)?)?;
    module.add_function(wrap_pyfunction!(normalize_source_text, module)?)?;
    module.add_function(wrap_pyfunction!(lower_source_to_ir_json_py, module)?)?;
    module.add_function(wrap_pyfunction!(compile_contract_artifact_json, module)?)?;
    module.add_function(wrap_pyfunction!(validate_contract_artifact_json, module)?)?;
    module.add_function(wrap_pyfunction!(compiler_version_json, module)?)?;
    module.add_function(wrap_pyfunction!(host_surface_json, module)?)?;
    Ok(())
}

fn parse_options(options_json: Option<&str>) -> PyResult<CompileOptions> {
    match options_json {
        Some(raw) if !raw.trim().is_empty() => serde_json::from_str(raw)
            .map_err(|error| PyValueError::new_err(format!("invalid options_json: {error}"))),
        _ => Ok(CompileOptions::default()),
    }
}

fn compiler_error(diagnostics: Vec<crate::diagnostic::CompilerDiagnostic>) -> PyErr {
    let message = diagnostics
        .first()
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .unwrap_or_else(|| "compiler failed".to_string());
    let payload = serde_json::to_string(&diagnostics).unwrap_or_else(|_| message.clone());
    CompilerError::new_err(format!("{message}\n{payload}"))
}
