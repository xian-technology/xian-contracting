//! `decode_and_validate_transaction`: static admission for the node.
use crate::transaction_admission::admit_transaction;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::IntoPyObjectExt;
use serde_json::Value;

/// The decoded transaction document (plain JSON types) if `raw` is admitted
/// for `chain_id`; `ValueError` with the refusal text otherwise.
#[pyfunction]
fn decode_and_validate_transaction(
    py: Python<'_>,
    raw: &[u8],
    chain_id: &str,
) -> PyResult<Py<PyAny>> {
    let document = admit_transaction(raw, chain_id)
        .map_err(|refusal| PyValueError::new_err(refusal.to_string()))?;
    json_to_py(py, &document)
}

fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(raw) => raw.into_py_any(py),
        Value::Number(number) => number_to_py(py, number),
        Value::String(raw) => raw.into_py_any(py),
        Value::Array(items) => list_to_py(py, items),
        Value::Object(items) => dict_to_py(py, items),
    }
}

fn list_to_py(py: Python<'_>, items: &[Value]) -> PyResult<Py<PyAny>> {
    let list = PyList::empty(py);
    for item in items {
        list.append(json_to_py(py, item)?)?;
    }
    Ok(list.into_any().unbind())
}

fn dict_to_py(py: Python<'_>, items: &serde_json::Map<String, Value>) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);
    for (key, item) in items {
        dict.set_item(key, json_to_py(py, item)?)?;
    }
    Ok(dict.into_any().unbind())
}

fn number_to_py(py: Python<'_>, number: &serde_json::Number) -> PyResult<Py<PyAny>> {
    if let Some(value) = number.as_i64() {
        value.into_py_any(py)
    } else if let Some(value) = number.as_u64() {
        value.into_py_any(py)
    } else if let Some(value) = number.as_f64() {
        value.into_py_any(py)
    } else {
        Err(PyValueError::new_err("Unsupported JSON number"))
    }
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(decode_and_validate_transaction, module)?)?;
    Ok(())
}
