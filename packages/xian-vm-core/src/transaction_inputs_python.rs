//! The block meta the executor reads transactions with, and a parity hook
//! for the inputs it reads.
use super::{bigint_to_py, py_to_vm, vm_to_py};
use crate::transaction_inputs::{prepared_tx, BlockMeta, PreparedTx};
use crate::VmExecutionContext;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use pyo3::IntoPyObjectExt;

fn item<'py>(meta: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    meta.get_item(key)?
        .ok_or_else(|| PyValueError::new_err(format!("block meta has no {key:?}")))
}

/// `current_block_meta`: `nanos`, `height`, `hash` and `chain_id`.
pub(super) fn block_meta_from_py(meta: &Bound<'_, PyDict>) -> PyResult<BlockMeta> {
    let vm = |key: &str| {
        py_to_vm(item(meta, key)?).map_err(|error| PyValueError::new_err(error.to_string()))
    };
    Ok(BlockMeta {
        nanos: item(meta, "nanos")?.extract()?,
        height: vm("height")?,
        hash: vm("hash")?,
        chain_id: vm("chain_id")?,
    })
}

/// Parity hook: the inputs the executor reads from `raw` for `block_meta`
/// (kwargs as `(name, Debug of the VM value)`, context values back in
/// Python), or `None` for bytes admission refuses.
#[pyfunction]
pub(super) fn _transaction_inputs_debug(
    py: Python<'_>,
    raw: &[u8],
    block_meta: &Bound<'_, PyDict>,
) -> PyResult<Py<PyAny>> {
    match prepared_tx(raw, &block_meta_from_py(block_meta)?) {
        Some(tx) => inputs_to_py(py, &tx),
        None => Ok(py.None()),
    }
}

/// `(sender, contract, function, chi_budget, size_bytes, kwargs, context)`.
fn inputs_to_py(py: Python<'_>, tx: &PreparedTx) -> PyResult<Py<PyAny>> {
    let context = identity_to_py(py, &tx.context)?;
    block_context_to_py(&context, &tx.context)?;
    (
        &tx.sender,
        &tx.contract,
        &tx.function,
        bigint_to_py(py, &tx.chi_budget)?,
        tx.size_bytes,
        rendered_kwargs(tx),
        context,
    )
        .into_py_any(py)
}

fn rendered_kwargs(tx: &PreparedTx) -> Vec<(String, String)> {
    tx.kwargs
        .iter()
        .map(|(key, value)| (key.clone(), format!("{value:?}")))
        .collect()
}

/// Who calls what: signer, caller, this, entry and submission name.
fn identity_to_py<'py>(
    py: Python<'py>,
    context: &VmExecutionContext,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("signer", &context.signer)?;
    dict.set_item("caller", &context.caller)?;
    dict.set_item("this", &context.this)?;
    let entry = context
        .entry
        .as_ref()
        .map(|(contract, function)| PyTuple::new(py, [contract, function]))
        .transpose()?;
    dict.set_item("entry", entry)?;
    dict.set_item("submission_name", &context.submission_name)?;
    Ok(dict)
}

/// The block context: now, block number and hash, chain id, input hash.
fn block_context_to_py(dict: &Bound<'_, PyDict>, context: &VmExecutionContext) -> PyResult<()> {
    let py = dict.py();
    for (key, value) in [
        ("now", &context.now),
        ("block_num", &context.block_num),
        ("block_hash", &context.block_hash),
        ("chain_id", &context.chain_id),
        ("__input_hash", &context.input_hash),
    ] {
        dict.set_item(key, vm_to_py(py, value)?)?;
    }
    Ok(())
}
