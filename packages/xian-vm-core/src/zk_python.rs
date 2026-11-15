//! The node's zk proof caches for node tooling
//! (`contracting.stdlib.bridge.zk`): the caches the block host verifies
//! through (`zk_cache`), cleared by the node, and the parity hook that serves
//! zk syscalls as the block host does.
use super::{exception_to_py, py_to_vm};
use crate::block_host::{zk, BlockHost, HostCharges, Modules, TxInputs};
use crate::block_state_python::PyBlockState;
use crate::lmdb_python::PyLmdbEnvironment;
use crate::settlement::Stop;
use crate::state_view::StateView;
use crate::zk_cache;
use crate::{VmBudget, VmValue};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyModule};

#[pyfunction]
fn zk_clear_prepared_vk_cache() {
    zk_cache::clear_prepared();
}

#[pyfunction]
fn zk_clear_verified_proof_cache() {
    zk_cache::clear_verified();
}

/// Parity hook: zk syscalls (`(syscall id, [args])`, as the VM passes them)
/// served by the block host over the node's LMDB environment and block
/// overlay, at the V2 VM boundary. Each outcome is `("ok", value)` with the
/// value's `Debug` rendering, `("raised", text, exception)` with
/// `exception` as `(type name, [args])` or `None`, or `("fault", reason)`.
#[pyfunction]
fn _zk_syscalls_debug(
    py: Python<'_>,
    environment: PyRef<'_, PyLmdbEnvironment>,
    overlay: PyRef<'_, PyBlockState>,
    calls: Vec<(String, Bound<'_, PyList>)>,
) -> PyResult<Vec<Py<PyAny>>> {
    let view = StateView::new(environment.store(), overlay.shared());
    let modules = Modules::default();
    let mut outcomes = Vec::with_capacity(calls.len());
    for (syscall_id, args) in calls {
        let args = args
            .iter()
            .map(|value| py_to_vm(value).map_err(|error| PyValueError::new_err(error.to_string())))
            .collect::<PyResult<Vec<VmValue>>>()?;
        let charges = HostCharges::new(VmBudget::new(0), false, "");
        let inputs = TxInputs {
            context: Default::default(),
            zk_enabled_without_state: true,
        };
        let mut host = BlockHost::new(view.clone(), &modules, charges, inputs);
        let served = zk::call(&mut host, &syscall_id, &args, &[])
            .ok_or_else(|| PyValueError::new_err(format!("{syscall_id} is not a zk syscall")))?;
        outcomes.push(outcome(py, served, host.finish().err())?);
    }
    Ok(outcomes)
}

fn outcome(
    py: Python<'_>,
    served: Result<VmValue, crate::VmExecutionError>,
    stop: Option<Stop>,
) -> PyResult<Py<PyAny>> {
    let outcome = match (served, stop) {
        (_, Some(Stop::Fault(reason))) => ("fault", reason),
        (Ok(value), None) => ("ok", format!("{value:?}")),
        (Err(error), None) => {
            let exception = exception_to_py(py, error.exception())?;
            let raised = ("raised", error.to_string(), exception).into_pyobject(py)?;
            return Ok(raised.into_any().unbind());
        }
    };
    Ok(outcome.into_pyobject(py)?.into_any().unbind())
}

pub(super) fn register(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    let functions = [
        wrap_pyfunction!(zk_clear_prepared_vk_cache, module),
        wrap_pyfunction!(zk_clear_verified_proof_cache, module),
        wrap_pyfunction!(_zk_syscalls_debug, module),
    ];
    for function in functions {
        module.add_function(function?)?;
    }
    Ok(())
}
