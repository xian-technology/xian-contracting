//! Parity hook: the block host's random syscalls on their own, for the
//! differential tests against `contracting.stdlib.bridge.random`.
use super::{context_from_py, exception_to_py, py_to_vm};
use crate::block_host::random::{call, Refusal, TxRandom};
use crate::interpreter::numeric_v2;
use crate::{VmValue, XIAN_VM_V2_PROFILE};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

/// One random syscall: its id, positional and keyword arguments.
type Call<'py> = (String, Bound<'py, PyList>, Bound<'py, PyDict>);
/// Positional and keyword arguments as the VM passes them to its host.
type VmArguments = (Vec<VmValue>, Vec<(String, VmValue)>);

/// Parity hook: `calls` served in order by one transaction's random state
/// for `context` (a transaction context dict), at the V2 VM boundary. Each
/// outcome is `("ok", value)` with the value's `Debug` rendering,
/// `("raised", text, exception)` with `exception` as `(type name, [args])`
/// or `None`, or `("handback", reason)`; a hand-back ends the calls as it
/// ends a transaction.
#[pyfunction]
fn _random_syscalls_debug(
    py: Python<'_>,
    context: Bound<'_, PyAny>,
    calls: Vec<Call<'_>>,
) -> PyResult<Vec<Py<PyAny>>> {
    let _scope = numeric_v2::Scope::enter(XIAN_VM_V2_PROFILE);
    let context = context_from_py(&context).map_err(value_error)?;
    let mut random = TxRandom::new(&context);
    let mut outcomes = Vec::with_capacity(calls.len());
    for (syscall_id, args, kwargs) in calls {
        let (args, kwargs) = vm_arguments(&args, &kwargs)?;
        let served = call(&mut random, &syscall_id, args, kwargs).ok_or_else(|| {
            PyValueError::new_err(format!("{syscall_id} is not a random syscall"))
        })?;
        let handed_back = matches!(served, Err(Refusal::Handback(_)));
        outcomes.push(outcome(py, served)?);
        if handed_back {
            break;
        }
    }
    Ok(outcomes)
}

/// A call's arguments as the VM passes them to its host.
fn vm_arguments(args: &Bound<'_, PyList>, kwargs: &Bound<'_, PyDict>) -> PyResult<VmArguments> {
    let args = args
        .iter()
        .map(|value| py_to_vm(value).map_err(value_error))
        .collect::<PyResult<_>>()?;
    let kwargs = kwargs
        .iter()
        .map(|(key, value)| Ok((key.extract()?, py_to_vm(value).map_err(value_error)?)))
        .collect::<PyResult<_>>()?;
    Ok((args, kwargs))
}

fn outcome(py: Python<'_>, served: crate::block_host::random::Served) -> PyResult<Py<PyAny>> {
    let outcome = match served {
        Ok(value) => ("ok", format!("{value:?}")).into_pyobject(py)?.into_any(),
        Err(Refusal::Raised(error)) => {
            let exception = exception_to_py(py, error.exception())?;
            ("raised", error.to_string(), exception)
                .into_pyobject(py)?
                .into_any()
        }
        Err(Refusal::Handback(reason)) => ("handback", reason).into_pyobject(py)?.into_any(),
    };
    Ok(outcome.unbind())
}

fn value_error(error: crate::VmExecutionError) -> PyErr {
    PyValueError::new_err(error.to_string())
}

pub(super) fn register(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(_random_syscalls_debug, module)?)
}
