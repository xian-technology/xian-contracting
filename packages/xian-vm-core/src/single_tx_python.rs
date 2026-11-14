//! Python access to one transaction run by the block executor's rules.
//!
//! The simulator, contract-view queries, genesis contract deploys and the
//! local `ContractingClient` run a single call with exactly the code a block
//! runs (`BlockExecutor::execute`), over an LMDB environment and a block
//! overlay. A caller that must not keep the effects passes a fork
//! (`BlockState.snapshot()`) and drops it; one that keeps them passes its own
//! overlay, where the writes are staged as a block stages them.
use super::block_executor_python::Unshared;
use super::{bigint_to_py, context_from_py, event_to_py, exception_to_py, py_to_vm, vm_to_py};
use crate::block_executor::{BlockExecutor, BlockPolicy, FeeMode, PreparedTx, TxOutcome};
use crate::block_state_python::PyBlockState;
use crate::interpreter::numeric_v2;
use crate::lmdb_python::{LmdbStorageError, PyLmdbEnvironment};
use crate::panic_guard::catching;
use crate::settlement::Stop;
use crate::state_view::StateView;
use crate::{VmExecutionError, VmValue, XIAN_VM_V2_PROFILE};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::IntoPyObjectExt;

/// The call's keyword arguments as the VM receives them (the caller
/// coerced them as `coerce_call_kwargs` does).
fn kwargs_from_py(kwargs: &Bound<'_, PyDict>) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
    kwargs
        .iter()
        .map(|(key, value)| {
            let key = key
                .extract::<String>()
                .map_err(|error| VmExecutionError::new(error.to_string()))?;
            Ok((key, py_to_vm(value)?))
        })
        .collect()
}

/// The transaction, or `None` where `execute_contract` would not have
/// converted its inputs (left to the Python path).
#[allow(clippy::too_many_arguments)]
fn prepared(
    sender: String,
    contract: String,
    function: String,
    kwargs: &Bound<'_, PyDict>,
    context: &Bound<'_, PyDict>,
    chi_budget: &Bound<'_, PyAny>,
    size_bytes: usize,
) -> Option<PreparedTx> {
    let _scope = numeric_v2::Scope::enter(XIAN_VM_V2_PROFILE);
    let VmValue::Int(chi_budget) = py_to_vm(chi_budget.clone()).ok()? else {
        return None;
    };
    Some(PreparedTx {
        kwargs: kwargs_from_py(kwargs).ok()?,
        context: context_from_py(context.as_any()).ok()?,
        sender,
        contract,
        function,
        chi_budget,
        size_bytes,
    })
}

fn writes_to_py<'py>(py: Python<'py>, outcome: &TxOutcome) -> PyResult<Bound<'py, PyList>> {
    let writes = PyList::empty(py);
    for (key, value) in &outcome.writes {
        writes.append((key, vm_to_py(py, value)?))?;
    }
    Ok(writes)
}

fn events_to_py<'py>(py: Python<'py>, outcome: &TxOutcome) -> PyResult<Bound<'py, PyList>> {
    let events = PyList::empty(py);
    for event in &outcome.events {
        events.append(event_to_py(py, event)?)?;
    }
    Ok(events)
}

fn costs_to_py<'py>(py: Python<'py>, outcome: &TxOutcome) -> PyResult<Bound<'py, PyDict>> {
    let costs = PyDict::new(py);
    for (contract, cost) in &outcome.contract_costs {
        costs.set_item(contract, bigint_to_py(py, cost)?)?;
    }
    Ok(costs)
}

fn outcome_to_py(py: Python<'_>, outcome: &TxOutcome) -> PyResult<Py<PyAny>> {
    let entries: [(&str, PyResult<Py<PyAny>>); 8] = [
        ("status", outcome.status.into_py_any(py)),
        ("result", vm_to_py(py, &outcome.result)),
        ("exception", exception_to_py(py, outcome.exception.as_ref())),
        (
            "writes",
            writes_to_py(py, outcome).map(|items| items.into_any().unbind()),
        ),
        (
            "events",
            events_to_py(py, outcome).map(|items| items.into_any().unbind()),
        ),
        ("chi_used", bigint_to_py(py, &outcome.chi_used)),
        (
            "contract_costs",
            costs_to_py(py, outcome).map(|costs| costs.into_any().unbind()),
        ),
        ("unprepared", outcome.unprepared.into_py_any(py)),
    ];
    let dict = PyDict::new(py);
    for (key, value) in entries {
        dict.set_item(key, value?)?;
    }
    Ok(dict.into_any().unbind())
}

/// Run one call by the block executor's rules over `environment` and
/// `overlay` with the GIL released, staging its writes into `overlay`.
///
/// `context` is `execute_contract`'s context dictionary (the owner is read
/// from state); `estimate` settles the fee as a dry run (no reservation).
/// Returns `(outcome, None)` with the outcome as a dictionary (`status`,
/// `result`, `exception`, `writes` in receipt order, `events`, `chi_used`,
/// `contract_costs`, `unprepared`), or `(None, reason)` when the run is left
/// to the Python path (nothing is staged then). A storage fault raises
/// `LmdbStorageError`; a panic raises `RuntimeError`.
#[pyfunction]
#[pyo3(signature = (
    environment,
    overlay,
    *,
    sender,
    contract,
    function,
    kwargs,
    context,
    chi_budget,
    transaction_size_bytes,
    meter_execution,
    charge_fees,
    protected_keys,
    zk_enabled_without_state,
    estimate = false,
))]
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_tx(
    py: Python<'_>,
    environment: PyRef<'_, PyLmdbEnvironment>,
    overlay: PyRef<'_, PyBlockState>,
    sender: String,
    contract: String,
    function: String,
    kwargs: &Bound<'_, PyDict>,
    context: &Bound<'_, PyDict>,
    chi_budget: &Bound<'_, PyAny>,
    transaction_size_bytes: usize,
    meter_execution: bool,
    charge_fees: bool,
    protected_keys: Vec<String>,
    zk_enabled_without_state: bool,
    estimate: bool,
) -> PyResult<(Option<Py<PyAny>>, Option<String>)> {
    let Some(tx) = prepared(
        sender,
        contract,
        function,
        kwargs,
        context,
        chi_budget,
        transaction_size_bytes,
    ) else {
        return Ok((None, Some("inputs did not convert".to_owned())));
    };
    let policy = BlockPolicy {
        meter_execution,
        charge_fees,
        distribute_fee_rewards: false,
        protected_keys,
        zk_enabled_without_state,
    };
    let fee_mode = if estimate {
        FeeMode::Estimated
    } else {
        FeeMode::Reserved
    };
    let view = StateView::new(environment.env().clone(), overlay.shared());
    let executor = BlockExecutor::settling(view, policy, fee_mode);
    let work = Unshared((&executor, &tx));
    let run = py
        .detach(move || {
            let (executor, tx) = work.into_inner();
            // A run must never take the node down, a simulation above all.
            Unshared(catching(|| executor.execute(tx)))
        })
        .into_inner();
    match run {
        Err(panic) => Err(PyRuntimeError::new_err(format!(
            "the transaction executor panicked: {panic}"
        ))),
        Ok(Err(Stop::Fault(fault))) => Err(LmdbStorageError::new_err(fault)),
        Ok(Ok(outcome)) => Ok((Some(outcome_to_py(py, &outcome)?), None)),
    }
}

pub(super) fn register(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(execute_tx, module)?)
}
