//! Python access to the Rust block executor: the node adds a block's
//! transactions and runs them all.
use super::settlement_python::rewards_to_py;
use super::transaction_inputs_python::block_meta_from_py;
use super::{bigint_to_py, event_to_py, exception_to_py, vm_to_py};
use crate::block_executor::{BlockExecutor, BlockPolicy, PreparedTx, TxOutcome};
use crate::block_state_python::PyBlockState;
use crate::lmdb_python::{LmdbStorageError, PyLmdbEnvironment};
use crate::state_view::StateView;
use crate::transaction_inputs::{prepared_tx, BlockMeta};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

/// Values the executor moves across `Python::detach`.
///
/// SAFETY: `detach` runs its closure on the calling thread and returns
/// before the GIL is taken again, so nothing in here is ever touched by two
/// threads; the wrapper only satisfies the `Send` bound.
pub(super) struct Unshared<T>(pub(super) T);
unsafe impl<T> Send for Unshared<T> {}

impl<T> Unshared<T> {
    /// Moves the whole wrapper into a closure (a field access would capture
    /// only the field).
    pub(super) fn into_inner(self) -> T {
        self.0
    }
}

/// A block's transactions for the Rust executor, over the node's LMDB
/// environment and block overlay.
#[pyclass(name = "BlockExecutor", module = "xian_vm_core", unsendable)]
pub(super) struct PyBlockExecutor {
    executor: BlockExecutor,
    block_meta: BlockMeta,
    txs: Vec<PreparedTx>,
}

/// `items` converted one by one into a Python list.
fn list_to_py<T>(
    py: Python<'_>,
    items: &[T],
    convert: impl Fn(&T) -> PyResult<Py<PyAny>>,
) -> PyResult<Py<PyAny>> {
    let list = PyList::empty(py);
    for item in items {
        list.append(convert(item)?)?;
    }
    Ok(list.into_any().unbind())
}

fn outcome_to_py(py: Python<'_>, outcome: &TxOutcome) -> PyResult<Py<PyAny>> {
    let writes = list_to_py(py, &outcome.writes, |(key, value)| {
        Ok((key, vm_to_py(py, value)?)
            .into_pyobject(py)?
            .into_any()
            .unbind())
    })?;
    let events = list_to_py(py, &outcome.events, |event| {
        Ok(event_to_py(py, event)?.into_any().unbind())
    })?;
    let fields: Vec<Py<PyAny>> = vec![
        outcome.status.into_pyobject(py)?.into_any().unbind(),
        vm_to_py(py, &outcome.result)?,
        exception_to_py(py, outcome.exception.as_ref())?,
        writes,
        events,
        bigint_to_py(py, &outcome.chi_used)?,
        optional_to_py(py, outcome.rewards.as_ref(), |rewards| {
            rewards_to_py(py, rewards)
        })?,
        optional_to_py(py, outcome.chi_rate.as_ref(), |rate| bigint_to_py(py, rate))?,
        outcome.output_writes.into_pyobject(py)?.into_any().unbind(),
    ];
    Ok(pyo3::types::PyTuple::new(py, fields)?.into_any().unbind())
}

/// `value` converted, or `None`.
fn optional_to_py<T>(
    py: Python<'_>,
    value: Option<&T>,
    convert: impl Fn(&T) -> PyResult<Py<PyAny>>,
) -> PyResult<Py<PyAny>> {
    value.map_or_else(|| Ok(py.None()), convert)
}

#[pymethods]
impl PyBlockExecutor {
    #[new]
    #[pyo3(signature = (
        environment,
        overlay,
        *,
        meter_execution,
        charge_fees,
        distribute_fee_rewards,
        protected_keys,
        zk_enabled_without_state,
        block_meta,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        environment: PyRef<'_, PyLmdbEnvironment>,
        overlay: PyRef<'_, PyBlockState>,
        meter_execution: bool,
        charge_fees: bool,
        distribute_fee_rewards: bool,
        protected_keys: Vec<String>,
        zk_enabled_without_state: bool,
        block_meta: &Bound<'_, PyDict>,
    ) -> PyResult<Self> {
        let view = StateView::new(environment.env().clone(), overlay.shared());
        let policy = BlockPolicy {
            meter_execution,
            charge_fees,
            distribute_fee_rewards,
            protected_keys,
            zk_enabled_without_state,
        };
        Ok(Self {
            executor: BlockExecutor::new(view, policy),
            block_meta: block_meta_from_py(block_meta)?,
            txs: Vec::new(),
        })
    }

    /// Add an admitted transaction by its wire bytes; Rust reads its call,
    /// arguments and context (`transaction_inputs`). Bytes admission would
    /// refuse raise `ValueError`.
    fn add(&mut self, raw: &[u8]) -> PyResult<()> {
        let tx = prepared_tx(raw, &self.block_meta).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("not an admitted transaction")
        })?;
        self.txs.push(tx);
        Ok(())
    }

    fn __len__(&self) -> usize {
        self.txs.len()
    }

    /// Execute and stage every transaction with the GIL released. Returns
    /// one `(status, result, exception, writes, events, chi_used, rewards,
    /// chi_rate, output_writes)` per transaction (the last two feed the
    /// per-transaction log records). A host fault raises
    /// `LmdbStorageError`: the node halts.
    fn run(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAny>>> {
        let work = Unshared((&self.executor, self.txs.as_slice()));
        let outcomes = py
            .detach(move || {
                let (executor, txs) = work.into_inner();
                executor.begin_run();
                let outcomes: Result<Vec<TxOutcome>, _> =
                    txs.iter().map(|tx| executor.execute(tx)).collect();
                Unshared(outcomes)
            })
            .into_inner();
        let outcomes = outcomes.map_err(|fault| {
            let crate::settlement::Stop::Fault(fault) = fault;
            LmdbStorageError::new_err(fault)
        })?;
        outcomes
            .iter()
            .map(|outcome| outcome_to_py(py, outcome))
            .collect()
    }
}

pub(super) fn register(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_class::<PyBlockExecutor>()?;
    Ok(())
}
