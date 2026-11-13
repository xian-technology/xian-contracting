//! Python access to the Rust block executor: the node adds a block's
//! transactions and runs them from an index until one needs the Python path.
use super::settlement_python::rewards_to_py;
use super::{bigint_to_py, context_from_py, event_to_py, exception_to_py, py_to_vm, vm_to_py};
use crate::block_executor::{BlockExecutor, BlockPolicy, PreparedTx, TxOutcome};
use crate::block_state_python::PyBlockState;
use crate::lmdb_python::{LmdbStorageError, PyLmdbEnvironment};
use crate::settlement::Stop;
use crate::state_view::StateView;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

/// Values the executor moves across `Python::detach`.
///
/// SAFETY: `detach` runs its closure on the calling thread and returns
/// before the GIL is taken again, so nothing in here is ever touched by two
/// threads; the wrapper only satisfies the `Send` bound.
struct Unshared<T>(T);
unsafe impl<T> Send for Unshared<T> {}

impl<T> Unshared<T> {
    /// Moves the whole wrapper into a closure (a field access would capture
    /// only the field).
    fn into_inner(self) -> T {
        self.0
    }
}

/// A block's transactions for the Rust executor, over the node's LMDB
/// environment and block overlay.
#[pyclass(name = "BlockExecutor", module = "xian_vm_core", unsendable)]
pub(super) struct PyBlockExecutor {
    executor: BlockExecutor,
    /// `None` for a transaction whose inputs did not convert.
    txs: Vec<Option<PreparedTx>>,
}

fn prepared(
    sender: String,
    contract: String,
    function: String,
    kwargs: Option<&Bound<'_, PyDict>>,
    context: &Bound<'_, PyAny>,
    chi_budget: &Bound<'_, PyAny>,
    size_bytes: usize,
) -> Option<PreparedTx> {
    let kwargs = kwargs?;
    let mut converted = Vec::with_capacity(kwargs.len());
    for (key, value) in kwargs.iter() {
        converted.push((key.extract::<String>().ok()?, py_to_vm(value).ok()?));
    }
    let chi_budget = match py_to_vm(chi_budget.clone()).ok()? {
        crate::VmValue::Int(value) => value,
        _ => return None,
    };
    Some(PreparedTx {
        sender,
        contract,
        function,
        kwargs: converted,
        context: context_from_py(context).ok()?,
        chi_budget,
        size_bytes,
    })
}

fn outcome_to_py(py: Python<'_>, outcome: &TxOutcome) -> PyResult<Py<PyAny>> {
    let writes = PyList::empty(py);
    for (key, value) in &outcome.writes {
        writes.append((key, vm_to_py(py, value)?))?;
    }
    let events = PyList::empty(py);
    for event in &outcome.events {
        events.append(event_to_py(py, event)?)?;
    }
    let rewards = match &outcome.rewards {
        Some(rewards) => rewards_to_py(py, rewards)?,
        None => py.None(),
    };
    let fields: Vec<Py<PyAny>> = vec![
        outcome.status.into_pyobject(py)?.into_any().unbind(),
        vm_to_py(py, &outcome.result)?,
        exception_to_py(py, outcome.exception.as_ref())?,
        writes.into_any().unbind(),
        events.into_any().unbind(),
        bigint_to_py(py, &outcome.chi_used)?,
        rewards,
    ];
    Ok(pyo3::types::PyTuple::new(py, fields)?.into_any().unbind())
}

#[pymethods]
impl PyBlockExecutor {
    #[new]
    #[pyo3(signature = (environment, overlay, *, charge_fees, distribute_fee_rewards, protected_keys))]
    fn new(
        environment: PyRef<'_, PyLmdbEnvironment>,
        overlay: PyRef<'_, PyBlockState>,
        charge_fees: bool,
        distribute_fee_rewards: bool,
        protected_keys: Vec<String>,
    ) -> Self {
        let view = StateView::new(environment.env().clone(), overlay.shared());
        let policy = BlockPolicy {
            charge_fees,
            distribute_fee_rewards,
            protected_keys,
        };
        Self {
            executor: BlockExecutor::new(view, policy),
            txs: Vec::new(),
        }
    }

    /// Add a metered transaction: `kwargs` and `context` as the Python path
    /// hands them to the VM (`context` without the owner). `None` kwargs (or
    /// inputs that do not convert) leave the transaction to Python.
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        sender: String,
        contract: String,
        function: String,
        kwargs: Option<Bound<'_, PyDict>>,
        context: Bound<'_, PyAny>,
        chi_budget: Bound<'_, PyAny>,
        size_bytes: usize,
    ) {
        self.txs.push(prepared(
            sender,
            contract,
            function,
            kwargs.as_ref(),
            &context,
            &chi_budget,
            size_bytes,
        ));
    }

    fn __len__(&self) -> usize {
        self.txs.len()
    }

    /// Execute and stage the transactions from `start` with the GIL
    /// released, until the end or the first one the Python path must run.
    /// Returns `(outcomes, stop)`: one `(status, result, exception, writes,
    /// events, chi_used, rewards)` per executed transaction, and `(index,
    /// reason)` of the transaction left to Python (`None` at the end). A storage
    /// fault raises `LmdbStorageError`.
    fn run(
        &self,
        py: Python<'_>,
        start: usize,
    ) -> PyResult<(Vec<Py<PyAny>>, Option<(usize, String)>)> {
        let work = Unshared((&self.executor, self.txs.get(start..).unwrap_or(&[])));
        let (outcomes, stopped) = py
            .detach(move || {
                let (executor, txs) = work.into_inner();
                executor.begin_run();
                let mut outcomes = Vec::new();
                for (offset, tx) in txs.iter().enumerate() {
                    let Some(tx) = tx else {
                        return Unshared((
                            outcomes,
                            Some((offset, Stop::Handback("inputs did not convert".to_owned()))),
                        ));
                    };
                    match executor.execute(tx) {
                        Ok(outcome) => outcomes.push(outcome),
                        Err(stop) => return Unshared((outcomes, Some((offset, stop)))),
                    }
                }
                Unshared((outcomes, None))
            })
            .into_inner();
        let stop = match stopped {
            None => None,
            Some((_, Stop::Fault(fault))) => return Err(LmdbStorageError::new_err(fault)),
            Some((offset, Stop::Handback(reason))) => Some((start + offset, reason)),
        };
        let outcomes = outcomes
            .iter()
            .map(|outcome| outcome_to_py(py, outcome))
            .collect::<PyResult<_>>()?;
        Ok((outcomes, stop))
    }
}

pub(super) fn register(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_class::<PyBlockExecutor>()?;
    Ok(())
}
