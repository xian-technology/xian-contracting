//! Python access to the Rust block executor: the node adds a block's
//! transactions and runs them all.
use super::settlement_python::rewards_to_py;
use super::transaction_inputs_python::block_meta_from_py;
use super::{bigint_to_py, event_to_py, exception_to_py, vm_to_py};
use crate::block_executor::{BlockExecutor, BlockPolicy, PreparedTx, TxOutcome};
use crate::block_state_python::PyBlockState;
use crate::lmdb_python::{LmdbStorageError, PyLmdbEnvironment};
use crate::receipt_wire::encode_receipt;
use crate::state_view::StateView;
use crate::transaction_inputs::{prepared_transition, prepared_tx, BlockMeta};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use std::time::Instant;

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

fn outcome_to_py(
    py: Python<'_>,
    outcome: &TxOutcome,
    include_details: bool,
) -> PyResult<Py<PyAny>> {
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
        if include_details {
            vm_to_py(py, &outcome.result)?
        } else {
            py.None()
        },
        if include_details {
            exception_to_py(py, outcome.exception.as_ref())?
        } else {
            py.None()
        },
        writes,
        events,
        bigint_to_py(py, &outcome.chi_used)?,
        if include_details {
            optional_to_py(py, outcome.rewards.as_ref(), |rewards| {
                rewards_to_py(py, rewards)
            })?
        } else {
            py.None()
        },
        optional_to_py(py, outcome.chi_rate.as_ref(), |rate| bigint_to_py(py, rate))?,
        outcome.output_writes.into_pyobject(py)?.into_any().unbind(),
    ];
    Ok(PyTuple::new(py, fields)?.into_any().unbind())
}

fn outcomes_to_py(py: Python<'_>, outcomes: &[TxOutcome]) -> PyResult<Vec<Py<PyAny>>> {
    outcomes
        .iter()
        .map(|outcome| outcome_to_py(py, outcome, true))
        .collect()
}

/// `value` converted, or `None`.
fn optional_to_py<T>(
    py: Python<'_>,
    value: Option<&T>,
    convert: impl Fn(&T) -> PyResult<Py<PyAny>>,
) -> PyResult<Py<PyAny>> {
    value.map_or_else(|| Ok(py.None()), convert)
}

type PythonReceipt = (Py<PyBytes>, Py<PyAny>);
type ReceiptRun = (Vec<PythonReceipt>, u128, u128, u128);

struct NativeReceipt {
    hash: String,
    outcome: TxOutcome,
    wire: Option<Vec<u8>>,
}

impl NativeReceipt {
    fn new(hash: String, outcome: TxOutcome) -> PyResult<Self> {
        let wire = (outcome.status == 0)
            .then(|| encode_receipt(&hash, &outcome, None))
            .transpose()
            .map_err(receipt_error)?;
        Ok(Self {
            hash,
            outcome,
            wire,
        })
    }

    fn into_python(
        self,
        py: Python<'_>,
        include_details: bool,
        failure_text: &Bound<'_, PyAny>,
    ) -> PyResult<PythonReceipt> {
        let details = include_details || self.outcome.status != 0;
        let fields = outcome_to_py(py, &self.outcome, details)?;
        let wire = match self.wire {
            Some(wire) => wire,
            None => {
                // Preserve the host's human-readable failure representation.
                let tuple = fields.bind(py).cast::<PyTuple>()?;
                let text: Option<String> = failure_text
                    .call1((self.outcome.status, tuple.get_item(1)?, tuple.get_item(2)?))?
                    .extract()?;
                encode_receipt(&self.hash, &self.outcome, text.as_deref()).map_err(receipt_error)?
            }
        };
        Ok((PyBytes::new(py, &wire).unbind(), fields))
    }
}

fn receipt_error(error: crate::VmExecutionError) -> PyErr {
    super::VmRuntimeExecutionError::new_err(error.to_string())
}

fn elapsed_ns(start: Option<Instant>) -> u128 {
    start.map_or(0, |start| start.elapsed().as_nanos())
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
        let view = StateView::new(environment.store(), overlay.shared());
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

    /// Queue a lifecycle change only after ABCI has authenticated this exact wire
    /// document, its current record, proofs and fee policy.
    fn add_account_transition(&mut self, raw: &[u8], transition_chi: u64) -> PyResult<()> {
        let tx = prepared_transition(raw, &self.block_meta, transition_chi).ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err("not an authorized account transition")
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
        let (outcomes, _) = self.execute_detached::<false>(py)?;
        outcomes_to_py(py, &outcomes)
    }

    /// The outcomes from `run` plus the execution and conversion durations
    /// in nanoseconds. Execution is timed inside the detached region.
    fn run_profiled(&self, py: Python<'_>) -> PyResult<(Vec<Py<PyAny>>, u128, u128)> {
        let (outcomes, execution_ns) = self.execute_detached::<true>(py)?;
        let start = Instant::now();
        let converted = outcomes_to_py(py, &outcomes)?;
        Ok((converted, execution_ns, start.elapsed().as_nanos()))
    }

    /// Encode receipt bytes alongside the projection needed by ABCI.
    fn run_receipts(
        &self,
        py: Python<'_>,
        hashes: Vec<String>,
        include_details: bool,
        failure_text: &Bound<'_, PyAny>,
    ) -> PyResult<Vec<PythonReceipt>> {
        self.receipt_run::<false>(py, hashes, include_details, failure_text)
            .map(|(receipts, _, _, _)| receipts)
    }

    /// Return the receipts and timings for execution, detached success
    /// encoding, and projection (including Python-assisted failures).
    fn run_receipts_profiled(
        &self,
        py: Python<'_>,
        hashes: Vec<String>,
        include_details: bool,
        failure_text: &Bound<'_, PyAny>,
    ) -> PyResult<ReceiptRun> {
        self.receipt_run::<true>(py, hashes, include_details, failure_text)
    }
}

impl PyBlockExecutor {
    fn execute<const PROFILE: bool>(&self) -> PyResult<(Vec<TxOutcome>, u128)> {
        let start = PROFILE.then(Instant::now);
        self.executor.begin_run();
        let outcomes = self
            .txs
            .iter()
            .map(|tx| self.executor.execute(tx))
            .collect::<Result<_, _>>()
            .map_err(|fault| {
                let crate::settlement::Stop::Fault(fault) = fault;
                LmdbStorageError::new_err(fault)
            })?;
        Ok((outcomes, elapsed_ns(start)))
    }

    fn execute_detached<const PROFILE: bool>(
        &self,
        py: Python<'_>,
    ) -> PyResult<(Vec<TxOutcome>, u128)> {
        let work = Unshared(self);
        py.detach(move || Unshared(work.into_inner().execute::<PROFILE>()))
            .into_inner()
    }

    fn receipt_run<const PROFILE: bool>(
        &self,
        py: Python<'_>,
        hashes: Vec<String>,
        include_details: bool,
        failure_text: &Bound<'_, PyAny>,
    ) -> PyResult<ReceiptRun> {
        if hashes.len() != self.txs.len() {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "one receipt hash is required per transaction",
            ));
        }
        let work = Unshared(self);
        let (receipts, execution_ns, encoding_ns) = py.detach(move || {
            let (outcomes, execution_ns) = work.into_inner().execute::<PROFILE>()?;
            let start = PROFILE.then(Instant::now);
            let receipts = hashes
                .into_iter()
                .zip(outcomes)
                .map(|(hash, outcome)| NativeReceipt::new(hash, outcome))
                .collect::<PyResult<Vec<_>>>()?;
            Ok::<_, PyErr>((Unshared(receipts), execution_ns, elapsed_ns(start)))
        })?;
        let start = PROFILE.then(Instant::now);
        let projected = receipts
            .into_inner()
            .into_iter()
            .map(|receipt| receipt.into_python(py, include_details, failure_text))
            .collect::<PyResult<Vec<_>>>()?;
        Ok((projected, execution_ns, encoding_ns, elapsed_ns(start)))
    }
}

pub(super) fn register(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_class::<PyBlockExecutor>()?;
    Ok(())
}
