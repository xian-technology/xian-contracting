//! Python access to the block overlay (`contracting.storage.Driver` owns one).
//!
//! The state is shared with VM executions through an `Arc`; Python objects are
//! created only after its lock is released.
use crate::block_state::{BlockState, BlockStateError, Stored};
use crate::lmdb_python::PyLmdbEnvironment;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyFrozenSet, PyList};
use std::sync::{Arc, Mutex, MutexGuard};

fn to_py(error: BlockStateError) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

fn stored_to_py(py: Python<'_>, value: &Stored) -> Option<Py<PyBytes>> {
    value.as_ref().map(|bytes| PyBytes::new(py, bytes).unbind())
}

/// Pending writes of the current block as stored values, with per-transaction
/// access tracking and one discarding scope.
#[pyclass(name = "BlockState", module = "xian_vm_core", frozen)]
pub(crate) struct PyBlockState {
    state: Arc<Mutex<BlockState>>,
}

impl PyBlockState {
    fn from_state(state: BlockState) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// The state itself, for a VM execution reading through it.
    pub(crate) fn shared(&self) -> Arc<Mutex<BlockState>> {
        Arc::clone(&self.state)
    }

    fn lock(&self) -> MutexGuard<'_, BlockState> {
        lock(&self.state)
    }
}

pub(crate) fn lock(state: &Mutex<BlockState>) -> MutexGuard<'_, BlockState> {
    state.lock().expect("block state lock poisoned")
}

#[pymethods]
impl PyBlockState {
    #[new]
    fn new() -> Self {
        Self::from_state(BlockState::default())
    }

    /// `(held, value)`: whether the overlay holds `key`, and its stored value
    /// (`None` for a pending deletion).
    fn lookup(&self, py: Python<'_>, key: &str) -> (bool, Option<Py<PyBytes>>) {
        let entry = self.lock().lookup(key).cloned();
        match entry {
            None => (false, None),
            Some(value) => (true, stored_to_py(py, &value)),
        }
    }

    /// Stage `value` (stored bytes) for `key`; `None` stages a deletion.
    #[pyo3(signature = (key, value))]
    fn write(&self, key: &str, value: Option<&[u8]>) {
        self.lock().write(key, value.map(Arc::from));
    }

    /// `(key, value)` entries under `prefix`, in key order.
    #[pyo3(signature = (prefix = ""))]
    fn items<'py>(&self, py: Python<'py>, prefix: &str) -> PyResult<Bound<'py, PyList>> {
        let entries: Vec<(String, Stored)> = self
            .lock()
            .items(prefix)
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        PyList::new(
            py,
            entries
                .iter()
                .map(|(key, value)| (key, stored_to_py(py, value))),
        )
    }

    fn __len__(&self) -> usize {
        self.lock().len()
    }

    fn forget_prefix(&self, prefix: &str) -> PyResult<()> {
        self.lock().forget_prefix(prefix).map_err(to_py)
    }

    fn clear(&self) -> PyResult<()> {
        self.lock().clear().map_err(to_py)
    }

    #[getter]
    fn tracking(&self) -> bool {
        self.lock().tracking()
    }

    fn set_tracking(&self, enabled: bool) -> PyResult<()> {
        self.lock().set_tracking(enabled).map_err(to_py)
    }

    fn record_read(&self, key: &str) {
        self.lock().record_read(key);
    }

    fn record_prefix(&self, prefix: &str) {
        self.lock().record_prefix(prefix);
    }

    /// `(read keys, read prefixes)` of the current transaction; empty while
    /// tracking is off.
    fn access<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<(Bound<'py, PyFrozenSet>, Bound<'py, PyFrozenSet>)> {
        let (reads, prefixes): (Vec<String>, Vec<String>) = match self.lock().access() {
            Some(access) => (
                access.reads.iter().cloned().collect(),
                access.prefixes.iter().cloned().collect(),
            ),
            None => (Vec::new(), Vec::new()),
        };
        Ok((
            PyFrozenSet::new(py, &reads)?,
            PyFrozenSet::new(py, &prefixes)?,
        ))
    }

    fn clear_access(&self) -> PyResult<()> {
        self.lock().clear_access().map_err(to_py)
    }

    fn begin_discarding(&self) -> PyResult<()> {
        self.lock().begin_discarding().map_err(to_py)
    }

    /// Close the discarding scope, undoing every change made inside it.
    fn discard(&self) -> PyResult<()> {
        self.lock().discard().map_err(to_py)
    }

    #[getter]
    fn in_scope(&self) -> bool {
        self.lock().in_scope()
    }

    /// An independent copy (stored values are shared, never mutated).
    fn snapshot(&self) -> PyResult<Self> {
        self.lock().snapshot().map(Self::from_state).map_err(to_py)
    }

    /// Write the pending entries to `environment` in one transaction and
    /// clear the overlay; on any failure nothing is written or cleared.
    fn commit_into(&self, environment: PyRef<'_, PyLmdbEnvironment>) -> PyResult<()> {
        let env = environment.env().clone();
        self.lock()
            .commit(|writes| {
                env.write(|txn| {
                    for (key, value) in writes {
                        match value {
                            Some(value) => txn.put(key.as_bytes(), value)?,
                            None => txn.delete(key.as_bytes())?,
                        }
                    }
                    Ok(())
                })
            })
            .map_err(to_py)?
            .map_err(crate::lmdb_python::lmdb_error_to_py)
    }
}

pub(crate) fn register(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_class::<PyBlockState>()
}
