//! Python access to the block overlay (`contracting.storage.Driver` owns one).
//!
//! The state is shared with VM executions through an `Arc`; Python objects are
//! created only after its lock is released.
use crate::block_state::{BlockState, BlockStateError, Stored};
use crate::interpreter::numeric_v2;
use crate::lmdb_python::PyLmdbEnvironment;
use crate::python_bindings::py_to_vm;
use crate::set_member_codec::validate_set_normalization_work;
use crate::stored_value_encoder::encode_stored_value;
use crate::XIAN_VM_V2_PROFILE;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList};
use std::sync::{Arc, Mutex, MutexGuard};

fn to_py(error: BlockStateError) -> PyErr {
    PyRuntimeError::new_err(error.to_string())
}

fn stored_to_py(py: Python<'_>, value: &Stored) -> Option<Py<PyBytes>> {
    value.as_ref().map(|bytes| PyBytes::new(py, bytes).unbind())
}

/// The V2 stored bytes of a Python value: the VM boundary conversion, the
/// aggregate set normalization budget, then the stored-value writer. `None`
/// stages a deletion; a value V2 cannot store raises `ValueError`.
fn stored_bytes(value: &Bound<'_, PyAny>) -> PyResult<Stored> {
    if value.is_none() {
        return Ok(None);
    }
    let _scope = numeric_v2::Scope::enter(XIAN_VM_V2_PROFILE);
    py_to_vm(value.clone())
        .and_then(|value| {
            validate_set_normalization_work(&value)?;
            encode_stored_value(&value)
        })
        .map(|bytes| Some(Arc::from(bytes)))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

/// Pending writes of the current block as stored values, with one discarding
/// scope.
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

pub(crate) use crate::block_state::lock;

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

    /// Stage the V2 stored bytes of the Python value `value` for `key`
    /// (`None` stages a deletion); a value V2 cannot store raises
    /// `ValueError` and stages nothing.
    fn write_value(&self, key: &str, value: &Bound<'_, PyAny>) -> PyResult<()> {
        let stored = stored_bytes(value)?;
        self.lock().write(key, stored);
        Ok(())
    }

    /// `write_value` for every `(key, value)`, all or nothing: every value
    /// is encoded before any is staged.
    fn write_values(&self, items: Vec<(String, Bound<'_, PyAny>)>) -> PyResult<()> {
        let encoded = items
            .iter()
            .map(|(key, value)| Ok((key, stored_bytes(value)?)))
            .collect::<PyResult<Vec<_>>>()?;
        let mut state = self.lock();
        for (key, stored) in encoded {
            state.write(key, stored);
        }
        Ok(())
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

/// The bytes `BlockState.write_value` stores for `value` (`None` for
/// `None`, a deletion): what tooling outside execution (state roots over
/// values, exports) must hash or store. A value V2 cannot store raises
/// `ValueError`.
#[pyfunction]
fn stored_value_bytes<'py>(
    py: Python<'py>,
    value: &Bound<'py, PyAny>,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    Ok(stored_bytes(value)?.map(|bytes| PyBytes::new(py, &bytes)))
}

pub(crate) fn register(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_class::<PyBlockState>()?;
    module.add_function(wrap_pyfunction!(stored_value_bytes, module)?)
}
