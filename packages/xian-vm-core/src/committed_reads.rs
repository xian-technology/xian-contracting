//! Committed-state reads served in Rust from the node's LMDB environment.
//!
//! The host names the environment and the pending-write containers that shadow
//! it (`NativeVmHost.committed_storage`). A key held by one of them is read
//! through the host as before; every other key is read from LMDB and decoded
//! here. Those reads are reported back once per execution so the driver's read
//! bookkeeping matches a Python read. A read or decode failure is a host fault:
//! it aborts the execution and is raised to the caller as `LmdbStorageError`.
use super::vm_to_py;
use crate::lmdb_env::LmdbEnv;
use crate::lmdb_python::{LmdbStorageError, PyLmdbEnvironment};
use crate::stored_value::decode_stored_value;
use crate::{VmExecutionError, VmValue};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};

pub(super) struct CommittedState {
    env: LmdbEnv,
    pending: Vec<Py<PyDict>>,
    reads: Vec<(String, VmValue)>,
    fault: Option<PyErr>,
}

impl CommittedState {
    /// The committed state `host` offers, if any.
    pub(super) fn from_host(host: &Bound<'_, PyAny>) -> PyResult<Option<Self>> {
        if !host.hasattr("committed_storage")? {
            return Ok(None);
        }
        let storage = host.call_method0("committed_storage")?;
        if storage.is_none() {
            return Ok(None);
        }
        let (environment, pending) =
            storage.extract::<(PyRef<'_, PyLmdbEnvironment>, Bound<'_, PyTuple>)>()?;
        let pending = pending
            .iter()
            .map(|container| container.cast_into::<PyDict>().map(Bound::unbind))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(Self {
            env: environment.env().clone(),
            pending,
            reads: Vec::new(),
            fault: None,
        }))
    }

    /// `Some(value)` for a committed key (`None` inside when it is missing);
    /// `None` when a pending write shadows it and the host must answer.
    pub(super) fn read(&mut self, key: &str) -> Result<Option<Option<VmValue>>, VmExecutionError> {
        match self.shadowed(key) {
            Ok(true) => return Ok(None),
            Ok(false) => {}
            Err(error) => return Err(self.fail(error)),
        }
        let value = self.load(key).map_err(|error| self.fail(error))?;
        self.reads
            .push((key.to_owned(), value.clone().unwrap_or(VmValue::None)));
        Ok(Some(value))
    }

    fn shadowed(&self, key: &str) -> PyResult<bool> {
        Python::attach(|py| {
            for container in &self.pending {
                if container.bind(py).contains(key)? {
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    /// The decoded committed value of `key`; any failure is a host fault.
    fn load(&self, key: &str) -> PyResult<Option<VmValue>> {
        let stored = self
            .env
            .read(|txn| Ok(txn.get(key.as_bytes())?.map(decode_stored_value)))
            .map_err(|error| LmdbStorageError::new_err(format!("reading {key:?}: {error}")))?;
        stored.transpose().map_err(|error| {
            LmdbStorageError::new_err(format!("corrupt stored value at {key:?}: {error}"))
        })
    }

    fn fail(&mut self, error: PyErr) -> VmExecutionError {
        let failure = VmExecutionError::new(format!("host fault: {error}"));
        self.fault.get_or_insert(error);
        failure
    }

    /// Raise a host fault, or report the reads to the host.
    pub(super) fn finish(self, py: Python<'_>, host: &Bound<'_, PyAny>) -> PyResult<()> {
        if let Some(fault) = self.fault {
            return Err(fault);
        }
        if self.reads.is_empty() {
            return Ok(());
        }
        let reads = PyList::empty(py);
        for (key, value) in &self.reads {
            reads.append((key, vm_to_py(py, value)?))?;
        }
        host.call_method1("record_committed_reads", (reads,))?;
        Ok(())
    }
}
