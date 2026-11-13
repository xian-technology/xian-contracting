//! Storage reads served in Rust: the block overlay, then the node's LMDB
//! environment.
//!
//! The host names the environment, the driver's block overlay and the writes
//! it staged itself during this execution (`NativeVmHost.committed_storage`).
//! A key the host staged is read through the host as before; every other key
//! is read from the overlay or LMDB and decoded here. A read or decode failure
//! is a host fault: it aborts the execution and is raised to the caller as
//! `LmdbStorageError`.
use crate::block_state::BlockState;
use crate::block_state_python::{lock, PyBlockState};
use crate::lmdb_env::LmdbEnv;
use crate::lmdb_python::{LmdbStorageError, PyLmdbEnvironment};
use crate::stored_value::decode_stored_value;
use crate::{VmExecutionError, VmValue};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::sync::{Arc, Mutex};

pub(super) struct CommittedState {
    env: LmdbEnv,
    overlay: Arc<Mutex<BlockState>>,
    staged: Py<PyDict>,
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
        let (environment, overlay, staged) = storage.extract::<(
            PyRef<'_, PyLmdbEnvironment>,
            PyRef<'_, PyBlockState>,
            Bound<'_, PyDict>,
        )>()?;
        Ok(Some(Self {
            env: environment.env().clone(),
            overlay: overlay.shared(),
            staged: staged.unbind(),
            fault: None,
        }))
    }

    /// `Some(value)` for a stored key (`None` inside when it is missing);
    /// `None` when the host staged it and must answer.
    pub(super) fn read(&mut self, key: &str) -> Result<Option<Option<VmValue>>, VmExecutionError> {
        match self.staged_by_host(key) {
            Ok(true) => return Ok(None),
            Ok(false) => {}
            Err(error) => return Err(self.fail(error)),
        }
        let value = self.load(key).map_err(|error| self.fail(error))?;
        Ok(Some(value))
    }

    fn staged_by_host(&self, key: &str) -> PyResult<bool> {
        Python::attach(|py| {
            let staged = self.staged.bind(py);
            Ok(!staged.is_empty() && staged.contains(key)?)
        })
    }

    /// The decoded value of `key` in the overlay or else in LMDB; any failure
    /// is a host fault.
    fn load(&self, key: &str) -> PyResult<Option<VmValue>> {
        let pending = lock(&self.overlay).lookup(key).cloned();
        let stored = match pending {
            Some(entry) => entry.as_deref().map(decode_stored_value),
            None => self
                .env
                .read(|txn| Ok(txn.get(key.as_bytes())?.map(decode_stored_value)))
                .map_err(|error| LmdbStorageError::new_err(format!("reading {key:?}: {error}")))?,
        };
        stored.transpose().map_err(|error| {
            LmdbStorageError::new_err(format!("corrupt stored value at {key:?}: {error}"))
        })
    }

    fn fail(&mut self, error: PyErr) -> VmExecutionError {
        let failure = VmExecutionError::new(format!("host fault: {error}"));
        self.fault.get_or_insert(error);
        failure
    }

    /// Raise the host fault this execution hit, if any.
    pub(super) fn finish(self) -> PyResult<()> {
        match self.fault {
            Some(fault) => Err(fault),
            None => Ok(()),
        }
    }
}
