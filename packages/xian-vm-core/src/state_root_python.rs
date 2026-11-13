//! Python access to the consensus state root (xian-abci's `xian.state_root`).
use crate::lmdb_python::{lmdb_error_to_py, PyLmdbEnvironment};
use crate::state_root::{leaf_hash, DuplicateKey, Hash, StateRootTree};
use crate::state_root_storage::{storage_state_root, HashedKeys, StorageRootError};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

fn hash_arg(leaf: &[u8]) -> PyResult<Hash> {
    leaf.try_into()
        .map_err(|_| PyValueError::new_err("a state root leaf hash has 32 bytes"))
}

fn bytes(py: Python<'_>, value: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, value).unbind()
}

/// The state root treap over (key, leaf hash); see `state_root.rs`.
#[pyclass(name = "StateRootTree", module = "xian_vm_core")]
pub(crate) struct PyStateRootTree {
    tree: StateRootTree,
}

#[pymethods]
impl PyStateRootTree {
    #[new]
    fn new() -> Self {
        Self {
            tree: StateRootTree::default(),
        }
    }

    /// The tree of `(key, leaf hash)` pairs in any order.
    #[staticmethod]
    fn from_leaves(leaves: Vec<(String, Vec<u8>)>) -> PyResult<Self> {
        let leaves = leaves
            .into_iter()
            .map(|(key, leaf)| Ok((key, hash_arg(&leaf)?)))
            .collect::<PyResult<Vec<_>>>()?;
        StateRootTree::from_leaves(leaves)
            .map(|tree| Self { tree })
            .map_err(|DuplicateKey(key)| {
                PyValueError::new_err(format!("duplicate consensus state key: {key}"))
            })
    }

    /// The tree of the hashed entries committed in `environment` (keys not
    /// starting with `__`, `node_keys` and keys under `node_prefixes`), each
    /// leaf over the stored bytes. Reads one snapshot with the GIL released.
    #[staticmethod]
    fn from_storage(
        py: Python<'_>,
        environment: PyRef<'_, PyLmdbEnvironment>,
        node_keys: Vec<String>,
        node_prefixes: Vec<String>,
    ) -> PyResult<Self> {
        let env = environment.env().clone();
        let hashed = HashedKeys::new(node_keys, node_prefixes);
        match py.detach(move || storage_state_root(&env, &hashed)) {
            Ok(tree) => Ok(Self { tree }),
            Err(StorageRootError::Lmdb(error)) => Err(lmdb_error_to_py(error)),
            Err(StorageRootError::KeyNotText(key)) => Err(PyValueError::new_err(format!(
                "stored state key is not UTF-8: {}",
                String::from_utf8_lossy(&key)
            ))),
        }
    }

    #[getter]
    fn root_hash(&self, py: Python<'_>) -> Py<PyBytes> {
        bytes(py, &self.tree.root_hash())
    }

    fn __len__(&self) -> usize {
        self.tree.len()
    }

    fn leaf_hash(&self, py: Python<'_>, key: &str) -> Option<Py<PyBytes>> {
        self.tree.leaf_hash(key).map(|leaf| bytes(py, &leaf))
    }

    fn set_leaf(&mut self, key: &str, leaf: &[u8]) -> PyResult<()> {
        self.tree.set(key, hash_arg(leaf)?);
        Ok(())
    }

    /// Remove `key`; False when it was absent.
    fn remove(&mut self, key: &str) -> bool {
        self.tree.remove(key)
    }
}

/// The leaf hash of `key` whose value is stored as `stored`.
#[pyfunction]
fn state_root_leaf_hash(py: Python<'_>, key: &str, stored: &[u8]) -> Py<PyBytes> {
    bytes(py, &leaf_hash(key, stored))
}

pub(crate) fn register(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_class::<PyStateRootTree>()?;
    module.add_function(wrap_pyfunction!(state_root_leaf_hash, module)?)?;
    Ok(())
}
