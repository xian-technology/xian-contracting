//! Python access to the Rust-owned LMDB environment (`contracting.storage`).
//!
//! Python objects are created only after the environment lock is released: a
//! garbage collection run during allocation may drop a cursor, which takes it.
use crate::lmdb_env::{LmdbEnv, LmdbError, OpenOptions, SnapshotCursor};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::PathBuf;

create_exception!(xian_vm_core, LmdbStorageError, PyException);
create_exception!(xian_vm_core, LmdbMapFullError, LmdbStorageError);

fn to_py(error: LmdbError) -> PyErr {
    match error {
        LmdbError::MapFull => LmdbMapFullError::new_err(error.to_string()),
        other => LmdbStorageError::new_err(other.to_string()),
    }
}

fn bytes(py: Python<'_>, value: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, value).unbind()
}

/// One open environment (the unnamed main database of an LMDB directory).
#[pyclass(name = "LmdbEnvironment", module = "xian_vm_core", frozen)]
pub(crate) struct PyLmdbEnvironment {
    env: LmdbEnv,
}

#[pymethods]
impl PyLmdbEnvironment {
    #[new]
    #[pyo3(signature = (
        path, map_size, *, max_dbs = 1, readahead = true, writemap = false,
        sync = true, metasync = true, readonly = false, lock = true
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        path: PathBuf,
        map_size: usize,
        max_dbs: u32,
        readahead: bool,
        writemap: bool,
        sync: bool,
        metasync: bool,
        readonly: bool,
        lock: bool,
    ) -> PyResult<Self> {
        let options = OpenOptions {
            map_size,
            max_dbs,
            readahead,
            writemap,
            sync,
            metasync,
            readonly,
            lock,
        };
        LmdbEnv::open(&path, options)
            .map(|env| Self { env })
            .map_err(to_py)
    }

    fn close(&self) {
        self.env.close();
    }

    #[getter]
    fn closed(&self) -> bool {
        self.env.is_closed()
    }

    fn map_size(&self) -> PyResult<usize> {
        self.env.map_size().map_err(to_py)
    }

    fn set_map_size(&self, map_size: usize) -> PyResult<()> {
        self.env.set_map_size(map_size).map_err(to_py)
    }

    fn entries(&self) -> PyResult<usize> {
        self.env.read(|txn| txn.entries()).map_err(to_py)
    }

    fn get(&self, py: Python<'_>, key: &[u8]) -> PyResult<Option<Py<PyBytes>>> {
        let value = self
            .env
            .read(|txn| Ok(txn.get(key)?.map(<[u8]>::to_vec)))
            .map_err(to_py)?;
        Ok(value.map(|value| bytes(py, &value)))
    }

    /// The value of `key` and the entry count, from one snapshot.
    fn get_with_entries(
        &self,
        py: Python<'_>,
        key: &[u8],
    ) -> PyResult<(Option<Py<PyBytes>>, usize)> {
        let (value, entries) = self
            .env
            .read(|txn| Ok((txn.get(key)?.map(<[u8]>::to_vec), txn.entries()?)))
            .map_err(to_py)?;
        Ok((value.map(|value| bytes(py, &value)), entries))
    }

    fn exists(&self, key: &[u8]) -> PyResult<bool> {
        self.env
            .read(|txn| Ok(txn.get(key)?.is_some()))
            .map_err(to_py)
    }

    /// Apply puts (`value` bytes) and deletes (`value` None) in one transaction.
    fn write(&self, changes: Vec<(Vec<u8>, Option<Vec<u8>>)>) -> PyResult<()> {
        self.env
            .write(|txn| {
                for (key, value) in &changes {
                    match value {
                        Some(value) => txn.put(key, value)?,
                        None => txn.delete(key)?,
                    }
                }
                Ok(())
            })
            .map_err(to_py)
    }

    /// Apply `changes` only to an empty database, in the same transaction that
    /// checks it; returns whether they were applied.
    fn write_if_empty(&self, changes: Vec<(Vec<u8>, Vec<u8>)>) -> PyResult<bool> {
        let mut written = false;
        self.env
            .write(|txn| {
                if txn.entries()? > 0 {
                    return Ok(());
                }
                for (key, value) in &changes {
                    txn.put(key, value)?;
                }
                written = true;
                Ok(())
            })
            .map_err(to_py)?;
        Ok(written)
    }

    fn delete_prefix(&self, prefix: &[u8]) -> PyResult<()> {
        self.env
            .write(|txn| {
                let mut doomed = Vec::new();
                txn.scan_from(prefix, |key, _| {
                    let inside = key.starts_with(prefix);
                    if inside {
                        doomed.push(key.to_vec());
                    }
                    Ok(inside)
                })?;
                doomed.iter().try_for_each(|key| txn.delete(key))
            })
            .map_err(to_py)
    }

    /// Remove every entry (the database itself stays).
    fn clear(&self) -> PyResult<()> {
        self.env.write(|txn| txn.clear()).map_err(to_py)
    }

    fn keys(&self, py: Python<'_>, prefix: &[u8]) -> PyResult<Vec<Py<PyBytes>>> {
        let mut keys = Vec::new();
        self.env
            .read(|txn| {
                txn.scan_from(prefix, |key, _| {
                    let inside = key.starts_with(prefix);
                    if inside {
                        keys.push(key.to_vec());
                    }
                    Ok(inside)
                })
            })
            .map_err(to_py)?;
        Ok(keys.iter().map(|key| bytes(py, key)).collect())
    }

    fn items(&self, py: Python<'_>, prefix: &[u8]) -> PyResult<Vec<(Py<PyBytes>, Py<PyBytes>)>> {
        let mut items = Vec::new();
        self.env
            .read(|txn| {
                txn.scan_from(prefix, |key, value| {
                    let inside = key.starts_with(prefix);
                    if inside {
                        items.push((key.to_vec(), value.to_vec()));
                    }
                    Ok(inside)
                })
            })
            .map_err(to_py)?;
        Ok(items
            .iter()
            .map(|(key, value)| (bytes(py, key), bytes(py, value)))
            .collect())
    }

    /// Up to `limit` keys under `prefix` that sort after `after` (if given),
    /// starting at `start`, and whether more follow.
    fn key_page(
        &self,
        py: Python<'_>,
        prefix: &[u8],
        start: &[u8],
        after: Option<&[u8]>,
        limit: usize,
    ) -> PyResult<(Vec<Py<PyBytes>>, bool)> {
        let mut keys = Vec::new();
        let mut more = false;
        self.env
            .read(|txn| {
                txn.scan_from(start, |key, _| {
                    if !key.starts_with(prefix) {
                        return Ok(false);
                    }
                    if after.is_some_and(|after| key <= after) {
                        return Ok(true);
                    }
                    if keys.len() >= limit {
                        more = true;
                        return Ok(false);
                    }
                    keys.push(key.to_vec());
                    Ok(true)
                })
            })
            .map_err(to_py)?;
        Ok((keys.iter().map(|key| bytes(py, key)).collect(), more))
    }

    fn first_key_with_suffix(
        &self,
        py: Python<'_>,
        suffixes: Vec<Vec<u8>>,
    ) -> PyResult<Option<Py<PyBytes>>> {
        let mut found = None;
        self.env
            .read(|txn| {
                txn.scan_from(b"", |key, _| {
                    if suffixes.iter().any(|suffix| key.ends_with(suffix)) {
                        found = Some(key.to_vec());
                        return Ok(false);
                    }
                    Ok(true)
                })
            })
            .map_err(to_py)?;
        Ok(found.map(|key| bytes(py, &key)))
    }

    /// Entries under `prefix` in key order, read lazily from one snapshot.
    fn iter_items(&self, prefix: &[u8]) -> PyResult<PyLmdbItems> {
        let cursor = self.env.cursor_from(prefix).map_err(to_py)?;
        Ok(PyLmdbItems {
            cursor: std::sync::Mutex::new(Some(cursor)),
            prefix: prefix.to_vec(),
        })
    }
}

/// Iterator over `(key, value)` byte pairs from one read snapshot.
#[pyclass(name = "LmdbItems", module = "xian_vm_core", frozen)]
pub(crate) struct PyLmdbItems {
    cursor: std::sync::Mutex<Option<SnapshotCursor>>,
    prefix: Vec<u8>,
}

#[pymethods]
impl PyLmdbItems {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&self, py: Python<'_>) -> PyResult<Option<(Py<PyBytes>, Py<PyBytes>)>> {
        let mut slot = self
            .cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(cursor) = slot.as_mut() else {
            return Ok(None);
        };
        match cursor.next_entry().map_err(to_py)? {
            Some((key, value)) if key.starts_with(&self.prefix) => {
                Ok(Some((bytes(py, &key), bytes(py, &value))))
            }
            _ => {
                // Release the snapshot as soon as the range ends.
                *slot = None;
                Ok(None)
            }
        }
    }

    /// Release the snapshot early (a generator that is closed before its end).
    fn close(&self) {
        *self
            .cursor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

pub(crate) fn register(py: Python<'_>, module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_class::<PyLmdbEnvironment>()?;
    module.add_class::<PyLmdbItems>()?;
    module.add("LmdbStorageError", py.get_type::<LmdbStorageError>())?;
    module.add("LmdbMapFullError", py.get_type::<LmdbMapFullError>())?;
    Ok(())
}
