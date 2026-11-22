//! `decode_and_validate_transaction`: static admission for the node.
use crate::transaction_admission::admit_transaction;
use lru::LruCache;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use pyo3::IntoPyObjectExt;
use serde_json::Value;
use std::collections::HashMap;
use std::mem::size_of;

// Charge for the entry, key handle, LRU and index structure apart from the
// raw key bytes and the document's heap allocations.
const ENTRY_OVERHEAD: usize = 256;

struct CachedTransaction {
    document: Value,
    retained_bytes: usize,
}

/// Successful admissions scoped to one application and its fixed chain ID.
/// Cache misses use the same native rules as uncached admission.
#[pyclass(module = "xian_vm_core")]
struct TransactionAdmissionCache {
    #[pyo3(get)]
    chain_id: String,
    max_entries: usize,
    max_bytes: usize,
    transactions: LruCache<Box<[u8]>, CachedTransaction>,
    retained_bytes: usize,
    hits: u64,
    misses: u64,
    evictions: u64,
}

#[pymethods]
impl TransactionAdmissionCache {
    #[new]
    #[pyo3(signature = (chain_id, *, max_entries, max_bytes))]
    fn new(chain_id: String, max_entries: usize, max_bytes: usize) -> Self {
        Self {
            chain_id,
            max_entries,
            max_bytes,
            transactions: LruCache::unbounded(),
            retained_bytes: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    /// Materialize a fresh Python document for the caller to mutate.
    fn decode(&mut self, py: Python<'_>, raw: &[u8]) -> PyResult<Py<PyAny>> {
        if let Some(cached) = self.transactions.get(raw) {
            self.hits = self.hits.saturating_add(1);
            return json_to_py(py, &cached.document);
        }
        self.misses = self.misses.saturating_add(1);
        let document = admitted_document(raw, &self.chain_id)?;
        let output = json_to_py(py, &document)?;
        if self.max_entries != 0 && raw.len() < self.max_bytes {
            self.retain(raw, document);
        }
        Ok(output)
    }

    fn stats(&self) -> HashMap<&'static str, u64> {
        HashMap::from([
            ("hits", self.hits),
            ("misses", self.misses),
            ("evictions", self.evictions),
            ("entries", self.transactions.len() as u64),
            ("retained_bytes", self.retained_bytes as u64),
        ])
    }
}

impl TransactionAdmissionCache {
    fn retain(&mut self, raw: &[u8], document: Value) {
        let retained_bytes = raw
            .len()
            .saturating_add(ENTRY_OVERHEAD)
            .saturating_add(json_heap_bytes(&document));
        if retained_bytes > self.max_bytes {
            return;
        }
        while retained_bytes > self.max_bytes - self.retained_bytes
            || self.transactions.len() == self.max_entries
        {
            let (_, evicted) = self
                .transactions
                .pop_lru()
                .expect("an admissible entry only evicts from a nonempty cache");
            self.retained_bytes -= evicted.retained_bytes;
            self.evictions = self.evictions.saturating_add(1);
        }
        self.transactions.put(
            raw.into(),
            CachedTransaction {
                document,
                retained_bytes,
            },
        );
        self.retained_bytes += retained_bytes;
    }
}

// The default serde_json map uses a B-tree. Charge each nonempty map for a
// root node and room for further nodes, including sparsely occupied nodes.
// This budget counts retained data and is not a measure of allocator RSS.
fn json_heap_bytes(value: &Value) -> usize {
    match value {
        Value::String(text) => text.capacity(),
        Value::Array(items) => items.iter().fold(
            items.capacity().saturating_mul(size_of::<Value>()),
            |bytes, item| bytes.saturating_add(json_heap_bytes(item)),
        ),
        Value::Object(items) if !items.is_empty() => items.iter().fold(
            1024_usize.saturating_add(items.len().saturating_mul(256)),
            |bytes, (key, value)| {
                bytes
                    .saturating_add(key.capacity())
                    .saturating_add(json_heap_bytes(value))
            },
        ),
        _ => 0,
    }
}

fn admitted_document(raw: &[u8], chain_id: &str) -> PyResult<Value> {
    admit_transaction(raw, chain_id).map_err(|refusal| PyValueError::new_err(refusal.to_string()))
}

/// The decoded transaction document (plain JSON types) if `raw` is admitted
/// for `chain_id`; `ValueError` with the refusal text otherwise.
#[pyfunction]
fn decode_and_validate_transaction(
    py: Python<'_>,
    raw: &[u8],
    chain_id: &str,
) -> PyResult<Py<PyAny>> {
    let document = admitted_document(raw, chain_id)?;
    json_to_py(py, &document)
}

fn json_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(raw) => raw.into_py_any(py),
        Value::Number(number) => number_to_py(py, number),
        Value::String(raw) => raw.into_py_any(py),
        Value::Array(items) => list_to_py(py, items),
        Value::Object(items) => dict_to_py(py, items),
    }
}

fn list_to_py(py: Python<'_>, items: &[Value]) -> PyResult<Py<PyAny>> {
    let list = PyList::empty(py);
    for item in items {
        list.append(json_to_py(py, item)?)?;
    }
    Ok(list.into_any().unbind())
}

fn dict_to_py(py: Python<'_>, items: &serde_json::Map<String, Value>) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);
    for (key, item) in items {
        dict.set_item(key, json_to_py(py, item)?)?;
    }
    Ok(dict.into_any().unbind())
}

fn number_to_py(py: Python<'_>, number: &serde_json::Number) -> PyResult<Py<PyAny>> {
    if let Some(value) = number.as_i64() {
        value.into_py_any(py)
    } else if let Some(value) = number.as_u64() {
        value.into_py_any(py)
    } else if let Some(value) = number.as_f64() {
        value.into_py_any(py)
    } else {
        Err(PyValueError::new_err("Unsupported JSON number"))
    }
}

pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(decode_and_validate_transaction, module)?)?;
    module.add_class::<TransactionAdmissionCache>()?;
    Ok(())
}
