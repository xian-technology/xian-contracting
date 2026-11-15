//! Committed state kept in memory: the browser build's store, and a second
//! backend for tests. Entries are ordered by their key bytes, the order LMDB
//! keeps (its default comparison is `memcmp`), so every scan visits the same
//! entries in the same order as over the node's store.
use crate::block_state::Stored;
use crate::committed_store::CommittedStore;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock, RwLockReadGuard};

/// A key and its stored bytes.
pub(crate) type Entry = (Vec<u8>, Arc<[u8]>);

#[derive(Debug, Default)]
pub(crate) struct MemoryStore {
    entries: RwLock<BTreeMap<Vec<u8>, Arc<[u8]>>>,
}

impl MemoryStore {
    pub(crate) fn from_entries(entries: impl IntoIterator<Item = Entry>) -> Self {
        Self {
            entries: RwLock::new(entries.into_iter().collect()),
        }
    }

    fn entries(&self) -> RwLockReadGuard<'_, BTreeMap<Vec<u8>, Arc<[u8]>>> {
        // Writers never panic while holding the lock; recover the map anyway.
        self.entries
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every entry, in key order (values are shared, not copied).
    pub(crate) fn snapshot(&self) -> Vec<Entry> {
        self.entries()
            .iter()
            .map(|(key, value)| (key.clone(), Arc::clone(value)))
            .collect()
    }

    /// Persist an overlay's pending entries (`BlockState::commit`): a value
    /// is stored, a pending deletion removes the entry.
    pub(crate) fn apply(&self, writes: &BTreeMap<String, Stored>) {
        let mut entries = self
            .entries
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (key, value) in writes {
            match value {
                Some(value) => entries.insert(key.as_bytes().to_vec(), Arc::clone(value)),
                None => entries.remove(key.as_bytes()),
            };
        }
    }
}

impl CommittedStore for MemoryStore {
    fn read(&self, key: &[u8], read: &mut dyn FnMut(Option<&[u8]>)) -> Result<(), String> {
        read(self.entries().get(key).map(|value| &value[..]));
        Ok(())
    }

    fn scan_from(
        &self,
        start: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]) -> Result<bool, String>,
    ) -> Result<(), String> {
        let entries = self.entries();
        let range = entries
            .range::<[u8], _>((std::ops::Bound::Included(start), std::ops::Bound::Unbounded));
        for (key, value) in range {
            if !visit(key, value)? {
                break;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(text: &str) -> Stored {
        Some(Arc::from(text.as_bytes()))
    }

    fn scanned(store: &MemoryStore, start: &[u8], limit: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut seen = Vec::new();
        store
            .scan_from(start, &mut |key, value| {
                seen.push((key.to_vec(), value.to_vec()));
                Ok(seen.len() < limit)
            })
            .unwrap();
        seen
    }

    fn read(store: &MemoryStore, key: &str) -> Option<Vec<u8>> {
        let mut found = None;
        store
            .read(key.as_bytes(), &mut |value| {
                found = value.map(<[u8]>::to_vec)
            })
            .unwrap();
        found
    }

    #[test]
    fn scans_follow_key_byte_order_from_the_start_key() {
        // Byte order puts "a.b:z" (0x7a) before "a.b:é" (0xc3 0xa9) and
        // uppercase before lowercase, as LMDB's memcmp does.
        let keys = ["a.b:é", "a.b:z", "B", "a.y", "a"];
        let store = MemoryStore::from_entries(
            keys.iter()
                .map(|key| (key.as_bytes().to_vec(), Arc::from(key.as_bytes()))),
        );
        let listed: Vec<Vec<u8>> = scanned(&store, b"", usize::MAX)
            .into_iter()
            .map(|(key, _)| key)
            .collect();
        let expected: Vec<&[u8]> = vec![b"B", b"a", b"a.b:z", "a.b:é".as_bytes(), b"a.y"];
        assert_eq!(listed, expected);
        assert_eq!(scanned(&store, b"a.b:", 2).len(), 2);
        assert_eq!(scanned(&store, b"a.b:", 2)[0].0, b"a.b:z");
        assert!(scanned(&store, b"z", usize::MAX).is_empty());
    }

    #[test]
    fn a_visit_error_ends_the_scan_with_that_error() {
        let store = MemoryStore::from_entries([(b"a".to_vec(), Arc::from(&b"1"[..]))]);
        let error = store
            .scan_from(b"", &mut |_, _| Err("stop".to_owned()))
            .unwrap_err();
        assert_eq!(error, "stop");
    }

    #[test]
    fn applied_writes_store_values_and_remove_deleted_keys() {
        let store = MemoryStore::from_entries([
            (b"kept".to_vec(), Arc::from(&b"1"[..])),
            (b"gone".to_vec(), Arc::from(&b"2"[..])),
        ]);
        let writes = BTreeMap::from([
            ("gone".to_owned(), None),
            ("new".to_owned(), stored("3")),
            ("missing".to_owned(), None),
        ]);
        store.apply(&writes);
        assert_eq!(read(&store, "kept"), Some(b"1".to_vec()));
        assert_eq!(read(&store, "gone"), None);
        assert_eq!(read(&store, "new"), Some(b"3".to_vec()));
        let keys: Vec<Vec<u8>> = store.snapshot().into_iter().map(|(key, _)| key).collect();
        assert_eq!(keys, vec![b"kept".to_vec(), b"new".to_vec()]);
    }
}
