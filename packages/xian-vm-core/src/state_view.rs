//! The node's current state as Rust reads it: the block overlay first, then
//! the committed store (the node's LMDB environment, or memory), decoded with
//! the stored-value reader.
use crate::block_state::{lock, BlockState};
use crate::committed_store::CommittedStore;
use crate::stored_value::decode_stored_value;
use crate::VmValue;
use std::iter::Peekable;
use std::sync::{Arc, Mutex};
use std::vec::IntoIter;

#[derive(Clone)]
pub(crate) struct StateView {
    store: Arc<dyn CommittedStore>,
    overlay: Arc<Mutex<BlockState>>,
}

impl StateView {
    pub(crate) fn new(store: Arc<dyn CommittedStore>, overlay: Arc<Mutex<BlockState>>) -> Self {
        Self { store, overlay }
    }

    pub(crate) fn overlay(&self) -> &Arc<Mutex<BlockState>> {
        &self.overlay
    }

    /// The value at `key` as `Driver.get` returns it: `None` when it is
    /// missing or pending deletion. A read or decode failure is a host fault,
    /// described by the error.
    pub(crate) fn get(&self, key: &str) -> Result<Option<VmValue>, String> {
        let pending = lock(&self.overlay).lookup(key).cloned();
        let stored = match pending {
            Some(entry) => entry.as_deref().map(decode_stored_value),
            None => {
                let mut stored = None;
                self.store
                    .read(key.as_bytes(), &mut |value| {
                        stored = value.map(decode_stored_value);
                    })
                    .map_err(|error| format!("reading {key:?}: {error}"))?;
                stored
            }
        };
        stored
            .transpose()
            .map_err(|error| format!("corrupt stored value at {key:?}: {error}"))
    }

    /// The entries under `prefix` as `Driver.iter_items` yields them, in key
    /// order: the overlay's pending entries over the committed entries, a
    /// pending deletion hiding the stored entry. Pending values are decoded
    /// first, stored ones as the scan reaches them, all from one snapshot;
    /// `visit` returns false to stop the scan.
    /// A read or decode failure is a host fault, described by the error.
    pub(crate) fn visit_prefix(
        &self,
        prefix: &str,
        visit: &mut dyn FnMut(String, VmValue) -> bool,
    ) -> Result<(), String> {
        let mut merge = OverlayMerge::new(self.pending_under(prefix)?, visit);
        self.store
            .scan_from(prefix.as_bytes(), &mut |key, stored| {
                if !key.starts_with(prefix.as_bytes()) {
                    return Ok(false);
                }
                let key =
                    std::str::from_utf8(key).map_err(|error| format!("stored key: {error}"))?;
                merge.stored(key, || {
                    decode_stored_value(stored)
                        .map_err(|error| format!("corrupt stored value at {key:?}: {error}"))
                })
            })
            .map_err(|error| format!("scanning {prefix:?}: {error}"))?;
        merge.finish();
        Ok(())
    }

    /// The overlay's entries under `prefix`, decoded (`None`: a pending
    /// deletion).
    fn pending_under(&self, prefix: &str) -> Result<Vec<(String, Option<VmValue>)>, String> {
        let overlay = lock(&self.overlay);
        overlay
            .items(prefix)
            .map(|(key, entry)| {
                let value = entry.as_deref().map(decode_stored_value).transpose();
                value
                    .map(|value| (key.clone(), value))
                    .map_err(|error| format!("corrupt stored value at {key:?}: {error}"))
            })
            .collect()
    }
}

/// A scan's pending entries merged into the stored entries it reaches, as
/// `contracting.storage.ordered.iter_overlay_items` merges them: a pending
/// entry replaces the stored one with its key, a pending deletion (`None`)
/// hides it, and live entries go to the visitor until it asks to stop.
pub(crate) struct OverlayMerge<'v> {
    pending: Peekable<IntoIter<(String, Option<VmValue>)>>,
    visit: &'v mut dyn FnMut(String, VmValue) -> bool,
    stopped: bool,
}

impl<'v> OverlayMerge<'v> {
    /// `pending` in key order.
    pub(crate) fn new(
        pending: Vec<(String, Option<VmValue>)>,
        visit: &'v mut dyn FnMut(String, VmValue) -> bool,
    ) -> Self {
        Self {
            pending: pending.into_iter().peekable(),
            visit,
            stopped: false,
        }
    }

    fn entry(&mut self, key: String, value: Option<VmValue>) {
        if let (false, Some(value)) = (self.stopped, value) {
            self.stopped = !(self.visit)(key, value);
        }
    }

    /// The stored entry at `key`, after the pending entries ordered before
    /// it; its value is read only when the visitor gets it. False once the
    /// visitor stopped.
    pub(crate) fn stored<K, E>(
        &mut self,
        key: K,
        value: impl FnOnce() -> Result<VmValue, E>,
    ) -> Result<bool, E>
    where
        K: AsRef<str> + Into<String>,
    {
        let mut replaced = false;
        while let Some((pending_key, pending)) = self
            .pending
            .next_if(|(pending_key, _)| pending_key.as_str() <= key.as_ref())
        {
            replaced = pending_key == key.as_ref();
            self.entry(pending_key, pending);
        }
        if !replaced && !self.stopped {
            self.entry(key.into(), Some(value()?));
        }
        Ok(!self.stopped)
    }

    /// The pending entries after the last stored one.
    pub(crate) fn finish(mut self) {
        while let Some((key, value)) = self.pending.next() {
            self.entry(key, value);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::lmdb_env::{LmdbEnv, OpenOptions};
    use crate::memory_store::MemoryStore;
    use crate::stored_value_encoder::encode_stored_value;

    fn text(value: &str) -> VmValue {
        VmValue::String(value.to_owned())
    }

    pub(crate) fn encoded(value: &str) -> Arc<[u8]> {
        Arc::from(encode_stored_value(&text(value)).unwrap())
    }

    /// Where a fixture keeps its committed entries.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Backend {
        Lmdb,
        Memory,
    }

    pub(crate) const BACKENDS: [Backend; 2] = [Backend::Lmdb, Backend::Memory];

    /// A state view over a fresh committed store holding `stored` and an
    /// overlay holding `pending` (`None`: a pending deletion).
    pub(crate) struct Fixture {
        pub(crate) view: StateView,
        lmdb: Option<(LmdbEnv, std::path::PathBuf)>,
    }

    impl Fixture {
        /// The fixture over LMDB, the node's store.
        pub(crate) fn new(
            name: &str,
            stored: &[(&str, &[u8])],
            pending: &[(&str, Option<&str>)],
        ) -> Self {
            Self::over(Backend::Lmdb, name, stored, pending)
        }

        pub(crate) fn over(
            backend: Backend,
            name: &str,
            stored: &[(&str, &[u8])],
            pending: &[(&str, Option<&str>)],
        ) -> Self {
            let mut overlay = BlockState::default();
            for (key, value) in pending {
                overlay.write(key, value.map(encoded));
            }
            let overlay = Arc::new(Mutex::new(overlay));
            match backend {
                Backend::Lmdb => {
                    let (env, dir) = lmdb_store(name, stored);
                    let view = StateView::new(Arc::new(env.clone()), overlay);
                    Self {
                        view,
                        lmdb: Some((env, dir)),
                    }
                }
                Backend::Memory => {
                    let store = MemoryStore::from_entries(
                        stored
                            .iter()
                            .map(|(key, value)| (key.as_bytes().to_vec(), Arc::from(*value))),
                    );
                    Self {
                        view: StateView::new(Arc::new(store), overlay),
                        lmdb: None,
                    }
                }
            }
        }

        /// The first `limit` entries under `prefix`.
        fn scan(&self, prefix: &str, limit: usize) -> Result<Vec<(String, VmValue)>, String> {
            let mut seen = Vec::new();
            self.view.visit_prefix(prefix, &mut |key, value| {
                seen.push((key, value));
                seen.len() < limit
            })?;
            Ok(seen)
        }
    }

    fn lmdb_store(name: &str, stored: &[(&str, &[u8])]) -> (LmdbEnv, std::path::PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("xian-state-view-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let options = OpenOptions {
            map_size: 1 << 20,
            max_dbs: 1,
            readahead: true,
            writemap: false,
            sync: false,
            metasync: false,
            readonly: false,
            lock: true,
        };
        let env = LmdbEnv::open(&dir, options).unwrap();
        env.write(|txn| {
            stored
                .iter()
                .try_for_each(|(key, value)| txn.put(key.as_bytes(), value))
        })
        .unwrap();
        (env, dir)
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some((env, dir)) = self.lmdb.take() {
                env.close();
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, VmValue)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), text(value)))
            .collect()
    }

    fn hash_fixture(backend: Backend, name: &str) -> Fixture {
        let stored = ["g.h:z", "h:a", "h:b", "h:d", "i:a"].map(|key| (key, encoded(key)));
        let stored: Vec<(&str, &[u8])> = stored
            .iter()
            .map(|(key, value)| (*key, &value[..]))
            .collect();
        Fixture::over(
            backend,
            name,
            &stored,
            &[
                ("h:b", Some("pending b")),
                ("h:c", Some("pending c")),
                ("h:d", None),
                ("h:e", Some("pending e")),
                ("j:a", Some("pending j")),
            ],
        )
    }

    #[test]
    fn a_pinned_committed_store_keeps_gets_and_scans_on_one_base() {
        let old = encoded("old");
        let fixture = Fixture::new(
            "pinned-base",
            &[("h:a", &old), ("h:b", &old)],
            &[("h:b", Some("pending"))],
        );
        let env = &fixture.lmdb.as_ref().unwrap().0;
        let pinned = StateView::new(
            Arc::new(env.snapshot().unwrap()),
            fixture.view.overlay.clone(),
        );
        let new = encoded("new");
        env.write(|txn| {
            txn.put(b"h:a", &new)?;
            txn.delete(b"h:b")?;
            txn.put(b"h:c", &new)
        })
        .unwrap();

        assert_eq!(pinned.get("h:a").unwrap(), Some(text("old")));
        assert_eq!(pinned.get("h:c").unwrap(), None);
        let mut seen = Vec::new();
        pinned
            .visit_prefix("h:", &mut |key, value| {
                seen.push((key, value));
                true
            })
            .unwrap();
        assert_eq!(seen, entries(&[("h:a", "old"), ("h:b", "pending")]));
        assert_eq!(fixture.view.get("h:a").unwrap(), Some(text("new")));
    }

    #[test]
    fn pending_entries_replace_or_hide_stored_ones_in_key_order() {
        for backend in BACKENDS {
            pending_entries_replace_or_hide_stored_ones(backend);
        }
    }

    fn pending_entries_replace_or_hide_stored_ones(backend: Backend) {
        let fixture = hash_fixture(backend, "merge");
        assert_eq!(
            fixture.scan("h:", usize::MAX).unwrap(),
            entries(&[
                ("h:a", "h:a"),
                ("h:b", "pending b"),
                ("h:c", "pending c"),
                ("h:e", "pending e"),
            ])
        );
        assert_eq!(
            fixture.scan("j:", usize::MAX).unwrap(),
            entries(&[("j:a", "pending j")])
        );
        assert_eq!(
            fixture.scan("i:", usize::MAX).unwrap(),
            entries(&[("i:a", "i:a")])
        );
        assert_eq!(fixture.scan("k:", usize::MAX).unwrap(), Vec::new());
        // A prefix longer than LMDB's largest key still scans.
        assert_eq!(
            fixture.scan(&"h".repeat(600), usize::MAX).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn the_visitor_stops_the_scan() {
        for backend in BACKENDS {
            let fixture = hash_fixture(backend, "stop");
            for limit in 1..=4 {
                let seen = fixture.scan("h:", limit).unwrap();
                assert_eq!(seen.len(), limit);
            }
            // Stopping on a pending entry before a stored key ends the scan.
            let seen = fixture.scan("h:", 3).unwrap();
            assert_eq!(seen.last().unwrap().0, "h:c");
        }
    }

    #[test]
    fn reads_see_pending_entries_over_stored_ones() {
        for backend in BACKENDS {
            let fixture = hash_fixture(backend, "get");
            assert_eq!(fixture.view.get("h:a").unwrap(), Some(text("h:a")));
            assert_eq!(fixture.view.get("h:b").unwrap(), Some(text("pending b")));
            assert_eq!(fixture.view.get("h:d").unwrap(), None);
            assert_eq!(fixture.view.get("h:x").unwrap(), None);
        }
    }

    #[test]
    fn a_corrupt_value_in_the_scanned_range_is_a_fault() {
        for backend in BACKENDS {
            let fixture = Fixture::over(backend, "corrupt", &[("h:a", b"\xff")], &[]);
            let error = fixture.scan("h:", usize::MAX).unwrap_err();
            assert!(error.contains("corrupt stored value at \"h:a\""), "{error}");
            let error = fixture.view.get("h:a").unwrap_err();
            assert!(error.contains("corrupt stored value at \"h:a\""), "{error}");
        }
    }

    #[test]
    fn a_store_failure_is_a_fault_naming_the_read() {
        let fixture = hash_fixture(Backend::Lmdb, "closed");
        fixture.lmdb.as_ref().unwrap().0.close();
        assert_eq!(
            fixture.view.get("h:x").unwrap_err(),
            "reading \"h:x\": LMDB environment is closed"
        );
        assert_eq!(
            fixture.scan("i:", usize::MAX).unwrap_err(),
            "scanning \"i:\": LMDB environment is closed"
        );
    }
}
