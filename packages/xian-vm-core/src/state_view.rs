//! The node's current state as Rust reads it: the block overlay first, then
//! the committed LMDB environment, decoded with the stored-value reader.
use crate::block_state::{lock, BlockState};
use crate::lmdb_env::{LmdbEnv, LmdbError};
use crate::stored_value::decode_stored_value;
use crate::VmValue;
use std::iter::Peekable;
use std::sync::{Arc, Mutex};
use std::vec::IntoIter;

#[derive(Clone)]
pub(crate) struct StateView {
    env: LmdbEnv,
    overlay: Arc<Mutex<BlockState>>,
}

impl StateView {
    pub(crate) fn new(env: LmdbEnv, overlay: Arc<Mutex<BlockState>>) -> Self {
        Self { env, overlay }
    }

    pub(crate) fn overlay(&self) -> &Arc<Mutex<BlockState>> {
        &self.overlay
    }

    /// Book `key` as read, for a value served from a cache.
    pub(crate) fn record_read(&self, key: &str) {
        lock(&self.overlay).record_read(key);
    }

    /// The value at `key` as `Driver.get` returns it: `None` when it is
    /// missing or pending deletion. `track` books the key as read in the
    /// overlay's access tracking. A read or decode failure is a host fault,
    /// described by the error.
    pub(crate) fn get(&self, key: &str, track: bool) -> Result<Option<VmValue>, String> {
        let pending = {
            let mut overlay = lock(&self.overlay);
            if track {
                overlay.record_read(key);
            }
            overlay.lookup(key).cloned()
        };
        let stored = match pending {
            Some(entry) => entry.as_deref().map(decode_stored_value),
            None => self
                .env
                .read(|txn| Ok(txn.get(key.as_bytes())?.map(decode_stored_value)))
                .map_err(|error| format!("reading {key:?}: {error}"))?,
        };
        stored
            .transpose()
            .map_err(|error| format!("corrupt stored value at {key:?}: {error}"))
    }

    /// The entries under `prefix` as `Driver.iter_items` yields them, in key
    /// order: the overlay's pending entries over the LMDB entries, a pending
    /// deletion hiding the stored entry. Pending values are decoded first,
    /// stored ones as the scan reaches them, all from one LMDB snapshot;
    /// `visit` returns false to stop the scan. The prefix is booked as read.
    /// A read or decode failure is a host fault, described by the error.
    pub(crate) fn visit_prefix(
        &self,
        prefix: &str,
        visit: &mut dyn FnMut(String, VmValue) -> bool,
    ) -> Result<(), String> {
        let mut merge = Merge {
            pending: self.pending_under(prefix)?.into_iter().peekable(),
            visit,
            stopped: false,
        };
        self.env
            .read(|txn| {
                txn.scan_from(prefix.as_bytes(), |key, stored| {
                    if !key.starts_with(prefix.as_bytes()) {
                        return Ok(false);
                    }
                    let key = std::str::from_utf8(key)
                        .map_err(|error| LmdbError::Other(format!("stored key: {error}")))?;
                    merge.stored(key, stored)
                })
            })
            .map_err(|error| format!("scanning {prefix:?}: {error}"))?;
        merge.finish();
        Ok(())
    }

    /// The overlay's entries under `prefix`, decoded (`None`: a pending
    /// deletion), with the prefix booked as read.
    fn pending_under(&self, prefix: &str) -> Result<Vec<(String, Option<VmValue>)>, String> {
        let mut overlay = lock(&self.overlay);
        overlay.record_prefix(prefix);
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
/// `contracting.storage.ordered.iter_overlay_items` merges them; live entries
/// go to the visitor until it asks to stop.
struct Merge<'v> {
    pending: Peekable<IntoIter<(String, Option<VmValue>)>>,
    visit: &'v mut dyn FnMut(String, VmValue) -> bool,
    stopped: bool,
}

impl Merge<'_> {
    fn entry(&mut self, key: String, value: Option<VmValue>) {
        if let (false, Some(value)) = (self.stopped, value) {
            self.stopped = !(self.visit)(key, value);
        }
    }

    /// The stored entry at `key`, after the pending entries ordered before
    /// it; a pending entry with the same key replaces it. False once the
    /// visitor stopped.
    fn stored(&mut self, key: &str, stored: &[u8]) -> Result<bool, LmdbError> {
        let mut replaced = false;
        while let Some((pending_key, value)) = self
            .pending
            .next_if(|(pending_key, _)| pending_key.as_str() <= key)
        {
            replaced = pending_key == key;
            self.entry(pending_key, value);
        }
        if !replaced && !self.stopped {
            let value = decode_stored_value(stored).map_err(|error| {
                LmdbError::Other(format!("corrupt stored value at {key:?}: {error}"))
            })?;
            self.entry(key.to_owned(), Some(value));
        }
        Ok(!self.stopped)
    }

    /// The pending entries after the last stored one.
    fn finish(mut self) {
        while let Some((key, value)) = self.pending.next() {
            self.entry(key, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lmdb_env::OpenOptions;
    use crate::stored_value_encoder::encode_stored_value;

    fn text(value: &str) -> VmValue {
        VmValue::String(value.to_owned())
    }

    fn encoded(value: &str) -> Arc<[u8]> {
        Arc::from(encode_stored_value(&text(value)).unwrap())
    }

    /// A state view over a fresh LMDB environment holding `stored` and an
    /// overlay holding `pending` (`None`: a pending deletion).
    struct Fixture {
        view: StateView,
        dir: std::path::PathBuf,
    }

    impl Fixture {
        fn new(name: &str, stored: &[(&str, &[u8])], pending: &[(&str, Option<&str>)]) -> Self {
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
            let mut overlay = BlockState::default();
            for (key, value) in pending {
                overlay.write(key, value.map(encoded));
            }
            let view = StateView::new(env, Arc::new(Mutex::new(overlay)));
            Self { view, dir }
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

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.view.env.close();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, VmValue)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), text(value)))
            .collect()
    }

    fn hash_fixture(name: &str) -> Fixture {
        let stored = ["g.h:z", "h:a", "h:b", "h:d", "i:a"].map(|key| (key, encoded(key)));
        let stored: Vec<(&str, &[u8])> = stored
            .iter()
            .map(|(key, value)| (*key, &value[..]))
            .collect();
        Fixture::new(
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
    fn pending_entries_replace_or_hide_stored_ones_in_key_order() {
        let fixture = hash_fixture("merge");
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
        let fixture = hash_fixture("stop");
        for limit in 1..=4 {
            let seen = fixture.scan("h:", limit).unwrap();
            assert_eq!(seen.len(), limit);
        }
        // Stopping on a pending entry before a stored key ends the scan.
        let seen = fixture.scan("h:", 3).unwrap();
        assert_eq!(seen.last().unwrap().0, "h:c");
    }

    #[test]
    fn reads_see_pending_entries_over_stored_ones() {
        let fixture = hash_fixture("get");
        lock(fixture.view.overlay()).set_tracking(true).unwrap();
        assert_eq!(fixture.view.get("h:a", true).unwrap(), Some(text("h:a")));
        assert_eq!(
            fixture.view.get("h:b", true).unwrap(),
            Some(text("pending b"))
        );
        assert_eq!(fixture.view.get("h:d", false).unwrap(), None);
        assert_eq!(fixture.view.get("h:x", true).unwrap(), None);
        fixture.view.record_read("h:y");
        let overlay = lock(fixture.view.overlay());
        let reads: Vec<&str> = overlay
            .access()
            .unwrap()
            .reads
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(reads, ["h:a", "h:b", "h:x", "h:y"]);
    }

    #[test]
    fn the_scanned_prefix_is_booked_as_read() {
        let fixture = hash_fixture("tracked");
        lock(fixture.view.overlay()).set_tracking(true).unwrap();
        fixture.scan("h:", usize::MAX).unwrap();
        let overlay = lock(fixture.view.overlay());
        let access = overlay.access().unwrap();
        assert!(access.prefixes.contains("h:"));
        assert!(access.reads.is_empty());
    }

    #[test]
    fn a_corrupt_value_in_the_scanned_range_is_a_fault() {
        let fixture = Fixture::new("corrupt", &[("h:a", b"\xff")], &[]);
        let error = fixture.scan("h:", usize::MAX).unwrap_err();
        assert!(error.contains("corrupt stored value at \"h:a\""), "{error}");
    }
}
