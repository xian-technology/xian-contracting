//! Committed state as the engine reads it: the stored bytes of every key, in
//! key byte order. The node keeps it in LMDB (`lmdb_env`); the browser build
//! and tests keep it in memory (`memory_store`). Execution reads committed
//! state only through this trait and stages its writes in the block overlay
//! (`block_state`), so a backend is a store of bytes and nothing else: the
//! overlay's `commit` hands the pending entries to the backend's own writer.

/// The longest storage key, in UTF-8 bytes: LMDB 0.9's `MDB_MAXKEYSIZE`.
///
/// LMDB refuses a longer key only when the block commits, after every node
/// already agreed on the block's state root, so the chain would halt. Storage
/// keys are therefore a consensus rule fixed at this value: V2 fails the
/// transaction that forms a longer key, and the storage layer refuses to stage
/// one. It is a constant rather than a value read from the backend because a
/// rule must not move with the store (LMDB 1.0 derives its limit from the page
/// size, and the in-memory store has no limit of its own); a test pins that
/// the vendored LMDB stores exactly this many bytes.
pub const MAX_STORAGE_KEY_BYTES: usize = 511;

/// Why `key` cannot be stored, or `None` when it can.
pub fn storage_key_error(key: &str) -> Option<String> {
    (key.len() > MAX_STORAGE_KEY_BYTES).then(|| {
        format!(
            "Storage key is too long ({} bytes). Max is {MAX_STORAGE_KEY_BYTES}.",
            key.len()
        )
    })
}

/// A store of committed entries. Errors are the backend's failure text (a
/// host fault: the node halts).
#[cfg(any(feature = "engine", test))]
pub(crate) trait CommittedStore: Send + Sync {
    /// Call `read` with the bytes stored at `key` (`None`: no entry).
    fn read(&self, key: &[u8], read: &mut dyn FnMut(Option<&[u8]>)) -> Result<(), String>;

    /// Visit the entries from `start` (inclusive) in key byte order, all from
    /// one consistent snapshot, until `visit` returns false. A `visit` error
    /// ends the scan and is returned.
    fn scan_from(
        &self,
        start: &[u8],
        visit: &mut dyn FnMut(&[u8], &[u8]) -> Result<bool, String>,
    ) -> Result<(), String>;
}
