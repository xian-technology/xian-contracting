//! The node's current state as Rust reads it: the block overlay first, then
//! the committed LMDB environment, decoded with the stored-value reader.
use crate::block_state::{lock, BlockState};
use crate::lmdb_env::LmdbEnv;
use crate::stored_value::decode_stored_value;
use crate::VmValue;
use std::sync::{Arc, Mutex};

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
}
