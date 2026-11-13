//! The block overlay: state the current block wrote but has not committed.
//!
//! Values are held as stored values, the exact bytes LMDB keeps, so overlay
//! and committed state are read through one decoder and a commit writes the
//! bytes unchanged. A pending deletion is a tombstone. Keys are kept in key
//! order (UTF-8 byte order, as LMDB), which is what every consumer iterates in;
//! nothing depends on insertion order (the state root is a treap keyed by key).
//!
//! The state also tracks which keys and prefixes the current transaction read
//! (only while tracking is on; the legacy parallel executor consumes it), and
//! opens at most one discarding scope: every change made inside it is undone
//! when it closes, at a cost that follows what the scope touched.
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

/// A stored value, or `None` for a pending deletion.
pub(crate) type Stored = Option<Arc<[u8]>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockStateError {
    ScopeOpen(&'static str),
    NoScope,
}

impl std::fmt::Display for BlockStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScopeOpen(operation) => {
                write!(
                    f,
                    "BlockState.{operation} cannot run inside a discarding scope"
                )
            }
            Self::NoScope => f.write_str("no discarding scope is open"),
        }
    }
}

type Result<T> = std::result::Result<T, BlockStateError>;

/// Keys and prefixes one transaction read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Access {
    pub(crate) reads: BTreeSet<String>,
    pub(crate) prefixes: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
enum Tracked {
    Read,
    Prefix,
}

impl Access {
    fn of(&mut self, kind: Tracked) -> &mut BTreeSet<String> {
        match kind {
            Tracked::Read => &mut self.reads,
            Tracked::Prefix => &mut self.prefixes,
        }
    }
}

/// First-touch undo records of the open discarding scope.
#[derive(Debug, Clone, Default)]
struct Journal {
    /// Previous entry of each key the scope wrote; `None` when it had none.
    writes: Vec<(String, Option<Stored>)>,
    touched: HashSet<String>,
    /// Access first tracked inside the scope.
    tracked: Vec<(Tracked, String)>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BlockState {
    writes: BTreeMap<String, Stored>,
    access: Option<Access>,
    scope: Option<Journal>,
}

impl BlockState {
    /// `None` when the overlay does not hold `key`; otherwise its entry.
    pub(crate) fn lookup(&self, key: &str) -> Option<&Stored> {
        self.writes.get(key)
    }

    pub(crate) fn write(&mut self, key: &str, value: Stored) {
        if let Some(journal) = self.scope.as_mut() {
            if journal.touched.insert(key.to_owned()) {
                journal
                    .writes
                    .push((key.to_owned(), self.writes.get(key).cloned()));
            }
        }
        self.writes.insert(key.to_owned(), value);
    }

    /// Entries whose key starts with `prefix`, in key order.
    pub(crate) fn items<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a String, &'a Stored)> + 'a {
        self.writes
            .range::<str, _>((
                std::ops::Bound::Included(prefix),
                std::ops::Bound::Unbounded,
            ))
            .take_while(move |(key, _)| key.starts_with(prefix))
    }

    pub(crate) fn len(&self) -> usize {
        self.writes.len()
    }

    /// Forget pending entries under `prefix` (their committed state is being
    /// replaced wholesale).
    pub(crate) fn forget_prefix(&mut self, prefix: &str) -> Result<()> {
        self.require_no_scope("forget_prefix")?;
        let doomed: Vec<String> = self.items(prefix).map(|(key, _)| key.clone()).collect();
        for key in doomed {
            self.writes.remove(&key);
        }
        Ok(())
    }

    /// Drop every pending entry and the tracked access; tracking stays as set.
    pub(crate) fn clear(&mut self) -> Result<()> {
        self.clear_access()?;
        self.writes.clear();
        Ok(())
    }

    /// Persist the pending entries (in key order) with `persist`; the overlay
    /// and the tracked access are cleared only when it succeeds, so a failed
    /// commit leaves the block intact for a retry.
    pub(crate) fn commit<E>(
        &mut self,
        persist: impl FnOnce(&BTreeMap<String, Stored>) -> std::result::Result<(), E>,
    ) -> Result<std::result::Result<(), E>> {
        self.require_no_scope("commit")?;
        let outcome = persist(&self.writes);
        if outcome.is_ok() {
            self.writes.clear();
            self.forget_access();
        }
        Ok(outcome)
    }

    pub(crate) fn tracking(&self) -> bool {
        self.access.is_some()
    }

    /// Turning tracking off drops what was tracked; turning it on keeps it.
    pub(crate) fn set_tracking(&mut self, enabled: bool) -> Result<()> {
        self.require_no_scope("set_tracking")?;
        match (enabled, self.access.is_some()) {
            (true, false) => self.access = Some(Access::default()),
            (false, true) => self.access = None,
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn record_read(&mut self, key: &str) {
        self.track(Tracked::Read, key);
    }

    pub(crate) fn record_prefix(&mut self, prefix: &str) {
        self.track(Tracked::Prefix, prefix);
    }

    fn track(&mut self, kind: Tracked, item: &str) {
        let Some(access) = self.access.as_mut() else {
            return;
        };
        if access.of(kind).insert(item.to_owned()) {
            if let Some(journal) = self.scope.as_mut() {
                journal.tracked.push((kind, item.to_owned()));
            }
        }
    }

    fn forget_access(&mut self) {
        if let Some(access) = self.access.as_mut() {
            *access = Access::default();
        }
    }

    pub(crate) fn access(&self) -> Option<&Access> {
        self.access.as_ref()
    }

    pub(crate) fn clear_access(&mut self) -> Result<()> {
        self.require_no_scope("clear_access")?;
        self.forget_access();
        Ok(())
    }

    pub(crate) fn begin_discarding(&mut self) -> Result<()> {
        self.require_no_scope("begin_discarding")?;
        self.scope = Some(Journal::default());
        Ok(())
    }

    /// Close the scope and undo every change made inside it.
    pub(crate) fn discard(&mut self) -> Result<()> {
        let journal = self.scope.take().ok_or(BlockStateError::NoScope)?;
        for (key, previous) in journal.writes.into_iter().rev() {
            match previous {
                Some(entry) => self.writes.insert(key, entry),
                None => self.writes.remove(&key),
            };
        }
        if let Some(access) = self.access.as_mut() {
            for (kind, item) in &journal.tracked {
                access.of(*kind).remove(item);
            }
        }
        Ok(())
    }

    pub(crate) fn in_scope(&self) -> bool {
        self.scope.is_some()
    }

    /// An independent copy of the pending entries and tracked access.
    pub(crate) fn snapshot(&self) -> Result<Self> {
        self.require_no_scope("snapshot")?;
        Ok(self.clone())
    }

    fn require_no_scope(&self, operation: &'static str) -> Result<()> {
        if self.scope.is_some() {
            return Err(BlockStateError::ScopeOpen(operation));
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

    fn entries(state: &BlockState) -> Vec<(String, Stored)> {
        state
            .items("")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }

    #[test]
    fn a_tombstone_is_held_and_differs_from_an_absent_key() {
        let mut state = BlockState::default();
        state.write("a", None);
        assert_eq!(state.lookup("a"), Some(&None));
        assert_eq!(state.lookup("b"), None);
    }

    #[test]
    fn items_follow_key_order_whatever_the_write_order() {
        let mut forward = BlockState::default();
        let mut backward = BlockState::default();
        let keys = ["c.x", "a.y", "b.z", "a.b:é", "a.b:z"];
        for key in keys {
            forward.write(key, stored(key));
        }
        for key in keys.iter().rev() {
            backward.write(key, stored(key));
        }
        assert_eq!(entries(&forward), entries(&backward));
        let listed: Vec<_> = forward.items("a.").map(|(key, _)| key.as_str()).collect();
        assert_eq!(listed, ["a.b:z", "a.b:é", "a.y"]);
    }

    #[test]
    fn discarding_restores_the_exact_previous_entries() {
        let mut state = BlockState::default();
        state.write("kept", stored("1"));
        state.write("changed", stored("2"));
        state.write("deleted", stored("3"));
        let before = entries(&state);
        state.begin_discarding().unwrap();
        state.write("changed", stored("20"));
        state.write("changed", stored("21"));
        state.write("deleted", None);
        state.write("new", stored("4"));
        state.discard().unwrap();
        assert_eq!(entries(&state), before);
        assert!(!state.in_scope());
    }

    #[test]
    fn discarding_drops_only_the_access_tracked_inside_the_scope() {
        let mut state = BlockState::default();
        state.set_tracking(true).unwrap();
        state.record_read("before");
        state.record_prefix("p:");
        state.begin_discarding().unwrap();
        state.record_read("before");
        state.record_read("inside");
        state.record_prefix("p:");
        state.record_prefix("q:");
        state.discard().unwrap();
        let access = state.access().unwrap();
        assert_eq!(access.reads.iter().collect::<Vec<_>>(), ["before"]);
        assert_eq!(access.prefixes.iter().collect::<Vec<_>>(), ["p:"]);
    }

    #[test]
    fn nothing_is_tracked_while_tracking_is_off() {
        let mut state = BlockState::default();
        state.record_read("a");
        assert!(state.access().is_none());
        assert!(!state.tracking());
        state.set_tracking(true).unwrap();
        assert!(state.tracking());
        state.record_read("a");
        state.set_tracking(true).unwrap();
        assert_eq!(state.access().unwrap().reads.len(), 1);
        state.set_tracking(false).unwrap();
        state.set_tracking(true).unwrap();
        assert!(state.access().unwrap().reads.is_empty());
    }

    #[test]
    fn bulk_changes_are_refused_inside_a_scope() {
        let mut state = BlockState::default();
        state.begin_discarding().unwrap();
        assert!(state.clear().is_err());
        assert!(state.commit(|_| Ok::<(), ()>(())).is_err());
        assert!(state.forget_prefix("a").is_err());
        assert!(state.set_tracking(true).is_err());
        assert!(state.clear_access().is_err());
        assert!(state.snapshot().is_err());
        assert!(state.begin_discarding().is_err());
        state.discard().unwrap();
        assert_eq!(state.discard(), Err(BlockStateError::NoScope));
    }

    #[test]
    fn a_snapshot_is_independent_of_later_writes() {
        let mut state = BlockState::default();
        state.write("a", stored("1"));
        let snapshot = state.snapshot().unwrap();
        state.write("a", stored("2"));
        state.write("b", stored("3"));
        assert_eq!(entries(&snapshot), vec![("a".to_owned(), stored("1"))]);
    }

    #[test]
    fn forgetting_a_prefix_keeps_other_keys() {
        let mut state = BlockState::default();
        state.write("con_a.x", stored("1"));
        state.write("con_ab.x", stored("2"));
        state.write("con_a.y", None);
        state.forget_prefix("con_a.").unwrap();
        assert_eq!(entries(&state), vec![("con_ab.x".to_owned(), stored("2"))]);
    }

    #[test]
    fn a_failed_commit_keeps_the_overlay_and_a_successful_one_empties_it() {
        let mut state = BlockState::default();
        state.write("b", stored("2"));
        state.write("a", None);
        assert_eq!(
            state.commit(|_| Err("disk full")).unwrap(),
            Err("disk full")
        );
        assert_eq!(state.len(), 2);
        let mut persisted = Vec::new();
        let outcome = state.commit(|writes| {
            persisted.extend(
                writes
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
            Ok::<(), ()>(())
        });
        assert_eq!(outcome.unwrap(), Ok(()));
        assert_eq!(
            persisted,
            vec![("a".to_owned(), None), ("b".to_owned(), stored("2"))]
        );
        assert_eq!(state.len(), 0);
    }
}
