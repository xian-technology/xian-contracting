//! What a transaction's host syscalls stage: `NativeVmHost._pending_writes`
//! and `_pending_events`.
//!
//! The transaction's reads see a staged write before the block overlay and
//! LMDB, a hash scan merges the staged entries in key order, and a staged
//! `VmValue::None` hides the stored value. When the execution succeeds, the
//! staged writes override the VM's writes of the same keys and the staged
//! events come before the VM's events; when it fails, everything staged is
//! dropped.
use crate::state_view::OverlayMerge;
use crate::{VmEvent, VmValue};
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub(crate) struct HostWrites {
    writes: BTreeMap<String, VmValue>,
    events: Vec<VmEvent>,
}

impl HostWrites {
    /// The staged value at `key` (`Some(VmValue::None)`: a staged deletion).
    pub(crate) fn get(&self, key: &str) -> Option<&VmValue> {
        self.writes.get(key)
    }

    /// Stage a write; a later write of the same key replaces it.
    pub(crate) fn stage(&mut self, key: &str, value: VmValue) {
        self.writes.insert(key.to_owned(), value);
    }

    /// Stage an event, after the ones staged before.
    pub(crate) fn emit(&mut self, event: VmEvent) {
        self.events.push(event);
    }

    /// The staged entries under `prefix`, in key order (`None`: a staged
    /// deletion).
    fn under(&self, prefix: &str) -> Vec<(String, Option<VmValue>)> {
        self.writes
            .range(prefix.to_owned()..)
            .take_while(|(key, _)| key.starts_with(prefix))
            .map(|(key, value)| {
                let value = (!matches!(value, VmValue::None)).then(|| value.clone());
                (key.clone(), value)
            })
            .collect()
    }

    /// A merge of the staged entries under `prefix` into a scan that yields
    /// the live stored entries in key order (`iter_overlay_items` over
    /// `NativeVmHost._pending_writes`).
    pub(crate) fn merge_under<'v>(
        &self,
        prefix: &str,
        visit: &'v mut dyn FnMut(String, VmValue) -> bool,
    ) -> OverlayMerge<'v> {
        OverlayMerge::new(self.under(prefix), visit)
    }

    /// The execution's writes and events with the staged ones (`execute_contract`):
    /// a success takes them over its own, a failure drops them.
    pub(crate) fn settle(
        self,
        status: i32,
        writes: &mut BTreeMap<String, VmValue>,
        events: &mut Vec<VmEvent>,
    ) {
        if status != 0 {
            return;
        }
        writes.extend(self.writes);
        events.splice(0..0, self.events);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn int(value: i64) -> VmValue {
        VmValue::Int(value.into())
    }

    fn event(name: &str) -> VmEvent {
        VmEvent {
            contract: "con_x".to_owned(),
            event: name.to_owned(),
            signer: VmValue::None,
            caller: VmValue::None,
            data_indexed: Vec::new(),
            data: Vec::new(),
        }
    }

    fn staged(entries: &[(&str, VmValue)]) -> HostWrites {
        let mut writes = HostWrites::default();
        for (key, value) in entries {
            writes.stage(key, value.clone());
        }
        writes
    }

    /// The entries a scan of `stored` under `prefix` visits with `writes`
    /// staged, stopping after `limit`.
    fn scan(
        writes: &HostWrites,
        prefix: &str,
        stored: &[(&str, i64)],
        limit: usize,
    ) -> Vec<(String, VmValue)> {
        let mut seen = Vec::new();
        let mut visit = |key: String, value: VmValue| {
            seen.push((key, value));
            seen.len() < limit
        };
        let mut merge = writes.merge_under(prefix, &mut visit);
        for (key, value) in stored {
            let Ok(more) = merge.stored(*key, || Ok::<_, Infallible>(int(*value)));
            if !more {
                break;
            }
        }
        merge.finish();
        seen
    }

    fn entries(pairs: &[(&str, i64)]) -> Vec<(String, VmValue)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), int(*value)))
            .collect()
    }

    #[test]
    fn reads_see_the_last_staged_write_and_staged_deletions() {
        let mut writes = staged(&[("a", int(1)), ("b", VmValue::None)]);
        writes.stage("a", int(2));
        assert_eq!(writes.get("a"), Some(&int(2)));
        assert_eq!(writes.get("b"), Some(&VmValue::None));
        assert_eq!(writes.get("c"), None);
    }

    #[test]
    fn a_success_takes_staged_writes_over_its_own_and_staged_events_first() {
        let mut writes = staged(&[("k", int(1)), ("only_host", int(3))]);
        writes.emit(event("Host"));
        let mut effects = BTreeMap::from([("k".to_owned(), int(9)), ("vm".to_owned(), int(4))]);
        let mut events = vec![event("Vm")];
        writes.settle(0, &mut effects, &mut events);
        assert_eq!(
            effects,
            BTreeMap::from([
                ("k".to_owned(), int(1)),
                ("only_host".to_owned(), int(3)),
                ("vm".to_owned(), int(4)),
            ])
        );
        let names: Vec<&str> = events.iter().map(|event| event.event.as_str()).collect();
        assert_eq!(names, ["Host", "Vm"]);
    }

    #[test]
    fn a_failure_drops_everything_staged() {
        let mut writes = staged(&[("k", int(1))]);
        writes.emit(event("Host"));
        let mut effects = BTreeMap::new();
        let mut events = Vec::new();
        writes.settle(1, &mut effects, &mut events);
        assert!(effects.is_empty());
        assert!(events.is_empty());
    }

    #[test]
    fn scans_merge_staged_entries_in_key_order() {
        let writes = staged(&[
            ("h:a", int(10)),
            ("h:c", int(30)),
            ("h:e", VmValue::None),
            ("h:z", int(26)),
            ("other:b", int(0)),
        ]);
        let stored = [("h:b", 2), ("h:c", 3), ("h:d", 4), ("h:e", 5)];
        assert_eq!(
            scan(&writes, "h:", &stored, usize::MAX),
            entries(&[
                ("h:a", 10),
                ("h:b", 2),
                ("h:c", 30),
                ("h:d", 4),
                ("h:z", 26)
            ])
        );
    }

    #[test]
    fn a_scan_stops_when_the_visitor_asks() {
        let writes = staged(&[("h:a", int(1)), ("h:c", int(3)), ("h:y", int(25))]);
        let stored = [("h:b", 2), ("h:d", 4)];
        assert_eq!(
            scan(&writes, "h:", &stored, 3),
            entries(&[("h:a", 1), ("h:b", 2), ("h:c", 3)])
        );
        assert_eq!(scan(&writes, "h:", &stored, 1), entries(&[("h:a", 1)]));
        assert_eq!(
            scan(&writes, "h:", &[], 2),
            entries(&[("h:a", 1), ("h:c", 3)])
        );
    }

    #[test]
    fn a_scan_without_staged_entries_sees_the_stored_ones() {
        let writes = staged(&[("hash:a", int(1))]);
        let stored = [("h:a", 1), ("h:b", 2)];
        assert_eq!(scan(&writes, "h:", &stored, usize::MAX), entries(&stored));
    }
}
