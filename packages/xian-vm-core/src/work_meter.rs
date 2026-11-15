//! Element work inside one VM operation: value comparisons, container scans
//! and element copies. Such work grows with container size while the
//! operation's own gas is constant, so V2 (`xvm-gas-4` and later) charges each unit.
//!
//! Primitive helpers count units without a host. The interpreter charges
//! pending units before its next expression or statement and when a call
//! returns. One operation may not accumulate more than `MAX_PENDING_WORK`
//! uncharged units, nor more than the transaction's budget still covers, so
//! a checked count stops the work before it is done.
use crate::{VmBudget, VmExecutionError, VmHost};
use std::cell::{Cell, RefCell};

/// Raw chi per unit of element work. `xvm-gas-5` raised it from 8: copying or
/// allocating a member (a cloned integer, a split piece, a converted argument)
/// took 100-250 ns, while plain interpreter work runs at about 1 ns per raw chi.
pub(crate) const VM_GAS_ELEMENT_WORK: u64 = 24;
/// Units one operation may perform before the interpreter charges them.
pub(crate) const MAX_PENDING_WORK: u64 = 1 << 20;

thread_local! {
    static PENDING: Cell<u64> = const { Cell::new(0) };
    static UNMETERED: Cell<bool> = const { Cell::new(false) };
    /// The budget pending units will be charged to; none when unmetered.
    static BUDGET: RefCell<Option<VmBudget>> = const { RefCell::new(None) };
}

fn counting() -> bool {
    !UNMETERED.get()
}

/// Record `units` of element work done by the current operation.
pub(crate) fn count(units: u64) -> Result<(), VmExecutionError> {
    if !counting() {
        return Ok(());
    }
    let pending = PENDING.get().saturating_add(units);
    PENDING.set(pending);
    if pending > MAX_PENDING_WORK {
        return Err(VmExecutionError::new(
            "operation exceeds the element work limit",
        ));
    }
    if !affordable(pending) {
        return Err(VmExecutionError::new("Out of chi."));
    }
    Ok(())
}

/// Whether the budget covers charging `pending` units on top of its costs.
fn affordable(pending: u64) -> bool {
    BUDGET.with_borrow(|budget| {
        budget
            .as_ref()
            .is_none_or(|budget| budget.covers(pending.saturating_mul(VM_GAS_ELEMENT_WORK)))
    })
}

/// Record element work where the caller cannot fail. The pending limit is
/// enforced by the operation's next checked `count`.
pub(crate) fn note(units: u64) {
    if counting() {
        PENDING.set(PENDING.get().saturating_add(units));
    }
}

/// Members of one container object: the elements an allocation visits.
pub(crate) fn members(value: &crate::VmValue) -> u64 {
    use crate::VmValue;
    (match value {
        VmValue::List(items)
        | VmValue::Tuple(items)
        | VmValue::Set(items)
        | VmValue::BuiltinSet(items)
        | VmValue::FrozenSet(items) => items.len(),
        VmValue::Dict(entries) => entries.len(),
        _ => 0,
    }) as u64
}

/// Elements copied with one object: its members, or one unit per 64 bytes of
/// text or binary payload.
pub(crate) fn copied(value: &crate::VmValue) -> u64 {
    use crate::VmValue;
    match value {
        VmValue::String(text) => (text.len() / 64) as u64,
        VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => (bytes.len() / 64) as u64,
        other => members(other),
    }
}

/// Bytes of text covered by one unit of per-character work: case mapping,
/// character-class predicates and whitespace splitting look up every
/// character in the Unicode tables.
const CHARACTER_BYTES_PER_UNIT: usize = 2;
/// Bytes covered by one unit of a byte-level search or copy (`find`, `in`,
/// `replace`, `split(sep)`, slicing).
const SEARCH_BYTES_PER_UNIT: usize = 8;
/// Bytes covered by one unit of a byte-wise comparison (`==`, `<`, sorting).
const COMPARE_BYTES_PER_UNIT: usize = 128;

/// Units for per-character work over `bytes` of text.
pub(crate) fn characters(bytes: usize) -> u64 {
    (bytes / CHARACTER_BYTES_PER_UNIT) as u64
}

/// Units for searching or copying `bytes` of text or binary data.
pub(crate) fn searched(bytes: usize) -> u64 {
    (bytes / SEARCH_BYTES_PER_UNIT) as u64
}

/// Units for comparing two payloads; a comparison stops at the shorter one.
pub(crate) fn compared(left: usize, right: usize) -> u64 {
    (left.min(right) / COMPARE_BYTES_PER_UNIT) as u64
}

/// Charge pending units to `host`.
pub(crate) fn flush(host: &mut dyn VmHost) -> Result<(), VmExecutionError> {
    let pending = PENDING.replace(0);
    if pending == 0 {
        return Ok(());
    }
    host.charge_execution_cost(pending.saturating_mul(VM_GAS_ELEMENT_WORK))
}

/// Isolate one execution's work from an enclosing execution on this thread:
/// the enclosing pending units and budget are restored when the guard drops.
pub(crate) struct Isolation(u64, Option<VmBudget>);

impl Isolation {
    pub(crate) fn enter() -> Self {
        Self::charging(None)
    }

    /// An execution whose units are charged to `budget`: a checked count
    /// fails with `Out of chi.` once the budget no longer covers them.
    pub(crate) fn charging(budget: Option<VmBudget>) -> Self {
        Self(PENDING.replace(0), BUDGET.replace(budget))
    }
}

impl Drop for Isolation {
    fn drop(&mut self) {
        PENDING.set(self.0);
        BUDGET.set(self.1.take());
    }
}

/// Host work that is not part of the metered VM (decoding stored values):
/// nothing is counted until the guard drops.
#[cfg(any(feature = "engine", test))]
pub(crate) struct Unmetered(bool);

#[cfg(any(feature = "engine", test))]
impl Unmetered {
    pub(crate) fn enter() -> Self {
        Self(UNMETERED.replace(true))
    }
}

#[cfg(any(feature = "engine", test))]
impl Drop for Unmetered {
    fn drop(&mut self) {
        UNMETERED.set(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Host(u64);
    impl VmHost for Host {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
            self.0 += cost;
            Ok(())
        }
    }

    #[test]
    fn v2_counts_charge_once_and_isolate_nested_executions() {
        let mut host = Host::default();
        count(3).unwrap();
        {
            let _nested = Isolation::enter();
            count(5).unwrap();
            flush(&mut host).unwrap();
        }
        assert_eq!(host.0, 5 * VM_GAS_ELEMENT_WORK);
        flush(&mut host).unwrap();
        flush(&mut host).unwrap();
        assert_eq!(host.0, 8 * VM_GAS_ELEMENT_WORK);
    }

    #[test]
    fn one_operation_cannot_exceed_the_pending_limit() {
        let _isolated = Isolation::enter();
        count(MAX_PENDING_WORK).unwrap();
        assert!(count(1).is_err());
    }

    #[test]
    fn a_count_the_budget_cannot_cover_fails_before_the_work() {
        // 10,000 chi leave (10,000 - 5) * 1000 - 1 raw chi before the base
        // charge is exceeded: 416,499 units of 24.
        let budget = VmBudget::new(10_000_000);
        {
            let _charged = Isolation::charging(Some(budget.clone()));
            count(416_499).unwrap();
            assert_eq!(count(1).unwrap_err().to_string(), "Out of chi.");
        }
        // Charges made elsewhere count too; without a budget only the
        // operation limit applies.
        budget.charge(9_995_000).unwrap();
        {
            let _charged = Isolation::charging(Some(budget));
            count(41).unwrap();
            assert_eq!(count(1).unwrap_err().to_string(), "Out of chi.");
        }
        let _unbudgeted = Isolation::enter();
        count(MAX_PENDING_WORK).unwrap();
    }

    #[test]
    fn text_work_is_counted_per_payload_size() {
        assert_eq!((characters(1), characters(4)), (0, 2));
        assert_eq!((searched(7), searched(800)), (0, 100));
        assert_eq!((compared(1280, 256), compared(127, 4096)), (2, 0));
    }
}
