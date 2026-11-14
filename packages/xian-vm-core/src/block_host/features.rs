//! The chain's zk runtime feature (`contracting.runtime_features`): the
//! chain state's value (the block overlay and
//! LMDB, not a transaction's host writes), else the features installed on
//! the node's driver. Contract preparation, `contract.has_export` and
//! deployments refuse a contract that uses zk host syscalls while it is off,
//! and (revision 14) every zk syscall fails while it is off, however the
//! calling contract was reached.
use super::charges::host_runtime_error;
use super::{fault, BlockHost};
use crate::state_view::StateView;
use crate::{VmExecutionError, VmValue};
use num_bigint::BigInt;

/// `runtime_feature_state_key("zk")`.
const ZK_FEATURE_KEY: &str = "__runtime_features.zk";
/// `_coerce_runtime_feature_value`'s refusal.
const REFUSED: &str = "runtime feature 'zk' must be a boolean";

/// A feature value `_coerce_runtime_feature_value` refuses: anything but a
/// bool, 0, 1 or one of its ASCII words (revision 14: text with non-ASCII
/// characters is refused, whatever Python's Unicode `strip().lower()` makes
/// of it).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Unread;

/// `runtime_feature_enabled(driver, "zk")`; `Err` for a storage fault.
pub(crate) fn zk_enabled(
    view: &StateView,
    without_state: bool,
) -> Result<Result<bool, Unread>, String> {
    Ok(match view.get(ZK_FEATURE_KEY)? {
        None | Some(VmValue::None) => Ok(without_state),
        Some(value) => feature_value(&value),
    })
}

/// The refusal of a contract that uses zk host syscalls while the feature
/// is off (`_reject_disabled_runtime_features`).
pub(crate) fn zk_disabled(contract: &str) -> String {
    format!(
        "contract '{contract}' uses zk host syscalls, but the chain zk runtime feature is disabled"
    )
}

/// `_coerce_runtime_feature_value`.
pub(super) fn feature_value(value: &VmValue) -> Result<bool, Unread> {
    match value {
        VmValue::Bool(enabled) => Ok(*enabled),
        VmValue::String(text) => feature_text(text),
        VmValue::Int(number) if *number == BigInt::from(0) => Ok(false),
        VmValue::Int(number) if *number == BigInt::from(1) => Ok(true),
        _ => Err(Unread),
    }
}

/// A runtime feature given as text, after Python's `strip().lower()`.
fn feature_text(text: &str) -> Result<bool, Unread> {
    if !text.is_ascii() {
        return Err(Unread);
    }
    let normalized = text
        .trim_matches(|char: char| " \t\n\r\x0b\x0c\x1c\x1d\x1e\x1f".contains(char))
        .to_ascii_lowercase();
    match normalized.as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(Unread),
    }
}

/// The disabled feature's failure of a zk syscall.
pub(crate) fn zk_syscall_disabled(syscall_id: &str) -> String {
    format!("{syscall_id} is unavailable: the chain zk runtime feature is disabled")
}

impl BlockHost<'_> {
    /// Refuses `contract`, which uses zk host syscalls, while the zk
    /// feature is off.
    pub(super) fn require_zk(&mut self, contract: &str) -> Result<(), VmExecutionError> {
        self.zk_feature(|| zk_disabled(contract))
    }

    /// The zk feature for a zk syscall: off fails the call.
    pub(super) fn require_zk_syscall(&mut self, syscall_id: &str) -> Result<(), VmExecutionError> {
        self.zk_feature(|| zk_syscall_disabled(syscall_id))
    }

    fn zk_feature(&mut self, disabled: impl FnOnce() -> String) -> Result<(), VmExecutionError> {
        if self.zk_available()? {
            Ok(())
        } else {
            Err(host_runtime_error(disabled()))
        }
    }

    /// Whether the chain's zk feature is on (`zk.is_available`); a value the
    /// feature check refuses raises its `ValueError`.
    pub(super) fn zk_available(&mut self) -> Result<bool, VmExecutionError> {
        let enabled = zk_enabled(&self.view, self.tx.zk_enabled_without_state)
            .map_err(|error| self.halt(fault(error)))?;
        enabled.map_err(|Unread| {
            VmExecutionError::described("ValueError", format!("ValueError: {REFUSED}"), REFUSED)
        })
    }
}
