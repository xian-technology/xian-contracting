//! The chain's zk runtime feature (`contracting.runtime_features`) as the
//! Python path reads it: the chain state's value (the block overlay and
//! LMDB, not a transaction's host writes), else the features installed on
//! the node's driver. Contract preparation, `contract.has_export` and
//! deployments refuse a contract that uses zk host syscalls while it is off.
use super::charges::host_runtime_error;
use super::{fault, BlockHost};
use crate::state_view::StateView;
use crate::{VmExecutionError, VmValue};
use num_bigint::BigInt;

/// `runtime_feature_state_key("zk")`.
const ZK_FEATURE_KEY: &str = "__runtime_features.zk";
/// `_coerce_runtime_feature_value`'s refusal.
const REFUSED: &str = "runtime feature 'zk' must be a boolean";

/// A feature value without a reading.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unread {
    /// `_coerce_runtime_feature_value` refuses it.
    Refused,
    /// Text whose Python `strip().lower()` this port does not reproduce
    /// (non-ASCII).
    Untranslated,
}

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
        _ => Err(Unread::Refused),
    }
}

/// A runtime feature given as text, after Python's `strip().lower()`.
fn feature_text(text: &str) -> Result<bool, Unread> {
    if !text.is_ascii() {
        return Err(Unread::Untranslated);
    }
    let normalized = text
        .trim_matches(|char: char| " \t\n\r\x0b\x0c\x1c\x1d\x1e\x1f".contains(char))
        .to_ascii_lowercase();
    match normalized.as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(Unread::Refused),
    }
}

impl BlockHost<'_> {
    /// `NativeVmHost._reject_disabled_runtime_features` for `contract`,
    /// which uses zk host syscalls.
    pub(super) fn require_zk(&mut self, contract: &str) -> Result<(), VmExecutionError> {
        let enabled = zk_enabled(&self.view, self.tx.zk_enabled_without_state)
            .map_err(|error| self.halt(fault(error)))?;
        match enabled {
            Ok(true) => Ok(()),
            Ok(false) => Err(host_runtime_error(zk_disabled(contract))),
            Err(Unread::Refused) => Err(VmExecutionError::described(
                "ValueError",
                format!("ValueError: {REFUSED}"),
                REFUSED,
            )),
            Err(Unread::Untranslated) => self.back("runtime feature text the port does not read"),
        }
    }
}
