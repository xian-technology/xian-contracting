//! Consensus policy for classical host operations. An absent policy or an
//! exactly formed v1 migration policy permits them; every other value closes
//! the classical routes. The node owns account proof verification and writes.
use crate::VmValue;
use num_traits::ToPrimitive;

pub(crate) const POLICY_KEY: &str = "_accounts.policy";

pub(crate) fn record_key(owner: &str) -> String {
    format!("_accounts.records:{owner}")
}

pub(crate) fn allows_classical(policy: Option<&VmValue>) -> bool {
    let Some(value) = policy else { return true };
    policy_version(value) == Some(1)
}

/// Recognize the two exact policy encodings. Unknown or malformed state
/// grants neither legacy authority nor a reusable strict-account proof.
pub(crate) fn policy_version(value: &VmValue) -> Option<u64> {
    let VmValue::Dict(entries) = value else {
        return None;
    };
    let field = |name: &str| {
        entries.iter().find_map(|(key, value)| {
            matches!(key, VmValue::String(key) if key == name).then_some(value)
        })
    };
    let VmValue::Int(chi) = field("transition_chi")? else {
        return None;
    };
    if chi.to_u64()? == 0 {
        return None;
    }
    let VmValue::Int(version) = field("version")? else {
        return None;
    };
    match version.to_u64()? {
        1 if entries.len() == 3 && matches!(field("enrollment_open"), Some(VmValue::Bool(_))) => {
            Some(1)
        }
        2 if entries.len() == 2 => Some(2),
        _ => None,
    }
}
