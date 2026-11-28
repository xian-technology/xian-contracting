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
    let VmValue::Dict(entries) = value else {
        return false;
    };
    let field = |name: &str| {
        entries.iter().find_map(|(key, value)| {
            matches!(key, VmValue::String(key) if key == name).then_some(value)
        })
    };
    entries.len() == 3
        && matches!(field("version"), Some(VmValue::Int(version)) if version.to_u64() == Some(1))
        && matches!(field("enrollment_open"), Some(VmValue::Bool(_)))
        && matches!(field("transition_chi"), Some(VmValue::Int(chi)) if chi.to_u64().is_some_and(|n| n > 0))
}
