//! Random calls whose host work would grow with an argument, refused before
//! any host runs them (V2; archival V1 keeps its historical behaviour).
//!
//! The VM checks them on the arguments it hands to the host (after its own
//! boundary checks), before any host runs them, so no host ever
//! draws, formats or allocates in proportion to an unbounded argument:
//! - `getrandbits(k)` with `k` above the 512-bit V2 integer limit: its result
//!   could not cross the V2 boundary, which refuses it with the same text;
//! - `choices(population, k)` with `k` above the sequence allocation limit,
//!   like any other sequence that long (`sequence repetition exceeds ...`);
//! - `choice` and `choices` of a population that is not a sequence the VM
//!   indexes itself (list, tuple, str, bytes, bytearray): Python would index
//!   a dict by position or fail on the others, after converting all of it;
//! - `seed(salt)` with a salt other than a str, int (bool included) or
//!   `None` (decision 4 of the single-engine plan): the seed material holds
//!   the salt's text, and only those types have a text of their own size.
use super::{numeric_v2, MAX_SEQUENCE_LENGTH};
use crate::{VmExecutionError, VmValue};
use num_bigint::BigInt;

/// Refuse `syscall_id` when its host work would exceed the V2 bounds (in
/// V2 execution only).
pub(crate) fn check(
    syscall_id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<(), VmExecutionError> {
    if !numeric_v2::active() {
        return Ok(());
    }
    check_v2(syscall_id, args, kwargs)
}

/// The V2 bounds, for a V2-only host.
pub(crate) fn check_v2(
    syscall_id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<(), VmExecutionError> {
    match syscall_id {
        "random.getrandbits" => bits(bound(args, kwargs, &["k"], "k")),
        "random.choice" => population("choice", bound(args, kwargs, &["items"], "items")),
        "random.choices" => {
            population("choices", bound(args, kwargs, &["items", "k"], "items"))?;
            draws(bound(args, kwargs, &["items", "k"], "k"))
        }
        "random.seed" => salt(bound(args, kwargs, &["aux_salt"], "aux_salt")),
        _ => Ok(()),
    }
}

/// The argument for parameter `name` when the call binds to `params` as
/// Python binds it; `None` when it is missing or Python refuses the call
/// itself (the host then raises Python's own error, before any work).
fn bound<'a>(
    args: &'a [VmValue],
    kwargs: &'a [(String, VmValue)],
    params: &[&str],
    name: &str,
) -> Option<&'a VmValue> {
    let keywords = params.get(args.len()..)?;
    if !kwargs
        .iter()
        .all(|(key, _)| keywords.contains(&key.as_str()))
    {
        return None;
    }
    let position = params.iter().position(|param| *param == name)?;
    args.get(position).or_else(|| {
        kwargs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    })
}

/// An int argument, also when the VM holds it on its heap.
fn int(value: Option<&VmValue>) -> Option<BigInt> {
    match value? {
        VmValue::Int(number) => Some(number.clone()),
        VmValue::Reference(reference) => reference.with_value(|value| int(Some(value))),
        _ => None,
    }
}

fn bits(k: Option<&VmValue>) -> Result<(), VmExecutionError> {
    match int(k) {
        Some(k) if k > BigInt::from(xian_numeric::INTEGER_BITS) => Err(VmExecutionError::new(
            "integer exceeds the 512-bit magnitude limit",
        )),
        _ => Ok(()),
    }
}

fn draws(k: Option<&VmValue>) -> Result<(), VmExecutionError> {
    match int(k) {
        Some(k) if k > BigInt::from(MAX_SEQUENCE_LENGTH) => Err(VmExecutionError::new(
            "random.choices() exceeds the maximum allowed allocation size",
        )),
        _ => Ok(()),
    }
}

fn population(function: &str, items: Option<&VmValue>) -> Result<(), VmExecutionError> {
    match items.map(VmValue::type_name) {
        None | Some("list" | "tuple" | "str" | "bytes" | "bytearray") => Ok(()),
        Some(_) => Err(VmExecutionError::new(format!(
            "random.{function}() population must be a list, tuple, str, bytes or bytearray"
        ))),
    }
}

fn salt(salt: Option<&VmValue>) -> Result<(), VmExecutionError> {
    match salt.map(VmValue::type_name) {
        None | Some("none" | "str" | "int" | "bool") => Ok(()),
        Some(_) => Err(VmExecutionError::new(
            "random.seed() salt must be a str, int or None",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(value: impl Into<BigInt>) -> VmValue {
        VmValue::Int(value.into())
    }

    fn checked(syscall: &str, args: &[VmValue], kwargs: &[(&str, VmValue)]) -> Result<(), String> {
        let _scope = numeric_v2::Scope::enter(crate::XIAN_VM_V2_PROFILE);
        let kwargs: Vec<(String, VmValue)> = kwargs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect();
        check(syscall, args, &kwargs).map_err(|error| error.to_string())
    }

    #[test]
    fn getrandbits_is_bounded_by_the_v2_integer_limit() {
        let refused = Err("integer exceeds the 512-bit magnitude limit".to_owned());
        assert_eq!(checked("random.getrandbits", &[int(512)], &[]), Ok(()));
        assert_eq!(checked("random.getrandbits", &[int(513)], &[]), refused);
        assert_eq!(
            checked("random.getrandbits", &[], &[("k", int(1u64 << 40))]),
            refused
        );
        assert_eq!(
            checked("random.getrandbits", &[VmValue::Bool(true)], &[]),
            Ok(())
        );
        // The VM holds ints on its heap.
        let heap = crate::heap::VmHeap::default();
        let held = heap.capture(int(513)).unwrap();
        assert!(matches!(held, VmValue::Reference(_)));
        assert_eq!(checked("random.getrandbits", &[held], &[]), refused);
        // Python's own binding or type errors come first.
        assert_eq!(
            checked("random.getrandbits", &[int(1), int(600)], &[]),
            Ok(())
        );
        assert_eq!(
            checked("random.getrandbits", &[], &[("bits", int(600))]),
            Ok(())
        );
        assert_eq!(
            checked("random.getrandbits", &[VmValue::String("9".into())], &[]),
            Ok(())
        );
    }

    #[test]
    fn choices_are_bounded_by_the_sequence_limit() {
        let items = VmValue::List(vec![int(1)]);
        let refused =
            Err("random.choices() exceeds the maximum allowed allocation size".to_owned());
        let limit = MAX_SEQUENCE_LENGTH;
        let heap = crate::heap::VmHeap::default();
        let held = heap.capture(int(limit + 1)).unwrap();
        assert_eq!(
            checked("random.choices", &[items.clone(), held], &[]),
            refused
        );
        assert_eq!(
            checked("random.choices", &[items.clone(), int(limit)], &[]),
            Ok(())
        );
        assert_eq!(
            checked("random.choices", &[items.clone(), int(limit + 1)], &[]),
            refused
        );
        assert_eq!(
            checked(
                "random.choices",
                &[items.clone()],
                &[("k", int(1u64 << 40))]
            ),
            refused
        );
        assert_eq!(
            checked(
                "random.choices",
                &[],
                &[("k", int(1u64 << 40)), ("items", items.clone())]
            ),
            refused
        );
        assert_eq!(
            checked("random.choices", &[items], &[("n", int(1u64 << 40))]),
            Ok(())
        );
    }

    #[test]
    fn populations_are_sequences_the_vm_indexes() {
        let text = VmValue::String("ab".into());
        for items in [
            VmValue::List(vec![]),
            VmValue::Tuple(vec![]),
            text,
            VmValue::Bytes(vec![]),
        ] {
            assert_eq!(checked("random.choice", &[items.clone()], &[]), Ok(()));
            assert_eq!(
                checked("random.choices", &[items], &[("k", int(2))]),
                Ok(())
            );
        }
        for items in [
            VmValue::Dict(vec![]),
            VmValue::None,
            int(3),
            VmValue::Set(vec![]),
        ] {
            assert_eq!(
                checked("random.choice", &[], &[("items", items.clone())]),
                Err(
                    "random.choice() population must be a list, tuple, str, bytes or bytearray"
                        .into()
                )
            );
            assert_eq!(
                checked("random.choices", &[items, int(0)], &[]),
                Err(
                    "random.choices() population must be a list, tuple, str, bytes or bytearray"
                        .into()
                )
            );
        }
    }

    #[test]
    fn seed_salts_are_str_int_bool_or_none() {
        for salt in [
            VmValue::None,
            VmValue::String("s".into()),
            int(-7),
            VmValue::Bool(false),
        ] {
            assert_eq!(checked("random.seed", &[salt.clone()], &[]), Ok(()));
            assert_eq!(checked("random.seed", &[], &[("aux_salt", salt)]), Ok(()));
        }
        assert_eq!(checked("random.seed", &[], &[]), Ok(()));
        let refused = Err("random.seed() salt must be a str, int or None".to_owned());
        for salt in [
            VmValue::List(vec![]),
            VmValue::Tuple(vec![]),
            VmValue::Dict(vec![]),
        ] {
            assert_eq!(checked("random.seed", &[salt], &[]), refused);
        }
    }

    #[test]
    fn archival_v1_is_unbounded_as_before() {
        let _scope = numeric_v2::Scope::enter(crate::XIAN_VM_V1_PROFILE);
        assert!(check("random.getrandbits", &[int(1u64 << 40)], &[]).is_ok());
        assert!(check("random.seed", &[VmValue::List(vec![])], &[]).is_ok());
    }
}
