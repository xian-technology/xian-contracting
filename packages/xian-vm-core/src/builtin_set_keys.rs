//! Python-hashable keys for builtin sets, separate from wrapper serialization.
//!
//! Existing eligible values keep their canonical keys. Execution-local keys and
//! tuples containing them share a final stable encounter-order bucket. Equality
//! still distinguishes its members; sort-key equality never merges identities.
use super::*;

type Result<T> = std::result::Result<T, VmExecutionError>;

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum BuiltinKey {
    Legacy(VmSetKey),
    ExecutionLocal,
}

#[derive(Clone, Copy)]
enum Domain {
    Builtin,
    Wrapper,
}

#[derive(Default)]
struct KeyValidator {
    nodes: usize,
}

impl KeyValidator {
    fn classify(&mut self, value: &VmValue, domain: Domain, depth: usize) -> Result<bool> {
        self.nodes += 1;
        if depth > 128 || self.nodes > 1024 * 1024 {
            return Err(VmExecutionError::new(
                "builtin set key traversal limit exceeded",
            ));
        }
        if let VmValue::Reference(reference) = value {
            return reference.with_value(|value| self.contents(value, domain, depth));
        }
        self.contents(value, domain, depth)
    }

    fn contents(&mut self, value: &VmValue, domain: Domain, depth: usize) -> Result<bool> {
        match value {
            VmValue::Tuple(items) => self.children(items, domain, depth),
            VmValue::DecimalTuple(tuple) => self.children(tuple.fields(), domain, depth),
            // ContractingFrozenSet hashes itself even when its members (fixed
            // Decimal and time wrappers) are individually unhashable in Python.
            VmValue::FrozenSet(items) => self.children(items, Domain::Wrapper, depth),
            value => classify_leaf(value, domain),
        }
    }

    fn children(&mut self, items: &[VmValue], domain: Domain, depth: usize) -> Result<bool> {
        let mut local = false;
        for item in items {
            // Do not short-circuit: a callable cannot hide an invalid sibling.
            local |= self.classify(item, domain, depth + 1)?;
        }
        Ok(local)
    }
}

fn classify_leaf(value: &VmValue, domain: Domain) -> Result<bool> {
    match value {
        VmValue::None
        | VmValue::Bool(_)
        | VmValue::Int(_)
        | VmValue::Float(_)
        | VmValue::String(_)
        | VmValue::Bytes(_) => Ok(false),
        VmValue::RawDecimal(decimal) if !decimal.is_snan() => Ok(false),
        VmValue::Decimal(_) | VmValue::DateTime(_) | VmValue::TimeDelta(_)
            if matches!(domain, Domain::Wrapper) =>
        {
            Ok(false)
        }
        VmValue::DeploymentHandle
        | VmValue::ContractHandle(_)
        | VmValue::HostCallable(_)
        | VmValue::Builtin(_)
        | VmValue::BoundMethod(_)
        | VmValue::FunctionRef(_)
        | VmValue::TypeMarker(_)
        | VmValue::InterfaceDescriptor(_)
            if matches!(domain, Domain::Builtin) =>
        {
            Ok(true)
        }
        other => Err(VmExecutionError::new(format!(
            "unhashable type: '{}'",
            other.type_name()
        ))),
    }
}

fn key(value: &VmValue) -> Result<BuiltinKey> {
    if KeyValidator::default().classify(value, Domain::Builtin, 0)? {
        Ok(BuiltinKey::ExecutionLocal)
    } else {
        Ok(BuiltinKey::Legacy(vm_set_key(value)?))
    }
}

pub(in crate::interpreter) fn ensure_hashable(value: &VmValue) -> Result<()> {
    key(value).map(|_| ())
}

pub(in crate::interpreter) fn normalize(values: Vec<VmValue>) -> Result<Vec<VmValue>> {
    normalize_set_items_by_key(values, key)
}

pub(in crate::interpreter) fn insert(values: &mut Vec<VmValue>, value: VmValue) -> Result<()> {
    insert_set_item_by_key(values, value, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_only_leaves_are_rejected_but_wrapped_frozen_sets_are_hashable() {
        let values = [
            VmValue::Decimal(VmDecimal::one()),
            VmValue::DateTime(crate::VmDateTime::new(2024, 1, 2, 0, 0, 0, 0).unwrap()),
            VmValue::TimeDelta(crate::VmTimeDelta::from_raw_seconds(2).unwrap()),
        ];
        for value in values {
            assert!(ensure_hashable(&value).is_err());
            assert!(ensure_hashable(&VmValue::Tuple(vec![value.clone()])).is_err());
            let frozen = VmValue::FrozenSet(vec![value]);
            assert!(ensure_hashable(&frozen).is_ok());
            assert!(ensure_hashable(&VmValue::Tuple(vec![frozen])).is_ok());
        }
    }

    #[test]
    fn local_keys_follow_legacy_values_in_stable_encounter_order() {
        let first = VmValue::FunctionRef("first".into());
        let second = VmValue::Builtin("len".into());
        let result = normalize(vec![
            second.clone(),
            vm_int(2),
            first.clone(),
            VmValue::None,
            second.clone(),
        ])
        .unwrap();
        assert_eq!(result, vec![VmValue::None, vm_int(2), second, first]);
    }

    #[test]
    fn nested_local_keys_preserve_first_equal_representative_and_validate_siblings() {
        let function = VmValue::FunctionRef("first".into());
        let first = VmValue::Tuple(vec![function.clone(), VmValue::Bool(true)]);
        let equal = VmValue::Tuple(vec![function.clone(), vm_int(1)]);
        assert_eq!(normalize(vec![first.clone(), equal]).unwrap(), vec![first]);
        for invalid in [VmValue::List(vec![]), VmValue::Decimal(VmDecimal::one())] {
            assert!(ensure_hashable(&VmValue::Tuple(vec![function.clone(), invalid])).is_err());
        }
        assert!(ensure_hashable(&VmValue::FrozenSet(vec![function])).is_err());
    }

    #[test]
    fn method_retrieval_deduplicates_by_receiver_not_contents() {
        let heap = crate::heap::VmHeap::default();
        let left = heap.capture(VmValue::List(vec![])).unwrap();
        let right = heap.capture(VmValue::List(vec![])).unwrap();
        let method = |receiver: VmValue| {
            heap.capture(VmValue::BoundMethod(Box::new(crate::VmBoundMethod {
                receiver,
                method: "append".into(),
            })))
            .unwrap()
        };
        let original = method(left.clone());
        let repeated = method(left);
        let distinct = method(right);
        let result = normalize(vec![original.clone(), repeated, distinct.clone()]).unwrap();
        assert_eq!(result.len(), 2);
        assert!(result[0].identical(&original));
        assert!(result[1].identical(&distinct));
    }

    #[test]
    fn insertion_agrees_with_batch_normalization_for_execution_keys() {
        let function = VmValue::FunctionRef("first".into());
        let inputs = vec![
            VmValue::Builtin("len".into()),
            vm_int(1),
            function.clone(),
            VmValue::Bool(true),
            function,
        ];
        let mut inserted = vec![];
        for value in inputs.iter().cloned() {
            insert(&mut inserted, value).unwrap();
        }
        assert_eq!(inserted, normalize(inputs).unwrap());
    }
    #[test]
    fn callable_key_cost_tracks_names_without_walking_receiver_contents() {
        let heap = crate::heap::VmHeap::default();
        let receiver = heap.capture(VmValue::List(vec![])).unwrap();
        let method = heap
            .capture(VmValue::BoundMethod(Box::new(crate::VmBoundMethod {
                receiver: receiver.clone(),
                method: "append".into(),
            })))
            .unwrap();
        let VmValue::Reference(list) = receiver else {
            unreachable!()
        };
        list.append_sequence(method.clone()).unwrap();
        assert!(ensure_hashable(&method).is_ok());
        assert!(mapping_views::value_work(&method) < 128);
        let named = VmValue::FunctionRef("f".repeat(8192));
        assert!(mapping_views::value_work(&named) >= 8192);
    }
    #[test]
    fn builtin_key_traversal_bounds_are_explicit() {
        let mut nested = VmValue::FunctionRef("callback".into());
        for _ in 0..128 {
            nested = VmValue::Tuple(vec![nested]);
        }
        assert!(ensure_hashable(&nested).is_ok());
        let too_deep = VmValue::Tuple(vec![nested]);
        assert!(ensure_hashable(&too_deep)
            .unwrap_err()
            .to_string()
            .contains("traversal limit"));
        let mut validator = KeyValidator {
            nodes: 1024 * 1024 - 1,
        };
        assert!(validator
            .classify(&VmValue::None, Domain::Builtin, 0)
            .is_ok());
        assert!(validator
            .classify(&VmValue::None, Domain::Builtin, 0)
            .is_err());
    }
    #[test]
    fn eligible_legacy_key_order_and_signaling_nan_rejection_are_unchanged() {
        let expected = vec![
            VmValue::None,
            VmValue::Bool(true),
            vm_int(2),
            VmValue::Float(1.25),
            VmValue::String("x".into()),
            VmValue::Bytes(vec![120]),
            VmValue::Tuple(vec![vm_int(3)]),
            VmValue::FrozenSet(vec![VmValue::Decimal(VmDecimal::one())]),
            VmValue::RawDecimal(crate::VmRawDecimal::parse("4.75").unwrap()),
            VmValue::FunctionRef("callback".into()),
        ];
        assert_eq!(
            normalize(expected.iter().rev().cloned().collect()).unwrap(),
            expected
        );
        let signaling = VmValue::RawDecimal(crate::VmRawDecimal::parse("sNaN").unwrap());
        assert!(ensure_hashable(&signaling).is_err());
        assert!(ensure_hashable(&VmValue::Tuple(vec![
            VmValue::Builtin("len".into()),
            signaling
        ]))
        .is_err());
    }
}
