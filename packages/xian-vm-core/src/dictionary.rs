//! Dictionary key eligibility and matching. Keep insertion order and the first
//! key object when an equal key replaces its value, as the Python runtime does.
use super::*;

fn check_key(key: &VmValue) -> Result<(), VmExecutionError> {
    match key {
        VmValue::None
        | VmValue::Bool(_)
        | VmValue::Int(_)
        | VmValue::Float(_)
        | VmValue::String(_)
        | VmValue::Bytes(_)
        | VmValue::FrozenSet(_)
        | VmValue::Builtin(_)
        | VmValue::FunctionRef(_)
        | VmValue::TypeMarker(_) => Ok(()),
        VmValue::Tuple(items) => items.iter().try_for_each(check_key),
        other => Err(VmExecutionError::new(format!(
            "unhashable type: '{}'",
            other.type_name()
        ))),
    }
}

pub(in crate::interpreter) fn equal_position<'a>(
    values: impl Iterator<Item = &'a VmValue>,
    needle: &VmValue,
) -> Result<Option<usize>, VmExecutionError> {
    for (index, value) in values.enumerate() {
        if vm_values_equal(value, needle)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn key_position(
    entries: &[(VmValue, VmValue)],
    key: &VmValue,
) -> Result<Option<usize>, VmExecutionError> {
    check_key(key)?;
    equal_position(entries.iter().map(|(key, _)| key), key)
}

pub(in crate::interpreter) fn dict_set(
    entries: &mut Vec<(VmValue, VmValue)>,
    key: VmValue,
    value: VmValue,
) -> Result<(), VmExecutionError> {
    if let Some(index) = key_position(entries, &key)? {
        entries[index].1 = value;
    } else {
        entries.push((key, value));
    }
    Ok(())
}

pub(in crate::interpreter) fn dict_get(
    entries: &[(VmValue, VmValue)],
    key: &VmValue,
) -> Result<Option<VmValue>, VmExecutionError> {
    Ok(key_position(entries, key)?.map(|index| entries[index].1.clone()))
}

pub(in crate::interpreter) fn dict_pop(
    entries: &mut Vec<(VmValue, VmValue)>,
    key: &VmValue,
) -> Result<Option<VmValue>, VmExecutionError> {
    // CPython pop short-circuits empty dictionaries before hashing the key.
    if entries.is_empty() {
        return Ok(None);
    }
    Ok(key_position(entries, key)?.map(|index| entries.remove(index).1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dictionary_preserves_first_key_and_matches_numeric_probes() {
        let mut entries = vec![];
        dict_set(&mut entries, VmValue::Bool(true), vm_int(1)).unwrap();
        dict_set(&mut entries, vm_int(1), vm_int(2)).unwrap();
        dict_set(&mut entries, VmValue::String("tail".into()), vm_int(3)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], (VmValue::Bool(true), vm_int(2)));
        assert_eq!(
            dict_get(&entries, &VmValue::Float(1.0)).unwrap(),
            Some(vm_int(2))
        );
        assert_eq!(dict_get(&entries, &vm_int(9)).unwrap(), None);
        assert_eq!(dict_pop(&mut entries, &vm_int(1)).unwrap(), Some(vm_int(2)));
        assert_eq!(entries, vec![(VmValue::String("tail".into()), vm_int(3))]);
        assert_eq!(dict_pop(&mut entries, &vm_int(1)).unwrap(), None);
    }

    #[test]
    fn dictionary_rejects_invalid_keys_before_matching() {
        for key in [
            VmValue::List(vec![]),
            VmValue::Dict(vec![]),
            VmValue::ByteArray(vec![]),
            VmValue::Set(vec![]),
            VmValue::Tuple(vec![VmValue::List(vec![])]),
            VmValue::Decimal(VmDecimal::one()),
        ] {
            let mut entries = vec![];
            assert!(dict_set(&mut entries, key.clone(), vm_int(1)).is_err());
            assert!(entries.is_empty());
            assert!(dict_get(&entries, &key).is_err());
            assert_eq!(dict_pop(&mut entries, &key).unwrap(), None);
            entries.push((vm_int(1), vm_int(2)));
            assert!(dict_pop(&mut entries, &key).is_err());
            assert_eq!(entries.len(), 1);
        }
    }

    #[test]
    fn numeric_equality_does_not_round_integer_keys() {
        use std::cmp::Ordering;
        for (integer, float, expected) in [
            (9007199254740993_i64, 9007199254740992.0, Ordering::Greater),
            (9007199254740992, 9007199254740992.0, Ordering::Equal),
            (-9007199254740993, -9007199254740992.0, Ordering::Less),
            (1, 1.5, Ordering::Less),
            (-1, -1.5, Ordering::Greater),
            (0, -0.0, Ordering::Equal),
        ] {
            let left = vm_int(integer);
            let right = VmValue::Float(float);
            assert_eq!(
                vm_values_equal(&left, &right).unwrap(),
                expected == Ordering::Equal
            );
            assert_eq!(compare_vm_values(&left, &right).unwrap(), expected);
            assert_eq!(
                compare_vm_values(&right, &left).unwrap(),
                expected.reverse()
            );
        }
        let huge = VmValue::Int(BigInt::from(1) << 2048);
        assert!(!vm_values_equal(&huge, &VmValue::Float(f64::MAX)).unwrap());
    }
}
