//! Dictionary key eligibility and matching. Keep insertion order and the first
//! key object when an equal key replaces its value, as the Python runtime does.
//!
//! Archival V1 finds keys with a linear scan. V2 dictionaries find them
//! through a hash index (`crate::dict_index`) and change heap dictionaries
//! in place, so every alias sees the change and one operation costs the same
//! at any size. The index tries candidates in insertion order with the same
//! equality as the scan, so both return the same entry.
use super::*;
use crate::dict_index::{key_hash, DictIndex};
use crate::VmReference;

fn check_key(key: &VmValue) -> Result<(), VmExecutionError> {
    key.with_resolved(check_resolved_key)
}

fn check_resolved_key(key: &VmValue) -> Result<(), VmExecutionError> {
    match key {
        VmValue::None
        | VmValue::Bool(_)
        | VmValue::Int(_)
        | VmValue::Float(_)
        | VmValue::String(_)
        | VmValue::Bytes(_)
        | VmValue::FrozenSet(_)
        | VmValue::DeploymentHandle
        | VmValue::ContractHandle(_)
        | VmValue::HostCallable(_)
        | VmValue::Builtin(_)
        | VmValue::BoundMethod(_)
        | VmValue::FunctionRef(_)
        | VmValue::InterfaceSubject(_)
        | VmValue::InterfaceDescriptor(_)
        | VmValue::TypeMarker(_) => Ok(()),
        VmValue::RawDecimal(value) if !value.is_snan() => Ok(()),
        VmValue::DecimalTuple(value) => value.as_values().iter().try_for_each(check_key),
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

/// Position of `key` among `entries`: through `index` (built first when
/// missing) for a key with a hash, else by scanning.
fn find(
    entries: &[(VmValue, VmValue)],
    index: &mut Option<DictIndex>,
    key: &VmValue,
    hash: Option<u64>,
) -> Result<Option<usize>, VmExecutionError> {
    if let Some(hash) = hash {
        if index.is_none() {
            *index = DictIndex::build(entries)?;
        }
        if let Some(index) = index {
            return index.find(entries, hash, |stored| vm_values_equal(stored, key));
        }
    }
    equal_position(entries.iter().map(|(stored, _)| stored), key)
}

/// A V2 dictionary on the heap; its operations use the hash index.
pub(in crate::interpreter) fn indexed_dict(receiver: &VmValue) -> Option<&VmReference> {
    match receiver {
        VmValue::Reference(reference)
            if numeric_v2::active()
                && reference.with_value(|value| matches!(value, VmValue::Dict(_))) =>
        {
            Some(reference)
        }
        _ => None,
    }
}

fn object_position(
    dict: &VmReference,
    key: &VmValue,
) -> Result<(Option<usize>, Option<u64>), VmExecutionError> {
    check_key(key)?;
    let hash = key_hash(key)?;
    let position = dict.with_dict_index(|entries, index| find(entries, index, key, hash))?;
    Ok((position, hash))
}

pub(in crate::interpreter) fn dict_object_get(
    dict: &VmReference,
    key: &VmValue,
) -> Result<Option<VmValue>, VmExecutionError> {
    let (position, _) = object_position(dict, key)?;
    Ok(position.map(|position| dict.with_dict_index(|entries, _| entries[position].1.clone())))
}

/// Store `value` under `key`; a new key fails once the dictionary holds `limit` entries.
pub(in crate::interpreter) fn dict_object_set(
    dict: &VmReference,
    key: VmValue,
    value: VmValue,
    limit: usize,
) -> Result<(), VmExecutionError> {
    match object_position(dict, &key)? {
        (Some(position), _) => {
            dict.set_dict_value(position, value);
            Ok(())
        }
        (None, hash) => {
            if dict.with_dict_index(|entries, _| entries.len()) >= limit {
                return Err(VmExecutionError::new(
                    "dictionary allocation limit exceeded",
                ));
            }
            dict.push_dict_entry(key, value, hash)
        }
    }
}

pub(in crate::interpreter) fn dict_object_pop(
    dict: &VmReference,
    key: &VmValue,
) -> Result<Option<VmValue>, VmExecutionError> {
    // CPython pop short-circuits empty dictionaries before hashing the key.
    if dict.with_dict_index(|entries, _| entries.is_empty()) {
        return Ok(None);
    }
    let (position, hash) = object_position(dict, key)?;
    let Some(position) = position else {
        return Ok(None);
    };
    Ok(Some(remove(dict, position, hash)?.1))
}

/// Remove the last entry, as `popitem()` does.
pub(in crate::interpreter) fn dict_object_pop_last(
    dict: &VmReference,
) -> Result<Option<(VmValue, VmValue)>, VmExecutionError> {
    let Some((position, key)) = dict.with_dict_index(|entries, _| {
        entries
            .len()
            .checked_sub(1)
            .map(|last| (last, entries[last].0.clone()))
    }) else {
        return Ok(None);
    };
    let hash = key_hash(&key)?;
    remove(dict, position, hash).map(Some)
}

/// Entries one unit of element work moves when a removal closes its gap.
const SHIFTED_ENTRIES_PER_UNIT: usize = 16;

fn remove(
    dict: &VmReference,
    position: usize,
    hash: Option<u64>,
) -> Result<(VmValue, VmValue), VmExecutionError> {
    let shifted = dict.with_dict_index(|entries, _| entries.len() - position - 1);
    crate::work_meter::count((shifted / SHIFTED_ENTRIES_PER_UNIT) as u64)?;
    Ok(dict.remove_dict_entry(position, hash))
}

/// Entries of a dictionary being built by a display, comprehension, `dict()`,
/// `fromkeys()` or `|`. V2 finds keys through a hash index.
#[derive(Default)]
pub(in crate::interpreter) struct DictBuilder {
    entries: Vec<(VmValue, VmValue)>,
    index: Option<DictIndex>,
}

impl DictBuilder {
    pub(in crate::interpreter) fn from_entries(entries: Vec<(VmValue, VmValue)>) -> Self {
        Self {
            entries,
            index: None,
        }
    }

    pub(in crate::interpreter) fn entries(&self) -> &[(VmValue, VmValue)] {
        &self.entries
    }

    pub(in crate::interpreter) fn into_entries(self) -> Vec<(VmValue, VmValue)> {
        self.entries
    }

    pub(in crate::interpreter) fn contains(
        &mut self,
        key: &VmValue,
    ) -> Result<bool, VmExecutionError> {
        if !numeric_v2::active() {
            return Ok(dict_get(&self.entries, key)?.is_some());
        }
        check_key(key)?;
        let hash = key_hash(key)?;
        Ok(find(&self.entries, &mut self.index, key, hash)?.is_some())
    }

    pub(in crate::interpreter) fn set(
        &mut self,
        key: VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        if !numeric_v2::active() {
            return dict_set(&mut self.entries, key, value);
        }
        check_key(&key)?;
        let hash = key_hash(&key)?;
        match find(&self.entries, &mut self.index, &key, hash)? {
            Some(position) => self.entries[position].1 = value,
            None => {
                DictIndex::pushed(&mut self.index, hash)?;
                self.entries.push((key, value));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heap::VmHeap;

    /// xorshift64*: a fixed generator, so failures reproduce.
    struct Random(u64);
    impl Random {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    fn decimal(text: &str) -> VmValue {
        VmValue::Decimal(VmDecimal::from_str_literal(text).unwrap())
    }

    /// A random V2 key from small domains, so that equal keys are common.
    /// Some keys are heap objects, some are plain values.
    fn random_key(random: &mut Random, heap: &VmHeap, depth: usize) -> VmValue {
        let key = match random.below(if depth < 2 { 12 } else { 9 }) {
            0 => VmValue::None,
            1 => VmValue::Bool(random.below(2) == 1),
            2 => vm_int(random.below(5) as i64 - 2),
            3 => VmValue::Int(BigInt::from(random.below(3) as i64 - 1) << 80),
            4 => VmValue::String(["", "a", "1", "ab", "雪"][random.below(5) as usize].into()),
            5 => VmValue::Bytes([&b""[..], b"a", b"1"][random.below(3) as usize].to_vec()),
            6 => VmValue::Builtin(["len", "str"][random.below(2) as usize].into()),
            7 => [
                VmValue::FunctionRef("f".into()),
                VmValue::TypeMarker("Any".into()),
                VmValue::DeploymentHandle,
                VmValue::ContractHandle(VmContractHandle {
                    module: "con_a".into(),
                    origin: "con_a".into(),
                }),
            ][random.below(4) as usize]
                .clone(),
            8 => VmValue::BoundMethod(Box::new(crate::VmBoundMethod {
                receiver: VmValue::String("a".into()),
                method: ["upper", "lower"][random.below(2) as usize].into(),
            })),
            9 | 10 => VmValue::Tuple(
                (0..random.below(3))
                    .map(|_| random_key(random, heap, depth + 1))
                    .collect(),
            ),
            _ => {
                // Frozenset members are set keys and may be decimals;
                // decimal('1') == 1.
                let members = (0..random.below(4))
                    .map(|_| match random.below(4) {
                        0 => decimal(["1", "2", "1.5"][random.below(3) as usize]),
                        1 => vm_int(random.below(3) as i64),
                        2 => VmValue::Bool(random.below(2) == 1),
                        _ => VmValue::String(["a", "b"][random.below(2) as usize].into()),
                    })
                    .collect();
                VmValue::FrozenSet(normalize_set_items(members).unwrap())
            }
        };
        if random.below(2) == 0 {
            heap.capture(key).unwrap()
        } else {
            key
        }
    }

    #[test]
    fn equal_v2_keys_have_equal_hashes() {
        let _scope = numeric_v2::Scope::enter(crate::XIAN_VM_V2_PROFILE);
        let heap = VmHeap::default();
        let mut random = Random(0x9e37_79b9_7f4a_7c15);
        let keys: Vec<VmValue> = (0..700)
            .map(|_| random_key(&mut random, &heap, 0))
            .collect();
        let mut equal_pairs = 0;
        for left in &keys {
            for right in &keys {
                let _work = crate::work_meter::Isolation::enter();
                check_key(left).unwrap();
                let left_hash = key_hash(left).unwrap().expect("V2 key has a hash");
                let right_hash = key_hash(right).unwrap().expect("V2 key has a hash");
                if vm_values_equal(left, right).unwrap() {
                    equal_pairs += 1;
                    assert_eq!(left_hash, right_hash, "{left:?} == {right:?}");
                }
            }
        }
        // Not only the 700 reflexive pairs: equal distinct keys are exercised.
        assert!(equal_pairs > 10_000, "{equal_pairs}");
    }

    #[test]
    fn hash_edge_cases_follow_v2_equality() {
        let _scope = numeric_v2::Scope::enter(crate::XIAN_VM_V2_PROFILE);
        let _work = crate::work_meter::Isolation::enter();
        let heap = VmHeap::default();
        let hash = |value: &VmValue| key_hash(value).unwrap();
        let frozen = |items: Vec<VmValue>| VmValue::FrozenSet(normalize_set_items(items).unwrap());
        // 0 and -0 are one integer; a captured key hashes like its value.
        assert_eq!(hash(&vm_int(0)), hash(&VmValue::Int(-BigInt::from(0))));
        assert_eq!(hash(&vm_int(7)), hash(&heap.capture(vm_int(7)).unwrap()));
        // Frozensets: member order and decimal('1') == 1 do not change the hash.
        let one_two = frozen(vec![vm_int(1), vm_int(2)]);
        for equal in [
            frozen(vec![vm_int(2), vm_int(1)]),
            frozen(vec![decimal("1"), vm_int(2)]),
            heap.capture(frozen(vec![vm_int(2), decimal("1.0")]))
                .unwrap(),
        ] {
            assert!(vm_values_equal(&one_two, &equal).unwrap());
            assert_eq!(hash(&one_two), hash(&equal));
        }
        // Nested tuples hash by value, whatever their object structure.
        let inner = heap
            .capture(VmValue::Tuple(vec![vm_int(1), VmValue::String("a".into())]))
            .unwrap();
        let nested = VmValue::Tuple(vec![inner, VmValue::Tuple(vec![VmValue::None])]);
        let plain = VmValue::Tuple(vec![
            VmValue::Tuple(vec![vm_int(1), VmValue::String("a".into())]),
            heap.capture(VmValue::Tuple(vec![VmValue::None])).unwrap(),
        ]);
        assert!(vm_values_equal(&nested, &plain).unwrap());
        assert_eq!(hash(&nested), hash(&plain));
        // V2 keeps True and 1 apart; text and bytes never meet.
        assert!(!vm_values_equal(&VmValue::Bool(true), &vm_int(1)).unwrap());
        assert_ne!(hash(&VmValue::Bool(true)), hash(&vm_int(1)));
        assert_ne!(
            hash(&VmValue::String("a".into())),
            hash(&VmValue::Bytes(b"a".to_vec()))
        );
        // Values V2 cannot hold have no hash; their dictionary keeps scanning.
        for exotic in [
            VmValue::Float(1.0),
            VmValue::Float(f64::NAN),
            VmValue::RawDecimal(crate::VmRawDecimal::parse("1").unwrap()),
            VmValue::Tuple(vec![vm_int(1), VmValue::Float(f64::INFINITY)]),
        ] {
            assert_eq!(hash(&exotic), None);
        }
    }

    /// One random dictionary operation: (kind, key, value).
    fn random_operation(random: &mut Random, heap: &VmHeap) -> (u64, VmValue, VmValue) {
        (
            random.below(5),
            random_key(random, heap, 0),
            vm_int(random.below(100) as i64),
        )
    }

    #[test]
    fn indexed_builder_matches_the_linear_scan() {
        let _scope = numeric_v2::Scope::enter(crate::XIAN_VM_V2_PROFILE);
        let heap = VmHeap::default();
        let mut random = Random(42);
        for _ in 0..200 {
            let _work = crate::work_meter::Isolation::enter();
            let mut built = DictBuilder::default();
            let mut linear = vec![];
            for _ in 0..random.below(60) {
                let (kind, key, value) = random_operation(&mut random, &heap);
                if kind < 3 {
                    built.set(key.clone(), value.clone()).unwrap();
                    dict_set(&mut linear, key, value).unwrap();
                } else {
                    assert_eq!(
                        built.contains(&key).unwrap(),
                        dict_get(&linear, &key).unwrap().is_some()
                    );
                }
            }
            assert_eq!(built.into_entries(), linear);
        }
    }

    /// The archival way to mutate a heap dictionary: copy, change, replace.
    fn replaced(dict: &VmReference, change: impl FnOnce(&mut Vec<(VmValue, VmValue)>)) {
        let VmValue::Dict(mut entries) = dict.value() else {
            unreachable!()
        };
        change(&mut entries);
        dict.replace(VmValue::Dict(entries)).unwrap();
    }

    fn slots(dict: &VmReference) -> (Vec<usize>, usize) {
        dict.dictionary_slots(|slots| (slots.positions.clone(), slots.end))
    }

    #[test]
    fn in_place_operations_match_copy_and_replace() {
        let _scope = numeric_v2::Scope::enter(crate::XIAN_VM_V2_PROFILE);
        let heap = VmHeap::default();
        let mut random = Random(7);
        for _ in 0..100 {
            let _work = crate::work_meter::Isolation::enter();
            let in_place = heap.capture(VmValue::Dict(vec![])).unwrap();
            let copied = heap.capture(VmValue::Dict(vec![])).unwrap();
            let (VmValue::Reference(in_place), VmValue::Reference(copied)) = (&in_place, &copied)
            else {
                unreachable!()
            };
            for _ in 0..random.below(80) {
                let (kind, key, value) = random_operation(&mut random, &heap);
                match kind {
                    0 | 1 => {
                        dict_object_set(in_place, key.clone(), value.clone(), usize::MAX).unwrap();
                        replaced(copied, |entries| dict_set(entries, key, value).unwrap());
                    }
                    2 => {
                        let expected = copied.with_value(|v| match v {
                            VmValue::Dict(entries) => dict_get(entries, &key).unwrap(),
                            _ => unreachable!(),
                        });
                        assert_eq!(dict_object_get(in_place, &key).unwrap(), expected);
                    }
                    3 => {
                        let mut expected = None;
                        replaced(copied, |entries| {
                            expected = dict_pop(entries, &key).unwrap()
                        });
                        assert_eq!(dict_object_pop(in_place, &key).unwrap(), expected);
                    }
                    _ => {
                        let mut expected = None;
                        replaced(copied, |entries| expected = entries.pop());
                        assert_eq!(dict_object_pop_last(in_place).unwrap(), expected);
                    }
                }
                assert_eq!(in_place.value(), copied.value());
                assert_eq!(slots(in_place), slots(copied));
            }
        }
    }

    #[test]
    fn a_key_without_hash_keeps_the_dictionary_scanning() {
        let _scope = numeric_v2::Scope::enter(crate::XIAN_VM_V2_PROFILE);
        let _work = crate::work_meter::Isolation::enter();
        let heap = VmHeap::default();
        let VmValue::Reference(dict) = heap.capture(VmValue::Dict(vec![])).unwrap() else {
            unreachable!()
        };
        dict_object_set(&dict, vm_int(1), vm_int(10), usize::MAX).unwrap();
        dict_object_set(&dict, VmValue::Float(1.5), vm_int(15), usize::MAX).unwrap();
        dict_object_set(&dict, VmValue::String("a".into()), vm_int(20), usize::MAX).unwrap();
        // 1 == 1.0, found through the scan; the first key is kept.
        dict_object_set(&dict, VmValue::Float(1.0), vm_int(11), usize::MAX).unwrap();
        assert_eq!(
            dict_object_get(&dict, &VmValue::Float(1.5)).unwrap(),
            Some(vm_int(15))
        );
        assert_eq!(
            dict_object_get(&dict, &VmValue::String("a".into())).unwrap(),
            Some(vm_int(20))
        );
        assert_eq!(
            dict_object_pop(&dict, &VmValue::Float(1.5)).unwrap(),
            Some(vm_int(15))
        );
        // With the float gone the index is rebuilt and used again.
        assert_eq!(
            dict_object_get(&dict, &vm_int(1)).unwrap(),
            Some(vm_int(11))
        );
        assert!(dict.with_dict_index(|_, index| index.is_some()));
        assert_eq!(
            dict.value(),
            VmValue::Dict(vec![
                (vm_int(1), vm_int(11)),
                (VmValue::String("a".into()), vm_int(20))
            ])
        );
    }

    #[test]
    fn indexed_operations_keep_key_errors_and_limits() {
        let _scope = numeric_v2::Scope::enter(crate::XIAN_VM_V2_PROFILE);
        let _work = crate::work_meter::Isolation::enter();
        let heap = VmHeap::default();
        let VmValue::Reference(dict) = heap.capture(VmValue::Dict(vec![])).unwrap() else {
            unreachable!()
        };
        let list = VmValue::List(vec![]);
        // An empty dictionary pops nothing before looking at the key.
        assert_eq!(dict_object_pop(&dict, &list).unwrap(), None);
        assert_eq!(dict_object_pop_last(&dict).unwrap(), None);
        dict_object_set(&dict, vm_int(1), vm_int(1), 1).unwrap();
        for error in [
            dict_object_set(&dict, list.clone(), vm_int(1), 9).unwrap_err(),
            dict_object_get(&dict, &list).unwrap_err(),
            dict_object_pop(&dict, &list).unwrap_err(),
        ] {
            assert_eq!(error.to_string(), "unhashable type: 'list'");
        }
        // The limit stops new keys only.
        dict_object_set(&dict, vm_int(1), vm_int(2), 1).unwrap();
        assert!(dict_object_set(&dict, vm_int(2), vm_int(2), 1)
            .unwrap_err()
            .to_string()
            .contains("allocation limit"));
        assert_eq!(dict.value(), VmValue::Dict(vec![(vm_int(1), vm_int(2))]));
    }

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
