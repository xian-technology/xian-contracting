#[path = "builtin_set_keys.rs"]
pub(in crate::interpreter) mod builtin_set_keys;
#[path = "native_methods.rs"]
mod native_methods;
#[path = "set_kinds.rs"]
pub(in crate::interpreter) mod set_kinds;
pub(super) use native_methods::binary_methods;
pub(super) use native_methods::call_native_method_collected;
#[cfg(test)]
pub(super) use native_methods::call_native_method_with;
pub(super) use native_methods::string_methods;
pub(super) use native_methods::unicode_strings::is_whitespace as unicode_whitespace;

use super::*;

#[path = "dictionary.rs"]
mod dictionary;
pub(super) use dictionary::*;

pub(super) fn builtin_name_value(name: &str) -> Option<VmValue> {
    match name {
        "len" | "range" | "str" | "bool" | "int" | "bytes" | "bytearray" | "dict" | "list"
        | "tuple" | "set" | "frozenset" | "isinstance" | "issubclass" | "sorted" | "sum"
        | "min" | "max" | "all" | "any" | "map" | "filter" | "reversed" | "zip" | "pow"
        | "format" | "ord" | "abs" | "ascii" | "bin" | "hex" | "oct" | "chr" | "divmod"
        | "round" | "quantize" | "sqrt" | "mul_div_floor" | "mul_div_ceil" | "Exception" => {
            Some(VmValue::Builtin(name.to_owned()))
        }
        "Any" | "decimal" => Some(VmValue::TypeMarker(name.to_owned())),
        _ => None,
    }
}

pub(super) fn bytes_like_data(value: &VmValue) -> Option<&[u8]> {
    match value {
        VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => Some(bytes.as_slice()),
        _ => None,
    }
}

/// Element work of comparing two text or binary payloads byte by byte.
fn payload_comparison_units(left: &VmValue, right: &VmValue) -> u64 {
    let payload = |value: &VmValue| match value {
        VmValue::String(text) => Some((text.len(), true)),
        other => bytes_like_data(other).map(|bytes| (bytes.len(), false)),
    };
    match (payload(left), payload(right)) {
        (Some((left, left_text)), Some((right, right_text))) if left_text == right_text => {
            crate::work_meter::compared(left, right)
        }
        _ => 0,
    }
}

pub(super) fn byte_from_value(value: &VmValue) -> Result<u8, VmExecutionError> {
    let value = &value.snapshot();
    let bigint = match value {
        VmValue::Int(value) => value.clone(),
        other => {
            return Err(VmExecutionError::new(format!(
                "a bytes-like object is required, not '{}'",
                other.type_name()
            )))
        }
    };
    if bigint.sign() == Sign::Minus || bigint > BigInt::from(255u16) {
        return Err(VmExecutionError::new("byte must be in range(0, 256)"));
    }
    bigint_to_u32(&bigint, "byte value").map(|value| value as u8)
}

fn bytes_like_index_value(bytes: &[u8], index: &VmValue) -> Result<VmValue, VmExecutionError> {
    let idx = normalize_sequence_index(index, bytes.len())?;
    Ok(vm_int(bytes[idx]))
}

fn slice_bytes_like(
    bytes: Vec<u8>,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
    mutable: bool,
) -> Result<VmValue, VmExecutionError> {
    let sliced = slice_positions(bytes.len(), lower, upper, step)?
        .into_iter()
        .map(|index| bytes[index])
        .collect::<Vec<_>>();
    if mutable {
        Ok(VmValue::ByteArray(sliced))
    } else {
        Ok(VmValue::Bytes(sliced))
    }
}

fn repeat_bytes_like(bytes: &[u8], count: &BigInt) -> Result<Vec<u8>, VmExecutionError> {
    if count.sign() == Sign::Minus {
        return Ok(Vec::new());
    }
    let count = bigint_to_usize(count, "repeat count")?;
    let total_len = bytes.len().saturating_mul(count);
    if total_len > MAX_BINARY_ALLOCATION_BYTES {
        return Err(VmExecutionError::new(
            "binary repetition exceeds the maximum allowed allocation size",
        ));
    }
    let mut repeated = Vec::with_capacity(bytes.len().saturating_mul(count));
    for _ in 0..count {
        repeated.extend_from_slice(bytes);
    }
    Ok(repeated)
}

pub(super) fn integer_limit_error(kind: &str) -> VmExecutionError {
    VmExecutionError::new(format!(
        "{kind} exceeds the maximum allowed integer size of {MAX_INTEGER_BITS} bits"
    ))
}

pub(super) fn ensure_bigint_bits(value: &BigInt, kind: &str) -> Result<(), VmExecutionError> {
    if value.bits() > MAX_INTEGER_BITS {
        return Err(integer_limit_error(kind));
    }
    Ok(())
}

pub(super) fn checked_int_value(value: BigInt, kind: &str) -> Result<VmValue, VmExecutionError> {
    ensure_bigint_bits(&value, kind)?;
    Ok(VmValue::Int(value))
}

pub(super) fn ensure_int_input_size(value: &str) -> Result<(), VmExecutionError> {
    if value.len() > MAX_INT_STRING_CHARS {
        return Err(VmExecutionError::new(format!(
            "int() input exceeds the maximum allowed length of {MAX_INT_STRING_CHARS} characters"
        )));
    }
    Ok(())
}

pub(super) fn ensure_int_bytes_input_size(value: &[u8]) -> Result<(), VmExecutionError> {
    if value.len() > MAX_INT_STRING_CHARS {
        return Err(VmExecutionError::new(format!(
            "int() input exceeds the maximum allowed length of {MAX_INT_STRING_CHARS} characters"
        )));
    }
    Ok(())
}

fn checked_left_shift(left: BigInt, right: BigInt) -> Result<VmValue, VmExecutionError> {
    if right.sign() == Sign::Minus {
        return Err(VmExecutionError::new("negative shift count"));
    }
    let shift = bigint_to_usize(&right, "shift count")?;
    let shift_bits = u64::try_from(shift).unwrap_or(u64::MAX);
    if !left.is_zero() && left.bits().saturating_add(shift_bits) > MAX_INTEGER_BITS {
        return Err(integer_limit_error("left shift"));
    }
    checked_int_value(left << shift, "left shift")
}

fn checked_right_shift(left: BigInt, right: BigInt) -> Result<VmValue, VmExecutionError> {
    if right.sign() == Sign::Minus {
        return Err(VmExecutionError::new("negative shift count"));
    }
    if right > BigInt::from(MAX_INTEGER_BITS) {
        return Err(integer_limit_error("right shift count"));
    }
    let shift = bigint_to_usize(&right, "shift count")?;
    Ok(VmValue::Int(left >> shift))
}

fn compare_bytes_like(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    left.cmp(right)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum VmSetKey {
    None,
    Bool(bool),
    Int(BigInt),
    Decimal(BigInt),
    DateTime((i64, i64, i64, i64, i64, i64, i64)),
    TimeDelta(i64),
    String(String),
    Bytes(Vec<u8>),
    Tuple(Vec<VmSetKey>),
    FrozenSet(Vec<VmSetKey>),
}

pub(super) fn set_like_values(value: &VmValue) -> Option<&[VmValue]> {
    match value {
        VmValue::Set(values) | VmValue::FrozenSet(values) => Some(values.as_slice()),
        _ => None,
    }
}

pub(crate) fn normalize_set_items(values: Vec<VmValue>) -> Result<Vec<VmValue>, VmExecutionError> {
    normalize_set_items_by_key(values, vm_set_key)
}

fn normalize_set_items_by_key<K: Ord>(
    values: Vec<VmValue>,
    key_for: impl Fn(&VmValue) -> Result<K, VmExecutionError>,
) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut normalized: Vec<(VmValue, K)> = Vec::new();
    for value in values {
        let key = key_for(&value)?;
        if let Some(index) = equal_position(normalized.iter().map(|(value, _)| value), &value)? {
            if key < normalized[index].1 {
                normalized[index] = (value, key);
            }
        } else {
            normalized.push((value, key));
        }
    }
    normalized.sort_by(|left, right| left.1.cmp(&right.1));
    Ok(normalized.into_iter().map(|(value, _)| value).collect())
}

/// Insert into an already canonical set without re-normalizing every pair.
fn insert_set_item_by_key<K: Ord>(
    values: &mut Vec<VmValue>,
    value: VmValue,
    key_for: impl Fn(&VmValue) -> Result<K, VmExecutionError>,
) -> Result<(), VmExecutionError> {
    let key = key_for(&value)?;
    if let Some(index) = equal_position(values.iter(), &value)? {
        if key >= key_for(&values[index])? {
            return Ok(());
        }
        values.remove(index);
    }
    if values.len() >= MAX_SEQUENCE_LENGTH {
        return Err(VmExecutionError::new("set allocation limit exceeded"));
    }
    let position = set_insertion_position(values, &key, &key_for)?;
    values.insert(position, value);
    Ok(())
}

fn set_insertion_position<K: Ord>(
    values: &[VmValue],
    key: &K,
    key_for: &impl Fn(&VmValue) -> Result<K, VmExecutionError>,
) -> Result<usize, VmExecutionError> {
    for (index, existing) in values.iter().enumerate() {
        if key_for(existing)? > *key {
            return Ok(index);
        }
    }
    Ok(values.len())
}

fn vm_set_key(value: &VmValue) -> Result<VmSetKey, VmExecutionError> {
    let value = &value.snapshot();
    match value {
        VmValue::None => Ok(VmSetKey::None),
        VmValue::Bool(value) => Ok(VmSetKey::Bool(*value)),
        VmValue::Int(value) => Ok(VmSetKey::Int(value.clone())),
        VmValue::Decimal(value) => Ok(VmSetKey::Decimal(value.scaled.clone())),
        VmValue::DateTime(value) => Ok(VmSetKey::DateTime((
            value.year(),
            value.month(),
            value.day(),
            value.hour(),
            value.minute(),
            value.second(),
            value.microsecond(),
        ))),
        VmValue::TimeDelta(value) => Ok(VmSetKey::TimeDelta(value.seconds())),
        VmValue::String(value) => Ok(VmSetKey::String(value.clone())),
        VmValue::Bytes(value) => Ok(VmSetKey::Bytes(value.clone())),
        VmValue::Tuple(values) => Ok(VmSetKey::Tuple(
            values
                .iter()
                .map(vm_set_key)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        VmValue::FrozenSet(values) => Ok(VmSetKey::FrozenSet(
            values
                .iter()
                .map(vm_set_key)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        other => Err(VmExecutionError::new(format!(
            "unhashable type: '{}'",
            other.type_name()
        ))),
    }
}

pub(super) fn set_contains_value(
    values: &[VmValue],
    needle: &VmValue,
) -> Result<bool, VmExecutionError> {
    for value in values {
        if vm_values_equal(value, needle)? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn set_values_equal(
    left: &[VmValue],
    right: &[VmValue],
) -> Result<bool, VmExecutionError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for value in left {
        if !set_contains_value(right, value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn set_is_subset(left: &[VmValue], right: &[VmValue]) -> Result<bool, VmExecutionError> {
    for value in left {
        if !set_contains_value(right, value)? {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn set_union_values(left: &[VmValue], right: &[VmValue]) -> Vec<VmValue> {
    let mut values = left.to_vec();
    values.extend(right.iter().cloned());
    values
}

pub(super) fn set_intersection_values(
    left: &[VmValue],
    right: &[VmValue],
) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut values = Vec::new();
    for value in left {
        if set_contains_value(right, value)? {
            values.push(value.clone());
        }
    }
    Ok(values)
}

pub(super) fn set_difference_values(
    left: &[VmValue],
    right: &[VmValue],
) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut values = Vec::new();
    for value in left {
        if !set_contains_value(right, value)? {
            values.push(value.clone());
        }
    }
    Ok(values)
}

pub(super) fn set_symmetric_difference_values(
    left: &[VmValue],
    right: &[VmValue],
) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut values = set_difference_values(left, right)?;
    for value in right {
        if !set_contains_value(left, value)? {
            values.push(value.clone());
        }
    }
    Ok(values)
}

pub(super) fn apply_binary_operator(
    operator: &str,
    left: VmValue,
    right: VmValue,
) -> Result<VmValue, VmExecutionError> {
    let left = left.snapshot();
    let right = right.snapshot();
    if numeric_v2::handles_binary(&left, &right) {
        return numeric_v2::binary(operator, &left, &right);
    }
    if let (VmValue::BuiltinSet(a), VmValue::BuiltinSet(b)) = (&left, &right) {
        return set_kinds::binary(operator, a, b);
    }
    let left = if operator == "bitor" {
        mapping_views::unwrap_mapping(left)
    } else {
        left
    };
    let right = if operator == "bitor" {
        mapping_views::unwrap_mapping(right)
    } else {
        right
    };
    match operator {
        "add" => match (left, right) {
            (VmValue::DateTime(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::DateTime(left.add_timedelta(&right)?))
            }
            (VmValue::TimeDelta(left), VmValue::DateTime(right)) => {
                Ok(VmValue::DateTime(right.add_timedelta(&left)?))
            }
            (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::TimeDelta(left.add(&right)?))
            }
            (VmValue::Bytes(mut left), VmValue::Bytes(right)) => {
                left.extend(right);
                Ok(VmValue::Bytes(left))
            }
            (VmValue::Bytes(mut left), VmValue::ByteArray(right)) => {
                left.extend(right);
                Ok(VmValue::Bytes(left))
            }
            (VmValue::ByteArray(mut left), VmValue::Bytes(right)) => {
                left.extend(right);
                Ok(VmValue::ByteArray(left))
            }
            (VmValue::ByteArray(mut left), VmValue::ByteArray(right)) => {
                left.extend(right);
                Ok(VmValue::ByteArray(left))
            }
            (VmValue::String(left), VmValue::String(right)) => Ok(VmValue::String(left + &right)),
            (VmValue::List(mut left), VmValue::List(right)) => {
                left.extend(right);
                Ok(VmValue::List(left))
            }
            (VmValue::Tuple(mut left), VmValue::Tuple(right)) => {
                left.extend(right);
                Ok(VmValue::Tuple(left))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported add operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "sub" => match (left, right) {
            (VmValue::DateTime(left), VmValue::DateTime(right)) => {
                Ok(VmValue::TimeDelta(left.sub_datetime(&right)?))
            }
            (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::TimeDelta(left.sub(&right)?))
            }
            (VmValue::Set(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::Set(normalize_set_items(set_difference_values(
                    &values, right,
                )?)?))
            }
            (VmValue::FrozenSet(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::FrozenSet(normalize_set_items(
                    set_difference_values(&values, right)?,
                )?))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported sub operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "mul" => match (left, right) {
            (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::TimeDelta(left.mul_timedelta(&right)?))
            }
            (VmValue::TimeDelta(left), VmValue::Int(right)) => Ok(VmValue::TimeDelta(
                left.mul_int(bigint_to_i64(&right, "timedelta multiplier")?)?,
            )),
            (VmValue::Int(left), VmValue::TimeDelta(right)) => Ok(VmValue::TimeDelta(
                right.mul_int(bigint_to_i64(&left, "timedelta multiplier")?)?,
            )),
            (VmValue::List(values), VmValue::Int(count)) => {
                Ok(VmValue::List(repeat_values(&values, &count)?))
            }
            (VmValue::Int(count), VmValue::List(values)) => {
                Ok(VmValue::List(repeat_values(&values, &count)?))
            }
            (VmValue::Tuple(values), VmValue::Int(count)) => {
                Ok(VmValue::Tuple(repeat_values(&values, &count)?))
            }
            (VmValue::Int(count), VmValue::Tuple(values)) => {
                Ok(VmValue::Tuple(repeat_values(&values, &count)?))
            }
            (VmValue::String(value), VmValue::Int(count)) => {
                Ok(VmValue::String(repeat_string(&value, &count)?))
            }
            (VmValue::Int(count), VmValue::String(value)) => {
                Ok(VmValue::String(repeat_string(&value, &count)?))
            }
            (VmValue::Bytes(bytes), VmValue::Int(count))
            | (VmValue::Int(count), VmValue::Bytes(bytes)) => {
                Ok(VmValue::Bytes(repeat_bytes_like(&bytes, &count)?))
            }
            (VmValue::ByteArray(bytes), VmValue::Int(count))
            | (VmValue::Int(count), VmValue::ByteArray(bytes)) => {
                Ok(VmValue::ByteArray(repeat_bytes_like(&bytes, &count)?))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported mul operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "div" => match (left, right) {
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported div operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "floordiv" => match (left, right) {
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported floordiv operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "mod" => match (left, right) {
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported mod operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "pow" => match (left, right) {
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported pow operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "bitand" => match (left, right) {
            (VmValue::Set(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::Set(normalize_set_items(set_intersection_values(
                    &values, right,
                )?)?))
            }
            (VmValue::FrozenSet(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::FrozenSet(normalize_set_items(
                    set_intersection_values(&values, right)?,
                )?))
            }
            (left, right) => Ok(VmValue::Int(left.as_bigint()? & right.as_bigint()?)),
        },
        "bitor" => match (left, right) {
            (VmValue::Dict(entries), VmValue::Dict(other)) => {
                let mut union = DictBuilder::from_entries(entries);
                for (key, value) in other {
                    if union.entries().len() >= MAX_SEQUENCE_LENGTH && !union.contains(&key)? {
                        return Err(VmExecutionError::new(
                            "dictionary union exceeds allocation limit",
                        ));
                    }
                    union.set(key, value)?;
                }
                Ok(VmValue::Dict(union.into_entries()))
            }
            (VmValue::Set(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::Set(normalize_set_items(set_union_values(
                    &values, right,
                ))?))
            }
            (VmValue::FrozenSet(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::FrozenSet(normalize_set_items(set_union_values(
                    &values, right,
                ))?))
            }
            (left, right) => Ok(VmValue::Int(left.as_bigint()? | right.as_bigint()?)),
        },
        "bitxor" => match (left, right) {
            (VmValue::Set(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::Set(normalize_set_items(
                    set_symmetric_difference_values(&values, right)?,
                )?))
            }
            (VmValue::FrozenSet(values), right) if set_like_values(&right).is_some() => {
                let right = set_like_values(&right).expect("checked above");
                Ok(VmValue::FrozenSet(normalize_set_items(
                    set_symmetric_difference_values(&values, right)?,
                )?))
            }
            (left, right) => Ok(VmValue::Int(left.as_bigint()? ^ right.as_bigint()?)),
        },
        "lshift" => {
            let left = left.as_bigint()?;
            let right = right.as_bigint()?;
            checked_left_shift(left, right)
        }
        "rshift" => {
            let left = left.as_bigint()?;
            let right = right.as_bigint()?;
            checked_right_shift(left, right)
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported binary operator '{other}'"
        ))),
    }
}

pub(super) fn apply_inplace_operator(
    operator: &str,
    left: VmValue,
    right: VmValue,
) -> Result<VmValue, VmExecutionError> {
    let result = if operator == "add" {
        if let VmValue::List(mut values) = left.snapshot() {
            values.extend(iterate_value(&right)?);
            VmValue::List(values)
        } else {
            apply_binary_operator(operator, left.clone(), right)?
        }
    } else {
        apply_binary_operator(operator, left.clone(), right)?
    };
    if let VmValue::Reference(reference) = &left {
        if matches!(
            result,
            VmValue::List(_)
                | VmValue::Dict(_)
                | VmValue::Set(_)
                | VmValue::BuiltinSet(_)
                | VmValue::ByteArray(_)
        ) {
            reference.replace(result)?;
            return Ok(left);
        }
    }
    Ok(result)
}

pub(super) fn apply_unary_operator(
    operator: &str,
    operand: VmValue,
) -> Result<VmValue, VmExecutionError> {
    let operand = operand.snapshot();
    if operator != "not" && matches!(operand, VmValue::Bool(_)) {
        return Err(VmExecutionError::new("bool is not an arithmetic operand"));
    }
    match operator {
        "not" => Ok(VmValue::Bool(!operand.truthy())),
        "neg" => match operand {
            VmValue::Int(value) => Ok(VmValue::Int(-value)),
            VmValue::Decimal(value) => Ok(VmValue::Decimal(VmDecimal::from_scaled(-value.scaled)?)),
            other => Err(VmExecutionError::new(format!(
                "unsupported neg operand {}",
                other.type_name()
            ))),
        },
        "pos" => match operand {
            VmValue::Int(value) => Ok(VmValue::Int(value)),
            VmValue::Decimal(value) => Ok(VmValue::Decimal(value)),
            VmValue::TimeDelta(value) => Ok(VmValue::TimeDelta(value)),
            other => Err(VmExecutionError::new(format!(
                "unsupported pos operand {}",
                other.type_name()
            ))),
        },
        "invert" => Ok(VmValue::Int(!operand.as_bigint()?)),
        other => Err(VmExecutionError::new(format!(
            "unsupported unary operator '{other}'"
        ))),
    }
}

pub(super) fn apply_compare_operator(
    operator: &str,
    left: &VmValue,
    right: &VmValue,
) -> Result<bool, VmExecutionError> {
    if operator == "is" {
        return Ok(left.identical(right));
    }
    if operator == "is_not" {
        return Ok(!left.identical(right));
    }
    if let Some(result) = mapping_views::compare(operator, left, right) {
        return result;
    }
    if operator == "eq" {
        return vm_values_equal(left, right);
    }
    if operator == "not_eq" {
        return Ok(!vm_values_equal(left, right)?);
    }
    if operator == "in" {
        return contains_value(right, left);
    }
    if operator == "not_in" {
        return contains_value(right, left).map(|value| !value);
    }
    let left = &left.snapshot();
    let right = &right.snapshot();
    match operator {
        "gt" if set_like_values(left).is_some() && set_like_values(right).is_some() => {
            let left = set_like_values(left).expect("checked above");
            let right = set_like_values(right).expect("checked above");
            Ok(left.len() > right.len() && set_is_subset(right, left)?)
        }
        "gt_e" if set_like_values(left).is_some() && set_like_values(right).is_some() => {
            let left = set_like_values(left).expect("checked above");
            let right = set_like_values(right).expect("checked above");
            set_is_subset(right, left)
        }
        "lt" if set_like_values(left).is_some() && set_like_values(right).is_some() => {
            let left = set_like_values(left).expect("checked above");
            let right = set_like_values(right).expect("checked above");
            Ok(left.len() < right.len() && set_is_subset(left, right)?)
        }
        "lt_e" if set_like_values(left).is_some() && set_like_values(right).is_some() => {
            let left = set_like_values(left).expect("checked above");
            let right = set_like_values(right).expect("checked above");
            set_is_subset(left, right)
        }
        "gt" | "gt_e" | "lt" | "lt_e" => {
            Ok(ordering_holds(operator, compare_vm_values(left, right)?))
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported compare operator '{other}'"
        ))),
    }
}

/// Whether `ordering` (left against right) satisfies the order operator.
fn ordering_holds(operator: &str, ordering: std::cmp::Ordering) -> bool {
    match operator {
        "gt" => ordering.is_gt(),
        "gt_e" => ordering.is_ge(),
        "lt" => ordering.is_lt(),
        _ => ordering.is_le(),
    }
}

pub(super) fn native_attribute_value(
    value: &VmValue,
    attr: &str,
) -> Result<VmValue, VmExecutionError> {
    let value = &value.snapshot();
    match value {
        VmValue::DateTime(value) => match attr {
            "year" => Ok(vm_int(value.year())),
            "month" => Ok(vm_int(value.month())),
            "day" => Ok(vm_int(value.day())),
            "hour" => Ok(vm_int(value.hour())),
            "minute" => Ok(vm_int(value.minute())),
            "second" => Ok(vm_int(value.second())),
            "microsecond" => Ok(vm_int(value.microsecond())),
            other => Err(VmExecutionError::new(format!(
                "datetime has no attribute '{other}'"
            ))),
        },
        VmValue::TimeDelta(value) => match attr {
            "seconds" => Ok(vm_int(value.seconds())),
            "minutes" => Ok(vm_int(value.minutes())),
            "hours" => Ok(vm_int(value.hours())),
            "days" => Ok(vm_int(value.days())),
            "weeks" => Ok(vm_int(value.weeks())),
            other => Err(VmExecutionError::new(format!(
                "timedelta has no attribute '{other}'"
            ))),
        },
        other => Err(VmExecutionError::new(format!(
            "value of type {} has no native attribute '{}'",
            other.type_name(),
            attr
        ))),
    }
}

pub(super) fn time_datetime_new(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    let [year, month, day, hour, minute, second, microsecond] = time_arguments(
        args,
        kwargs,
        [
            "year",
            "month",
            "day",
            "hour",
            "minute",
            "second",
            "microsecond",
        ],
        3,
        datetime_component,
    )?;
    Ok(VmValue::DateTime(VmDateTime::new(
        year,
        month,
        day,
        hour,
        minute,
        second,
        microsecond,
    )?))
}

pub(super) fn time_datetime_strptime(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    host: &mut dyn VmHost,
) -> Result<VmValue, VmExecutionError> {
    let (args, _) = method_signatures::bind(
        &VmValue::TypeMarker("datetime.datetime".into()),
        "strptime",
        args,
        kwargs,
    )?;
    let date_string = args[0].as_string()?;
    let format = args[1].as_string()?;
    host.charge_execution_cost(VmDateTime::parse_work_cost(&date_string, &format)?)?;
    Ok(VmValue::DateTime(VmDateTime::parse(&date_string, &format)?))
}

pub(super) fn time_timedelta_new(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    let [weeks, days, hours, minutes, seconds] = time_arguments(
        args,
        kwargs,
        ["weeks", "days", "hours", "minutes", "seconds"],
        0,
        timedelta_component,
    )?;
    Ok(VmValue::TimeDelta(VmTimeDelta::new(
        weeks, days, hours, minutes, seconds,
    )?))
}

#[cfg(test)]
pub(super) fn hash_sha3_256_text(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    crypto_resources::dispatch("hash.sha3_256_text", &args, &kwargs, &mut NoopHost)
        .expect("known crypto syscall")
}

#[cfg(test)]
pub(super) fn hash_sha3_256_hex(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    crypto_resources::dispatch("hash.sha3_256_hex", &args, &kwargs, &mut NoopHost)
        .expect("known crypto syscall")
}

#[cfg(test)]
pub(super) fn crypto_ed25519_verify(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    crypto_resources::dispatch("crypto.ed25519_verify", &args, &kwargs, &mut NoopHost)
        .expect("known crypto syscall")
}

fn time_arguments<const N: usize>(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    names: [&str; N],
    required: usize,
    convert: fn(&VmValue) -> Result<i64, VmExecutionError>,
) -> Result<[i64; N], VmExecutionError> {
    if args.len() > N {
        return Err(VmExecutionError::new("too many time constructor arguments"));
    }
    let mut bound: [Option<VmValue>; N] = std::array::from_fn(|_| None);
    for (index, value) in args.into_iter().enumerate() {
        bound[index] = Some(value);
    }
    bind_time_keywords(&mut bound, &names, kwargs)?;
    if bound[..required].iter().any(Option::is_none) {
        return Err(VmExecutionError::new("missing time constructor argument"));
    }
    let mut result = [0; N];
    for (index, value) in bound.into_iter().enumerate() {
        if let Some(value) = value {
            result[index] = convert(&value)?;
        }
    }
    Ok(result)
}

fn bind_time_keywords<const N: usize>(
    bound: &mut [Option<VmValue>; N],
    names: &[&str; N],
    kwargs: Vec<(String, VmValue)>,
) -> Result<(), VmExecutionError> {
    for (name, value) in kwargs {
        let index = names
            .iter()
            .position(|candidate| *candidate == name)
            .ok_or_else(|| VmExecutionError::new("unknown time constructor argument"))?;
        if bound[index].replace(value).is_some() {
            return Err(VmExecutionError::new("duplicate time constructor argument"));
        }
    }
    Ok(())
}

fn datetime_component(value: &VmValue) -> Result<i64, VmExecutionError> {
    if !resolves_to!(value, VmValue::Int(_) | VmValue::Bool(_)) {
        return Err(VmExecutionError::new(
            "datetime components must be integers",
        ));
    }
    value.as_i64()
}

fn timedelta_component(value: &VmValue) -> Result<i64, VmExecutionError> {
    numeric_text::int_value(vec![value.clone()], vec![])?.as_i64()
}

pub(crate) fn python_is_printable(character: char) -> bool {
    native_methods::unicode_strings::is_printable(character)
}

pub(super) fn repeat_values(
    values: &[VmValue],
    count: &BigInt,
) -> Result<Vec<VmValue>, VmExecutionError> {
    if count.sign() == Sign::Minus {
        return Ok(Vec::new());
    }
    let count = bigint_to_usize(count, "sequence repeat count")?;
    let total_len = values.len().saturating_mul(count);
    if total_len > MAX_SEQUENCE_LENGTH {
        return Err(VmExecutionError::new(
            "sequence repetition exceeds the maximum allowed allocation size",
        ));
    }
    let mut repeated = Vec::with_capacity(values.len().saturating_mul(count));
    for _ in 0..count {
        repeated.extend(values.iter().cloned());
    }
    Ok(repeated)
}

pub(super) fn repeat_string(value: &str, count: &BigInt) -> Result<String, VmExecutionError> {
    if count.sign() == Sign::Minus {
        return Ok(String::new());
    }
    let count = bigint_to_usize(count, "string repeat count")?;
    let total_len = value.len().saturating_mul(count);
    if total_len > MAX_BINARY_ALLOCATION_BYTES {
        return Err(VmExecutionError::new(
            "string repetition exceeds the maximum allowed allocation size",
        ));
    }
    Ok(value.repeat(count))
}

#[cfg(test)]
pub(super) fn call_native_method(
    receiver: VmValue,
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<NativeMethodResult, VmExecutionError> {
    call_native_method_with(
        receiver,
        method,
        args,
        kwargs,
        &crate::heap::VmHeap::default(),
        &mut |_, _| Err(VmExecutionError::new("callback requires an executing VM")),
    )
}

pub(super) fn compare_vm_values(
    left: &VmValue,
    right: &VmValue,
) -> Result<std::cmp::Ordering, VmExecutionError> {
    compare_values_at(left, right, 0)
}

fn compare_values_at(
    left: &VmValue,
    right: &VmValue,
    depth: usize,
) -> Result<std::cmp::Ordering, VmExecutionError> {
    if depth > 128 {
        return Err(VmExecutionError::new("comparison depth limit exceeded"));
    }
    crate::work_meter::count(1)?;
    left.with_resolved(|left| {
        right.with_resolved(|right| compare_resolved_values(left, right, depth))
    })
}

fn compare_resolved_values(
    left: &VmValue,
    right: &VmValue,
    depth: usize,
) -> Result<std::cmp::Ordering, VmExecutionError> {
    if let Some(ordering) = numeric_v2::ordering(left, right) {
        return ordering;
    }
    crate::work_meter::count(payload_comparison_units(left, right))?;
    match (left, right) {
        (VmValue::List(left), VmValue::List(right))
        | (VmValue::Tuple(left), VmValue::Tuple(right)) => {
            for (a, b) in left.iter().zip(right) {
                if !vm_values_equal(a, b)? {
                    return compare_values_at(a, b, depth + 1);
                }
            }
            Ok(left.len().cmp(&right.len()))
        }
        (VmValue::DateTime(left), VmValue::DateTime(right)) => Ok(left.value.cmp(&right.value)),
        (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
            Ok(left.raw_seconds.cmp(&right.raw_seconds))
        }
        (VmValue::Bool(left), VmValue::Bool(right)) => Ok(left.cmp(right)),
        (VmValue::Int(left), VmValue::Int(right)) => Ok(left.cmp(right)),
        (VmValue::String(left), VmValue::String(right)) => Ok(left.cmp(right)),
        (left, right) if bytes_like_data(left).is_some() && bytes_like_data(right).is_some() => {
            Ok(compare_bytes_like(
                bytes_like_data(left).expect("checked above"),
                bytes_like_data(right).expect("checked above"),
            ))
        }
        (left, right) => Err(VmExecutionError::new(format!(
            "values {} and {} are not order-comparable",
            left.type_name(),
            right.type_name()
        ))),
    }
}

pub(super) fn compare_numeric_values(
    left: &VmValue,
    right: &VmValue,
) -> Result<Option<std::cmp::Ordering>, VmExecutionError> {
    let left_numeric = matches!(
        left,
        VmValue::Bool(_) | VmValue::Int(_) | VmValue::Decimal(_)
    );
    let right_numeric = matches!(
        right,
        VmValue::Bool(_) | VmValue::Int(_) | VmValue::Decimal(_)
    );
    if !left_numeric || !right_numeric {
        return Ok(None);
    }

    match (left, right) {
        (VmValue::Bool(left), VmValue::Bool(right)) => Ok(Some(left.cmp(right))),
        _ => Ok(Some(compare_vm_values(left, right)?)),
    }
}

pub(super) fn vm_values_equal(left: &VmValue, right: &VmValue) -> Result<bool, VmExecutionError> {
    vm_values_equal_at(left, right, 0)
}

fn is_interface_descriptor(value: &VmValue) -> bool {
    match value {
        VmValue::Reference(reference) => reference.with_value(is_interface_descriptor),
        VmValue::DeploymentHandle
        | VmValue::InterfaceSubject(_)
        | VmValue::InterfaceDescriptor(_) => true,
        _ => false,
    }
}

fn vm_values_equal_at(
    left: &VmValue,
    right: &VmValue,
    depth: usize,
) -> Result<bool, VmExecutionError> {
    // An identity match is still a visited element (`xvm-gas-5`): comparing
    // a list with its copy checks every shared member.
    crate::work_meter::count(1)?;
    if left.identical(right) {
        return Ok(true);
    }
    // Descriptor equality uses identity only. Do not clone its public fields
    // (which can include cycles) to compare two distinct objects.
    if is_interface_descriptor(left) || is_interface_descriptor(right) {
        return Ok(false);
    }
    if depth > 128 {
        return Err(VmExecutionError::new(
            "maximum equality recursion depth exceeded",
        ));
    }
    if let Some(mapping) = mapping_proxy_target(left) {
        return vm_values_equal_at(&mapping, right, depth + 1);
    }
    if let Some(mapping) = mapping_proxy_target(right) {
        return vm_values_equal_at(left, &mapping, depth + 1);
    }
    if let Some(result) = mapping_views::compare("eq", left, right) {
        return result;
    }
    left.with_resolved(|left| {
        right.with_resolved(|right| resolved_values_equal(left, right, depth))
    })
}

fn mapping_proxy_target(value: &VmValue) -> Option<VmValue> {
    value.with_resolved(|resolved| match resolved {
        VmValue::MappingProxy(mapping) => Some((**mapping).clone()),
        _ => None,
    })
}

/// Equality of two resolved (non-reference) values; members may be references.
fn resolved_values_equal(
    left: &VmValue,
    right: &VmValue,
    depth: usize,
) -> Result<bool, VmExecutionError> {
    if numeric_v2::bool_number_pair(left, right) {
        return Ok(false);
    }
    if let Some(ordering) = compare_numeric_values(left, right)? {
        return Ok(ordering == std::cmp::Ordering::Equal);
    }
    crate::work_meter::count(payload_comparison_units(left, right))?;

    match (left, right) {
        (VmValue::ContractHandle(_), _) | (_, VmValue::ContractHandle(_)) => Ok(false),
        (VmValue::Iterator(_), _) | (_, VmValue::Iterator(_)) => Ok(false),
        (VmValue::Range(left), VmValue::Range(right)) => Ok(left.equivalent(right)),
        (VmValue::BuiltinSet(left), VmValue::BuiltinSet(right)) => set_values_equal(left, right),
        (VmValue::Set(left), VmValue::Set(right))
        | (VmValue::Set(left), VmValue::FrozenSet(right))
        | (VmValue::FrozenSet(left), VmValue::Set(right))
        | (VmValue::FrozenSet(left), VmValue::FrozenSet(right)) => set_values_equal(left, right),
        (VmValue::List(left), VmValue::List(right))
        | (VmValue::Tuple(left), VmValue::Tuple(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (left_item, right_item) in left.iter().zip(right.iter()) {
                if !vm_values_equal_at(left_item, right_item, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (VmValue::Dict(left), VmValue::Dict(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (left_key, left_value) in left {
                let Some(right_value) = dict_get(right, left_key)? else {
                    return Ok(false);
                };
                if !vm_values_equal_at(left_value, &right_value, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (left, right) if bytes_like_data(left).is_some() && bytes_like_data(right).is_some() => {
            Ok(bytes_like_data(left) == bytes_like_data(right))
        }
        _ => Ok(left == right),
    }
}

fn text_contains(value: &str, needle: &VmValue) -> Result<bool, VmExecutionError> {
    match &needle.snapshot() {
        VmValue::String(needle) => {
            crate::work_meter::count(crate::work_meter::searched(value.len() + needle.len()))?;
            Ok(value.contains(needle))
        }
        _ => Err(VmExecutionError::new(
            "string membership requires a string needle",
        )),
    }
}

fn bytes_contains(value: &[u8], needle: &VmValue) -> Result<bool, VmExecutionError> {
    match &needle.snapshot() {
        VmValue::Int(_) | VmValue::Bool(_) => Ok(value.contains(&byte_from_value(needle)?)),
        VmValue::Bytes(needle) | VmValue::ByteArray(needle) => {
            crate::work_meter::count(crate::work_meter::searched(value.len() + needle.len()))?;
            // Linear-time search; a window scan is quadratic in the needle.
            Ok(memchr::memmem::find(value, needle).is_some())
        }
        other => Err(VmExecutionError::new(format!(
            "a bytes-like object is required, not '{}'",
            other.type_name()
        ))),
    }
}

pub(super) fn contains_value(
    container: &VmValue,
    needle: &VmValue,
) -> Result<bool, VmExecutionError> {
    if let Some(dict) = indexed_dict(container) {
        return Ok(dict_object_get(dict, needle)?.is_some());
    }
    let container = &container.snapshot();
    match container {
        VmValue::Range(range) => {
            crate::scalar_methods::range_index(range, needle).map(|index| index.is_some())
        }
        VmValue::MappingProxy(mapping) => contains_value(mapping, needle),
        VmValue::View(view) => mapping_views::contains(view, needle),
        VmValue::String(value) => text_contains(value, needle),
        VmValue::Bytes(value) | VmValue::ByteArray(value) => bytes_contains(value, needle),
        VmValue::BuiltinSet(values) => {
            if resolves_to!(needle, VmValue::BuiltinSet(_)) {
                return Ok(false);
            }
            builtin_set_keys::ensure_hashable(needle)?;
            set_contains_value(values, needle)
        }
        VmValue::Set(values) | VmValue::FrozenSet(values) => set_contains_value(values, needle),
        VmValue::List(values) | VmValue::Tuple(values) => {
            for item in values {
                if vm_values_equal(item, needle)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        VmValue::Dict(entries) => Ok(dict_get(entries, needle)?.is_some()),
        other => Err(VmExecutionError::new(format!(
            "membership is not supported for {}",
            other.type_name()
        ))),
    }
}

pub(super) fn iterate_value(value: &VmValue) -> Result<Vec<VmValue>, VmExecutionError> {
    let value = &value.snapshot();
    match value {
        VmValue::Range(_) | VmValue::Iterator(_) => {
            crate::iteration::collect(value, &crate::heap::VmHeap::default(), &mut |_, _| {
                Err(VmExecutionError::new(
                    "iterator callback requires an executing VM",
                ))
            })
        }
        VmValue::List(values)
        | VmValue::Tuple(values)
        | VmValue::Set(values)
        | VmValue::BuiltinSet(values)
        | VmValue::FrozenSet(values) => Ok(values.clone()),
        VmValue::Dict(entries) => Ok(entries.iter().map(|(key, _)| key.clone()).collect()),
        VmValue::String(value) => Ok(value
            .chars()
            .map(|ch| VmValue::String(ch.to_string()))
            .collect()),
        VmValue::Bytes(value) | VmValue::ByteArray(value) => {
            Ok(value.iter().copied().map(vm_int).collect())
        }
        other => Err(VmExecutionError::new(format!(
            "value of type {} is not iterable",
            other.type_name()
        ))),
    }
}

pub(super) fn assign_subscript(
    container: VmValue,
    index: &VmValue,
    value: VmValue,
) -> Result<VmValue, VmExecutionError> {
    if let VmValue::Reference(reference) = &container {
        let list_length = reference.with_value(|resolved| match resolved {
            VmValue::List(values) => Some(values.len()),
            _ => None,
        });
        if let Some(length) = list_length {
            let idx = normalize_sequence_index(index, length)?;
            reference.set_list_item(idx, value);
            return Ok(container);
        }
        if let Some(dict) = indexed_dict(&container) {
            dict_object_set(dict, index.clone(), value, usize::MAX)?;
            return Ok(container);
        }
        let updated = assign_subscript(reference.value(), index, value)?;
        reference.replace(updated)?;
        return Ok(container);
    }
    match container {
        VmValue::List(mut values) => {
            let idx = normalize_sequence_index(index, values.len())?;
            values[idx] = value;
            Ok(VmValue::List(values))
        }
        VmValue::Dict(mut entries) => {
            dict_set(&mut entries, index.clone(), value)?;
            Ok(VmValue::Dict(entries))
        }
        VmValue::ByteArray(mut bytes) => {
            let idx = normalize_sequence_index(index, bytes.len())?;
            bytes[idx] = byte_from_value(&value)?;
            Ok(VmValue::ByteArray(bytes))
        }
        other => Err(VmExecutionError::new(format!(
            "subscript assignment is not supported for {}",
            other.type_name()
        ))),
    }
}

fn missing_key(
    found: Result<Option<VmValue>, VmExecutionError>,
    index: &VmValue,
) -> Result<VmValue, VmExecutionError> {
    found?.ok_or_else(|| VmExecutionError::new(format!("missing dict key {}", index.python_repr())))
}

pub(super) fn subscript_value(
    container: VmValue,
    index: &VmValue,
) -> Result<VmValue, VmExecutionError> {
    if let Some(dict) = indexed_dict(&container) {
        return missing_key(dict_object_get(dict, index), index);
    }
    if let Some(result) = container.with_resolved(|resolved| match resolved {
        VmValue::List(values) | VmValue::Tuple(values) => {
            Some(normalize_sequence_index(index, values.len()).map(|idx| values[idx].clone()))
        }
        VmValue::Dict(entries) => Some(missing_key(dict_get(entries, index), index)),
        _ => None,
    }) {
        return result;
    }
    // Lists, tuples and dicts were answered above.
    let container = container.snapshot();
    match container {
        VmValue::MappingProxy(mapping) => subscript_value(*mapping, index),
        VmValue::Range(range) => range
            .get(&index.as_bigint()?)
            .ok_or_else(|| VmExecutionError::new("range index out of bounds")),
        VmValue::String(value) => {
            crate::work_meter::count(crate::work_meter::searched(value.len()))?;
            let idx = normalize_sequence_index(index, value.chars().count())?;
            let character = value.chars().nth(idx).expect("index is within the string");
            Ok(VmValue::String(character.to_string()))
        }
        VmValue::Bytes(value) | VmValue::ByteArray(value) => bytes_like_index_value(&value, index),
        other => Err(VmExecutionError::new(format!(
            "subscript access is not supported for {}",
            other.type_name()
        ))),
    }
}

pub(super) fn subscript_slice_value(
    container: VmValue,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
) -> Result<VmValue, VmExecutionError> {
    let container = container.snapshot();
    match container {
        VmValue::Range(range) => Ok(VmValue::Range(range.sliced(lower, upper, step)?)),
        VmValue::List(values) => Ok(VmValue::List(
            slice_positions(values.len(), lower, upper, step)?
                .into_iter()
                .map(|index| values[index].clone())
                .collect(),
        )),
        VmValue::Tuple(values) => Ok(VmValue::Tuple(
            slice_positions(values.len(), lower, upper, step)?
                .into_iter()
                .map(|index| values[index].clone())
                .collect(),
        )),
        VmValue::String(value) => slice_text(&value, lower, upper, step).map(VmValue::String),
        VmValue::Bytes(value) => slice_bytes_like(value, lower, upper, step, false),
        VmValue::ByteArray(value) => slice_bytes_like(value, lower, upper, step, true),
        other => Err(VmExecutionError::new(format!(
            "slice access is not supported for {}",
            other.type_name()
        ))),
    }
}

pub(super) fn normalize_sequence_index(
    index: &VmValue,
    length: usize,
) -> Result<usize, VmExecutionError> {
    let raw = index.as_bigint()?;
    let length_value = BigInt::from(length);
    let adjusted = if raw.sign() == Sign::Minus {
        &length_value + &raw
    } else {
        raw
    };
    if adjusted.sign() == Sign::Minus || adjusted >= length_value {
        return Err(VmExecutionError::new("sequence index out of bounds"));
    }
    bigint_to_usize(&adjusted, "sequence index")
}

pub(super) fn normalize_sequence_insert_index(
    index: &VmValue,
    length: usize,
) -> Result<usize, VmExecutionError> {
    let raw = index.as_bigint()?;
    let length_value = BigInt::from(length);
    let adjusted = if raw.sign() == Sign::Minus {
        &length_value + &raw
    } else {
        raw
    };
    let clamped = if adjusted.sign() == Sign::Minus {
        BigInt::from(0usize)
    } else if adjusted > length_value {
        length_value
    } else {
        adjusted
    };
    bigint_to_usize(&clamped, "sequence insert index")
}

fn search_string(value: &str, method: &str, args: &[VmValue]) -> Result<VmValue, VmExecutionError> {
    if args.is_empty() || args.len() > 3 {
        return Err(VmExecutionError::new(
            "string search expects one to three arguments",
        ));
    }
    let length = value.chars().count();
    let (start, end) = string_search_bounds(length, args.get(1), args.get(2))?;
    let valid = start <= end && start <= length;
    let segment = substring_by_char_bounds(value, start, end);
    if matches!(method, "startswith" | "endswith") {
        let candidates = string_match_candidates(&args[0])?;
        return Ok(VmValue::Bool(
            valid
                && candidates.iter().any(|needle| {
                    if method == "startswith" {
                        segment.starts_with(needle)
                    } else {
                        segment.ends_with(needle)
                    }
                }),
        ));
    }
    let needle = args[0].as_string()?;
    if method == "count" {
        return Ok(vm_int(if valid {
            segment.matches(&needle).count()
        } else {
            0
        }));
    }
    let found = if valid {
        segment
            .find(&needle)
            .map(|index| start + segment[..index].chars().count())
    } else {
        None
    };
    Ok(vm_int(found.map_or(-1, |index| index as i64)))
}

fn string_search_bounds(
    length: usize,
    start: Option<&VmValue>,
    end: Option<&VmValue>,
) -> Result<(usize, usize), VmExecutionError> {
    let normalize =
        |value: Option<&VmValue>, default, maximum| -> Result<usize, VmExecutionError> {
            let value = value.filter(|v| !resolves_to!(v, VmValue::None));
            let Some(value) = value else {
                return Ok(default);
            };
            let mut value = string_methods::index_integer(value)?;
            if value.is_negative() {
                value += length;
            }
            bigint_to_usize(
                &value.max(BigInt::zero()).min(BigInt::from(maximum)),
                "search bound",
            )
        };
    Ok((
        normalize(start, 0, length + 1)?,
        normalize(end, length, length)?,
    ))
}

pub(super) fn normalize_search_bounds(
    length: usize,
    start: Option<&VmValue>,
    end: Option<&VmValue>,
) -> Result<(usize, usize), VmExecutionError> {
    let length_value = BigInt::from(length);
    let normalize =
        |value: Option<&VmValue>, default: &BigInt| -> Result<BigInt, VmExecutionError> {
            let Some(value) = value else {
                return Ok(default.clone());
            };
            let mut raw = value.as_bigint()?;
            if raw.sign() == Sign::Minus {
                raw += &length_value;
            }
            if raw.sign() == Sign::Minus {
                raw = BigInt::zero();
            }
            if raw > length_value {
                raw = length_value.clone();
            }
            Ok(raw)
        };

    let start = normalize(start, &BigInt::zero())?;
    let end = normalize(end, &length_value)?;
    let clamped_end = if start > end { start.clone() } else { end };
    Ok((
        bigint_to_usize(&start, "sequence search start")?,
        bigint_to_usize(&clamped_end, "sequence search end")?,
    ))
}

pub(super) fn slice_positions(
    length: usize,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
) -> Result<Vec<usize>, VmExecutionError> {
    let (start, stop, step) =
        crate::iteration::slice_indices(&BigInt::from(length), lower, upper, step)?;
    // Normalized bounds lie in [-1, length]. A step wider than the sequence
    // selects at most the first position, so saturating it is exact.
    let bound = |value: BigInt| value.to_i64().expect("slice bounds are normalized");
    let (mut index, stop) = (bound(start), bound(stop));
    let step = step.to_i64().unwrap_or(if step.is_positive() {
        i64::MAX
    } else {
        i64::MIN
    });
    let mut positions = Vec::new();
    while (step > 0 && index < stop) || (step < 0 && index > stop) {
        positions.push(index as usize);
        let Some(next) = index.checked_add(step) else {
            break;
        };
        index = next;
    }
    Ok(positions)
}

/// Slice text by character positions without allocating one string per
/// character.
fn slice_text(
    value: &str,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
) -> Result<String, VmExecutionError> {
    crate::work_meter::count(crate::work_meter::searched(value.len()))?;
    let characters = value.chars().collect::<Vec<_>>();
    Ok(slice_positions(characters.len(), lower, upper, step)?
        .into_iter()
        .map(|position| characters[position])
        .collect())
}

pub(super) fn substring_by_char_bounds(value: &str, start: usize, end: usize) -> String {
    value
        .chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}

pub(super) fn string_match_candidates(value: &VmValue) -> Result<Vec<String>, VmExecutionError> {
    let value = &value.snapshot();
    match value {
        VmValue::String(candidate) => Ok(vec![candidate.clone()]),
        VmValue::Tuple(values) => values
            .iter()
            .map(VmValue::as_string)
            .collect::<Result<Vec<_>, _>>(),
        other => Err(VmExecutionError::new(format!(
            "expected str or tuple[str, ...], found {}",
            other.type_name()
        ))),
    }
}

pub(super) fn split_string(
    value: &str,
    separator: Option<&str>,
    maxsplit: Option<usize>,
) -> Result<Vec<String>, VmExecutionError> {
    match separator {
        Some("") => Err(VmExecutionError::new("empty separator")),
        Some(separator) => {
            if matches!(maxsplit, Some(0)) {
                return Ok(vec![value.to_owned()]);
            }
            let mut parts = Vec::new();
            let mut remaining = value;
            let mut splits = 0usize;
            while maxsplit.is_none_or(|limit| splits < limit) {
                let Some(index) = remaining.find(separator) else {
                    break;
                };
                parts.push(remaining[..index].to_owned());
                remaining = &remaining[index + separator.len()..];
                splits += 1;
            }
            parts.push(remaining.to_owned());
            Ok(parts)
        }
        None => {
            let mut remaining =
                value.trim_start_matches(native_methods::unicode_strings::is_whitespace);
            if remaining.is_empty() {
                return Ok(Vec::new());
            }
            if matches!(maxsplit, Some(0)) {
                return Ok(vec![remaining.to_owned()]);
            }

            let mut parts = Vec::new();
            let mut splits = 0usize;
            while !remaining.is_empty() && maxsplit.is_none_or(|limit| splits < limit) {
                let start = remaining
                    .char_indices()
                    .find(|(_, ch)| !native_methods::unicode_strings::is_whitespace(*ch))
                    .map(|(index, _)| index)
                    .unwrap_or(remaining.len());
                remaining = &remaining[start..];
                if remaining.is_empty() {
                    break;
                }

                let boundary = remaining
                    .char_indices()
                    .find(|(_, ch)| native_methods::unicode_strings::is_whitespace(*ch))
                    .map(|(index, _)| index)
                    .unwrap_or(remaining.len());
                if boundary == remaining.len() {
                    parts.push(remaining.to_owned());
                    return Ok(parts);
                }

                parts.push(remaining[..boundary].to_owned());
                remaining = &remaining[boundary..];
                remaining =
                    remaining.trim_start_matches(native_methods::unicode_strings::is_whitespace);
                splits += 1;
            }
            if !remaining.is_empty() {
                parts.push(remaining.to_owned());
            }
            Ok(parts)
        }
    }
}

pub(super) fn type_matches(value: &VmValue, marker: &VmValue) -> bool {
    let value = &value.snapshot();
    let marker = &marker.snapshot();
    match marker {
        VmValue::TypeMarker(name) => type_matches_name(value, name),
        VmValue::Builtin(name) => type_matches_name(value, name),
        VmValue::Tuple(markers) => markers.iter().any(|marker| type_matches(value, marker)),
        _ => false,
    }
}

pub(super) fn type_matches_name(value: &VmValue, name: &str) -> bool {
    let value = &value.snapshot();
    match name {
        "Any" => true,
        "bool" => matches!(value, VmValue::Bool(_)),
        "int" => matches!(value, VmValue::Int(_)),
        "decimal" => matches!(value, VmValue::Decimal(_)),
        "datetime.datetime" => matches!(value, VmValue::DateTime(_)),
        "datetime.timedelta" => matches!(value, VmValue::TimeDelta(_)),
        "str" => matches!(value, VmValue::String(_)),
        "bytes" => matches!(value, VmValue::Bytes(_)),
        "bytearray" => matches!(value, VmValue::ByteArray(_)),
        "list" => matches!(value, VmValue::List(_)),
        "dict" => matches!(value, VmValue::Dict(_)),
        "tuple" => matches!(value, VmValue::Tuple(_)),
        "set" => matches!(value, VmValue::Set(_)),
        "frozenset" => matches!(value, VmValue::FrozenSet(_)),
        _ => false,
    }
}

pub(super) fn ascii_string_repr(value: &str) -> String {
    let mut rendered = String::from("'");
    for ch in value.chars() {
        match ch {
            '\'' => rendered.push_str("\\'"),
            '\\' => rendered.push_str("\\\\"),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            ch if ch.is_ascii() && !ch.is_ascii_control() => rendered.push(ch),
            ch => {
                let code = u32::from(ch);
                if code <= 0xff {
                    rendered.push_str(&format!("\\x{code:02x}"));
                } else if code <= 0xffff {
                    rendered.push_str(&format!("\\u{code:04x}"));
                } else {
                    rendered.push_str(&format!("\\U{code:08x}"));
                }
            }
        }
    }
    rendered.push('\'');
    rendered
}

pub(super) fn format_integer_builtin(value: &BigInt, radix: u32, prefix: &str) -> String {
    if value.sign() == Sign::Minus {
        format!("-{prefix}{}", (-value).to_str_radix(radix))
    } else {
        format!("{prefix}{}", value.to_str_radix(radix))
    }
}

pub(super) fn option_string_value(value: &Option<String>) -> VmValue {
    value
        .as_ref()
        .map(|value| VmValue::String(value.clone()))
        .unwrap_or(VmValue::None)
}

pub(super) fn option_entry_value(value: &Option<(String, String)>) -> VmValue {
    value
        .as_ref()
        .map(|(contract, function)| {
            VmValue::Tuple(vec![
                VmValue::String(contract.clone()),
                VmValue::String(function.clone()),
            ])
        })
        .unwrap_or(VmValue::None)
}

pub(super) fn normalize_event_payload(
    schema: &VmValue,
    payload: VmValue,
) -> Result<(Vec<(String, VmValue)>, Vec<(String, VmValue)>), VmExecutionError> {
    let schema = &schema.detached()?;
    let payload = payload.detached()?;
    let schema_entries = match schema {
        VmValue::Dict(entries) => entries,
        other => {
            return Err(VmExecutionError::new(format!(
                "event schema must be a dict, got {}",
                other.type_name()
            )))
        }
    };
    let payload_entries = match payload {
        VmValue::Dict(entries) => entries,
        other => {
            return Err(VmExecutionError::new(format!(
                "event payload must be a dict, got {}",
                other.type_name()
            )))
        }
    };

    let mut data_indexed = Vec::new();
    let mut data = Vec::new();

    for (schema_key, schema_value) in schema_entries {
        let key = match schema_key {
            VmValue::String(value) => value.clone(),
            other => {
                return Err(VmExecutionError::new(format!(
                    "event schema keys must be strings, got {}",
                    other.type_name()
                )))
            }
        };
        let value =
            dict_get(&payload_entries, &VmValue::String(key.clone()))?.ok_or_else(|| {
                VmExecutionError::new(format!("event payload is missing key '{}'", key))
            })?;
        if event_param_is_indexed(schema_value) {
            data_indexed.push((key, value));
        } else {
            data.push((key, value));
        }
    }

    if payload_entries.len() != data_indexed.len() + data.len() {
        return Err(VmExecutionError::new("event payload has unexpected keys"));
    }

    Ok((data_indexed, data))
}

pub(super) fn event_param_is_indexed(schema_value: &VmValue) -> bool {
    match schema_value {
        VmValue::Dict(entries) => {
            matches!(
                dict_get(entries, &VmValue::String("idx".to_owned())),
                Ok(Some(VmValue::Bool(true)))
            )
        }
        _ => false,
    }
}

pub(super) fn contract_target_label(target: &VmContractTarget) -> &str {
    match target {
        VmContractTarget::StaticImport { module, .. }
        | VmContractTarget::DynamicImport { module }
        | VmContractTarget::LocalHandle { module, .. }
        | VmContractTarget::FactoryCall { module, .. } => module,
    }
}

pub(super) fn normalize_hash_key(value: &VmValue) -> Result<String, VmExecutionError> {
    let value = &value.snapshot();
    let normalized = match value {
        VmValue::Tuple(values) => {
            if values.len() > MAX_HASH_DIMENSIONS {
                return Err(VmExecutionError::new(format!(
                    "Too many dimensions ({}) for hash. Max is {MAX_HASH_DIMENSIONS}",
                    values.len()
                )));
            }
            let mut rendered = Vec::new();
            for item in values {
                let part = storage_key_part(item)?;
                rendered.push(part);
            }
            rendered.join(STORAGE_DELIMITER)
        }
        other => storage_key_part(other)?,
    };

    let max_size = crate::committed_store::MAX_STORAGE_KEY_BYTES;
    if normalized.len() > max_size {
        return Err(VmExecutionError::new(format!(
            "Key is too long ({}). Max is {max_size}.",
            normalized.len()
        )));
    }

    Ok(normalized)
}

/// Hand one storage write to the host. V2 fails a write whose key the store
/// cannot hold here, at the write, not when the block commits.
pub(super) fn record_storage_write(
    host: &mut dyn VmHost,
    key: &str,
    value: &VmValue,
) -> Result<(), VmExecutionError> {
    if let Some(message) = crate::committed_store::storage_key_error(key) {
        return Err(VmExecutionError::new(message));
    }
    host.record_storage_write(key, value)?;
    host.charge_storage_write(key, value)
}

/// The key suffix selected by `Hash.all(*prefix)`/`clear(*prefix)`, including
/// its trailing delimiter; empty selects the whole hash. Only a call without
/// arguments does that, so `""` is an ordinary first dimension.
pub(super) fn hash_scan_prefix(values: &[VmValue]) -> Result<String, VmExecutionError> {
    let prefix = normalize_hash_key(&VmValue::Tuple(values.to_vec()))?;
    if values.is_empty() {
        return Ok(String::new());
    }
    Ok(format!("{prefix}{STORAGE_DELIMITER}"))
}

pub(super) fn storage_key_part(value: &VmValue) -> Result<String, VmExecutionError> {
    let value = &value.snapshot();
    let rendered = match value {
        VmValue::String(value) => value.clone(),
        VmValue::Int(value) => value.to_string(),
        VmValue::Bool(true) => "True".to_owned(),
        VmValue::Bool(false) => "False".to_owned(),
        VmValue::None => "None".to_owned(),
        VmValue::TypeMarker(name) => name.clone(),
        other => other.python_repr(),
    };

    if rendered.contains(STORAGE_DELIMITER) {
        return Err(VmExecutionError::new("Illegal delimiter in key."));
    }
    if rendered.contains(STORAGE_INDEX_SEPARATOR) {
        return Err(VmExecutionError::new("Illegal separator in key."));
    }
    Ok(rendered)
}

pub(super) fn foreign_storage_key(contract: &str, name: &str) -> String {
    format!("{contract}{STORAGE_DELIMITER}{name}")
}

pub(super) fn variable_storage_key(contract: &str, binding: &str) -> String {
    format!("{contract}{STORAGE_INDEX_SEPARATOR}{binding}")
}

pub(super) fn hash_storage_key(
    contract: &str,
    binding: &str,
    key: &VmValue,
) -> Result<String, VmExecutionError> {
    Ok(format!(
        "{}{}{}",
        variable_storage_key(contract, binding),
        STORAGE_DELIMITER,
        normalize_hash_key(key)?
    ))
}

pub(super) fn hash_storage_key_from_normalized(
    contract: &str,
    binding: &str,
    normalized_key: &str,
) -> String {
    format!(
        "{}{}{}",
        variable_storage_key(contract, binding),
        STORAGE_DELIMITER,
        normalized_key
    )
}

pub(super) fn split_foreign_storage_key(key: &str) -> Result<(String, String), VmExecutionError> {
    let Some((contract, binding)) = key.split_once(STORAGE_DELIMITER) else {
        return Err(VmExecutionError::new(format!(
            "invalid foreign storage key '{key}'"
        )));
    };
    Ok((contract.to_owned(), binding.to_owned()))
}

/// The charge of a zk syscall before the host runs it (`None` for a
/// syscall without one), after checking its call shape.
pub(super) fn explicit_syscall_metering_cost(
    syscall_id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<Option<u64>, VmExecutionError> {
    let arity = match syscall_id {
        "zk.verify_groth16_bn254" | "zk.verify_groth16" | "zk.shielded_note_append_commitments" => {
            3
        }
        "zk.warm_verified_proofs"
        | "zk.shielded_command_nullifier_digest"
        | "zk.shielded_output_payload_hash" => 1,
        "zk.shielded_command_binding" => return Ok(Some(100_000)),
        "zk.shielded_command_execution_tag" => return Ok(Some(50_000)),
        _ => return Ok(None),
    };
    if !kwargs.is_empty() || args.len() != arity {
        return Err(arity_error(syscall_id, arity));
    }
    zk_argument_cost(syscall_id, args).map(Some)
}

fn arity_error(syscall_id: &str, arity: usize) -> VmExecutionError {
    let expected = match arity {
        1 => "one positional argument",
        _ => "three positional arguments",
    };
    VmExecutionError::new(format!("{syscall_id}() expects {expected}"))
}

/// The charge of a zk syscall whose call shape was checked.
fn zk_argument_cost(syscall_id: &str, args: &[VmValue]) -> Result<u64, VmExecutionError> {
    match syscall_id {
        "zk.verify_groth16_bn254" => verification_cost(args, zk_payload_metering_cost),
        "zk.verify_groth16" => verification_cost(args, zk_registry_metering_cost),
        "zk.warm_verified_proofs" => Ok(zk_warm_metering_cost(&args[0])),
        "zk.shielded_note_append_commitments" => {
            per_item_cost(&args[2], "commitments", 250_000, 500_000)
        }
        "zk.shielded_command_nullifier_digest" => {
            per_item_cost(&args[0], "input_nullifiers", 100_000, 50_000)
        }
        // zk.shielded_output_payload_hash: one raw chi per payload byte.
        _ => Ok(hex_payload_bytes(&args[0].as_string()?)),
    }
}

/// A verification's charge from its key (id or bytes), proof and inputs.
fn verification_cost(
    args: &[VmValue],
    cost: fn(&str, &str, &[String]) -> u64,
) -> Result<u64, VmExecutionError> {
    Ok(cost(
        &args[0].as_string()?,
        &args[1].as_string()?,
        &as_string_list(&args[2], "public_inputs")?,
    ))
}

/// `base` plus `each` per string of the list `value`.
fn per_item_cost(
    value: &VmValue,
    label: &str,
    base: u64,
    each: u64,
) -> Result<u64, VmExecutionError> {
    Ok(base + as_string_list(value, label)?.len() as u64 * each)
}

pub(super) fn as_string_list(
    value: &VmValue,
    label: &str,
) -> Result<Vec<String>, VmExecutionError> {
    match value {
        VmValue::List(values) | VmValue::Tuple(values) => values
            .iter()
            .map(VmValue::as_string)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| VmExecutionError::new(format!("{label} must be a list of strings"))),
        _ => Err(VmExecutionError::new(format!(
            "{label} must be a list of strings"
        ))),
    }
}

pub(super) fn hex_payload_bytes(value: &str) -> u64 {
    match value.strip_prefix("0x") {
        Some(payload) if payload.len() % 2 == 0 => (payload.len() / 2) as u64,
        _ => 0,
    }
}

fn hex_list_bytes(values: &[String]) -> u64 {
    values.iter().map(|value| hex_payload_bytes(value)).sum()
}

pub(super) fn zk_payload_metering_cost(
    vk_hex: &str,
    proof_hex: &str,
    public_inputs: &[String],
) -> u64 {
    let payload_bytes =
        hex_payload_bytes(vk_hex) + hex_payload_bytes(proof_hex) + hex_list_bytes(public_inputs);
    750_000 + (public_inputs.len() as u64 * 50_000) + (payload_bytes * 50)
}

pub(super) fn zk_registry_metering_cost(
    vk_id: &str,
    proof_hex: &str,
    public_inputs: &[String],
) -> u64 {
    let payload_bytes =
        vk_id.len() as u64 + hex_payload_bytes(proof_hex) + hex_list_bytes(public_inputs);
    500_000 + 250_000 + (public_inputs.len() as u64 * 50_000) + (payload_bytes * 25)
}

/// `zk.warm_verified_proofs(requests)`: each request may cost the host a
/// verification, so each is charged as `zk.verify_groth16` charges its
/// arguments (a field that is not text counts as empty; the host refuses the
/// request after the charge).
pub(super) fn zk_warm_metering_cost(requests: &VmValue) -> u64 {
    let VmValue::List(requests) = requests else {
        return 0;
    };
    requests
        .iter()
        .map(zk_warm_request_metering_cost)
        .fold(0, u64::saturating_add)
}

fn zk_warm_request_metering_cost(request: &VmValue) -> u64 {
    let public_inputs: Vec<String> = match request_field(request, "public_inputs") {
        Some(VmValue::List(values)) => values
            .iter()
            .map(|value| text_or_empty(Some(value)).to_owned())
            .collect(),
        _ => Vec::new(),
    };
    zk_registry_metering_cost(
        text_or_empty(request_field(request, "vk_id")),
        text_or_empty(request_field(request, "proof_hex")),
        &public_inputs,
    )
}

/// `request.get(name)` of a dict request (its last entry under `name`).
fn request_field<'a>(request: &'a VmValue, name: &str) -> Option<&'a VmValue> {
    let VmValue::Dict(entries) = request else {
        return None;
    };
    entries
        .iter()
        .rev()
        .find(|(key, _)| matches!(key, VmValue::String(key) if key == name))
        .map(|(_, value)| value)
}

fn text_or_empty(value: Option<&VmValue>) -> &str {
    match value {
        Some(VmValue::String(text)) => text,
        _ => "",
    }
}

pub(super) fn resolve_contract_import_arg(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<String, VmExecutionError> {
    if let Some((_, value)) = kwargs.iter().find(|(key, _)| key == "module") {
        return value.as_string();
    }
    if let Some((_, value)) = kwargs.iter().find(|(key, _)| key == "name") {
        return value.as_string();
    }
    let first = args
        .first()
        .ok_or_else(|| VmExecutionError::new("contract.import expects a module name"))?;
    first.as_string()
}

pub(super) fn required_value<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Value, VmExecutionError> {
    object
        .get(field)
        .ok_or_else(|| VmExecutionError::new(format!("missing field '{field}'")))
}

pub(super) fn required_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a [Value], VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be an array")))
}

pub(super) fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be a string")))
}

pub(super) fn optional_string<'a>(object: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    object.get(field).and_then(Value::as_str)
}

pub(super) fn required_string_value(value: &Value) -> Result<&str, VmExecutionError> {
    value
        .as_str()
        .ok_or_else(|| VmExecutionError::new("value must be a string"))
}

pub(super) fn required_bool(
    object: &Map<String, Value>,
    field: &str,
) -> Result<bool, VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be a bool")))
}

pub(super) fn required_bigint(
    object: &Map<String, Value>,
    field: &str,
) -> Result<BigInt, VmExecutionError> {
    let value = object
        .get(field)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be an int")))?;
    match value {
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                return Ok(BigInt::from(value));
            }
            if let Some(value) = number.as_u64() {
                return Ok(BigInt::from(value));
            }
            BigInt::from_str(&number.to_string())
                .map_err(|_| VmExecutionError::new(format!("field '{field}' must be an int")))
        }
        Value::String(value) => BigInt::from_str(value)
            .map_err(|_| VmExecutionError::new(format!("field '{field}' must be an int"))),
        _ => Err(VmExecutionError::new(format!(
            "field '{field}' must be an int"
        ))),
    }
}

pub(super) fn as_object<'a>(
    value: &'a Value,
    label: &str,
) -> Result<&'a Map<String, Value>, VmExecutionError> {
    value.as_object().ok_or_else(|| {
        VmExecutionError::new(format!(
            "{label} must be an object, got {}",
            serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_owned())
        ))
    })
}

#[cfg(test)]
mod signature_security_tests {
    use super::*;

    #[test]
    fn crypto_verify_rejects_small_order_identity_forgery() {
        let identity = format!("01{}", "00".repeat(31));
        let signature = format!("{}{}", identity, "00".repeat(32));
        let result = crypto_ed25519_verify(
            vec![
                VmValue::String(identity),
                VmValue::String("xian parity test".into()),
                VmValue::String(signature),
            ],
            vec![],
        )
        .unwrap();
        assert!(matches!(result, VmValue::Bool(false)));
    }

    #[test]
    fn crypto_verify_accepts_rfc8032_vector() {
        let result = crypto_ed25519_verify(
            vec![
                VmValue::String(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a".into(),
                ),
                VmValue::String(String::new()),
                VmValue::String(
                    concat!(
                        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb",
                        "8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
                    )
                    .into(),
                ),
            ],
            vec![],
        )
        .unwrap();
        assert!(matches!(result, VmValue::Bool(true)));
    }

    #[test]
    fn crypto_verify_rejects_small_and_mixed_order_signature_points() {
        // Known-scalar signatures with R = identity or B plus order-four torsion.
        for signature in [
            concat!(
                "0100000000000000000000000000000000000000000000000000000000000000",
                "edaf87719b1f81c47646a414a04a0710b9c7ff5918a34e01e53c30bb2e2f5f00"
            ),
            concat!(
                "5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea7",
                "e38ee9f538979938c47d1e0f5577a489466ef86883378ba092d0b1de2f59307"
            ),
        ] {
            let result = crypto_ed25519_verify(
                vec![
                    VmValue::String(
                        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737".into(),
                    ),
                    VmValue::String("xian parity test".into()),
                    VmValue::String(signature.into()),
                ],
                vec![],
            )
            .unwrap();
            assert!(matches!(result, VmValue::Bool(false)));
        }
    }
}

#[cfg(test)]
mod slice_boundary_tests {
    use super::*;

    #[test]
    fn reverse_slice_clips_start_and_stop_to_last_element() {
        assert_eq!(
            slice_positions(3, Some(99.into()), None, Some((-1).into())).unwrap(),
            vec![2, 1, 0]
        );
        assert_eq!(
            slice_positions(0, Some(99.into()), None, Some((-1).into())).unwrap(),
            Vec::<usize>::new()
        );
        assert_eq!(
            slice_positions(3, Some(2.into()), Some(99.into()), Some((-1).into())).unwrap(),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn slice_step_does_not_wrap() {
        assert_eq!(
            slice_positions(3, Some(1.into()), None, Some(i64::MAX.into())).unwrap(),
            vec![1]
        );
        assert_eq!(
            slice_positions(3, None, None, Some(i64::MIN.into())).unwrap(),
            vec![2]
        );
        assert!(slice_positions(3, None, None, Some(0.into())).is_err());
        let huge = BigInt::from(10).pow(40);
        assert_eq!(
            slice_positions(3, None, None, Some(huge.clone())).unwrap(),
            vec![0]
        );
        assert_eq!(
            slice_positions(3, None, None, Some(-huge)).unwrap(),
            vec![2]
        );
    }

    #[test]
    fn text_slices_select_characters_not_bytes() {
        let text = |lower: Option<i64>, upper: Option<i64>, step: Option<i64>| {
            slice_text(
                "aé😀b",
                lower.map(Into::into),
                upper.map(Into::into),
                step.map(Into::into),
            )
            .unwrap()
        };
        assert_eq!(text(Some(1), None, None), "é😀b");
        assert_eq!(text(None, Some(-1), None), "aé😀");
        assert_eq!(text(None, None, Some(-1)), "b😀éa");
        assert_eq!(text(None, None, Some(2)), "a😀");
        assert_eq!(text(Some(3), Some(1), None), "");
        assert_eq!(text(Some(-2), None, Some(-2)), "😀a");
    }

    #[test]
    fn payload_comparisons_count_the_shorter_text_or_binary_payload() {
        let text = |length| VmValue::String("a".repeat(length));
        let bytes = |length| VmValue::Bytes(vec![0; length]);
        assert_eq!(payload_comparison_units(&text(1280), &text(256)), 2);
        assert_eq!(
            payload_comparison_units(&bytes(1280), &VmValue::ByteArray(vec![0; 1280])),
            10
        );
        assert_eq!(payload_comparison_units(&text(1280), &bytes(1280)), 0);
        assert_eq!(payload_comparison_units(&text(1280), &vm_int(1)), 0);
    }

    #[test]
    fn membership_searches_text_and_bytes_linearly() {
        let haystack = VmValue::Bytes([vec![b'a'; 4096], b"ab".to_vec()].concat());
        assert!(contains_value(&haystack, &VmValue::Bytes(b"aab".to_vec())).unwrap());
        assert!(contains_value(&haystack, &VmValue::Bytes(vec![])).unwrap());
        assert!(!contains_value(&haystack, &VmValue::Bytes(b"ba".to_vec())).unwrap());
        assert!(contains_value(&haystack, &vm_int(98)).unwrap());
        assert!(contains_value(&haystack, &VmValue::String("a".into())).is_err());
        let text = VmValue::String("xyz".into());
        assert!(contains_value(&text, &VmValue::String("yz".into())).unwrap());
        assert!(contains_value(&text, &vm_int(1)).is_err());
    }
}

/// Shuffle positions through the host so nested objects keep their identities.
pub(super) fn shuffle_shared(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    host: &mut dyn VmHost,
) -> Result<VmValue, VmExecutionError> {
    let reference = shuffle_receiver(args, kwargs)?;
    let original = reference.value();
    let items = shuffle_items(&original)?;
    let indexes = VmValue::List((0..items.len()).map(vm_int).collect());
    let order = iterate_value(&host.handle_syscall("random.shuffle", vec![indexes], vec![])?)?;
    let shuffled = order
        .iter()
        .map(|index| shuffled_item(&items, index))
        .collect::<Result<Vec<_>, _>>()?;
    reference.replace(repacked(&original, shuffled)?)?;
    Ok(VmValue::None)
}

/// The shuffled items as a sequence of the original's type.
fn repacked(original: &VmValue, items: Vec<VmValue>) -> Result<VmValue, VmExecutionError> {
    Ok(match original {
        VmValue::ByteArray(_) => VmValue::ByteArray(
            items
                .iter()
                .map(byte_from_value)
                .collect::<Result<_, _>>()?,
        ),
        _ => VmValue::List(items),
    })
}

fn shuffle_receiver<'a>(
    args: &'a [VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<&'a crate::VmReference, VmExecutionError> {
    match (args, kwargs.is_empty()) {
        ([VmValue::Reference(reference)], true) => Ok(reference),
        ([_], true) => Err(not_shufflable()),
        _ => Err(VmExecutionError::new(
            "random.shuffle() expects one argument",
        )),
    }
}

/// The items whose positions the host shuffles.
fn shuffle_items(sequence: &VmValue) -> Result<Vec<VmValue>, VmExecutionError> {
    match sequence {
        VmValue::List(values) => Ok(values.clone()),
        // One integer per byte, as a list's copy holds one per item.
        VmValue::ByteArray(bytes) => {
            crate::work_meter::count(bytes.len() as u64)?;
            Ok(bytes.iter().map(|byte| vm_int(*byte)).collect())
        }
        _ => Err(not_shufflable()),
    }
}

fn shuffled_item(items: &[VmValue], index: &VmValue) -> Result<VmValue, VmExecutionError> {
    let invalid = || VmExecutionError::new("invalid shuffle index");
    let index = index.as_bigint()?.to_usize().ok_or_else(invalid)?;
    items.get(index).cloned().ok_or_else(invalid)
}

fn not_shufflable() -> VmExecutionError {
    VmExecutionError::new("random.shuffle() requires a mutable sequence")
}

/// Ask the deterministic host to select positions, keeping selected objects shared.
pub(super) fn random_selection_shared(
    syscall: &str,
    mut args: Vec<VmValue>,
    mut kwargs: Vec<(String, VmValue)>,
    host: &mut dyn VmHost,
) -> Result<VmValue, VmExecutionError> {
    if let Some(cost) = explicit_syscall_metering_cost(syscall, &args, &kwargs)? {
        host.charge_execution_cost(cost)?;
    }
    let values = replace_random_population(&mut args, &mut kwargs);
    let args = args
        .iter()
        .map(VmValue::detached)
        .collect::<Result<Vec<_>, _>>()?;
    let kwargs = kwargs
        .into_iter()
        .map(|(key, value)| Ok((key, value.detached()?)))
        .collect::<Result<Vec<_>, VmExecutionError>>()?;
    super::random_bounds::check(syscall, &args, &kwargs)?;
    let selected = host.handle_syscall(syscall, args, kwargs)?;
    let Some(values) = values else {
        return Ok(selected);
    };
    if syscall == "random.choices" {
        return Ok(VmValue::List(
            iterate_value(&selected)?
                .iter()
                .map(|index| selected_object(&values, index))
                .collect::<Result<_, _>>()?,
        ));
    }
    selected_object(&values, &selected)
}

fn replace_random_population(
    args: &mut [VmValue],
    kwargs: &mut [(String, VmValue)],
) -> Option<Vec<VmValue>> {
    let source = args.first_mut().or_else(|| {
        kwargs
            .iter_mut()
            .find(|(key, _)| key == "items")
            .map(|(_, value)| value)
    })?;
    let values = match source.snapshot() {
        VmValue::List(values) | VmValue::Tuple(values) => values,
        _ => return None,
    };
    *source = VmValue::List((0..values.len()).map(vm_int).collect());
    Some(values)
}

fn selected_object(values: &[VmValue], index: &VmValue) -> Result<VmValue, VmExecutionError> {
    let index = index
        .as_bigint()?
        .to_usize()
        .ok_or_else(|| VmExecutionError::new("invalid random selection index"))?;
    values
        .get(index)
        .cloned()
        .ok_or_else(|| VmExecutionError::new("invalid random selection index"))
}

#[cfg(test)]
mod storage_key_tests {
    use super::*;

    #[derive(Default)]
    struct WriteLog(Vec<String>);

    impl VmHost for WriteLog {
        fn record_storage_write(
            &mut self,
            key: &str,
            _value: &VmValue,
        ) -> Result<(), VmExecutionError> {
            self.0.push(key.to_owned());
            Ok(())
        }
    }

    fn text(len: usize) -> VmValue {
        VmValue::String("k".repeat(len))
    }

    #[test]
    fn hash_keys_are_bounded_by_the_storage_key_limit() {
        assert!(normalize_hash_key(&text(511)).is_ok());
        let error = normalize_hash_key(&text(512)).unwrap_err();
        assert_eq!(error.to_string(), "Key is too long (512). Max is 511.");
    }

    #[test]
    fn v2_fails_a_write_whose_key_the_store_cannot_hold_before_the_host_sees_it() {
        let largest = "k".repeat(crate::committed_store::MAX_STORAGE_KEY_BYTES);
        let over = format!("{largest}k");
        let mut host = WriteLog::default();
        record_storage_write(&mut host, &largest, &VmValue::None).unwrap();
        let error = record_storage_write(&mut host, &over, &VmValue::None).unwrap_err();
        assert_eq!(
            error.to_string(),
            "Storage key is too long (512 bytes). Max is 511."
        );
        assert_eq!(host.0, vec![largest]);
    }
}

#[cfg(test)]
mod zk_metering_tests {
    use super::*;

    fn text(value: &str) -> VmValue {
        VmValue::String(value.to_owned())
    }

    fn request(entries: Vec<(&str, VmValue)>) -> VmValue {
        VmValue::Dict(
            entries
                .into_iter()
                .map(|(key, value)| (text(key), value))
                .collect(),
        )
    }

    fn warm_cost(requests: Vec<VmValue>) -> u64 {
        let args = [VmValue::List(requests)];
        explicit_syscall_metering_cost("zk.warm_verified_proofs", &args, &[])
            .unwrap()
            .unwrap()
    }

    #[test]
    fn each_warmed_proof_costs_what_verify_groth16_charges() {
        let field = format!("0x{}", "01".repeat(32));
        let inputs = VmValue::List(vec![text(&field), text(&field)]);
        let full = request(vec![
            ("vk_id", text("demo")),
            ("proof_hex", text("0xabcd")),
            ("public_inputs", inputs.clone()),
        ]);
        let verify_args = [text("demo"), text("0xabcd"), inputs];
        let verify = explicit_syscall_metering_cost("zk.verify_groth16", &verify_args, &[])
            .unwrap()
            .unwrap();
        // 750 chi, 50 per input and 25 raw per byte of id, proof and inputs.
        assert_eq!(verify, 750_000 + 2 * 50_000 + (4 + 2 + 2 * 32) * 25);
        assert_eq!(warm_cost(vec![full.clone()]), verify);
        assert_eq!(warm_cost(vec![full.clone(), full]), 2 * verify);
        // A request the host refuses still pays the verification base
        // before the refusal; fields that are not text count as empty.
        let base = 750_000;
        assert_eq!(warm_cost(vec![text("x")]), base);
        let odd = request(vec![
            ("vk_id", VmValue::Int(5.into())),
            ("public_inputs", VmValue::List(vec![VmValue::None])),
        ]);
        assert_eq!(warm_cost(vec![odd]), base + 50_000);
        assert_eq!(warm_cost(vec![]), 0);
        // Hex that is not 0x-prefixed or not whole bytes counts no bytes.
        let unpriced = request(vec![("proof_hex", text("0xabc")), ("vk_id", text(""))]);
        assert_eq!(warm_cost(vec![unpriced]), base);
        let raw_args = [
            text("0x1234"),
            text("abcd"),
            VmValue::List(vec![text(&field)]),
        ];
        let raw = explicit_syscall_metering_cost("zk.verify_groth16_bn254", &raw_args, &[]);
        assert_eq!(raw.unwrap(), Some(750_000 + 50_000 + (2 + 32) * 50));
        let not_a_list = [text("requests")];
        let refused = explicit_syscall_metering_cost("zk.warm_verified_proofs", &not_a_list, &[]);
        assert_eq!(refused.unwrap(), Some(0));
        assert!(explicit_syscall_metering_cost("zk.warm_verified_proofs", &[], &[]).is_err());
    }

    #[test]
    fn the_other_zk_charges_follow_their_arguments() {
        let cost = |id: &str, args: &[VmValue]| explicit_syscall_metering_cost(id, args, &[]);
        let fields = |n: usize| VmValue::List(vec![text("0x01"); n]);
        let append = [VmValue::Int(0.into()), fields(1), fields(3)];
        assert_eq!(
            cost("zk.shielded_note_append_commitments", &append).unwrap(),
            Some(1_750_000)
        );
        let digest = [fields(2)];
        assert_eq!(
            cost("zk.shielded_command_nullifier_digest", &digest).unwrap(),
            Some(200_000)
        );
        assert_eq!(
            cost("zk.shielded_output_payload_hash", &[text("0xabcd")]).unwrap(),
            Some(2)
        );
        assert_eq!(
            cost("zk.shielded_output_payload_hash", &[text("")]).unwrap(),
            Some(0)
        );
        assert_eq!(
            cost("zk.shielded_command_binding", &[]).unwrap(),
            Some(100_000)
        );
        assert_eq!(
            cost("zk.shielded_command_execution_tag", &[]).unwrap(),
            Some(50_000)
        );
        assert_eq!(cost("zk.is_available", &[]).unwrap(), None);
        let three = cost("zk.verify_groth16", &[text("a")]).unwrap_err();
        assert_eq!(
            three.to_string(),
            "zk.verify_groth16() expects three positional arguments"
        );
        let one = cost("zk.shielded_output_payload_hash", &[]).unwrap_err();
        assert_eq!(
            one.to_string(),
            "zk.shielded_output_payload_hash() expects one positional argument"
        );
        let keyword = [("payload_hex".to_owned(), text("0x"))];
        let by_name = explicit_syscall_metering_cost(
            "zk.shielded_output_payload_hash",
            &[text("0x")],
            &keyword,
        );
        assert!(by_name.is_err());
        assert!(cost("zk.shielded_command_nullifier_digest", &[text("x")]).is_err());
    }
}
