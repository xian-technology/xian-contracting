//! Lossless xian-set-1 member grammar. Ordinary value encodings are unchanged.
use crate::{VmExecutionError, VmValue};
use num_traits::Signed;
use serde_json::{json, Value};

type Result<T> = std::result::Result<T, VmExecutionError>;
pub(crate) const CODEC: &str = "xian-set-1";
pub(crate) const MAX_DEPTH: usize = 64;
pub(crate) const MAX_NODES: usize = 131072;
pub(crate) const MAX_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_NORMALIZATION_WORK: usize = 8388608;
const MAX_RAW: usize = 131072;

pub(crate) fn is_reserved_tag(name: &str) -> bool {
    matches!(
        name,
        "__fixed__"
            | "__delta__"
            | "__frozenset__"
            | "__bytes__"
            | "__bytearray__"
            | "__set__"
            | "__time__"
            | "__big_int__"
    )
}

fn limit() -> VmExecutionError {
    VmExecutionError::new("set codec resource limit exceeded")
}
#[derive(Default)]
struct Budget {
    bytes: usize,
    nodes: usize,
    normalization_work: usize,
}
impl Budget {
    fn add(&mut self, size: usize) -> Result<()> {
        self.bytes = self.bytes.checked_add(size).ok_or_else(limit)?;
        if self.bytes > MAX_BYTES {
            return Err(limit());
        }
        Ok(())
    }
    fn visit(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return Err(limit());
        }
        Ok(())
    }
    fn normalize(&mut self, count: usize) -> Result<()> {
        self.normalization_work = self
            .normalization_work
            .saturating_add(count.saturating_mul(count));
        if self.normalization_work > MAX_NORMALIZATION_WORK {
            return Err(VmExecutionError::new(
                "set codec normalization work limit exceeded",
            ));
        }
        Ok(())
    }
    fn scalar(&mut self, value: Value) -> Result<Value> {
        self.add(json_size(&value)?)?;
        Ok(value)
    }
    fn text(&mut self, tag: &str, text: &str) -> Result<Value> {
        self.add(3 + string_size(tag)? + string_size(text)?)?;
        Ok(json!([tag, text]))
    }
    fn children(&mut self, tag: &str, values: &[VmValue], depth: usize) -> Result<Value> {
        if values.len() > MAX_NODES {
            return Err(limit());
        }
        self.add(5 + string_size(tag)? + values.len().saturating_sub(1))?;
        if tag == "frozenset" {
            self.normalize(values.len())?;
        }
        let members = values
            .iter()
            .map(|value| self.member(value, depth + 1))
            .collect::<Result<Vec<_>>>()?;
        Ok(json!([tag, members]))
    }
    fn member(&mut self, value: &VmValue, depth: usize) -> Result<Value> {
        if let VmValue::Reference(reference) = value {
            return reference.with_value(|value| self.member(value, depth));
        }
        self.visit(depth)?;
        match value {
            VmValue::None => self.scalar(json!(["none"])),
            VmValue::Bool(value) => self.scalar(json!(["bool", value])),
            VmValue::Int(value) => {
                if value.bits() > crate::interpreter::MAX_INTEGER_BITS {
                    return Err(limit());
                }
                self.text("int", &value.to_string())
            }
            VmValue::Float(value) if value.is_finite() => {
                self.text("float", &format!("{:016x}", value.to_bits()))
            }
            VmValue::Float(_) => Err(VmExecutionError::new(
                "set codec requires finite numeric members",
            )),
            VmValue::Decimal(value) => self.text("fixed", &value.scaled.to_string()),
            VmValue::RawDecimal(value) => {
                if !value.is_finite() {
                    return Err(VmExecutionError::new(
                        "set codec requires finite numeric members",
                    ));
                }
                if value.exponent.unsigned_abs() as usize > MAX_RAW
                    || value.coefficient.bits() > crate::interpreter::MAX_INTEGER_BITS
                {
                    return Err(limit());
                }
                if value.to_string().len() > MAX_RAW {
                    return Err(VmExecutionError::new(
                        "set codec raw decimal text limit exceeded",
                    ));
                }
                let digits = value.coefficient.abs().to_str_radix(10);
                if digits.len() > MAX_RAW {
                    return Err(limit());
                }
                self.scalar(json!([
                    "raw_decimal",
                    u8::from(value.is_negative()),
                    digits,
                    value.exponent
                ]))
            }
            VmValue::String(value) => self.text("str", value),
            VmValue::Bytes(value) => {
                if value.len() > MAX_BYTES / 2 {
                    return Err(limit());
                }
                self.text("bytes", &hex::encode(value))
            }
            VmValue::DateTime(value) => self.scalar(json!([
                "datetime",
                [
                    value.year(),
                    value.month(),
                    value.day(),
                    value.hour(),
                    value.minute(),
                    value.second(),
                    value.microsecond()
                ]
            ])),
            VmValue::TimeDelta(value) => self.text("timedelta", &value.seconds().to_string()),
            VmValue::Tuple(values) => self.children("tuple", values, depth),
            VmValue::FrozenSet(values) => self.children("frozenset", values, depth),
            other => Err(VmExecutionError::new(format!(
                "unsupported set member: {}",
                other.type_name()
            ))),
        }
    }
}

fn string_size(value: &str) -> Result<usize> {
    let mut size: usize = 2;
    for character in value.chars() {
        size = size
            .checked_add(match character {
                '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
                '\u{0}'..='\u{1f}' => 6,
                other if other.is_ascii() => 1,
                other if (other as u32) <= 0xffff => 6,
                _ => 12,
            })
            .ok_or_else(limit)?;
        if size > MAX_BYTES {
            return Err(limit());
        }
    }
    Ok(size)
}
fn json_size(value: &Value) -> Result<usize> {
    Ok(match value {
        Value::String(value) => string_size(value)?,
        Value::Array(values) => values.iter().try_fold(
            2 + values.len().saturating_sub(1),
            |size, value| -> Result<usize> {
                size.checked_add(json_size(value)?).ok_or_else(limit)
            },
        )?,
        other => other.to_string().len(),
    })
}

pub(crate) fn encode_set_value(value: &VmValue) -> Result<Value> {
    if let VmValue::Reference(reference) = value {
        return reference.with_value(encode_set_value);
    }
    let (tag, members) = match value {
        VmValue::Set(values) => ("__set__", values),
        VmValue::FrozenSet(values) => ("__frozenset__", values),
        _ => return Err(VmExecutionError::new("expected deterministic wrapper set")),
    };
    if members.len() > MAX_NODES {
        return Err(limit());
    }
    let mut budget = Budget::default();
    budget.normalize(members.len())?;
    budget.add(
        json!({tag: {"codec": CODEC, "items": []}})
            .to_string()
            .len()
            + members.len().saturating_sub(1),
    )?;
    let items = members
        .iter()
        .map(|value| budget.member(value, 1))
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({tag: {"codec": CODEC, "items": items}}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VmDecimal, VmRawDecimal};
    #[test]
    fn typed_members_preserve_float_bits_raw_quantum_and_fixed_scale() {
        let value = VmValue::Set(vec![
            VmValue::Float(-0.0),
            VmValue::RawDecimal(VmRawDecimal::parse("1.2300").unwrap()),
            VmValue::Decimal(VmDecimal::from_vm_value(&VmValue::String("1.25".into())).unwrap()),
        ]);
        assert_eq!(
            encode_set_value(&value).unwrap(),
            json!({"__set__":{"codec":"xian-set-1","items":[["float","8000000000000000"],["raw_decimal",0,"12300",-4],["fixed","1250000000000000000000000000000"]]}})
        );
    }
    #[test]
    fn tuple_and_frozen_set_nodes_stay_hashable_and_typed() {
        let value = VmValue::FrozenSet(vec![VmValue::Tuple(vec![
            VmValue::Int(1.into()),
            VmValue::FrozenSet(vec![VmValue::String("雪".into())]),
        ])]);
        assert_eq!(
            encode_set_value(&value).unwrap(),
            json!({"__frozenset__":{"codec":"xian-set-1","items":[["tuple",[["int","1"],["frozenset",[["str","雪"]]]]]]}})
        );
    }
    #[test]
    fn resource_and_finiteness_limits_are_independent_of_metering() {
        assert!(encode_set_value(&VmValue::Set(vec![VmValue::Float(f64::NAN)])).is_err());
        assert!(encode_set_value(&VmValue::Set(vec![VmValue::Int(1.into()); 2897])).is_err());
        let mut member = VmValue::None;
        for _ in 0..63 {
            member = VmValue::Tuple(vec![member]);
        }
        assert!(encode_set_value(&VmValue::Set(vec![member.clone()])).is_ok());
        assert!(encode_set_value(&VmValue::Set(vec![VmValue::Tuple(vec![member])])).is_err());
        assert!(
            encode_set_value(&VmValue::Set(vec![VmValue::String("x".repeat(MAX_BYTES))])).is_err()
        );
    }
}

#[cfg(test)]
mod shared_wire_tests {
    use super::*;
    use crate::{VmDateTime, VmDecimal, VmRawDecimal, VmTimeDelta};
    use num_bigint::BigInt;

    #[test]
    fn matches_python_shared_structural_goldens() {
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/set_member_codec.json"
        ))
        .unwrap();
        for case in fixtures.as_array().unwrap() {
            let name = case["id"].as_str().unwrap();
            let member = match name {
                "none" => VmValue::None,
                "bool" => VmValue::Bool(true),
                "int" => VmValue::Int(BigInt::from(1) << 90usize),
                "negative_zero" => VmValue::Float(-0.0),
                "fixed" => VmValue::Decimal(
                    VmDecimal::from_vm_value(&VmValue::String("1.25".into())).unwrap(),
                ),
                "raw" => VmValue::RawDecimal(VmRawDecimal::parse("1.2300").unwrap()),
                "raw_negative_zero" => VmValue::RawDecimal(VmRawDecimal::parse("-0.00").unwrap()),
                "unicode" => VmValue::String("雪😀\n".into()),
                "bytes" => VmValue::Bytes(vec![0, 255]),
                "datetime" => {
                    VmValue::DateTime(VmDateTime::new(2026, 1, 2, 3, 4, 5, 123456).unwrap())
                }
                "timedelta" => VmValue::TimeDelta(VmTimeDelta::from_raw_seconds(-90001).unwrap()),
                "tuple" => VmValue::Tuple(vec![
                    VmValue::Int(1.into()),
                    VmValue::String("a".into()),
                    VmValue::RawDecimal(VmRawDecimal::parse("2.00").unwrap()),
                ]),
                "nested_frozen" => VmValue::FrozenSet(vec![VmValue::Tuple(vec![
                    VmValue::Int(1.into()),
                    VmValue::Int(2.into()),
                ])]),
                "empty_set" | "empty_frozen" => VmValue::None,
                _ => panic!("unknown golden {name}"),
            };
            let value = match name {
                "empty_set" => VmValue::Set(vec![]),
                "empty_frozen" => VmValue::FrozenSet(vec![]),
                _ => VmValue::Set(vec![member]),
            };
            assert_eq!(encode_set_value(&value).unwrap(), case["wire"], "{name}");
        }
    }

    #[test]
    fn ascii_cap_accounts_for_astral_pairs_and_exact_limit() {
        assert_eq!(string_size("😀").unwrap(), 14);
        assert_eq!(string_size("\n\u{1}").unwrap(), 10);
        let mut budget = Budget::default();
        budget.add(MAX_BYTES).unwrap();
        assert!(budget.add(1).is_err());
        let mut budget = Budget::default();
        budget.normalization_work = MAX_NORMALIZATION_WORK - 9;
        budget.normalize(3).unwrap();
        assert!(budget.normalize(1).is_err());
    }
    #[test]
    fn raw_text_limit_covers_sign_and_quantum_overhead() {
        let mut raw = VmRawDecimal::parse(&"9".repeat(MAX_RAW)).unwrap();
        assert!(encode_set_value(&VmValue::Set(vec![VmValue::RawDecimal(raw.clone())])).is_ok());
        raw.coefficient = -raw.coefficient;
        assert!(encode_set_value(&VmValue::Set(vec![VmValue::RawDecimal(raw.clone())])).is_err());
        raw.coefficient = -raw.coefficient;
        raw.exponent = -1;
        assert!(encode_set_value(&VmValue::Set(vec![VmValue::RawDecimal(raw)])).is_err());
    }
}

/// Whole-persistence-payload guard. Count every serialized occurrence, including
/// aliases, while borrowing heap values and bounding the traversal itself.
pub(crate) fn validate_set_normalization_work(value: &VmValue) -> Result<()> {
    #[derive(Default)]
    struct Walker {
        work: usize,
        visited: usize,
        active: std::collections::HashSet<usize>,
    }
    impl Walker {
        fn visit(&mut self, value: &VmValue, depth: usize) -> Result<()> {
            self.visited += 1;
            if depth > 128 || self.visited > 1024 * 1024 {
                return Err(limit());
            }
            if let VmValue::Reference(reference) = value {
                let id = reference.id();
                if !self.active.insert(id) {
                    return Err(VmExecutionError::new("cyclic persistent value"));
                }
                let result = reference.with_value(|value| self.visit(value, depth + 1));
                self.active.remove(&id);
                return result;
            }
            match value {
                VmValue::Set(items) | VmValue::FrozenSet(items) => {
                    self.work = self
                        .work
                        .saturating_add(items.len().saturating_mul(items.len()));
                    if self.work > MAX_NORMALIZATION_WORK {
                        return Err(VmExecutionError::new(
                            "set codec aggregate normalization work limit exceeded",
                        ));
                    }
                    self.items(items, depth)
                }
                VmValue::List(items) | VmValue::Tuple(items) => self.items(items, depth),
                VmValue::Dict(items) => {
                    for (key, value) in items {
                        self.visit(key, depth + 1)?;
                        self.visit(value, depth + 1)?;
                    }
                    Ok(())
                }
                _ => Ok(()),
            }
        }
        fn items(&mut self, items: &[VmValue], depth: usize) -> Result<()> {
            for item in items {
                self.visit(item, depth + 1)?;
            }
            Ok(())
        }
    }
    Walker::default().visit(value, 0)
}

#[cfg(test)]
mod aggregate_tests {
    use super::*;
    #[test]
    fn many_roots_cannot_each_spend_the_full_normalization_budget() {
        let members = (0..2896)
            .map(|i| VmValue::Int(i.into()))
            .collect::<Vec<_>>();
        let set = VmValue::Set(members);
        assert!(validate_set_normalization_work(&set).is_ok());
        assert!(validate_set_normalization_work(&VmValue::List(vec![set.clone(), set])).is_err());
        assert!(validate_set_normalization_work(&VmValue::List(vec![
            VmValue::Int(1.into());
            MAX_NODES
        ]))
        .is_ok());
    }
}
