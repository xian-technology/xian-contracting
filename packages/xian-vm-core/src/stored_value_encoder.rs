//! Writer for V2 stored values: the exact bytes Python's
//! `xian_runtime_types.encoding.encode` produces for the value the host
//! stores, so a write made in Rust is byte-identical to one made in Python.
//!
//! The format is compact JSON (`separators=(",", ":")`, `ensure_ascii`):
//! integers beyond 2^53-1 and exact decimals, times, durations, bytes and sets
//! are tagged objects, dictionaries keep their order and must have string keys
//! that are not codec tags. A value Python refuses to store is refused here.
use crate::set_member_codec::{encode_set_value, is_reserved_tag};
use crate::{VmExecutionError, VmValue};
use num_bigint::BigInt;
use serde_json::Value;
use std::fmt::Write as _;

type Result<T> = std::result::Result<T, VmExecutionError>;

const SAFE_INTEGER_BITS: u64 = 53;
const MAX_INTEGER_BITS: u64 = 512;
/// Python's persistent value traversal limits.
const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 1024 * 1024;

fn refused(reason: impl Into<String>) -> VmExecutionError {
    VmExecutionError::new(format!("value cannot be stored: {}", reason.into()))
}

/// The stored-value bytes of `value`.
pub(crate) fn encode_stored_value(value: &VmValue) -> Result<Vec<u8>> {
    let mut writer = Writer::default();
    writer.value(value, 0)?;
    Ok(writer.out.into_bytes())
}

#[derive(Default)]
struct Writer {
    out: String,
    nodes: usize,
}

impl Writer {
    fn visit(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > MAX_DEPTH || self.nodes > MAX_NODES {
            return Err(refused("persistent value traversal limit exceeded"));
        }
        Ok(())
    }

    fn value(&mut self, value: &VmValue, depth: usize) -> Result<()> {
        if let VmValue::Reference(_) = value {
            return self.value(&value.detached()?, depth);
        }
        self.visit(depth)?;
        match value {
            VmValue::List(items) | VmValue::Tuple(items) => self.list(items, depth),
            VmValue::DecimalTuple(tuple) => self.list(&tuple.as_values(), depth),
            VmValue::Dict(entries) => self.dict(entries, depth),
            other => self.scalar(other),
        }
    }

    fn scalar(&mut self, value: &VmValue) -> Result<()> {
        match value {
            VmValue::None => self.out.push_str("null"),
            VmValue::Bool(true) => self.out.push_str("true"),
            VmValue::Bool(false) => self.out.push_str("false"),
            VmValue::Int(number) => self.integer(number)?,
            VmValue::String(text) => write_string(&mut self.out, text),
            other => self.tagged(other)?,
        }
        Ok(())
    }

    fn integer(&mut self, number: &BigInt) -> Result<()> {
        let bits = number.bits();
        if bits > MAX_INTEGER_BITS {
            return Err(refused("integer exceeds 512 bits"));
        }
        if bits <= SAFE_INTEGER_BITS {
            let _ = write!(self.out, "{number}");
        } else {
            self.out.push_str("{\"__big_int__\":\"");
            let _ = write!(self.out, "{number}");
            self.out.push_str("\"}");
        }
        Ok(())
    }

    fn list(&mut self, items: &[VmValue], depth: usize) -> Result<()> {
        self.out.push('[');
        for (index, item) in items.iter().enumerate() {
            if index > 0 {
                self.out.push(',');
            }
            self.value(item, depth + 1)?;
        }
        self.out.push(']');
        Ok(())
    }

    fn dict(&mut self, entries: &[(VmValue, VmValue)], depth: usize) -> Result<()> {
        self.out.push('{');
        for (index, (key, item)) in entries.iter().enumerate() {
            let key = key.snapshot();
            let VmValue::String(key) = &key else {
                return Err(refused("wire JSON object keys must be strings"));
            };
            if is_reserved_tag(key) {
                return Err(refused(format!(
                    "reserved runtime codec dictionary key: {key}"
                )));
            }
            self.visit(depth + 1)?;
            if index > 0 {
                self.out.push(',');
            }
            write_string(&mut self.out, key);
            self.out.push(':');
            self.value(item, depth + 1)?;
        }
        self.out.push('}');
        Ok(())
    }

    /// Values Python stores as a one-key codec object.
    fn tagged(&mut self, value: &VmValue) -> Result<()> {
        match value {
            VmValue::Decimal(decimal) => self.tag_text("__fixed__", &decimal.to_string()),
            VmValue::RawDecimal(raw) => self.tag_text("__fixed__", &raw.to_fixed()?.to_string()),
            VmValue::Bytes(bytes) => self.tag_text("__bytes__", &hex::encode(bytes)),
            VmValue::ByteArray(bytes) => self.tag_text("__bytearray__", &hex::encode(bytes)),
            VmValue::DateTime(time) => self.tag_integers(
                "__time__",
                &[
                    time.year(),
                    time.month(),
                    time.day(),
                    time.hour(),
                    time.minute(),
                    time.second(),
                    time.microsecond(),
                ],
            ),
            VmValue::TimeDelta(delta) => {
                let seconds = delta.seconds();
                self.tag_integers(
                    "__delta__",
                    &[seconds.div_euclid(86_400), seconds.rem_euclid(86_400)],
                )
            }
            VmValue::Set(_) | VmValue::FrozenSet(_) => {
                write_json(&mut self.out, &encode_set_value(value)?);
            }
            VmValue::Float(_) => return Err(refused("binary float is not a contract number")),
            other => {
                return Err(refused(format!(
                    "unsupported storage value '{}'",
                    other.type_name()
                )))
            }
        }
        Ok(())
    }

    fn tag_text(&mut self, tag: &str, text: &str) {
        self.out.push_str("{\"");
        self.out.push_str(tag);
        self.out.push_str("\":");
        write_string(&mut self.out, text);
        self.out.push('}');
    }

    fn tag_integers(&mut self, tag: &str, numbers: &[i64]) {
        self.out.push_str("{\"");
        self.out.push_str(tag);
        self.out.push_str("\":[");
        for (index, number) in numbers.iter().enumerate() {
            if index > 0 {
                self.out.push(',');
            }
            let _ = write!(self.out, "{number}");
        }
        self.out.push_str("]}");
    }
}

/// A JSON string as Python's `json.dumps` writes it with `ensure_ascii`:
/// printable ASCII as is, the short escapes, everything else as lower-case
/// `\uXXXX` (UTF-16 surrogate pairs above the BMP).
fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(character),
            other => {
                let mut units = [0u16; 2];
                for unit in other.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// The set codec's JSON envelope, written like the rest of the value.
fn write_json(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => {
            let _ = write!(out, "{number}");
        }
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json(out, item);
            }
            out.push(']');
        }
        Value::Object(entries) => {
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_json(out, item);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stored_value::decode_stored_value;

    fn encoded(value: VmValue) -> String {
        String::from_utf8(encode_stored_value(&value).unwrap()).unwrap()
    }

    #[test]
    fn strings_are_escaped_like_python_ensure_ascii() {
        let text = "a\"\\\n\r\t\u{8}\u{c}\u{1}\u{7f}é€😀~ ";
        assert_eq!(
            encoded(VmValue::String(text.into())),
            r#""a\"\\\n\r\t\b\f\u0001\u007f\u00e9\u20ac\ud83d\ude00~ ""#
        );
    }

    #[test]
    fn integers_past_two_to_the_53_are_tagged() {
        let safe = BigInt::from((1i64 << 53) - 1);
        assert_eq!(encoded(VmValue::Int(safe.clone())), "9007199254740991");
        assert_eq!(encoded(VmValue::Int(-safe)), "-9007199254740991");
        assert_eq!(
            encoded(VmValue::Int(BigInt::from(1i64 << 53))),
            r#"{"__big_int__":"9007199254740992"}"#
        );
        let too_big = BigInt::from(1) << 512;
        assert!(encode_stored_value(&VmValue::Int(too_big)).is_err());
    }

    #[test]
    fn dictionaries_keep_order_and_refuse_non_text_or_tag_keys() {
        let entries = vec![
            (VmValue::String("z".into()), VmValue::Int(1.into())),
            (VmValue::String("a".into()), VmValue::None),
        ];
        assert_eq!(encoded(VmValue::Dict(entries)), r#"{"z":1,"a":null}"#);
        for key in [VmValue::Int(1.into()), VmValue::String("__fixed__".into())] {
            assert!(encode_stored_value(&VmValue::Dict(vec![(key, VmValue::None)])).is_err());
        }
    }

    #[test]
    fn floats_and_runtime_objects_are_refused() {
        assert!(encode_stored_value(&VmValue::Float(1.5)).is_err());
        assert!(encode_stored_value(&VmValue::Builtin("len".into())).is_err());
    }

    #[test]
    fn nesting_beyond_python_depth_limit_is_refused() {
        let mut value = VmValue::List(vec![]);
        for _ in 0..MAX_DEPTH {
            value = VmValue::List(vec![value]);
        }
        assert!(encode_stored_value(&value).is_ok());
        assert!(encode_stored_value(&VmValue::List(vec![value])).is_err());
    }

    #[test]
    fn decoding_the_encoding_round_trips_tagged_values() {
        for text in [
            r#"{"__fixed__":"1.5"}"#,
            r#"{"__time__":[2026,1,2,3,4,5,6]}"#,
            r#"{"__delta__":[-1,86399]}"#,
            r#"{"__bytes__":"00ff"}"#,
            r#"{"__bytearray__":"ab"}"#,
            r#"[1,"x",{"k":[true,false,null]}]"#,
        ] {
            let value = decode_stored_value(text.as_bytes()).unwrap();
            assert_eq!(encoded(value), text);
        }
    }
}
