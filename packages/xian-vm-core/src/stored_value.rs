//! Strict reader for V2 stored values.
//!
//! Committed state holds the bytes `xian_runtime_types.encoding.encode(value,
//! vm_profile="xian_vm_v2")` wrote. Reading them in Python means
//! `decode(data)` (strict JSON, then `decode_wire_numbers`) followed by the VM
//! boundary conversion (`py_to_vm`). This module does both in one pass and
//! yields the same `VmValue`, or rejects the same inputs:
//!
//! - UTF-8, then JSON as Python's `json.loads` reads it (whitespace, string
//!   escapes, surrogate pairs, duplicate keys: the last value wins at the first
//!   position), except that fractions, exponents, `NaN`/`Infinity`, `-0`,
//!   integers beyond 2**53 - 1 and more than 16 digits are rejected;
//! - the traversal limits of `_validate_serializable_value` (depth 128, about
//!   one million nodes; set envelopes are bounded by the set codec instead);
//! - the runtime tags `__fixed__`, `__big_int__`, `__time__`, `__delta__`,
//!   `__bytes__`, `__bytearray__`, `__set__` and `__frozenset__` with their
//!   canonical payload rules, including the `xian-set-1` member grammar, its
//!   budgets and its canonical member order;
//! - strings that are not Unicode scalar text (lone surrogate escapes), which
//!   cannot cross the VM boundary.
//!
//! The encoder never writes anything else, so a rejected value means the store
//! is corrupt; callers treat it as a host fault, never a transaction outcome.
//! Python also accepts a `__delta__` payload spelled as a two-character string
//! or a two-key object (tuple unpacking feeds `int()`); the encoder never
//! writes those, and this reader rejects them.
use crate::interpreter::numeric_v2;
use crate::set_member_codec::{self, is_reserved_tag};
use crate::{VmDateTime, VmDecimal, VmExecutionError, VmTimeDelta, VmValue};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;

type Result<T> = std::result::Result<T, VmExecutionError>;

const SAFE_INTEGER: i64 = (1 << 53) - 1;
/// Deeper JSON is rejected before Python's limits could accept it: plain
/// values stop at depth 128 and set members at 64 (two JSON levels each).
const MAX_PARSE_DEPTH: usize = 512;
const MAX_VALUE_DEPTH: usize = 128;
const MAX_VALUE_NODES: usize = 1024 * 1024;
const MAX_FIXED_TEXT: usize = 93;
const MAX_BIG_INT_TEXT: usize = 156;
const MAX_SET_INTEGER_TEXT: usize = 315_654;
const MAX_SET_INTEGER_BITS: u64 = 1_048_576;

fn corrupt(reason: impl Into<String>) -> VmExecutionError {
    VmExecutionError::new(reason)
}

/// Decode one stored V2 value. Decoding is host work: like the Python reader it is not metered.
pub(crate) fn decode_stored_value(data: &[u8]) -> Result<VmValue> {
    let _scope = numeric_v2::Scope::enter(crate::XIAN_VM_V2_PROFILE);
    let _unmetered = crate::work_meter::Unmetered::enter();
    let text = std::str::from_utf8(data).map_err(|_| corrupt("stored value is not UTF-8"))?;
    let document = Parser::new(text).document()?;
    validate_traversal(&document)?;
    Decoder::default().value(&document)
}

/// A JSON string; `scalar` is false when it holds a lone surrogate escape
/// (kept as U+FFFD), which Python keeps but the VM cannot represent.
#[derive(Debug, Clone, PartialEq)]
struct Text {
    text: String,
    scalar: bool,
}

impl Text {
    fn scalar(&self) -> Result<&str> {
        if self.scalar {
            Ok(&self.text)
        } else {
            Err(corrupt("stored text is not Unicode scalar text"))
        }
    }

    fn chars(&self) -> usize {
        self.text.chars().count()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(Text),
    Array(Vec<Json>),
    Object(Vec<(Text, Json)>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    at: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            text,
            at: 0,
        }
    }

    fn document(mut self) -> Result<Json> {
        if self.text.starts_with('\u{feff}') {
            return Err(corrupt("stored value starts with a byte order mark"));
        }
        self.skip_whitespace();
        let value = self.value(0)?;
        self.skip_whitespace();
        if self.at != self.bytes.len() {
            return Err(corrupt("extra data after the stored value"));
        }
        Ok(value)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<()> {
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(corrupt("malformed stored JSON"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json> {
        if depth > MAX_PARSE_DEPTH {
            return Err(corrupt("stored JSON nesting limit exceeded"));
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Json::Str),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => self.literal(),
        }
    }

    fn literal(&mut self) -> Result<Json> {
        for (word, value) in [
            ("null", Json::Null),
            ("true", Json::Bool(true)),
            ("false", Json::Bool(false)),
        ] {
            if self.bytes[self.at..].starts_with(word.as_bytes()) {
                self.at += word.len();
                return Ok(value);
            }
        }
        Err(corrupt("malformed stored JSON"))
    }

    fn digits(&mut self) -> usize {
        let start = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - start
    }

    /// Python reads `-?(0|[1-9][0-9]*)`; a fraction or exponent makes a float.
    fn number(&mut self) -> Result<Json> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err(corrupt("malformed stored JSON number")),
        }
        if self.float_follows() {
            return Err(corrupt("V2 fractional JSON numbers require __fixed__"));
        }
        safe_integer(&self.text[start..self.at]).map(Json::Int)
    }

    /// A fraction (`.` and a digit) or an exponent (`e`, a sign, a digit).
    fn float_follows(&self) -> bool {
        let digit_at = |index: usize| matches!(self.bytes.get(index), Some(b'0'..=b'9'));
        match self.peek() {
            Some(b'.') => digit_at(self.at + 1),
            Some(b'e' | b'E') => {
                let sign = matches!(self.bytes.get(self.at + 1), Some(b'+' | b'-'));
                digit_at(self.at + 1 + usize::from(sign))
            }
            _ => false,
        }
    }

    fn hex4(&mut self) -> Result<u32> {
        let digits = self
            .bytes
            .get(self.at..self.at + 4)
            .ok_or_else(|| corrupt("invalid \\uXXXX escape"))?;
        let mut value = 0;
        for digit in digits {
            value = value * 16
                + char::from(*digit)
                    .to_digit(16)
                    .ok_or_else(|| corrupt("invalid \\uXXXX escape"))?;
        }
        self.at += 4;
        Ok(value)
    }

    /// `\uXXXX`, joined with a following low surrogate escape as Python does.
    fn unicode_escape(&mut self, out: &mut Text) -> Result<()> {
        let code = self.hex4()?;
        if (0xd800..0xdc00).contains(&code) && self.bytes[self.at..].starts_with(b"\\u") {
            let resume = self.at;
            self.at += 2;
            let low = self.hex4()?;
            if (0xdc00..0xe000).contains(&low) {
                let joined = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                out.text
                    .push(char::from_u32(joined).expect("joined surrogates"));
                return Ok(());
            }
            self.at = resume;
        }
        match char::from_u32(code) {
            Some(character) => out.text.push(character),
            None => {
                out.text.push('\u{fffd}');
                out.scalar = false;
            }
        }
        Ok(())
    }

    fn string(&mut self) -> Result<Text> {
        self.expect(b'"')?;
        let mut out = Text {
            text: String::new(),
            scalar: true,
        };
        loop {
            let start = self.at;
            while matches!(self.peek(), Some(byte) if byte != b'"' && byte != b'\\' && byte >= 0x20)
            {
                self.at += 1;
            }
            out.text.push_str(&self.text[start..self.at]);
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    self.escape(&mut out)?;
                }
                _ => return Err(corrupt("invalid control character or unterminated string")),
            }
        }
    }

    fn escape(&mut self, out: &mut Text) -> Result<()> {
        let escape = self.peek().ok_or_else(|| corrupt("unterminated string"))?;
        self.at += 1;
        let character = match escape {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => return self.unicode_escape(out),
            _ => return Err(corrupt("invalid string escape")),
        };
        out.text.push(character);
        Ok(())
    }

    fn array(&mut self, depth: usize) -> Result<Json> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_whitespace();
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(corrupt("malformed stored JSON array")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json> {
        self.expect(b'{')?;
        let mut entries = ObjectEntries::default();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Object(entries.entries));
        }
        loop {
            self.skip_whitespace();
            let key = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            entries.insert(key, self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Object(entries.entries));
                }
                _ => return Err(corrupt("malformed stored JSON object")),
            }
        }
    }
}

/// Object members as Python's dict keeps them: the first position, the last value.
#[derive(Default)]
struct ObjectEntries {
    entries: Vec<(Text, Json)>,
    positions: HashMap<(String, bool), usize>,
}

impl ObjectEntries {
    fn insert(&mut self, key: Text, value: Json) {
        let identity = (key.text.clone(), key.scalar);
        match self.positions.get(&identity) {
            Some(&index) => self.entries[index].1 = value,
            None => {
                self.positions.insert(identity, self.entries.len());
                self.entries.push((key, value));
            }
        }
    }
}

fn safe_integer(token: &str) -> Result<i64> {
    let unsafe_integer = || corrupt("V2 JSON requires canonical safe integers or __big_int__");
    if token == "-0" || token.trim_start_matches('-').len() > 16 {
        return Err(unsafe_integer());
    }
    let value = i64::from_str(token).map_err(|_| corrupt("malformed stored JSON number"))?;
    if value.abs() > SAFE_INTEGER {
        return Err(unsafe_integer());
    }
    Ok(value)
}

fn is_set_envelope(entries: &[(Text, Json)]) -> bool {
    matches!(entries, [(key, _)] if key.scalar && matches!(key.text.as_str(), "__set__" | "__frozenset__"))
}

/// The depth and node limits `_validate_serializable_value` applies; set
/// envelopes are bounded by the set codec instead.
fn validate_traversal(document: &Json) -> Result<()> {
    fn visit(node: &Json, depth: usize, count: &mut usize) -> Result<()> {
        *count += 1;
        if depth > MAX_VALUE_DEPTH || *count > MAX_VALUE_NODES {
            return Err(corrupt("persistent value traversal limit exceeded"));
        }
        match node {
            Json::Object(entries) if is_set_envelope(entries) => Ok(()),
            Json::Object(entries) => entries.iter().try_for_each(|(_, child)| {
                // The key is a node of its own at the child's depth.
                *count += 1;
                if depth + 1 > MAX_VALUE_DEPTH || *count > MAX_VALUE_NODES {
                    return Err(corrupt("persistent value traversal limit exceeded"));
                }
                visit(child, depth + 1, count)
            }),
            Json::Array(items) => items
                .iter()
                .try_for_each(|child| visit(child, depth + 1, count)),
            _ => Ok(()),
        }
    }
    visit(document, 0, &mut 0)
}

/// Aggregate set normalization work across one stored value.
#[derive(Default)]
struct Decoder {
    normalization: NormalizationWork<true>,
}

impl Decoder {
    fn value(&mut self, node: &Json) -> Result<VmValue> {
        Ok(match node {
            Json::Null => VmValue::None,
            Json::Bool(value) => VmValue::Bool(*value),
            Json::Int(value) => VmValue::Int(BigInt::from(*value)),
            Json::Str(text) => VmValue::String(text.scalar()?.to_owned()),
            Json::Array(items) => VmValue::List(
                items
                    .iter()
                    .map(|item| self.value(item))
                    .collect::<Result<_>>()?,
            ),
            Json::Object(entries) => self.object(entries)?,
        })
    }

    fn object(&mut self, entries: &[(Text, Json)]) -> Result<VmValue> {
        if entries
            .iter()
            .any(|(key, _)| key.scalar && is_reserved_tag(&key.text))
        {
            let [(tag, payload)] = entries else {
                return Err(corrupt("runtime wrapper must contain a single key"));
            };
            return self.tagged(&tag.text, payload);
        }
        entries
            .iter()
            .map(|(key, item)| Ok((VmValue::String(key.scalar()?.to_owned()), self.value(item)?)))
            .collect::<Result<_>>()
            .map(VmValue::Dict)
    }

    fn tagged(&mut self, tag: &str, payload: &Json) -> Result<VmValue> {
        match tag {
            "__fixed__" => fixed_payload(payload),
            "__big_int__" => big_int_payload(payload),
            "__set__" | "__frozenset__" => self.set_payload(tag, payload),
            _ => listed_payload(tag, payload),
        }
    }

    fn set_payload(&mut self, tag: &str, payload: &Json) -> Result<VmValue> {
        let items = set_items(payload)?;
        let mut budget = SetBudget::default();
        let envelope = if tag == "__set__" { 46 } else { 52 };
        budget.add(envelope + items.len().saturating_sub(1))?;
        self.normalization.add(items.len())?;
        budget.normalization.add(items.len())?;
        let members = items
            .iter()
            .map(|item| self.member(item, &mut budget, 1))
            .collect::<Result<Vec<_>>>()?;
        let members = crate::interpreter::normalize_set_members(members)?;
        let value = if tag == "__set__" {
            VmValue::Set(members)
        } else {
            VmValue::FrozenSet(members)
        };
        require_canonical_set(tag, payload, &value)?;
        Ok(value)
    }

    fn member(&mut self, node: &Json, budget: &mut SetBudget, depth: usize) -> Result<VmValue> {
        budget.visit(depth)?;
        let (tag, parts) = member_parts(node)?;
        if let ("tuple" | "frozenset", [_, Json::Array(children)]) = (tag, parts) {
            return self.container_member(tag, children, budget, depth);
        }
        match (tag, parts) {
            ("none", [_]) => {
                budget.scalar(parts)?;
                Ok(VmValue::None)
            }
            ("none", _) | (_, [_] | [_, _, _, _]) => Err(corrupt("invalid typed set member arity")),
            (_, [_, payload]) if valid_member_payload(tag, payload) => {
                budget.scalar(parts)?;
                set_scalar(tag, payload)
            }
            _ => Err(corrupt("invalid typed set member payload")),
        }
    }

    fn container_member(
        &mut self,
        tag: &str,
        children: &[Json],
        budget: &mut SetBudget,
        depth: usize,
    ) -> Result<VmValue> {
        budget.container(tag, children.len())?;
        if tag == "frozenset" {
            self.normalization.add(children.len())?;
            budget.normalization.add(children.len())?;
        }
        let children = children
            .iter()
            .map(|child| self.member(child, budget, depth + 1))
            .collect::<Result<Vec<_>>>()?;
        Ok(if tag == "tuple" {
            VmValue::Tuple(children)
        } else {
            VmValue::FrozenSet(crate::interpreter::normalize_set_members(children)?)
        })
    }
}

/// The tag and parts of a member node: `[tag]`, `[tag, payload]` or a raw
/// decimal's four parts. Members V2 never encodes are rejected here.
fn member_parts(node: &Json) -> Result<(&str, &[Json])> {
    let malformed = || corrupt("malformed typed set member");
    let Json::Array(parts) = node else {
        return Err(malformed());
    };
    let Some(Json::Str(tag)) = parts.first() else {
        return Err(malformed());
    };
    if !matches!(parts.len(), 1 | 2 | 4) {
        return Err(malformed());
    }
    let tag = if tag.scalar { tag.text.as_str() } else { "" };
    if matches!(tag, "raw_decimal" | "float") {
        return Err(corrupt(
            "V2 set members cannot contain binary float or raw Decimal",
        ));
    }
    if let ("int", [_, Json::Str(text)]) = (tag, parts.as_slice()) {
        if text.chars() > MAX_BIG_INT_TEXT {
            return Err(corrupt("integer exceeds 512 bits"));
        }
    }
    Ok((tag, parts))
}

fn valid_member_payload(tag: &str, payload: &Json) -> bool {
    match (tag, payload) {
        ("bool", Json::Bool(_)) => true,
        ("datetime", Json::Array(items)) => {
            items.len() == 7
                && items
                    .iter()
                    .all(|item| matches!(item, Json::Int(value) if value.abs() <= 999_999))
        }
        ("int" | "fixed" | "timedelta" | "str" | "bytes", Json::Str(_)) => true,
        _ => false,
    }
}

/// The `{"codec": "xian-set-1", "items": [...]}` envelope's items.
fn set_items(payload: &Json) -> Result<&[Json]> {
    let Json::Object(entries) = payload else {
        return Err(corrupt("V2 set requires a typed member envelope"));
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.scalar && key.text == name)
            .map(|(_, value)| value)
    };
    let codec_matches = matches!(
        field("codec"),
        Some(Json::Str(text)) if text.scalar && text.text == set_member_codec::CODEC
    );
    match field("items") {
        Some(Json::Array(items)) if codec_matches && entries.len() == 2 => {
            if items.len() > set_member_codec::MAX_NODES {
                return Err(corrupt("invalid set codec items"));
            }
            Ok(items)
        }
        _ => Err(corrupt("unsupported or malformed set codec envelope")),
    }
}

/// Accept only the canonical member order and representatives.
fn require_canonical_set(tag: &str, payload: &Json, value: &VmValue) -> Result<()> {
    let canonical = set_member_codec::encode_set_value(value)?;
    if canonical
        .get(tag)
        .is_some_and(|envelope| json_matches(payload, envelope))
    {
        Ok(())
    } else {
        Err(corrupt("noncanonical set codec members"))
    }
}

/// Tags whose list payload must hold safe integers only.
fn listed_payload(tag: &str, payload: &Json) -> Result<VmValue> {
    if let Json::Array(items) = payload {
        if !items.iter().all(|item| matches!(item, Json::Int(_))) {
            return Err(corrupt("invalid numeric value in runtime wrapper"));
        }
    }
    match tag {
        "__time__" => time_payload(payload),
        "__delta__" => delta_payload(payload),
        "__bytes__" => hex_payload(payload).map(VmValue::Bytes),
        "__bytearray__" => hex_payload(payload).map(VmValue::ByteArray),
        _ => Err(corrupt(format!("unknown runtime tag {tag}"))),
    }
}

/// Set normalization work (`n * n` per normalized set): one aggregate budget
/// per stored value, one for each decoded set.
#[derive(Default)]
struct NormalizationWork<const AGGREGATE: bool>(usize);

impl<const AGGREGATE: bool> NormalizationWork<AGGREGATE> {
    fn add(&mut self, count: usize) -> Result<()> {
        self.0 = self.0.saturating_add(count.saturating_mul(count));
        if self.0 > set_member_codec::MAX_NORMALIZATION_WORK {
            return Err(corrupt(if AGGREGATE {
                "set codec aggregate normalization work limit exceeded"
            } else {
                "set codec normalization work limit exceeded"
            }));
        }
        Ok(())
    }
}

fn set_scalar(tag: &str, payload: &Json) -> Result<VmValue> {
    match (tag, payload) {
        ("bool", Json::Bool(value)) => Ok(VmValue::Bool(*value)),
        ("int" | "fixed" | "timedelta", Json::Str(text)) => set_number(tag, set_integer(text)?),
        ("str", Json::Str(text)) => Ok(VmValue::String(text.scalar()?.to_owned())),
        ("bytes", Json::Str(text)) => set_bytes(text.scalar()?).map(VmValue::Bytes),
        ("datetime", Json::Array(items)) => datetime(items),
        _ => Err(corrupt("invalid typed set member payload")),
    }
}

fn set_number(tag: &str, number: BigInt) -> Result<VmValue> {
    match tag {
        "int" => checked_integer(number).map(VmValue::Int),
        "fixed" => VmDecimal::from_scaled(number).map(VmValue::Decimal),
        _ => number
            .to_i64()
            .ok_or_else(|| corrupt("timedelta overflow"))
            .and_then(VmTimeDelta::from_raw_seconds)
            .map(VmValue::TimeDelta),
    }
}

/// Lowercase hex pairs, as `bytes.hex()` writes them.
fn set_bytes(hex: &str) -> Result<Vec<u8>> {
    let invalid = || corrupt("invalid typed set member payload");
    if !hex
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(invalid());
    }
    hex::decode(hex).map_err(|_| invalid())
}

/// `xian-set-1` integer text: `0|-?[1-9][0-9]*`, at most 2**20 bits.
fn set_integer(text: &Text) -> Result<BigInt> {
    let text = text.scalar()?;
    if text.len() > MAX_SET_INTEGER_TEXT || !canonical_integer_text(text) {
        return Err(corrupt("invalid canonical set integer"));
    }
    let number = BigInt::from_str(text).map_err(|_| corrupt("invalid canonical set integer"))?;
    if number.bits() > MAX_SET_INTEGER_BITS {
        return Err(corrupt("set codec integer bit limit exceeded"));
    }
    Ok(number)
}

fn canonical_integer_text(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if text == "0" {
        return true;
    }
    !digits.is_empty()
        && !digits.starts_with('0')
        && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn checked_integer(number: BigInt) -> Result<BigInt> {
    if number.bits() > xian_numeric::INTEGER_BITS {
        return Err(corrupt("integer exceeds 512 bits"));
    }
    Ok(number)
}

fn fixed_payload(payload: &Json) -> Result<VmValue> {
    let Json::Str(text) = payload else {
        return Err(corrupt("noncanonical __fixed__ decimal string"));
    };
    let text = text.scalar()?;
    if text.chars().count() > MAX_FIXED_TEXT
        || xian_numeric::canonical_decimal(text).ok().as_deref() != Some(text)
    {
        return Err(corrupt("noncanonical __fixed__ decimal string"));
    }
    numeric_v2::exact_decimal(text).map(VmValue::Decimal)
}

fn big_int_payload(payload: &Json) -> Result<VmValue> {
    let Json::Str(text) = payload else {
        return Err(corrupt("invalid __big_int__ decimal string"));
    };
    let text = text.scalar()?;
    if text.is_empty() || text.chars().count() > MAX_BIG_INT_TEXT || !canonical_integer_text(text) {
        return Err(corrupt("noncanonical __big_int__"));
    }
    let number = BigInt::from_str(text).map_err(|_| corrupt("noncanonical __big_int__"))?;
    let number = checked_integer(number)?;
    if number.abs() <= BigInt::from(SAFE_INTEGER) {
        return Err(corrupt("noncanonical __big_int__"));
    }
    Ok(VmValue::Int(number))
}

fn int_items(items: &[Json]) -> Option<Vec<i64>> {
    items
        .iter()
        .map(|item| match item {
            Json::Int(value) => Some(*value),
            _ => None,
        })
        .collect()
}

/// `Datetime(*parts)`: three to seven integer components.
fn datetime(items: &[Json]) -> Result<VmValue> {
    let parts = int_items(items)
        .filter(|parts| (3..=7).contains(&parts.len()))
        .ok_or_else(|| corrupt("invalid __time__ payload"))?;
    let part = |index: usize| parts.get(index).copied().unwrap_or(0);
    VmDateTime::new(
        part(0),
        part(1),
        part(2),
        part(3),
        part(4),
        part(5),
        part(6),
    )
    .map(VmValue::DateTime)
}

fn time_payload(payload: &Json) -> Result<VmValue> {
    match payload {
        Json::Array(items) => datetime(items),
        _ => Err(corrupt("invalid __time__ payload")),
    }
}

fn delta_payload(payload: &Json) -> Result<VmValue> {
    let parts = match payload {
        Json::Array(items) => int_items(items),
        _ => None,
    };
    let Some([days, seconds]) = parts.as_deref() else {
        return Err(corrupt("invalid __delta__ payload"));
    };
    let raw = i128::from(*days) * 86_400 + i128::from(*seconds);
    i64::try_from(raw)
        .map_err(|_| corrupt("timedelta overflow"))
        .and_then(VmTimeDelta::from_raw_seconds)
        .map(VmValue::TimeDelta)
}

/// `bytes.fromhex`: pairs of hex digits, ASCII whitespace between pairs.
fn hex_payload(payload: &Json) -> Result<Vec<u8>> {
    let Json::Str(text) = payload else {
        return Err(corrupt("invalid hex payload"));
    };
    let mut bytes = Vec::new();
    let mut characters = text.scalar()?.chars().peekable();
    let digit = |character: Option<char>| {
        character
            .and_then(|character| character.to_digit(16))
            .ok_or_else(|| corrupt("invalid hex payload"))
    };
    loop {
        while characters.peek().is_some_and(|character| {
            matches!(character, ' ' | '\t' | '\n' | '\r' | '\u{b}' | '\u{c}')
        }) {
            characters.next();
        }
        if characters.peek().is_none() {
            return Ok(bytes);
        }
        let high = digit(characters.next())?;
        let low = digit(characters.next())?;
        bytes.push((high * 16 + low) as u8);
    }
}

/// Byte, node and normalization budgets of one decoded set (`_Budget`).
#[derive(Default)]
struct SetBudget {
    bytes: usize,
    nodes: usize,
    normalization: NormalizationWork<false>,
}

impl SetBudget {
    fn add(&mut self, size: usize) -> Result<()> {
        self.bytes = self.bytes.saturating_add(size);
        if self.bytes > set_member_codec::MAX_BYTES {
            return Err(corrupt("set codec encoded byte limit exceeded"));
        }
        Ok(())
    }

    fn visit(&mut self, depth: usize) -> Result<()> {
        self.nodes += 1;
        if depth > set_member_codec::MAX_DEPTH || self.nodes > set_member_codec::MAX_NODES {
            return Err(corrupt("set codec depth or node limit exceeded"));
        }
        Ok(())
    }

    fn container(&mut self, tag: &str, length: usize) -> Result<()> {
        if length > set_member_codec::MAX_NODES {
            return Err(corrupt("set codec node limit exceeded"));
        }
        self.add(5 + tag.len() + 2 + length.saturating_sub(1))
    }

    /// The encoded size of a scalar member node, as Python measures it.
    fn scalar(&mut self, parts: &[Json]) -> Result<()> {
        let mut size = 2 + parts.len().saturating_sub(1);
        for part in parts {
            size = size.saturating_add(json_size(part)?);
        }
        self.add(size)
    }
}

/// `len(json.dumps(part, separators=(",", ":")))` for a scalar member part.
fn json_size(part: &Json) -> Result<usize> {
    Ok(match part {
        Json::Str(text) => json_string_size(text)?,
        Json::Bool(true) => 4,
        Json::Bool(false) => 5,
        Json::Array(items) => items
            .iter()
            .map(json_size)
            .sum::<Result<usize>>()?
            .saturating_add(2 + items.len().saturating_sub(1)),
        Json::Int(value) => value.to_string().len(),
        Json::Null => 4,
        Json::Object(_) => 0,
    })
}

fn json_string_size(text: &Text) -> Result<usize> {
    let text = text
        .scalar()
        .map_err(|_| corrupt("set codec rejects non-scalar Unicode"))?;
    let mut size = 2usize;
    for character in text.chars() {
        let code = u32::from(character);
        size += match character {
            '\\' | '"' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            _ if code < 32 => 6,
            _ if code < 128 => 1,
            _ if code < 65_536 => 6,
            _ => 12,
        };
        if size > set_member_codec::MAX_BYTES {
            return Err(corrupt("set codec encoded byte limit exceeded"));
        }
    }
    Ok(size)
}

/// Python `==` between a parsed payload and the canonical encoding.
fn json_matches(node: &Json, canonical: &Value) -> bool {
    match (node, canonical) {
        (Json::Null, Value::Null) => true,
        (Json::Bool(left), Value::Bool(right)) => left == right,
        (Json::Int(left), Value::Number(right)) => right.as_i64() == Some(*left),
        (Json::Str(left), Value::String(right)) => left.scalar && &left.text == right,
        (Json::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(l, r)| json_matches(l, r))
        }
        (Json::Object(left), Value::Object(right)) => object_matches(left, right),
        _ => false,
    }
}

fn object_matches(left: &[(Text, Json)], right: &serde_json::Map<String, Value>) -> bool {
    left.len() == right.len()
        && left.iter().all(|(key, value)| {
            key.scalar
                && right
                    .get(&key.text)
                    .is_some_and(|expected| json_matches(value, expected))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(text: &str) -> Result<VmValue> {
        decode_stored_value(text.as_bytes())
    }

    fn rejects(text: &str) {
        assert!(decode(text).is_err(), "accepted {text:?}");
    }

    #[test]
    fn plain_json_keeps_order_and_python_duplicate_key_semantics() {
        assert_eq!(
            decode(r#" {"b": [1, true, null], "a": "x", "b": -7} "#).unwrap(),
            VmValue::Dict(vec![
                (VmValue::String("b".into()), VmValue::Int(BigInt::from(-7))),
                (VmValue::String("a".into()), VmValue::String("x".into())),
            ])
        );
    }

    #[test]
    fn numbers_outside_the_exact_integer_language_are_rejected() {
        for text in [
            "1.5",
            "1e3",
            "1E+3",
            "-0",
            "01",
            "NaN",
            "Infinity",
            "-Infinity",
            "9007199254740992",
            "12345678901234567",
            "1.",
            "-",
            "+1",
        ] {
            rejects(text);
        }
        assert_eq!(
            decode("-9007199254740991").unwrap(),
            VmValue::Int(BigInt::from(-SAFE_INTEGER))
        );
    }

    #[test]
    fn strings_follow_python_escapes_and_reject_lone_surrogates() {
        assert_eq!(
            decode(r#""😀é\/\t""#).unwrap(),
            VmValue::String("\u{1f600}\u{e9}/\t".into())
        );
        for text in [
            r#""\ud800""#,
            r#""\udc00\ud800""#,
            "\"a\u{1}\"",
            r#""\x""#,
            r#""\u12g4""#,
        ] {
            rejects(text);
        }
        // A lone surrogate value overwritten by a duplicate key never reaches the VM.
        assert!(decode(r#"{"a": "\ud800", "a": 1}"#).is_ok());
    }

    #[test]
    fn tagged_scalars_decode_to_vm_values() {
        assert!(matches!(
            decode(r#"{"__fixed__":"1.5"}"#).unwrap(),
            VmValue::Decimal(_)
        ));
        assert_eq!(
            decode(r#"{"__big_int__":"9007199254740992"}"#).unwrap(),
            VmValue::Int(BigInt::from(SAFE_INTEGER + 1))
        );
        assert_eq!(
            decode(r#"{"__bytes__":"0aFf 10"}"#).unwrap(),
            VmValue::Bytes(vec![10, 255, 16])
        );
        assert_eq!(
            decode(r#"{"__delta__":[1,5]}"#).unwrap(),
            VmValue::TimeDelta(VmTimeDelta::from_raw_seconds(86_405).unwrap())
        );
        assert_eq!(
            decode(r#"{"__time__":[2024,2,29]}"#).unwrap(),
            VmValue::DateTime(VmDateTime::new(2024, 2, 29, 0, 0, 0, 0).unwrap())
        );
        for text in [
            r#"{"__fixed__":"1.50"}"#,
            r#"{"__fixed__":1}"#,
            r#"{"__big_int__":"5"}"#,
            r#"{"__big_int__":"+9007199254740992"}"#,
            r#"{"__bytes__":"0"}"#,
            r#"{"__time__":[2023,2,29]}"#,
            r#"{"__time__":[2024,1,1,0,0,0,0,0]}"#,
            r#"{"__time__":[2024,true,1]}"#,
            r#"{"__delta__":"12"}"#,
            r#"{"__fixed__":"1","x":2}"#,
        ] {
            rejects(text);
        }
    }

    #[test]
    fn sets_require_the_canonical_member_order() {
        let set =
            |items: &str| format!(r#"{{"__set__":{{"codec":"xian-set-1","items":{items}}}}}"#);
        assert_eq!(
            decode(&set(r#"[["int","1"],["str","a"]]"#)).unwrap(),
            VmValue::Set(vec![
                VmValue::Int(BigInt::from(1)),
                VmValue::String("a".into())
            ])
        );
        rejects(&set(r#"[["str","a"],["int","1"]]"#));
        rejects(&set(r#"[["int","1"],["int","1"]]"#));
        rejects(&set(r#"[["float","3ff0000000000000"]]"#));
        rejects(r#"{"__set__":[1,2]}"#);
    }

    /// Python's readings (`decode` + `py_to_vm`) of encoded samples and of
    /// noncanonical and limit spellings; `null` marks a rejection.
    #[test]
    fn matches_python_readings_of_the_shared_corpus() {
        let cases: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/stored_value_readings.json"
        ))
        .unwrap();
        for case in cases.as_array().unwrap() {
            let data = hex::decode(case["hex"].as_str().unwrap()).unwrap();
            let reading = decode_stored_value(&data)
                .ok()
                .map(|value| format!("{value:?}"));
            assert_eq!(
                reading.as_deref(),
                case["reading"].as_str(),
                "{}",
                String::from_utf8_lossy(&data)
            );
        }
    }

    #[test]
    fn traversal_limits_match_python() {
        let nested = |depth: usize| format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        assert!(decode(&nested(128)).is_ok());
        rejects(&nested(129));
        rejects(&nested(100_000));
    }
}
