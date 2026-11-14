//! The static admission rules: key sets, field formats, signature, chain id
//! and submission name, checked in this order (the first refusal wins).
use crate::{canonical_json, AdmissionError, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{Map, Value};
use std::collections::HashSet;

const METADATA_KEYS: [&str; 1] = ["signature"];
/// The payload fields; all of them are signed.
const PAYLOAD_KEYS: [&str; 7] = [
    "chain_id",
    "contract",
    "function",
    "kwargs",
    "nonce",
    "sender",
    "chi_supplied",
];
const MALFORMED: &str = "Transaction has wrongly formatted dictionary";

type Object = Map<String, Value>;

fn refused(message: &str) -> AdmissionError {
    AdmissionError::new(message)
}

/// The fields of a payload whose shape passed the key checks.
struct Fields<'a> {
    sender: &'a str,
    signature: &'a str,
    contract: &'a str,
    function: &'a str,
    chain_id: &'a str,
    kwargs: &'a Map<String, Value>,
}

/// Apply every static rule to a decoded transaction document.
pub fn validate_transaction_static(document: &Value, chain_id: &str) -> Result<()> {
    let (metadata, payload) = sections(document)?;
    require_payload_keys(payload)?;
    let fields = fields(metadata, payload)?;
    require_formats(&fields, payload)?;
    require_signature(&fields, payload)?;
    if fields.chain_id != chain_id {
        return Err(refused("Wrong chain_id"));
    }
    require_submission_name(&fields)
}

/// The metadata and payload objects; metadata holds exactly the signature.
fn sections(document: &Value) -> Result<(&Object, &Object)> {
    let document = object(Some(document), MALFORMED)?;
    let metadata = object(document.get("metadata"), "Metadata is missing")?;
    if metadata.len() != 1 {
        return Err(refused("Wrong number of metadata entries"));
    }
    exact_keys(metadata, &METADATA_KEYS)?;
    let payload = object(document.get("payload"), "Payload is missing")?;
    Ok((metadata, payload))
}

fn require_payload_keys(payload: &Map<String, Value>) -> Result<()> {
    for key in ["sender", "contract", "function"] {
        if !matches!(payload.get(key), Some(Value::String(text)) if !text.is_empty()) {
            return Err(AdmissionError::new(format!(
                "Payload key '{key}' is missing"
            )));
        }
    }
    if !is_truthy(payload.get("chi_supplied")) {
        return Err(refused("Payload key 'chi_supplied' is missing"));
    }
    exact_keys(payload, &PAYLOAD_KEYS)
}

fn fields<'a>(
    metadata: &'a Map<String, Value>,
    payload: &'a Map<String, Value>,
) -> Result<Fields<'a>> {
    Ok(Fields {
        sender: string(payload.get("sender"))?,
        signature: string(metadata.get("signature"))?,
        contract: string(payload.get("contract"))?,
        function: string(payload.get("function"))?,
        chain_id: string(payload.get("chain_id"))?,
        kwargs: object(payload.get("kwargs"), MALFORMED)?,
    })
}

fn require_formats(fields: &Fields<'_>, payload: &Map<String, Value>) -> Result<()> {
    let formatted = is_canonical_hex(fields.sender, 64)
        && is_canonical_hex(fields.signature, 128)
        && is_identifier(fields.contract)
        && is_identifier(fields.function)
        && fields.kwargs.keys().all(|key| is_identifier(key))
        && is_non_negative_integer(payload.get("nonce"))
        && is_non_negative_integer(payload.get("chi_supplied"));
    if formatted {
        Ok(())
    } else {
        Err(refused(MALFORMED))
    }
}

fn require_signature(fields: &Fields<'_>, payload: &Map<String, Value>) -> Result<()> {
    let signed = Value::Object(payload.clone());
    if contains_non_integer_number(&signed) {
        return Err(refused(MALFORMED));
    }
    let message = canonical_json(&signed)?;
    if verify_signature(fields.sender, fields.signature, &message) {
        Ok(())
    } else {
        Err(refused("Bad signature"))
    }
}

fn require_submission_name(fields: &Fields<'_>) -> Result<()> {
    if fields.contract != "submission" || fields.function != "submit_contract" {
        return Ok(());
    }
    match fields.kwargs.get("name") {
        Some(Value::String(name)) if contract_name_is_formatted(name) => Ok(()),
        _ => Err(refused("Transaction contract name is invalid")),
    }
}

fn verify_signature(public_key_hex: &str, signature_hex: &str, message: &str) -> bool {
    let Some(public_key) = fixed_bytes::<32>(public_key_hex) else {
        return false;
    };
    let Some(signature) = fixed_bytes::<64>(signature_hex) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
        return false;
    };
    verifying_key
        .verify_strict(message.as_bytes(), &Signature::from_bytes(&signature))
        .is_ok()
}

fn fixed_bytes<const N: usize>(hex_text: &str) -> Option<[u8; N]> {
    hex::decode(hex_text).ok()?.try_into().ok()
}

fn exact_keys(map: &Map<String, Value>, expected: &[&str]) -> Result<()> {
    let expected: HashSet<&str> = expected.iter().copied().collect();
    let actual: HashSet<&str> = map.keys().map(String::as_str).collect();
    if expected == actual {
        Ok(())
    } else {
        Err(refused("Transaction has unexpected or missing keys"))
    }
}

/// Python truthiness of a JSON value (the required-key check reads it so).
fn is_truthy(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(raw)) => *raw,
        Some(Value::Number(raw)) => raw.as_i64() != Some(0),
        Some(Value::String(raw)) => !raw.is_empty(),
        Some(Value::Array(raw)) => !raw.is_empty(),
        Some(Value::Object(raw)) => !raw.is_empty(),
        Some(Value::Null) | None => false,
    }
}

fn object<'a>(value: Option<&'a Value>, message: &str) -> Result<&'a Map<String, Value>> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| refused(message))
}

fn string(value: Option<&Value>) -> Result<&str> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| refused(MALFORMED))
}

/// A submission name: `con_` and at most 64 lowercase letters, digits and `_`.
pub(crate) fn contract_name_is_formatted(value: &str) -> bool {
    value.len() <= 64
        && value.starts_with("con_")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(crate) fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && chars.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Canonical hex is exactly `expected_len` characters from [0-9a-f]. Accounts
/// are keyed by the sender string, so accepting uppercase would alias one key.
pub(crate) fn is_canonical_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_non_negative_integer(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Number(number)) if number.as_u64().is_some())
}

fn contains_non_integer_number(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_i64().is_none() && number.as_u64().is_none(),
        Value::Array(items) => items.iter().any(contains_non_integer_number),
        Value::Object(items) => items.values().any(contains_non_integer_number),
        _ => false,
    }
}
