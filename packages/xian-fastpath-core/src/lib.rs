//! Transaction wire decoding and the static admission rules.
//!
//! A transaction arrives as the hex text of its canonical JSON document
//! (`{"metadata":{"signature":..},"payload":{..}}`). [`decode_transaction`]
//! reads it and refuses anything but the canonical spelling;
//! [`validate_transaction_static`] applies the rules that need no state: the
//! exact key sets, the field formats, the Ed25519 signature over the signed
//! payload fields, the chain id and the submission name. The runtime value
//! grammar of the payload (numeric wrappers, sets) is checked by the VM's
//! stored-value reader in `xian-vm-core`, which links this crate and exposes
//! admission to the node.
mod canonical;
pub mod compact_account;
mod rules;

use serde_json::Value;
use std::fmt;

pub use canonical::canonical_json;
pub use rules::{
    validate_account_candidate, validate_account_payload, validate_transaction_static,
    ACCOUNT_TX_FORMAT,
};

/// Transaction-admission rule revision. Bump it whenever the set of admitted
/// transactions changes; nodes fence on it at startup.
/// Revision 2: sender and signature must be canonical lowercase hex.
/// Revision 3: the document holds exactly `metadata` and `payload` (unsigned
/// keys beside them changed the transaction hash and the block bytes), and the
/// wire hex must be lowercase (uppercase digits gave one signed document many
/// transaction hashes).
/// Revision 4 adds a separate, explicitly unauthenticated account candidate decoder.
pub const ADMISSION_REVISION: &str = "xian-fastpath-admission-4";

/// Why a transaction is not admitted; the text reaches receipts and logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionError(String);

impl AdmissionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AdmissionError {}

pub type Result<T> = std::result::Result<T, AdmissionError>;

/// A transaction document read from its wire bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodedTransaction {
    /// The whole JSON document.
    pub document: Value,
    /// Its canonical JSON text (the wire bytes decoded).
    pub text: String,
    /// The canonical JSON text of its `payload`.
    pub payload_json: String,
}

/// Read the wire bytes: hex, UTF-8, JSON (at most 127 levels deep), and the
/// canonical spelling (sorted keys, no whitespace, no redundant escapes).
pub fn decode_transaction(raw: &[u8]) -> Result<DecodedTransaction> {
    let (text, document) = parse_wire_document(raw)?;
    canonical_transaction(text, document)
}

/// Drop a candidate whose declared chi exceeds the remaining proposal budget.
/// A candidate that fits still has to pass canonical decoding and admission.
pub fn decode_transaction_with_chi_limit(
    raw: &[u8],
    max_chi: u64,
) -> Result<Option<DecodedTransaction>> {
    let (text, document) = parse_wire_document(raw)?;
    if exceeds_chi_limit(&document, max_chi) {
        return Ok(None);
    }
    canonical_transaction(text, document).map(Some)
}

/// Use the exact integer read by admission. Other shapes go through admission.
pub fn exceeds_chi_limit(document: &Value, max_chi: u64) -> bool {
    document["payload"]["chi_supplied"]
        .as_u64()
        .is_some_and(|chi| chi > max_chi)
}

fn parse_wire_document(raw: &[u8]) -> Result<(String, Value)> {
    let text = wire_text(raw)?;
    let document: Value = serde_json::from_str(&text).map_err(json_parse_error)?;
    Ok((text, document))
}

fn canonical_transaction(text: String, document: Value) -> Result<DecodedTransaction> {
    if text != canonical_json(&document)? {
        return Err(AdmissionError::new("Transaction bytes are not canonical"));
    }
    let payload = document
        .get("payload")
        .ok_or_else(|| AdmissionError::new("Invalid payload"))?;
    let payload_json = canonical_json(payload)?;
    Ok(DecodedTransaction {
        document,
        text,
        payload_json,
    })
}

/// The JSON text inside the hex wire encoding. Only lowercase hex is read:
/// CometBFT names a transaction by the hash of its wire bytes, so one signed
/// document has exactly one spelling.
fn wire_text(raw: &[u8]) -> Result<String> {
    let hex_text =
        std::str::from_utf8(raw).map_err(|error| AdmissionError::new(error.to_string()))?;
    if hex_text.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(AdmissionError::new("Transaction bytes are not canonical"));
    }
    let bytes = hex::decode(hex_text).map_err(|error| AdmissionError::new(error.to_string()))?;
    String::from_utf8(bytes).map_err(|error| AdmissionError::new(error.utf8_error().to_string()))
}

fn json_parse_error(error: serde_json::Error) -> AdmissionError {
    let message = error.to_string();
    if message.contains("recursion limit exceeded") {
        AdmissionError::new("recursion limit exceeded")
    } else {
        AdmissionError::new(message)
    }
}

#[cfg(test)]
mod tests;
