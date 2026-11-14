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
mod rules;

use serde_json::Value;
use std::fmt;

pub use canonical::canonical_json;
pub use rules::validate_transaction_static;

/// Transaction-admission rule revision. Bump it whenever the set of admitted
/// transactions changes; nodes fence on it at startup.
/// Revision 2: sender and signature must be canonical lowercase hex.
/// Revision 3: the document holds exactly `metadata` and `payload` (unsigned
/// keys beside them changed the transaction hash and the block bytes).
pub const ADMISSION_REVISION: &str = "xian-fastpath-admission-3";

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
    let text = wire_text(raw)?;
    let document: Value = serde_json::from_str(&text).map_err(json_parse_error)?;
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

/// The JSON text inside the hex wire encoding.
fn wire_text(raw: &[u8]) -> Result<String> {
    let hex_text =
        std::str::from_utf8(raw).map_err(|error| AdmissionError::new(error.to_string()))?;
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
