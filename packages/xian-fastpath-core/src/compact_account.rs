//! Strict-policy ordinary spend: tag, fixed binary signature frame, canonical
//! UTF-8 JSON payload. Account proofs and the active policy are checked by ABCI.
use crate::{canonical_json, AdmissionError, Result};
use serde_json::{json, Value};

pub const TAG: &[u8] = b"XIAN\x01";
pub const MAX_PAYLOAD_BYTES: usize = 131_072;
const FRAME_BYTES: usize = 3401;
const FRAME_TAG: &[u8] = b"XIAN-ACCOUNT-AUTH\0\x01\x01";

pub struct CompactAccount<'a> {
    pub payload: Value,
    pub payload_bytes: &'a [u8],
    pub signature: &'a [u8],
}

impl CompactAccount<'_> {
    pub fn into_document(self) -> Value {
        json!({"payload": self.payload, "metadata": {
            "tx_format": crate::ACCOUNT_TX_FORMAT,
            "auth": {"scheme": "ed25519_ml_dsa_65_v1", "signature": hex::encode(self.signature)}
        }})
    }
}

pub fn decode(raw: &[u8]) -> Result<CompactAccount<'_>> {
    let body = raw
        .strip_prefix(TAG)
        .ok_or_else(|| AdmissionError::new("Invalid account wire tag"))?;
    if !(FRAME_BYTES + 1..=FRAME_BYTES + MAX_PAYLOAD_BYTES).contains(&body.len()) {
        return Err(AdmissionError::new(
            "Invalid compact account transaction length",
        ));
    }
    let (signature, payload_bytes) = body.split_at(FRAME_BYTES);
    if !signature.starts_with(FRAME_TAG) {
        return Err(AdmissionError::new("Invalid account signature frame"));
    }
    let payload: Value = serde_json::from_slice(payload_bytes).map_err(crate::json_parse_error)?;
    if canonical_json(&payload)?.as_bytes() != payload_bytes {
        return Err(AdmissionError::new("Transaction bytes are not canonical"));
    }
    if payload["contract"] == "_accounts" {
        return Err(AdmissionError::new(
            "Account transitions require lifecycle encoding",
        ));
    }
    Ok(CompactAccount {
        payload,
        payload_bytes,
        signature,
    })
}
