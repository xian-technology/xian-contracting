//! Static transaction admission, the one implementation CheckTx,
//! PrepareProposal, ProcessProposal and FinalizeBlock use: the wire decoding
//! and static rules of `xian-fastpath-core`, then the V2 wire grammar of the
//! payload (canonical numeric wrappers, sets, safe integers), which the
//! stored-value reader defines. A transaction refused here never executes.
use crate::stored_value::decode_stored_value;
use serde_json::Value;
use xian_fastpath_core::{decode_transaction, validate_transaction_static, AdmissionError};

pub(crate) use xian_fastpath_core::ADMISSION_REVISION;

/// The decoded transaction document if `raw` is admitted for `chain_id`.
pub(crate) fn admit_transaction(raw: &[u8], chain_id: &str) -> Result<Value, AdmissionError> {
    let decoded = decode_transaction(raw)?;
    validate_transaction_static(&decoded.document, chain_id)?;
    require_wire_payload(&decoded.payload_json)?;
    Ok(decoded.document)
}

/// The payload must read as V2 wire values (`decode_wire_numbers`).
fn require_wire_payload(payload_json: &str) -> Result<(), AdmissionError> {
    decode_stored_value(payload_json.as_bytes())
        .map(drop)
        .map_err(|_| AdmissionError::new("Transaction bytes are not canonical"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn signed_wire(kwargs: Value) -> Vec<u8> {
        let key = SigningKey::from_bytes(&[3; 32]);
        let payload = json!({
            "chain_id": "local", "chi_supplied": 10, "contract": "currency",
            "function": "transfer", "kwargs": kwargs, "nonce": 0,
            "sender": hex::encode(key.verifying_key().to_bytes()),
        });
        let message = xian_fastpath_core::canonical_json(&payload).unwrap();
        let signature = hex::encode(key.sign(message.as_bytes()).to_bytes());
        let document = json!({"metadata": {"signature": signature}, "payload": payload});
        hex::encode(xian_fastpath_core::canonical_json(&document).unwrap()).into_bytes()
    }

    #[test]
    fn canonical_wire_values_are_admitted() {
        let kwargs = json!({"a": {"__fixed__": "1.5"}, "b": {"__big_int__": "9007199254740992"}});
        let admitted = admit_transaction(&signed_wire(kwargs.clone()), "local").unwrap();
        assert_eq!(admitted["payload"]["kwargs"], kwargs);
    }

    #[test]
    fn noncanonical_wire_values_are_refused_after_the_static_rules() {
        for kwargs in [
            json!({"a": {"__fixed__": "1.50"}}),
            json!({"a": 9007199254740992_u64}),
            json!({"a": {"__set__": [["int", 2], ["int", 1]]}}),
        ] {
            let refused = admit_transaction(&signed_wire(kwargs), "local").unwrap_err();
            assert_eq!(refused.message(), "Transaction bytes are not canonical");
        }
        let refused = admit_transaction(&signed_wire(json!({"a": 1})), "other").unwrap_err();
        assert_eq!(refused.message(), "Wrong chain_id");
    }
}
