//! Static transaction admission, the one implementation CheckTx,
//! PrepareProposal, ProcessProposal and FinalizeBlock use: the wire decoding
//! and static rules of `xian-fastpath-core`, then the V2 wire grammar of the
//! payload (canonical numeric wrappers, sets, safe integers), which the
//! stored-value reader defines. A transaction refused here never executes.
use crate::stored_value::decode_stored_value;
use serde_json::Value;
use xian_fastpath_core::{
    decode_transaction, decode_transaction_with_chi_limit, validate_transaction_static,
    AdmissionError, DecodedTransaction,
};

/// The decoded transaction document if `raw` is admitted for `chain_id`.
pub(crate) fn admit_transaction(raw: &[u8], chain_id: &str) -> Result<Value, AdmissionError> {
    admit_decoded(decode_transaction(raw)?, chain_id)
}

pub(crate) fn admit_transaction_with_chi_limit(
    raw: &[u8],
    chain_id: &str,
    max_chi: u64,
) -> Result<Option<Value>, AdmissionError> {
    decode_transaction_with_chi_limit(raw, max_chi)?
        .map(|decoded| admit_decoded(decoded, chain_id))
        .transpose()
}

fn admit_decoded(decoded: DecodedTransaction, chain_id: &str) -> Result<Value, AdmissionError> {
    validate_transaction_static(&decoded.document, chain_id)?;
    require_wire_payload(decoded.payload_json.as_bytes())?;
    Ok(decoded.document)
}

pub(crate) fn compact_candidate<'a>(
    raw: &'a [u8],
    chain_id: &str,
) -> Result<xian_fastpath_core::compact_account::CompactAccount<'a>, AdmissionError> {
    let compact = xian_fastpath_core::compact_account::decode(raw)?;
    xian_fastpath_core::validate_account_payload(&compact.payload, chain_id)?;
    require_wire_payload(compact.payload_bytes)?;
    Ok(compact)
}

/// Structural decoding only. The caller must verify account proofs against
/// committed state before admitting, executing or caching a decision.
pub(crate) fn account_candidate(raw: &[u8], chain_id: &str) -> Result<Value, AdmissionError> {
    use xian_fastpath_core::compact_account;
    if raw.starts_with(compact_account::TAG) {
        return compact_candidate(raw, chain_id).map(|compact| compact.into_document());
    }
    if raw.len() > 524_288 {
        return Err(AdmissionError::new(
            "Account transaction exceeds wire size limit",
        ));
    }
    let decoded = decode_transaction(raw)?;
    if decoded.payload_json.len() > compact_account::MAX_PAYLOAD_BYTES {
        return Err(AdmissionError::new(
            "Account transaction exceeds payload size limit",
        ));
    }
    xian_fastpath_core::validate_account_candidate(&decoded.document, chain_id)?;
    require_wire_payload(decoded.payload_json.as_bytes())?;
    Ok(decoded.document)
}

/// The payload must read as V2 wire values (`decode_wire_numbers`).
fn require_wire_payload(payload_json: &[u8]) -> Result<(), AdmissionError> {
    decode_stored_value(payload_json)
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

#[cfg(test)]
mod account_tests {
    use super::*;
    use serde_json::json;

    fn wire(contract: &str, kwargs: Value) -> Vec<u8> {
        let document = json!({
            "metadata": {"tx_format":"xian_account_v1","auth":{"signature":"test"}},
            "payload": {"chain_id":"local","sender":"ab".repeat(32),"nonce":0,
                "chi_supplied":50,"contract":contract,"function":"call","kwargs":kwargs}
        });
        hex::encode(xian_fastpath_core::canonical_json(&document).unwrap()).into_bytes()
    }

    #[test]
    fn account_candidates_share_native_wire_rules_but_are_never_legacy_admitted() {
        for contract in ["currency", "_accounts"] {
            let raw = wire(contract, json!({"quantity":{"__fixed__":"1.5"}}));
            assert!(account_candidate(&raw, "local").is_ok());
            assert!(account_candidate(&raw, "other").is_err());
            assert!(admit_transaction(&raw, "local").is_err());
        }
        for (contract, kwargs) in [
            ("_spoof", json!({})),
            ("ok", json!({"n":9007199254740992_u64})),
            ("ok", json!({"n":{"__fixed__":"1.50"}})),
            ("ok", json!({"bad key":1})),
        ] {
            assert!(account_candidate(&wire(contract, kwargs), "local").is_err());
        }
        assert!(account_candidate(&wire("ok", json!({"s":"x".repeat(131_072)})), "local").is_err());
    }
}

#[cfg(test)]
mod compact_tests {
    use super::*;
    use serde_json::json;
    fn frame() -> Vec<u8> {
        let mut bytes = b"XIAN\x01XIAN-ACCOUNT-AUTH\0\x01\x01".to_vec();
        bytes.resize(5 + 3401, 0);
        bytes
    }
    fn payload() -> Value {
        json!({"chain_id":"local","sender":"ab".repeat(32),"nonce":0,
            "chi_supplied":30,"contract":"currency","function":"send","kwargs":{"text":"π"}})
    }
    fn raw(payload: &str) -> Vec<u8> {
        [frame().as_slice(), payload.as_bytes()].concat()
    }
    #[test]
    fn compact_spends_have_one_wire_spelling_and_no_legacy_admission() {
        let body = xian_fastpath_core::canonical_json(&payload()).unwrap();
        let bytes = raw(&body);
        let doc = account_candidate(&bytes, "local").unwrap();
        assert_eq!(doc["payload"], payload());
        assert_eq!(
            doc["metadata"]["auth"]["signature"],
            hex::encode(&bytes[5..3406])
        );
        assert!(admit_transaction(&bytes, "local").is_err());
        assert!(account_candidate(&bytes, "other").is_err());
        for invalid in [
            raw(&(body.clone() + " ")),
            raw(&body.replace("π", "\\u03c0")),
            raw(&body.replace("currency", "_accounts")),
            raw(&body.replace("\"nonce\":0", "\"nonce\":0,\"nonce\":0")),
            raw(&body.replace("\"π\"", "9007199254740992")),
            vec![0; 2],
        ] {
            assert!(account_candidate(&invalid, "local").is_err());
        }
        let mut invalid = bytes;
        invalid[5] ^= 1;
        assert!(account_candidate(&invalid, "local").is_err());
    }
}
