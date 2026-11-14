use super::rules::{contract_name_is_formatted, is_canonical_hex, is_identifier};
use super::*;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;

const CHAIN: &str = "xian-local";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn payload() -> Value {
    json!({
        "chain_id": CHAIN, "chi_supplied": 100, "contract": "currency",
        "function": "transfer", "kwargs": {"amount": 1, "to": "bob"}, "nonce": 0,
        "sender": hex::encode(key().verifying_key().to_bytes()),
    })
}

fn wire(document: &Value) -> Vec<u8> {
    hex::encode(canonical_json(document).unwrap()).into_bytes()
}

fn signed(payload: Value) -> Value {
    let message = canonical_json(&payload).unwrap();
    let signature = hex::encode(key().sign(message.as_bytes()).to_bytes());
    json!({"metadata": {"signature": signature}, "payload": payload})
}

fn admit(document: &Value) -> Result<()> {
    let decoded = decode_transaction(&wire(document))?;
    validate_transaction_static(&decoded.document, CHAIN)
}

fn refusal(document: &Value) -> String {
    admit(document).unwrap_err().to_string()
}

#[test]
fn admission_revision_identifies_the_exact_document_keys_rule() {
    assert_eq!(ADMISSION_REVISION, "xian-fastpath-admission-3");
}

#[test]
fn canonical_hex_accepts_only_exact_lowercase_digits() {
    let lower = "0123456789abcdef".repeat(4);
    assert!(is_canonical_hex(&lower, 64));
    assert!(!is_canonical_hex(&lower.to_uppercase(), 64));
    assert!(!is_canonical_hex(&format!("{}A", &lower[..63]), 64));
    assert!(!is_canonical_hex(&lower[..63], 64));
    assert!(!is_canonical_hex(&format!("{lower}0"), 64));
    assert!(!is_canonical_hex(&format!("{} ", &lower[..63]), 64));
    assert!(!is_canonical_hex(&format!("{}g", &lower[..63]), 64));
    assert!(!is_canonical_hex(&format!("{}\u{ff41}", &lower[..61]), 64));
}

#[test]
fn a_signed_canonical_transaction_is_admitted() {
    let document = signed(payload());
    let decoded = decode_transaction(&wire(&document)).unwrap();
    assert_eq!(decoded.document, document);
    assert_eq!(decoded.payload_json, canonical_json(&payload()).unwrap());
    assert!(validate_transaction_static(&decoded.document, CHAIN).is_ok());
}

#[test]
fn only_the_canonical_spelling_decodes() {
    let text = canonical_json(&signed(payload())).unwrap();
    let spaced = text.replacen(":", ": ", 1);
    let refused = decode_transaction(hex::encode(spaced).as_bytes()).unwrap_err();
    assert_eq!(refused.message(), "Transaction bytes are not canonical");
    assert_eq!(
        decode_transaction(b"0").unwrap_err().to_string(),
        "Odd number of digits"
    );
    assert_eq!(
        decode_transaction(hex::encode("{}").as_bytes())
            .unwrap_err()
            .to_string(),
        "Invalid payload"
    );
}

fn nested_wire(levels: usize) -> Vec<u8> {
    // The document, its payload and kwargs, then lists.
    let mut nested = json!("leaf");
    for _ in 0..levels - 3 {
        nested = json!([nested]);
    }
    let mut document = signed(payload());
    document["payload"]["kwargs"] = json!({ "deep": nested });
    hex::encode(serde_json::to_string(&document).unwrap()).into_bytes()
}

#[test]
fn documents_nest_at_most_127_containers_deep() {
    assert!(decode_transaction(&nested_wire(127)).is_ok());
    let refused = decode_transaction(&nested_wire(128)).unwrap_err();
    assert_eq!(refused.message(), "recursion limit exceeded");
}

#[test]
fn nesting_beyond_the_limit_is_refused() {
    let mut nested = json!("leaf");
    for _ in 0..130 {
        nested = json!([nested]);
    }
    let mut document = signed(payload());
    document["payload"]["kwargs"] = json!({ "deep": nested });
    let text = serde_json::to_string(&document).unwrap();
    let refused = decode_transaction(hex::encode(text).as_bytes()).unwrap_err();
    assert_eq!(refused.message(), "recursion limit exceeded");
}

#[test]
fn static_rules_refuse_in_their_order() {
    let mut document = signed(payload());
    document["metadata"]["extra"] = json!(1);
    assert_eq!(refusal(&document), "Wrong number of metadata entries");

    let mut body = payload();
    body["function"] = json!("");
    assert_eq!(refusal(&signed(body)), "Payload key 'function' is missing");

    let mut body = payload();
    body["chi_supplied"] = json!(0);
    assert_eq!(
        refusal(&signed(body)),
        "Payload key 'chi_supplied' is missing"
    );

    let mut body = payload();
    body["nonce"] = json!(-1);
    assert_eq!(
        refusal(&signed(body)),
        "Transaction has wrongly formatted dictionary"
    );

    let mut document = signed(payload());
    document["payload"]["nonce"] = json!(1);
    assert_eq!(refusal(&document), "Bad signature");

    let mut body = payload();
    body["chain_id"] = json!("other");
    assert_eq!(refusal(&signed(body)), "Wrong chain_id");

    let mut body = payload();
    body["contract"] = json!("submission");
    body["function"] = json!("submit_contract");
    body["kwargs"] = json!({"name": "con_Upper", "code": ""});
    assert_eq!(
        refusal(&signed(body)),
        "Transaction contract name is invalid"
    );
}

#[test]
fn names_and_identifiers_follow_the_python_rules() {
    assert!(contract_name_is_formatted("con_token_1"));
    assert!(contract_name_is_formatted(&format!(
        "con_{}",
        "a".repeat(60)
    )));
    assert!(!contract_name_is_formatted(&format!(
        "con_{}",
        "a".repeat(61)
    )));
    assert!(!contract_name_is_formatted("con_Token"));
    assert!(!contract_name_is_formatted("token"));
    assert!(is_identifier("a_1"));
    assert!(!is_identifier("_a"));
    assert!(!is_identifier("1a"));
    assert!(!is_identifier(""));
    assert!(!is_identifier("é"));
}

fn with_payload(update: impl FnOnce(&mut Value)) -> Value {
    let mut body = payload();
    update(&mut body);
    signed(body)
}

#[test]
fn chi_supplied_is_required_as_python_truthiness_reads_it() {
    for (value, expected) in [
        (json!(""), "Payload key 'chi_supplied' is missing"),
        (json!([]), "Payload key 'chi_supplied' is missing"),
        (json!({}), "Payload key 'chi_supplied' is missing"),
        (json!(false), "Payload key 'chi_supplied' is missing"),
        (json!(null), "Payload key 'chi_supplied' is missing"),
        (json!("x"), "Transaction has wrongly formatted dictionary"),
        (json!([1]), "Transaction has wrongly formatted dictionary"),
        (
            json!({"a": 1}),
            "Transaction has wrongly formatted dictionary",
        ),
        (json!(true), "Transaction has wrongly formatted dictionary"),
    ] {
        let document = with_payload(|body| body["chi_supplied"] = value.clone());
        assert_eq!(refusal(&document), expected, "{value}");
    }
}

#[test]
fn payload_key_sets_are_exact() {
    let mut document = signed(payload());
    document["payload"]["extra"] = json!(1);
    assert_eq!(
        refusal(&document),
        "Transaction has unexpected or missing keys"
    );
}

#[test]
fn only_integers_are_signed_numbers() {
    let negative = with_payload(|body| body["kwargs"] = json!({"amount": -5}));
    assert!(admit(&negative).is_ok());
    let fraction = with_payload(|body| body["kwargs"] = json!({"amount": 0.5}));
    assert_eq!(
        refusal(&fraction),
        "Transaction has wrongly formatted dictionary"
    );
}

#[test]
fn a_sender_that_is_no_curve_point_cannot_sign() {
    // y = 2 has no x on edwards25519.
    let not_a_point = format!("02{}", "00".repeat(31));
    let document = with_payload(|body| body["sender"] = json!(not_a_point));
    assert_eq!(refusal(&document), "Bad signature");
}

#[test]
fn only_submit_contract_needs_a_submission_name() {
    let other = with_payload(|body| {
        body["contract"] = json!("submission");
        body["function"] = json!("other");
        body["kwargs"] = json!({"name": "Bad Name"});
    });
    assert!(admit(&other).is_ok());
}

#[test]
fn canonical_json_sorts_keys_and_drops_whitespace() {
    let value = json!({"b": [1, "é", null, true], "a": {"y": -2, "x": "\n"}});
    assert_eq!(
        canonical_json(&value).unwrap(),
        "{\"a\":{\"x\":\"\\n\",\"y\":-2},\"b\":[1,\"é\",null,true]}"
    );
}

#[test]
fn the_document_holds_exactly_metadata_and_payload() {
    // Keys beside them are not signed: they changed the transaction hash and
    // the bytes a block carries without the sender's consent.
    for extra in ["zzz", "aaa", "b_meta"] {
        let mut document = signed(payload());
        document[extra] = json!(1);
        assert_eq!(
            refusal(&document),
            "Transaction has unexpected or missing keys",
            "{extra}"
        );
    }
}
