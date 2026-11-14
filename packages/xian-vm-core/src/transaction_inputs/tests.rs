use super::*;
use serde_json::json;

fn meta() -> BlockMeta {
    BlockMeta {
        nanos: 1_700_000_000_123_456_789,
        height: VmValue::Int(BigInt::from(7)),
        hash: VmValue::String("ab".repeat(32)),
        chain_id: VmValue::String("xian-local".into()),
    }
}

fn wire(payload: Value) -> Vec<u8> {
    let document = json!({"metadata": {"signature": "abc"}, "payload": payload});
    hex::encode(canonical_json(&document).unwrap()).into_bytes()
}

fn payload(contract: &str, kwargs: Value) -> Value {
    json!({
        "chain_id": "xian-local", "chi_supplied": 250, "contract": contract,
        "function": "call", "kwargs": kwargs, "nonce": 3, "sender": "alice",
    })
}

#[test]
fn the_size_counts_python_ascii_escapes() {
    // json.dumps({"a": "é😀\x7f☃"}, ensure_ascii=True) has 38 characters.
    assert_eq!(ascii_json_size("{\"a\":\"é😀\u{7f}\u{2603}\"}"), 38);
    assert_eq!(ascii_json_size("{\"a\":\"~ \\n\"}"), 12);
}

#[test]
fn the_input_hash_is_sha3_of_nanos_and_signature() {
    assert_eq!(
        input_hash(1_700_000_000_123_456_789, "abc"),
        "e9499448e65e9943d40b6b3e9466042535819c179ccb8a5ac09aacc0a786eded"
    );
}

#[test]
fn the_block_time_keeps_microseconds() {
    let expected = VmDateTime::new(2023, 11, 14, 22, 13, 20, 123_456).unwrap();
    assert_eq!(
        block_time(1_700_000_000_123_456_789),
        Some(VmValue::DateTime(expected))
    );
}

#[test]
fn a_transaction_reads_into_its_execution_inputs() {
    let kwargs = json!({"amount": {"__fixed__": "1.5"}, "to": "bob", "n": 2});
    let raw = wire(payload("currency", kwargs));
    let tx = prepared_tx(&raw, &meta()).unwrap();
    assert_eq!(
        (tx.sender.as_str(), tx.contract.as_str()),
        ("alice", "currency")
    );
    assert_eq!(tx.function, "call");
    assert_eq!(tx.chi_budget, BigInt::from(250));
    let names: Vec<&str> = tx.kwargs.iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(names, ["amount", "n", "to"]);
    assert_eq!(tx.kwargs[1].1, VmValue::Int(BigInt::from(2)));
    assert_eq!(tx.size_bytes, raw.len() / 2);
    assert_eq!(tx.context.signer.as_deref(), Some("alice"));
    assert_eq!(tx.context.entry, Some(("currency".into(), "call".into())));
    assert_eq!(tx.context.block_num, meta().height);
    assert_eq!(
        tx.context.input_hash,
        VmValue::String(input_hash(meta().nanos, "abc"))
    );
    assert_eq!(tx.context.submission_name, None);
}

#[test]
fn submission_names_reach_the_context_only_as_text() {
    let named = wire(payload("submission", json!({"name": "con_x", "code": ""})));
    let tx = prepared_tx(&named, &meta()).unwrap();
    assert_eq!(tx.context.submission_name.as_deref(), Some("con_x"));
    let unnamed = wire(payload("submission", json!({"name": null})));
    assert_eq!(
        prepared_tx(&unnamed, &meta())
            .unwrap()
            .context
            .submission_name,
        None
    );
    let numbered = wire(payload("submission", json!({"name": 5})));
    assert_eq!(
        prepared_tx(&numbered, &meta())
            .unwrap()
            .context
            .submission_name,
        None
    );
    let elsewhere = wire(payload("currency", json!({"name": 5})));
    assert!(prepared_tx(&elsewhere, &meta()).is_some());
}

#[test]
fn bytes_admission_refuses_have_no_inputs() {
    let unsafe_int = wire(payload("currency", json!({"a": 9_007_199_254_740_992_u64})));
    assert!(prepared_tx(&unsafe_int, &meta()).is_none());
    let mut document =
        json!({"metadata": {"signature": "abc"}, "payload": payload("c", json!({}))});
    document["extra"] = json!(1);
    let extra = hex::encode(canonical_json(&document).unwrap()).into_bytes();
    assert!(prepared_tx(&extra, &meta()).is_none());
    assert!(prepared_tx(b"zz", &meta()).is_none());
}

#[test]
fn any_integer_budget_reaches_the_executor() {
    for (budget, expected) in [
        (json!(-5), Some(BigInt::from(-5))),
        (json!(u64::MAX), Some(BigInt::from(u64::MAX))),
        (json!(true), None),
        (json!("5"), None),
    ] {
        let mut body = payload("currency", json!({}));
        body["chi_supplied"] = budget;
        assert_eq!(
            prepared_tx(&wire(body), &meta()).map(|tx| tx.chi_budget),
            expected
        );
    }
}
