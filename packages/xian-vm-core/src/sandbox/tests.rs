use super::*;
use serde_json::{json, Value};

const TOKEN: &str = include_str!("../../tests/vectors/sandbox/con_token.py");

fn environment() -> Value {
    json!({
        "now": {"__time__": [2026, 11, 15, 12, 0, 0, 0]},
        "block_num": 7,
        "block_hash": "ab".repeat(32),
        "chain_id": "xian-sandbox-test",
    })
}

fn chain() -> Sandbox {
    Sandbox::create(&json!({"environment": environment()}).to_string()).unwrap()
}

fn parsed(text: &str) -> Value {
    serde_json::from_str(text).unwrap()
}

fn deployed() -> Sandbox {
    let chain = chain();
    let outcome = parsed(
        &chain
            .deploy(
                &json!({
                    "sender": "alice",
                    "name": "con_token",
                    "source": TOKEN,
                    "constructor_args": {"supply": 500},
                    "environment": environment(),
                })
                .to_string(),
            )
            .unwrap(),
    );
    assert_eq!(outcome["status"], 0, "{outcome}");
    chain
}

fn call(chain: &Sandbox, function: &str, kwargs: Value) -> Value {
    call_with(chain, function, kwargs, json!({}))
}

fn call_with(chain: &Sandbox, function: &str, kwargs: Value, extra: Value) -> Value {
    let mut request = json!({
        "sender": "alice",
        "contract": "con_token",
        "function": function,
        "kwargs": kwargs,
        "environment": environment(),
    });
    request
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    parsed(&chain.call(&request.to_string()).unwrap())
}

#[test]
fn a_new_chain_holds_the_submission_contract() {
    let chain = chain();
    assert_eq!(parsed(&chain.contracts()), json!(["submission"]));
    let info = parsed(&chain.contract("submission").unwrap());
    let methods: Vec<&str> = info["methods"]
        .as_array()
        .unwrap()
        .iter()
        .map(|method| method["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        methods,
        ["submit_contract", "change_developer", "change_owner"]
    );
    assert_eq!(info["submitted"], r#"{"__time__":[2026,11,15,12,0,0,0]}"#);
    assert_eq!(info["owner"], Value::Null);
    assert!(chain.contract("con_missing").is_none());
}

#[test]
fn a_deployed_contract_runs_its_constructor_and_lists_its_methods() {
    let chain = deployed();
    assert_eq!(
        parsed(&chain.contracts()),
        json!(["con_token", "submission"])
    );
    assert_eq!(
        chain.get("con_token.balances:alice").as_deref(),
        Some("500")
    );
    assert_eq!(
        chain.get("con_token.metadata:symbol").as_deref(),
        Some("\"TKN\"")
    );
    let info = parsed(&chain.contract("con_token").unwrap());
    assert_eq!(info["developer"], "\"alice\"");
    assert_eq!(info["construct"]["name"], "seed");
    let transfer = &info["methods"][0];
    assert_eq!(transfer["name"], "transfer");
    assert_eq!(
        transfer["docstring"],
        "Move amount from the caller to `to`."
    );
    assert_eq!(
        transfer["arguments"],
        json!([
            {"name": "amount", "type": "decimal", "kind": "positional_or_keyword", "optional": false},
            {"name": "to", "type": "str", "kind": "positional_or_keyword", "optional": false},
        ])
    );
}

#[test]
fn a_call_reports_result_writes_and_events_as_wire_text() {
    let chain = deployed();
    let outcome = call(
        &chain,
        "transfer",
        json!({"amount": {"__fixed__": "1.5"}, "to": "bob"}),
    );
    assert_eq!(outcome["status"], 0);
    assert_eq!(outcome["result"], r#"{"__fixed__":"1.5"}"#);
    assert_eq!(outcome["error"], Value::Null);
    assert_eq!(
        outcome["writes"],
        json!([
            ["con_token.balances:alice", r#"{"__fixed__":"498.5"}"#],
            ["con_token.balances:bob", r#"{"__fixed__":"1.5"}"#],
            ["con_token.last_seen", "\"bob\""],
        ])
    );
    let event = &outcome["events"][0];
    assert_eq!(event["event"], "Transfer");
    assert_eq!(event["data_indexed"], r#"{"sender":"alice","to":"bob"}"#);
    assert_eq!(event["data"], r#"{"amount":{"__fixed__":"1.5"}}"#);
    assert!(outcome["chi_used"].as_u64().unwrap() > 0);
    assert_eq!(
        chain.get("con_token.balances:bob").as_deref(),
        Some(r#"{"__fixed__":"1.5"}"#)
    );
}

#[test]
fn numbers_cross_exactly() {
    let chain = deployed();
    let sum = call(
        &chain,
        "add",
        json!({"a": {"__fixed__": "0.1"}, "b": {"__fixed__": "0.2"}}),
    );
    assert_eq!(sum["result"], r#"{"__fixed__":"0.3"}"#);
    let power = call(&chain, "power", json!({"base": 2, "exponent": 70}));
    assert_eq!(
        power["result"],
        r#"{"__big_int__":"1180591620717411303424"}"#
    );
    let big = call(
        &chain,
        "power",
        json!({"base": {"__big_int__": "9007199254740993"}, "exponent": 1}),
    );
    assert_eq!(big["result"], r#"{"__big_int__":"9007199254740993"}"#);
    // A decimal parameter takes an int as the decimal it equals.
    let coerced = call(
        &chain,
        "add",
        json!({"a": {"__big_int__": "9007199254740993"}, "b": 0}),
    );
    assert_eq!(coerced["result"], r#"{"__fixed__":"9007199254740993"}"#);
}

#[test]
fn inputs_the_node_would_refuse_are_errors() {
    let chain = deployed();
    for kwargs in [
        json!({"a": 1.5, "b": 1}),
        json!({"a": 9007199254740993_u64, "b": 1}),
        json!({"a": {"__fixed__": "1.50"}, "b": 1}),
    ] {
        let request = json!({
            "sender": "alice", "contract": "con_token", "function": "add", "kwargs": kwargs,
        });
        let error = chain.call(&request.to_string()).unwrap_err();
        assert!(
            error.0.contains("arguments the VM does not take"),
            "{error}"
        );
    }
    let unknown = json!({"sender": "a", "contract": "c", "function": "f", "gas": 1});
    assert_eq!(
        chain.call(&unknown.to_string()).unwrap_err().0,
        "call request has an unknown field \"gas\""
    );
    let missing = json!({"contract": "c", "function": "f"});
    assert_eq!(
        chain.call(&missing.to_string()).unwrap_err().0,
        "sender is required"
    );
    assert!(chain.call("[1]").is_err());
    assert!(chain.call("{").is_err());
}

#[test]
fn a_failed_call_reports_its_error_and_commits_nothing() {
    let chain = deployed();
    let before = chain.export();
    let outcome = call(
        &chain,
        "transfer",
        json!({"amount": {"__fixed__": "501"}, "to": "bob"}),
    );
    assert_eq!(outcome["status"], 1);
    assert_eq!(outcome["error"], "Insufficient balance.");
    assert_eq!(
        outcome["result"],
        r#""AssertionError('Insufficient balance.')""#
    );
    assert_eq!(outcome["exception"]["name"], "AssertionError");
    assert_eq!(
        outcome["exception"]["args"],
        json!(["\"Insufficient balance.\""])
    );
    assert_eq!(outcome["writes"], json!([]));
    assert_eq!(chain.export(), before);
}

#[test]
fn a_dry_run_leaves_state_unchanged() {
    let chain = deployed();
    let before = chain.export();
    let outcome = call_with(
        &chain,
        "transfer",
        json!({"amount": 5, "to": "bob"}),
        json!({"commit": false}),
    );
    assert_eq!(outcome["status"], 0);
    assert_eq!(outcome["writes"].as_array().unwrap().len(), 3);
    assert_eq!(chain.export(), before);
}

#[test]
fn metering_bounds_a_loop_and_can_be_switched_off() {
    let chain = deployed();
    let bounded = call_with(
        &chain,
        "spin",
        json!({"count": 100_000}),
        json!({"chi_budget": 50}),
    );
    assert_eq!(bounded["status"], 1);
    assert_eq!(bounded["chi_used"], 50);
    let unmetered = call_with(
        &chain,
        "spin",
        json!({"count": 100_000}),
        json!({"metering": false}),
    );
    assert_eq!(unmetered["status"], 0);
    assert_eq!(unmetered["result"], "4999950000");
}

#[test]
fn exports_round_trip_and_clones_are_independent() {
    let chain = deployed();
    let snapshot = chain.export();
    let imported = Sandbox::import(&snapshot).unwrap();
    assert_eq!(imported.export(), snapshot);
    assert_eq!(imported.state_root(), chain.state_root());
    let copy = chain.duplicate();
    call(&copy, "transfer", json!({"amount": 5, "to": "bob"}));
    assert_eq!(chain.export(), snapshot);
    assert_ne!(copy.export(), snapshot);
    assert_ne!(copy.state_root(), chain.state_root());
}

#[test]
fn imports_refuse_what_the_node_would_not_store() {
    let snapshot = |entries: Value| json!({"format": "xian-vm-state/1", "entries": entries});
    let refusals = [
        (snapshot(json!([["a", "1.5"]])), "snapshot value at \"a\""),
        (
            snapshot(json!([["a", r#"{"__fixed__":"1.50"}"#]])),
            "snapshot value at \"a\"",
        ),
        (
            snapshot(json!([["a", "{ \"x\": 1}"]])),
            "not in canonical stored form",
        ),
        (
            snapshot(json!([["k".repeat(512), "1"]])),
            "Storage key is too long",
        ),
        (json!({"format": "other", "entries": []}), "snapshot format"),
        (snapshot(json!({"a": "1"})), "snapshot entries"),
    ];
    for (snapshot, reason) in refusals {
        let error = Sandbox::import(&snapshot.to_string()).err().unwrap();
        assert!(error.0.contains(reason), "{error} lacks {reason}");
    }
}

#[test]
fn the_state_editor_writes_checked_values_and_removes_contracts() {
    let chain = deployed();
    chain
        .set_value("con_token.balances:carol", Some(r#"{"__fixed__":"2.5"}"#))
        .unwrap();
    assert_eq!(
        chain.get("con_token.balances:carol").as_deref(),
        Some(r#"{"__fixed__":"2.5"}"#)
    );
    chain.set_value("con_token.balances:carol", None).unwrap();
    assert_eq!(chain.get("con_token.balances:carol"), None);
    assert!(chain.set_value("x", Some("1.5")).is_err());
    assert!(chain.set_value(&"k".repeat(512), Some("1")).is_err());
    chain.remove_contract("con_token");
    assert_eq!(parsed(&chain.contracts()), json!(["submission"]));
    assert_eq!(parsed(&chain.items("con_token.", None)), json!([]));
}

#[test]
fn items_list_a_prefix_in_key_order_up_to_a_limit() {
    let chain = deployed();
    call(&chain, "transfer", json!({"amount": 5, "to": "bob"}));
    assert_eq!(
        parsed(&chain.items("con_token.balances:", None)),
        json!([
            ["con_token.balances:alice", r#"{"__fixed__":"495"}"#],
            ["con_token.balances:bob", r#"{"__fixed__":"5"}"#],
        ])
    );
    assert_eq!(
        parsed(&chain.items("con_token.balances:", Some(1)))
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn runtime_info_names_the_engine_revision() {
    let info = parsed(&runtime_info());
    assert_eq!(
        info["execution_revision"],
        crate::XIAN_VM_EXECUTION_REVISION
    );
    assert_eq!(info["gas_schedule"], "xvm-gas-6");
    assert_eq!(info["vm_profile"], "xian_vm_v2");
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
}

/// The scenario every backend runs (`tests/vectors/sandbox`): each step's
/// outcome on its own line, then the exported state and its root. The
/// golden transcript was written by the LMDB backend (xian-contracting
/// `tests/integration/test_vm_sandbox_parity.py`); the npm package's test
/// runs the same scenario through the WebAssembly build.
fn scenario_transcript() -> String {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/sandbox");
    let scenario: Value =
        serde_json::from_str(&std::fs::read_to_string(directory.join("scenario.json")).unwrap())
            .unwrap();
    let chain = Sandbox::create(&scenario["create"].to_string()).unwrap();
    let mut lines = Vec::new();
    for step in scenario["steps"].as_array().unwrap() {
        let (kind, request) = step.as_object().unwrap().iter().next().unwrap();
        let mut request = request.clone();
        if let Some(file) = request.as_object_mut().unwrap().remove("source_file") {
            let source = std::fs::read_to_string(directory.join(file.as_str().unwrap())).unwrap();
            request["source"] = Value::String(source);
        }
        let outcome = match kind.as_str() {
            "deploy" => chain.deploy(&request.to_string()),
            _ => chain.call(&request.to_string()),
        };
        lines.push(outcome.unwrap_or_else(|error| panic!("{step}: {error}")));
    }
    lines.push(chain.export());
    lines.push(chain.state_root().unwrap());
    lines.join("\n") + "\n"
}

#[test]
fn the_scenario_matches_the_lmdb_backend_byte_for_byte() {
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/sandbox");
    let transcript = scenario_transcript();
    if let Ok(path) = std::env::var("XIAN_SANDBOX_TRANSCRIPT_OUT") {
        std::fs::write(path, &transcript).unwrap();
    }
    let golden = std::fs::read_to_string(directory.join("transcript.txt")).unwrap();
    assert_eq!(transcript, golden);
}

/// A paid call of `transfer(amount)` with a 10,000-chi budget at 100 chi per
/// token: its receipt and the sender's native balance afterwards, next to
/// the chi the same call uses (a free dry run).
fn paid_transfer(amount: u64) -> (u64, Value, Option<String>) {
    let chain = deployed();
    chain.set_value("chi_cost.S:value", Some("100")).unwrap();
    chain
        .set_value("currency.balances:alice", Some("1000"))
        .unwrap();
    let kwargs = json!({"amount": amount, "to": "bob"});
    let budget = json!({"chi_budget": 10_000});
    let mut dry = budget.clone();
    dry["commit"] = json!(false);
    let used = call_with(&chain, "transfer", kwargs.clone(), dry)["chi_used"]
        .as_u64()
        .unwrap();
    let mut paid = budget;
    paid["charge_fees"] = json!(true);
    let outcome = call_with(&chain, "transfer", kwargs, paid);
    (used, outcome, chain.get("currency.balances:alice"))
}

/// `1000 - chi / 100` as the stored decimal.
fn balance_after(chi: u64) -> String {
    let cents = 100_000 - chi;
    let text = format!("{}.{:02}", cents / 100, cents % 100);
    let text = text.trim_end_matches('0').trim_end_matches('.');
    format!(r#"{{"__fixed__":"{text}"}}"#)
}

#[test]
fn a_paid_call_pays_half_of_the_chi_it_left_unused() {
    for (amount, status) in [(5, 0), (5_000, 1)] {
        let (used, outcome, balance) = paid_transfer(amount);
        assert_eq!(outcome["status"], status, "{outcome}");
        let charged = used + (10_000 - used) / 2;
        assert_eq!(outcome["chi_used"], charged, "{outcome}");
        assert_eq!(balance, Some(balance_after(charged)));
    }
}

/// A chain whose contracts `con_c0 .. con_c{length - 1}` each import the
/// one before; deployed by a factory.
fn import_chain(length: usize) -> Sandbox {
    let chain = chain();
    let factory = "@export\ndef build(start: int, n: int):\n    sub = importlib.import_module('submission')\n    for i in range(start, start + n):\n        code = '@export\\ndef f():\\n    return 1\\n'\n        if i > 0:\n            code = 'import con_c' + str(i - 1) + '\\n' + code\n        sub.submit_contract(name='con_c' + str(i), code=code)\n    return n\n";
    let deployed = parsed(
        &chain
            .deploy(
                &json!({"sender": "alice", "name": "con_factory", "source": factory,
                        "constructor_args": {}, "environment": environment()})
                .to_string(),
            )
            .unwrap(),
    );
    assert_eq!(deployed["status"], 0, "{deployed}");
    // A deployment costs 15,000 chi: at most 50 fit one transaction.
    for start in (0..length).step_by(50) {
        let batch = (length - start).min(50);
        let built = parsed(
            &chain
                .call(
                    &json!({"sender": "alice", "contract": "con_factory", "function": "build",
                            "kwargs": {"start": start, "n": batch}, "environment": environment()})
                    .to_string(),
                )
                .unwrap(),
        );
        assert_eq!(built["status"], 0, "{built}");
    }
    chain
}

fn call_top(chain: &Sandbox, top: usize) -> Value {
    parsed(
        &chain
            .call(
                &json!({"sender": "alice", "contract": format!("con_c{top}"), "function": "f",
                        "kwargs": {}, "environment": environment()})
                .to_string(),
            )
            .unwrap(),
    )
}

#[test]
fn an_import_graph_deeper_than_the_execution_depth_cannot_run() {
    // Preparation walks the static import graph recursively before any
    // chi is charged: a chain of a few thousand contracts would overflow
    // the validators' stack. The graph may be as deep as a call may be.
    let limit = crate::execution_stack::MAX_EXECUTION_DEPTH;
    let chain = import_chain(limit + 1);
    assert_eq!(call_top(&chain, limit - 1)["status"], 0);
    let refused = call_top(&chain, limit);
    assert_eq!(refused["status"], 1);
    assert_eq!(
        refused["error"],
        format!("xian_vm_v2 import graph is deeper than {limit} contracts: con_c{limit}")
    );
}

#[test]
fn an_import_cycle_cannot_run() {
    let chain = chain();
    for (name, imported) in [("con_x", "con_y"), ("con_y", "con_x")] {
        let source = format!("import {imported}\n@export\ndef f():\n    return 1\n");
        let deployed = parsed(
            &chain
                .deploy(
                    &json!({"sender": "alice", "name": name, "source": source,
                            "constructor_args": {}, "environment": environment()})
                    .to_string(),
                )
                .unwrap(),
        );
        assert_eq!(deployed["status"], 0, "{deployed}");
    }
    let refused = parsed(
        &chain
            .call(
                &json!({"sender": "alice", "contract": "con_x", "function": "f",
                        "kwargs": {}, "environment": environment()})
                .to_string(),
            )
            .unwrap(),
    );
    assert_eq!(
        refused["error"],
        "xian_vm_v2 import graph contains a cycle: con_x -> con_y -> con_x"
    );
}

/// A chain holding `source` as `con_probe`.
fn deployed_source(source: &str) -> Sandbox {
    let chain = chain();
    let deployed = parsed(
        &chain
            .deploy(
                &json!({"sender": "alice", "name": "con_probe", "source": source,
                        "constructor_args": {}, "environment": environment()})
                .to_string(),
            )
            .unwrap(),
    );
    assert_eq!(deployed["status"], 0, "{deployed}");
    chain
}

fn chi_of(chain: &Sandbox, function: &str, kwargs: Value) -> u64 {
    let outcome = parsed(
        &chain
            .call(
                &json!({"sender": "alice", "contract": "con_probe", "function": function,
                        "kwargs": kwargs, "environment": environment()})
                .to_string(),
            )
            .unwrap(),
    );
    assert_eq!(outcome["status"], 0, "{outcome}");
    outcome["chi_used"].as_u64().unwrap()
}

#[test]
fn shuffling_a_bytearray_pays_for_each_position() {
    // The shuffle expands the payload into one integer per byte, shuffles
    // their positions in the host and packs them back: work per byte,
    // which was charged only per 64 bytes of copied payload.
    let chain = deployed_source(
        "@export\ndef mix(n: int):\n    random.seed()\n    data = bytearray(n)\n    random.shuffle(data)\n    return len(data)\n",
    );
    let extra = 64_000u64;
    let small = chi_of(&chain, "mix", json!({"n": 64}));
    let large = chi_of(&chain, "mix", json!({"n": 64 + extra}));
    // One element-work unit (24 raw chi) per extra position at least.
    assert!(
        (large - small) * 1_000 >= extra * 24,
        "{extra} more bytes cost only {} chi",
        large - small
    );
}

#[test]
fn repeating_an_empty_sequence_is_empty_at_any_count() {
    // Python: [] * 2**64 == []. The count was converted to a machine word
    // first, so counts of 2**64 and more failed natively and counts of
    // 2**32 and more failed in the 32-bit browser build.
    let chain = deployed_source(
        "@export\ndef rep(k: int):\n    n = 2 ** k\n    return [len([] * n), len(n * ()), len('' * n), len(b'' * n), len(bytearray() * n)]\n\n@export\ndef big(k: int):\n    return len([1] * 2 ** k)\n",
    );
    let call = |function: &str, k: u32| {
        parsed(
            &chain
                .call(
                    &json!({"sender": "alice", "contract": "con_probe", "function": function,
                            "kwargs": {"k": k}, "environment": environment()})
                    .to_string(),
                )
                .unwrap(),
        )
    };
    for k in [33, 64, 200] {
        let outcome = call("rep", k);
        assert_eq!(outcome["status"], 0, "{outcome}");
        assert_eq!(outcome["result"], "[0,0,0,0,0]");
    }
    for k in [33, 64] {
        assert_eq!(
            call("big", k)["error"],
            "sequence repetition exceeds the maximum allowed allocation size"
        );
    }
}

/// `n` references to one 16 KiB payload handed to the host as a storage
/// value, a syscall argument or the result. The list costs a few hundred
/// chi to build; each crossing copies every reference in full.
const SHARED_PAYLOAD_CROSSINGS: &str = "v = Variable()\n\n@export\ndef cross(kind: str, n: int):\n    items = ['0x' + 'ab' * 8191] * n\n    if kind == 'set':\n        v.set(items)\n    if kind == 'syscall':\n        zk.shielded_output_payload_hashes(items)\n    if kind == 'return':\n        return items\n    return n\n";

#[test]
fn a_boundary_copy_is_paid_before_it_is_made() {
    // 8000 references copy 125 MiB, within the bound of one copy but far
    // beyond what 5000 chi pays for: the copy stops at the budget instead
    // of being made first and charged (or not) afterwards.
    let chain = deployed_source(SHARED_PAYLOAD_CROSSINGS);
    for kind in ["set", "syscall", "return"] {
        let outcome = parsed(
            &chain
                .call(
                    &json!({"sender": "alice", "contract": "con_probe", "function": "cross",
                            "kwargs": {"kind": kind, "n": 8_000}, "environment": environment(),
                            "chi_budget": 5_000})
                    .to_string(),
                )
                .unwrap(),
        );
        assert_eq!(outcome["status"], 1, "{kind}: {outcome}");
        assert_eq!(outcome["error"], "Out of chi.", "{kind}");
        assert_eq!(outcome["chi_used"], 5_000, "{kind}");
    }
}

#[test]
fn iterating_a_text_holds_no_copy_of_its_characters() {
    // A string iterator held one heap object per character, and the heap
    // keeps every iterator until the transaction ends: 32 joins of a
    // 20 KB text retained about 8 MB each and failed at the heap limit.
    let chain = deployed_source(
        "@export\ndef joins(n: int):\n    s = 'ab' * 10000\n    total = 0\n    for i in range(n):\n        total += len(''.join(s)) + len(''.join(reversed(s)))\n    for ch in s:\n        total += len(ch)\n    return total\n",
    );
    let outcome = parsed(
        &chain
            .call(
                &json!({"sender": "alice", "contract": "con_probe", "function": "joins",
                        "kwargs": {"n": 32}, "environment": environment()})
                .to_string(),
            )
            .unwrap(),
    );
    assert_eq!(outcome["status"], 0, "{outcome}");
    assert_eq!(outcome["result"], (32 * 40_000 + 20_000).to_string());
}
