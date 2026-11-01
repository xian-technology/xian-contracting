use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use xian_compiler_core::{lower_source_to_ir_json, CompileOptions};

#[test]
fn lower_source_preserves_interface_storage_type_host_bindings() {
    let source = r#"
TOKEN_INTERFACE = [
    importlib.Var("balances", Hash),
    importlib.Var("approvals", Hash),
    importlib.Var("metadata", Variable),
    importlib.Var("foreign_balances", ForeignHash),
    importlib.Var("foreign_owner", ForeignVariable),
]

@export
def interface():
    return TOKEN_INTERFACE
"#;

    let payload = lower_source_to_ir_json("interface_contract", source, &CompileOptions::default())
        .expect("interface source should lower");
    let ir: Value = serde_json::from_str(&payload).expect("IR JSON should parse");
    let elements = ir["global_declarations"][0]["value"]["elements"]
        .as_array()
        .expect("interface list should lower as array");
    let mut seen = BTreeMap::new();

    for element in elements {
        assert_eq!(element["syscall_id"], "contract.interface.var");
        assert_eq!(element["func"]["host_binding_id"], "contract.interface.var");

        let storage_name = element["args"][0]["value"]
            .as_str()
            .expect("interface variable name should be a string");
        let type_arg = &element["args"][1];
        seen.insert(
            storage_name.to_owned(),
            (
                type_arg["id"]
                    .as_str()
                    .expect("interface type should be a name")
                    .to_owned(),
                type_arg["host_binding_id"]
                    .as_str()
                    .expect("interface type should carry a host binding")
                    .to_owned(),
            ),
        );
    }

    assert_eq!(
        seen,
        BTreeMap::from([
            (
                "approvals".to_owned(),
                ("Hash".to_owned(), "storage.hash.new".to_owned()),
            ),
            (
                "balances".to_owned(),
                ("Hash".to_owned(), "storage.hash.new".to_owned()),
            ),
            (
                "foreign_balances".to_owned(),
                (
                    "ForeignHash".to_owned(),
                    "storage.foreign_hash.new".to_owned(),
                ),
            ),
            (
                "foreign_owner".to_owned(),
                (
                    "ForeignVariable".to_owned(),
                    "storage.foreign_variable.new".to_owned(),
                ),
            ),
            (
                "metadata".to_owned(),
                ("Variable".to_owned(), "storage.variable.new".to_owned()),
            ),
        ])
    );

    let dependency_ids = ir["host_dependencies"]
        .as_array()
        .expect("host dependencies should be an array")
        .iter()
        .map(|item| {
            item["id"]
                .as_str()
                .expect("host dependency should include an id")
        })
        .collect::<BTreeSet<_>>();

    assert!(dependency_ids.contains("contract.interface.var"));
    assert!(dependency_ids.contains("module.importlib"));
    assert!(dependency_ids.contains("storage.hash.new"));
    assert!(dependency_ids.contains("storage.variable.new"));
    assert!(dependency_ids.contains("storage.foreign_hash.new"));
    assert!(dependency_ids.contains("storage.foreign_variable.new"));
}

#[test]
fn lower_source_treats_contract_handle_helper_parameters_as_export_targets() {
    let source = r#"
def load_token(token: str):
    return importlib.import_module(token)

def assert_balance(token, account: str):
    return token.balance_of(address=account)

@export
def inspect(token_name: str, account: str):
    token = load_token(token_name)
    return assert_balance(token, account)
"#;

    let payload = lower_source_to_ir_json("handle_helper", source, &CompileOptions::default())
        .expect("helper source should lower");
    let ir: Value = serde_json::from_str(&payload).expect("IR JSON should parse");
    let functions = ir["functions"]
        .as_array()
        .expect("functions should be an array");
    let assert_balance = functions
        .iter()
        .find(|function| function["name"] == "assert_balance")
        .expect("assert_balance should be lowered");
    let lowered_call = &assert_balance["body"][0]["value"];

    assert_eq!(lowered_call["syscall_id"], "contract.export_call");
    assert_eq!(lowered_call["function_name"], "balance_of");
    assert_eq!(lowered_call["contract_target"]["kind"], "local_handle");
    assert_eq!(lowered_call["contract_target"]["binding"], "token");
    assert_eq!(lowered_call["contract_target"]["source"]["id"], "token");

    let dependency_ids = ir["host_dependencies"]
        .as_array()
        .expect("host dependencies should be an array")
        .iter()
        .map(|item| {
            item["id"]
                .as_str()
                .expect("host dependency should include an id")
        })
        .collect::<BTreeSet<_>>();
    assert!(dependency_ids.contains("contract.export_call"));
}

#[test]
fn lexical_comprehension_bindings_keep_only_outer_iterable_host_dispatch() {
    let source = "@export\ndef probe():\n    return [hashlib.sha3('x') for hashlib in hashlib.sha3('abc')]\n";
    let payload =
        lower_source_to_ir_json("con_scopes", source, &CompileOptions::default()).unwrap();
    let ir: Value = serde_json::from_str(&payload).unwrap();
    let expression = &ir["functions"][0]["body"][0]["value"];
    assert!(expression["element"]["syscall_id"].is_null());
    assert!(expression["element"]["func"]["host_binding_id"].is_null());
    assert_eq!(
        expression["generators"][0]["iter"]["syscall_id"],
        "hash.sha3_256_legacy"
    );
}

#[test]
fn lexical_later_generator_targets_shadow_earlier_filters() {
    let source =
        "@export\ndef probe():\n    return [x for x in [1] if hashlib for hashlib in [1]]\n";
    let payload =
        lower_source_to_ir_json("con_scopes", source, &CompileOptions::default()).unwrap();
    let ir: Value = serde_json::from_str(&payload).unwrap();
    let filter = &ir["functions"][0]["body"][0]["value"]["generators"][0]["ifs"][0];
    assert!(filter["host_binding_id"].is_null());
}

#[test]
fn lexical_storage_targets_are_plain_subscripts_even_before_local_assignment() {
    let source = "h = Hash()\n@export\ndef probe():\n    h[0] += 1\n    h = {}\n    return h[0]\n";
    let payload =
        lower_source_to_ir_json("con_scopes", source, &CompileOptions::default()).unwrap();
    let ir: Value = serde_json::from_str(&payload).unwrap();
    let body = &ir["functions"][0]["body"];
    assert_eq!(body[0]["node"], "aug_assign");
    assert_eq!(body[0]["target"]["node"], "subscript");
    assert_eq!(body[2]["value"]["node"], "subscript");
}

#[test]
fn lexical_variadic_parameters_shadow_module_calls() {
    for parameters in ["*hashlib", "**hashlib"] {
        let source = format!("def probe({parameters}):\n    return hashlib.sha3('x')\n@export\ndef public_probe():\n    return 1\n");
        let payload =
            lower_source_to_ir_json("con_scopes", &source, &CompileOptions::default()).unwrap();
        let ir: Value = serde_json::from_str(&payload).unwrap();
        let call = &ir["functions"][0]["body"][0]["value"];
        assert!(call["syscall_id"].is_null());
        assert!(call["func"]["value"]["host_binding_id"].is_null());
    }
}
