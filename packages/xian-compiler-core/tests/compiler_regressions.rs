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
