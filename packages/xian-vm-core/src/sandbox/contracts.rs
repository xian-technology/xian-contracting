//! What a call form needs to know about a deployed contract: its stored
//! source and IR, its metadata, and its exported functions with their
//! arguments (`ContractInfo` in the package's API).
use super::outcome::{array, json_string, wire_text, Object};
use crate::block_host::{
    DEPLOYER_KEY, DEVELOPER_KEY, INITIATOR_KEY, IR_KEY, OWNER_KEY, SOURCE_KEY, TIME_KEY,
};
use crate::{parse_module_ir, FunctionIr, VmValue};

/// The contract of a key holding a deployed contract's IR.
pub(crate) fn contract_of_ir_key(key: &str) -> Option<&str> {
    key.split_once('.')
        .and_then(|(name, field)| (field == IR_KEY).then_some(name))
}

/// The keys of contract `name`'s metadata field `field`.
pub(crate) fn field_key(name: &str, field: &str) -> String {
    format!("{name}.{field}")
}

fn optional_text(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), json_string)
}

fn arguments_json(function: &FunctionIr) -> String {
    array(function.parameters.iter().map(|parameter| {
        Object::default()
            .text("name", &parameter.name)
            .raw("type", &optional_text(parameter.annotation.as_deref()))
            .text("kind", &parameter.kind)
            .raw(
                "optional",
                if parameter.default.is_some() {
                    "true"
                } else {
                    "false"
                },
            )
            .finish()
    }))
}

fn method_json(function: &FunctionIr) -> String {
    Object::default()
        .text("name", &function.name)
        .raw("arguments", &arguments_json(function))
        .raw("returns", &optional_text(function.returns.as_deref()))
        .raw("docstring", &optional_text(function.docstring.as_deref()))
        .finish()
}

fn construct_json(functions: &[FunctionIr]) -> String {
    functions
        .iter()
        .find(|function| function.visibility == "construct")
        .map_or_else(
            || "null".to_owned(),
            |function| {
                Object::default()
                    .text("name", &function.name)
                    .raw("arguments", &arguments_json(function))
                    .finish()
            },
        )
}

/// `ContractInfo` JSON of contract `name`, or `None` when it has no IR.
/// `read` returns the value stored at a key.
pub(crate) fn contract_json(name: &str, read: impl Fn(&str) -> Option<VmValue>) -> Option<String> {
    let text_at = |field: &str| match read(&field_key(name, field)) {
        Some(VmValue::String(text)) => Some(text),
        _ => None,
    };
    let ir = text_at(IR_KEY)?;
    let functions = parse_module_ir(&ir)
        .map(|module| module.functions)
        .unwrap_or_default();
    let exported = functions
        .iter()
        .filter(|function| function.visibility == "export");
    let metadata = |object: Object, label: &str, field: &str| {
        let value = read(&field_key(name, field));
        object.raw(
            label,
            &value.map_or_else(
                || "null".to_owned(),
                |value| json_string(&wire_text(&value)),
            ),
        )
    };
    let object = Object::default()
        .text("name", name)
        .raw("source", &optional_text(text_at(SOURCE_KEY).as_deref()))
        .text("vm_ir_json", &ir);
    let object = [
        ("owner", OWNER_KEY),
        ("developer", DEVELOPER_KEY),
        ("deployer", DEPLOYER_KEY),
        ("initiator", INITIATOR_KEY),
        ("submitted", TIME_KEY),
    ]
    .into_iter()
    .fold(object, |object, (label, field)| {
        metadata(object, label, field)
    });
    Some(
        object
            .raw("methods", &array(exported.map(method_json)))
            .raw("construct", &construct_json(&functions))
            .finish(),
    )
}
