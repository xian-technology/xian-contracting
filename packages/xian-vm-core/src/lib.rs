#![recursion_limit = "256"]

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::fmt;

mod interpreter;
mod metering;

pub const XIAN_IR_V1: &str = "xian_ir_v1";
pub const XIAN_VM_V1_PROFILE: &str = "xian_vm_v1";
pub const XIAN_VM_HOST_CATALOG_V1: &str = "xian_vm_v1_host_v1";
pub const XIAN_VM_SUPPORTED_BYTECODE_VERSIONS: &[&str] = &["xvm-1"];
pub const XIAN_VM_SUPPORTED_GAS_SCHEDULES: &[&str] = &["xvm-gas-1"];

pub use interpreter::*;
pub use metering::*;

#[cfg(feature = "python-extension")]
mod python_bindings;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub line: u64,
    pub col: u64,
    pub end_line: u64,
    pub end_col: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportIr {
    pub node: String,
    pub span: Span,
    pub module: String,
    pub alias: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostDependency {
    pub binding: String,
    pub id: String,
    pub kind: String,
    pub category: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParameterIr {
    pub name: String,
    pub kind: String,
    pub annotation: Option<String>,
    pub default: Option<Value>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecoratorIr {
    pub node: String,
    pub span: Span,
    pub name: String,
    pub args: Vec<Value>,
    pub keywords: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionIr {
    pub node: String,
    pub span: Span,
    pub name: String,
    pub visibility: String,
    pub decorator: Option<DecoratorIr>,
    pub docstring: Option<String>,
    pub parameters: Vec<ParameterIr>,
    pub returns: Option<String>,
    pub body: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleIr {
    pub ir_version: String,
    pub vm_profile: String,
    pub host_catalog_version: String,
    pub module_name: String,
    pub source_hash: String,
    pub docstring: Option<String>,
    pub imports: Vec<ImportIr>,
    pub global_declarations: Vec<Value>,
    pub functions: Vec<FunctionIr>,
    pub module_body: Vec<Value>,
    pub host_dependencies: Vec<HostDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrValidationError {
    message: String,
}

impl IrValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for IrValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IrValidationError {}

pub fn parse_module_ir(input: &str) -> Result<ModuleIr, IrValidationError> {
    let module: ModuleIr =
        serde_json::from_str(input).map_err(|err| IrValidationError::new(err.to_string()))?;
    validate_module_ir(&module)?;
    Ok(module)
}

pub fn validate_module_ir(module: &ModuleIr) -> Result<(), IrValidationError> {
    if module.ir_version != XIAN_IR_V1 {
        return Err(IrValidationError::new(format!(
            "unsupported ir_version '{}'",
            module.ir_version
        )));
    }
    if module.vm_profile != XIAN_VM_V1_PROFILE {
        return Err(IrValidationError::new(format!(
            "unsupported vm_profile '{}'",
            module.vm_profile
        )));
    }
    if module.host_catalog_version != XIAN_VM_HOST_CATALOG_V1 {
        return Err(IrValidationError::new(format!(
            "unsupported host_catalog_version '{}'",
            module.host_catalog_version
        )));
    }
    ensure_non_empty("module_name", &module.module_name)?;
    ensure_hex_hash("source_hash", &module.source_hash)?;

    let mut seen_imports = HashSet::new();
    for import in &module.imports {
        validate_import(import)?;
        let key = import.alias.as_deref().unwrap_or(&import.module);
        if !seen_imports.insert(key.to_owned()) {
            return Err(IrValidationError::new(format!(
                "duplicate import binding '{}'",
                key
            )));
        }
    }

    let mut global_names = HashSet::new();
    for declaration in &module.global_declarations {
        let name = validate_global_declaration(declaration)?;
        if !global_names.insert(name.clone()) {
            return Err(IrValidationError::new(format!(
                "duplicate global declaration '{}'",
                name
            )));
        }
    }

    let mut function_names = HashSet::new();
    for function in &module.functions {
        validate_function(function)?;
        if !function_names.insert(function.name.clone()) {
            return Err(IrValidationError::new(format!(
                "duplicate function '{}'",
                function.name
            )));
        }
    }

    for statement in &module.module_body {
        validate_statement(statement)?;
    }

    let mut dependency_ids = HashSet::new();
    for dependency in &module.host_dependencies {
        validate_host_dependency(dependency)?;
        if !dependency_ids.insert(dependency.id.clone()) {
            return Err(IrValidationError::new(format!(
                "duplicate host dependency '{}'",
                dependency.id
            )));
        }
    }

    Ok(())
}

fn validate_import(import: &ImportIr) -> Result<(), IrValidationError> {
    if import.node != "import" {
        return Err(IrValidationError::new("import node must be 'import'"));
    }
    validate_span(&import.span)?;
    ensure_non_empty("import.module", &import.module)?;
    if let Some(alias) = &import.alias {
        ensure_non_empty("import.alias", alias)?;
    }
    Ok(())
}

fn validate_host_dependency(dependency: &HostDependency) -> Result<(), IrValidationError> {
    ensure_non_empty("host_dependency.binding", &dependency.binding)?;
    ensure_non_empty("host_dependency.id", &dependency.id)?;
    ensure_non_empty("host_dependency.kind", &dependency.kind)?;
    ensure_non_empty("host_dependency.category", &dependency.category)?;
    ensure_allowed(
        "host_dependency.kind",
        &dependency.kind,
        &[
            "syscall",
            "context_field",
            "env_value",
            "type_marker",
            "value",
        ],
    )
}

fn validate_function(function: &FunctionIr) -> Result<(), IrValidationError> {
    if function.node != "function" {
        return Err(IrValidationError::new("function node must be 'function'"));
    }
    validate_span(&function.span)?;
    ensure_non_empty("function.name", &function.name)?;
    ensure_allowed(
        "function.visibility",
        &function.visibility,
        &["construct", "export", "private"],
    )?;

    if let Some(decorator) = &function.decorator {
        if decorator.node != "decorator" {
            return Err(IrValidationError::new("decorator node must be 'decorator'"));
        }
        validate_span(&decorator.span)?;
        ensure_non_empty("decorator.name", &decorator.name)?;
        for value in &decorator.args {
            validate_expression(value)?;
        }
        for keyword in &decorator.keywords {
            validate_keyword(keyword)?;
        }
    }

    for parameter in &function.parameters {
        validate_parameter(parameter)?;
    }

    for statement in &function.body {
        validate_statement(statement)?;
    }

    Ok(())
}

fn validate_parameter(parameter: &ParameterIr) -> Result<(), IrValidationError> {
    ensure_non_empty("parameter.name", &parameter.name)?;
    ensure_allowed(
        "parameter.kind",
        &parameter.kind,
        &["positional_or_keyword", "keyword_only", "vararg", "kwarg"],
    )?;
    validate_span(&parameter.span)?;
    if let Some(default) = &parameter.default {
        validate_expression(default)?;
    }
    Ok(())
}

fn validate_global_declaration(declaration: &Value) -> Result<String, IrValidationError> {
    let object = expect_object(declaration, "global declaration")?;
    let node = expect_string_field(object, "node")?;
    validate_object_span(object)?;
    let name = expect_string_field(object, "name")?.to_owned();
    ensure_non_empty("global_declaration.name", &name)?;

    match node {
        "storage_decl" => {
            ensure_non_empty(
                "storage_decl.storage_type",
                expect_string_field(object, "storage_type")?,
            )?;
            ensure_non_empty(
                "storage_decl.syscall_id",
                expect_string_field(object, "syscall_id")?,
            )?;
            for argument in expect_array_field(object, "args")? {
                validate_expression(argument)?;
            }
            for keyword in expect_array_field(object, "keywords")? {
                validate_keyword(keyword)?;
            }
        }
        "event_decl" => {
            ensure_non_empty(
                "event_decl.syscall_id",
                expect_string_field(object, "syscall_id")?,
            )?;
            ensure_non_empty(
                "event_decl.event_name",
                expect_string_field(object, "event_name")?,
            )?;
            validate_expression(expect_value_field(object, "params")?)?;
        }
        "binding_decl" => {
            validate_expression(expect_value_field(object, "value")?)?;
        }
        _ => {
            return Err(IrValidationError::new(format!(
                "unsupported global declaration node '{}'",
                node
            )))
        }
    }

    Ok(name)
}

fn validate_statement(statement: &Value) -> Result<(), IrValidationError> {
    let object = expect_object(statement, "statement")?;
    let node = expect_string_field(object, "node")?;
    validate_object_span(object)?;

    match node {
        "assign" => {
            for target in expect_array_field(object, "targets")? {
                validate_target(target)?;
            }
            validate_expression(expect_value_field(object, "value")?)?;
        }
        "storage_set" => {
            validate_storage_access_base(object, &["Hash"], "syscall_id", &["storage.hash.set"])?;
            validate_expression(expect_value_field(object, "key")?)?;
            validate_expression(expect_value_field(object, "value")?)?;
        }
        "storage_mutate" => {
            validate_storage_access_base(
                object,
                &["Hash"],
                "write_syscall_id",
                &["storage.hash.set"],
            )?;
            ensure_allowed(
                "storage_mutate.read_syscall_id",
                expect_string_field(object, "read_syscall_id")?,
                &["storage.hash.get"],
            )?;
            validate_expression(expect_value_field(object, "key")?)?;
            ensure_allowed(
                "storage_mutate.operator",
                expect_string_field(object, "operator")?,
                &["add", "sub", "mul", "div", "floordiv", "mod", "pow"],
            )?;
            validate_expression(expect_value_field(object, "value")?)?;
        }
        "aug_assign" => {
            ensure_allowed(
                "aug_assign.operator",
                expect_string_field(object, "operator")?,
                &["add", "sub", "mul", "div", "floordiv", "mod", "pow"],
            )?;
            validate_target(expect_value_field(object, "target")?)?;
            validate_expression(expect_value_field(object, "value")?)?;
        }
        "return" => {
            if let Some(value) = object.get("value") {
                if !value.is_null() {
                    validate_expression(value)?;
                }
            }
        }
        "expr" => {
            validate_expression(expect_value_field(object, "value")?)?;
        }
        "if" => {
            validate_expression(expect_value_field(object, "test")?)?;
            validate_statement_array(expect_array_field(object, "body")?)?;
            validate_statement_array(expect_array_field(object, "orelse")?)?;
        }
        "for" => {
            validate_target(expect_value_field(object, "target")?)?;
            validate_expression(expect_value_field(object, "iter")?)?;
            validate_statement_array(expect_array_field(object, "body")?)?;
            validate_statement_array(expect_array_field(object, "orelse")?)?;
        }
        "assert" => {
            validate_expression(expect_value_field(object, "test")?)?;
            if let Some(value) = object.get("message") {
                if !value.is_null() {
                    validate_expression(value)?;
                }
            }
        }
        "break" | "continue" | "pass" => {}
        _ => {
            return Err(IrValidationError::new(format!(
                "unsupported statement node '{}'",
                node
            )))
        }
    }

    Ok(())
}

fn validate_statement_array(values: &[Value]) -> Result<(), IrValidationError> {
    for value in values {
        validate_statement(value)?;
    }
    Ok(())
}

fn validate_storage_access_base(
    object: &Map<String, Value>,
    allowed_storage_types: &[&str],
    syscall_field: &str,
    allowed_syscalls: &[&str],
) -> Result<(), IrValidationError> {
    ensure_non_empty("storage.binding", expect_string_field(object, "binding")?)?;
    ensure_allowed(
        "storage.storage_type",
        expect_string_field(object, "storage_type")?,
        allowed_storage_types,
    )?;
    ensure_allowed(
        syscall_field,
        expect_string_field(object, syscall_field)?,
        allowed_syscalls,
    )
}

fn validate_target(target: &Value) -> Result<(), IrValidationError> {
    let object = expect_object(target, "target")?;
    let node = expect_string_field(object, "node")?;
    validate_object_span(object)?;

    match node {
        "name" => ensure_non_empty("target.name.id", expect_string_field(object, "id")?),
        "attribute" => {
            validate_expression(expect_value_field(object, "value")?)?;
            ensure_non_empty(
                "target.attribute.attr",
                expect_string_field(object, "attr")?,
            )?;
            Ok(())
        }
        "subscript" => {
            validate_expression(expect_value_field(object, "value")?)?;
            validate_expression(expect_value_field(object, "slice")?)?;
            Ok(())
        }
        "tuple_target" | "list_target" => {
            for value in expect_array_field(object, "elements")? {
                validate_target(value)?;
            }
            Ok(())
        }
        _ => Err(IrValidationError::new(format!(
            "unsupported target node '{}'",
            node
        ))),
    }
}

fn validate_expression(expression: &Value) -> Result<(), IrValidationError> {
    let object = expect_object(expression, "expression")?;
    let node = expect_string_field(object, "node")?;
    validate_object_span(object)?;

    match node {
        "name" => ensure_non_empty("expression.name.id", expect_string_field(object, "id")?),
        "constant" => {
            ensure_allowed(
                "expression.constant.value_type",
                expect_string_field(object, "value_type")?,
                &["none", "bool", "int", "float", "str"],
            )?;
            if object.get("value_type").and_then(Value::as_str) == Some("float") {
                ensure_non_empty(
                    "expression.constant.literal",
                    expect_string_field(object, "literal")?,
                )?;
            }
            Ok(())
        }
        "list" | "tuple" | "f_string" => {
            for value in expect_array_field(object, "elements")
                .or_else(|_| expect_array_field(object, "values"))?
            {
                validate_expression(value)?;
            }
            Ok(())
        }
        "dict" => {
            for entry in expect_array_field(object, "entries")? {
                let entry_obj = expect_object(entry, "dict entry")?;
                validate_expression(expect_value_field(entry_obj, "key")?)?;
                validate_expression(expect_value_field(entry_obj, "value")?)?;
            }
            Ok(())
        }
        "attribute" => {
            validate_expression(expect_value_field(object, "value")?)?;
            ensure_non_empty(
                "expression.attribute.attr",
                expect_string_field(object, "attr")?,
            )?;
            Ok(())
        }
        "subscript" => {
            validate_expression(expect_value_field(object, "value")?)?;
            validate_expression(expect_value_field(object, "slice")?)?;
            Ok(())
        }
        "storage_get" => {
            validate_storage_access_base(
                object,
                &["Hash", "ForeignHash"],
                "syscall_id",
                &["storage.hash.get", "storage.foreign_hash.get"],
            )?;
            validate_expression(expect_value_field(object, "key")?)?;
            Ok(())
        }
        "slice" => {
            validate_optional_expression(object.get("lower"))?;
            validate_optional_expression(object.get("upper"))?;
            validate_optional_expression(object.get("step"))?;
            Ok(())
        }
        "call" => {
            validate_expression(expect_value_field(object, "func")?)?;
            for argument in expect_array_field(object, "args")? {
                validate_expression(argument)?;
            }
            for keyword in expect_array_field(object, "keywords")? {
                validate_keyword(keyword)?;
            }
            validate_optional_non_empty_string(object.get("syscall_id"))?;
            validate_optional_non_empty_string(object.get("event_binding"))?;
            validate_optional_non_empty_string(object.get("receiver_binding"))?;
            validate_optional_non_empty_string(object.get("receiver_type"))?;
            validate_optional_non_empty_string(object.get("method"))?;
            validate_optional_non_empty_string(object.get("function_name"))?;
            validate_optional_contract_target(object.get("contract_target"))?;

            if let Some(syscall_id) = object.get("syscall_id").and_then(Value::as_str) {
                match syscall_id {
                    "storage.variable.get"
                    | "storage.variable.set"
                    | "storage.foreign_variable.get" => {
                        ensure_non_empty(
                            "call.receiver_binding",
                            expect_string_field(object, "receiver_binding")?,
                        )?;
                        ensure_allowed(
                            "call.receiver_type",
                            expect_string_field(object, "receiver_type")?,
                            &["Variable", "ForeignVariable"],
                        )?;
                        ensure_non_empty("call.method", expect_string_field(object, "method")?)?;
                    }
                    "contract.export_call" => {
                        ensure_non_empty(
                            "call.function_name",
                            expect_string_field(object, "function_name")?,
                        )?;
                        validate_contract_target(expect_value_field(object, "contract_target")?)?;
                    }
                    "event.log.emit" => {
                        ensure_non_empty(
                            "call.event_binding",
                            expect_string_field(object, "event_binding")?,
                        )?;
                    }
                    _ => {}
                }
            }
            Ok(())
        }
        "compare" => {
            validate_expression(expect_value_field(object, "left")?)?;
            for operator in expect_array_field(object, "operators")? {
                let name = expect_string(operator, "compare operator")?;
                ensure_allowed(
                    "compare.operator",
                    name,
                    &[
                        "eq", "not_eq", "gt", "gt_e", "lt", "lt_e", "in", "not_in", "is", "is_not",
                    ],
                )?;
            }
            for comparator in expect_array_field(object, "comparators")? {
                validate_expression(comparator)?;
            }
            Ok(())
        }
        "bool_op" => {
            ensure_allowed(
                "bool_op.operator",
                expect_string_field(object, "operator")?,
                &["and", "or"],
            )?;
            for value in expect_array_field(object, "values")? {
                validate_expression(value)?;
            }
            Ok(())
        }
        "bin_op" => {
            ensure_allowed(
                "bin_op.operator",
                expect_string_field(object, "operator")?,
                &["add", "sub", "mul", "div", "floordiv", "mod", "pow"],
            )?;
            validate_expression(expect_value_field(object, "left")?)?;
            validate_expression(expect_value_field(object, "right")?)?;
            Ok(())
        }
        "unary_op" => {
            ensure_allowed(
                "unary_op.operator",
                expect_string_field(object, "operator")?,
                &["not", "neg", "pos"],
            )?;
            validate_expression(expect_value_field(object, "operand")?)?;
            Ok(())
        }
        "if_expr" => {
            validate_expression(expect_value_field(object, "test")?)?;
            validate_expression(expect_value_field(object, "body")?)?;
            validate_expression(expect_value_field(object, "orelse")?)?;
            Ok(())
        }
        "formatted_value" => {
            validate_expression(expect_value_field(object, "value")?)?;
            validate_optional_non_empty_string(object.get("conversion"))?;
            validate_optional_expression(object.get("format_spec"))?;
            Ok(())
        }
        _ => Err(IrValidationError::new(format!(
            "unsupported expression node '{}'",
            node
        ))),
    }
}

fn validate_optional_expression(value: Option<&Value>) -> Result<(), IrValidationError> {
    if let Some(value) = value {
        if !value.is_null() {
            validate_expression(value)?;
        }
    }
    Ok(())
}

fn validate_keyword(keyword: &Value) -> Result<(), IrValidationError> {
    let object = expect_object(keyword, "keyword")?;
    validate_object_span(object)?;
    ensure_non_empty("keyword.arg", expect_string_field(object, "arg")?)?;
    validate_expression(expect_value_field(object, "value")?)?;
    Ok(())
}

fn validate_optional_contract_target(value: Option<&Value>) -> Result<(), IrValidationError> {
    if let Some(value) = value {
        if !value.is_null() {
            validate_contract_target(value)?;
        }
    }
    Ok(())
}

fn validate_contract_target(value: &Value) -> Result<(), IrValidationError> {
    let object = expect_object(value, "contract_target")?;
    validate_object_span(object)?;
    let kind = expect_string_field(object, "kind")?;
    ensure_allowed(
        "contract_target.kind",
        kind,
        &[
            "static_import",
            "local_handle",
            "dynamic_import",
            "factory_call",
        ],
    )?;

    match kind {
        "static_import" => {
            ensure_non_empty(
                "contract_target.binding",
                expect_string_field(object, "binding")?,
            )?;
        }
        "local_handle" => {
            ensure_non_empty(
                "contract_target.binding",
                expect_string_field(object, "binding")?,
            )?;
            validate_expression(expect_value_field(object, "source")?)?;
        }
        "dynamic_import" => {
            validate_expression(expect_value_field(object, "source")?)?;
        }
        "factory_call" => {
            ensure_non_empty(
                "contract_target.factory",
                expect_string_field(object, "factory")?,
            )?;
            validate_expression(expect_value_field(object, "source")?)?;
        }
        _ => unreachable!(),
    }

    Ok(())
}

fn validate_span(span: &Span) -> Result<(), IrValidationError> {
    if span.end_line < span.line {
        return Err(IrValidationError::new("span.end_line must be >= span.line"));
    }
    if span.line == 0 || span.end_line == 0 {
        return Err(IrValidationError::new("span line values must be positive"));
    }
    Ok(())
}

fn validate_object_span(object: &Map<String, Value>) -> Result<(), IrValidationError> {
    let span_value = expect_value_field(object, "span")?;
    let span: Span = serde_json::from_value(span_value.clone())
        .map_err(|err| IrValidationError::new(err.to_string()))?;
    validate_span(&span)
}

fn ensure_non_empty(label: &str, value: &str) -> Result<(), IrValidationError> {
    if value.is_empty() {
        return Err(IrValidationError::new(format!(
            "{} must not be empty",
            label
        )));
    }
    Ok(())
}

fn ensure_allowed(label: &str, value: &str, allowed: &[&str]) -> Result<(), IrValidationError> {
    if allowed.iter().any(|item| item == &value) {
        return Ok(());
    }
    Err(IrValidationError::new(format!(
        "{} has unsupported value '{}'",
        label, value
    )))
}

fn ensure_hex_hash(label: &str, value: &str) -> Result<(), IrValidationError> {
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(IrValidationError::new(format!(
            "{} must be a 64-character hex string",
            label
        )));
    }
    Ok(())
}

fn expect_object<'a>(
    value: &'a Value,
    label: &str,
) -> Result<&'a Map<String, Value>, IrValidationError> {
    value
        .as_object()
        .ok_or_else(|| IrValidationError::new(format!("{} must be an object", label)))
}

fn expect_value_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Value, IrValidationError> {
    object
        .get(field)
        .ok_or_else(|| IrValidationError::new(format!("missing required field '{}'", field)))
}

fn expect_string_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, IrValidationError> {
    let value = expect_value_field(object, field)?;
    expect_string(value, field)
}

fn expect_string<'a>(value: &'a Value, label: &str) -> Result<&'a str, IrValidationError> {
    value
        .as_str()
        .ok_or_else(|| IrValidationError::new(format!("{} must be a string", label)))
}

fn expect_array_field<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a [Value], IrValidationError> {
    expect_value_field(object, field)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| IrValidationError::new(format!("{} must be an array", field)))
}

fn validate_optional_non_empty_string(value: Option<&Value>) -> Result<(), IrValidationError> {
    if let Some(value) = value {
        if value.is_null() {
            return Ok(());
        }
        ensure_non_empty("optional string", expect_string(value, "optional string")?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_module_ir, validate_module_ir, ModuleIr};
    use serde_json::{json, Value};

    fn sample_module_value() -> Value {
        json!({
            "ir_version": "xian_ir_v1",
            "vm_profile": "xian_vm_v1",
            "host_catalog_version": "xian_vm_v1_host_v1",
            "module_name": "sample_token",
            "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "docstring": null,
            "imports": [],
            "global_declarations": [
                {
                    "node": "storage_decl",
                    "span": {"line": 1, "col": 0, "end_line": 1, "end_col": 28},
                    "name": "balances",
                    "storage_type": "Hash",
                    "syscall_id": "storage.hash.new",
                    "args": [],
                    "keywords": [
                        {
                            "arg": "default_value",
                            "span": {"line": 1, "col": 16, "end_line": 1, "end_col": 27},
                            "value": {
                                "node": "constant",
                                "span": {"line": 1, "col": 26, "end_line": 1, "end_col": 27},
                                "value_type": "int",
                                "value": 0
                            }
                        }
                    ]
                }
            ],
            "functions": [
                {
                    "node": "function",
                    "span": {"line": 3, "col": 0, "end_line": 5, "end_col": 23},
                    "name": "balance_of",
                    "visibility": "export",
                    "decorator": {
                        "node": "decorator",
                        "span": {"line": 2, "col": 1, "end_line": 2, "end_col": 7},
                        "name": "export",
                        "args": [],
                        "keywords": []
                    },
                    "docstring": null,
                    "parameters": [
                        {
                            "name": "account",
                            "kind": "positional_or_keyword",
                            "annotation": "str",
                            "default": null,
                            "span": {"line": 3, "col": 15, "end_line": 3, "end_col": 27}
                        }
                    ],
                    "returns": "int",
                    "body": [
                        {
                            "node": "return",
                            "span": {"line": 5, "col": 4, "end_line": 5, "end_col": 23},
                            "value": {
                                "node": "subscript",
                                "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 23},
                                "value": {
                                    "node": "name",
                                    "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 19},
                                    "id": "balances",
                                    "host_binding_id": null
                                },
                                "slice": {
                                    "node": "name",
                                    "span": {"line": 5, "col": 20, "end_line": 5, "end_col": 27},
                                    "id": "account",
                                    "host_binding_id": null
                                }
                            }
                        }
                    ]
                }
            ],
            "module_body": [],
            "host_dependencies": [
                {
                    "binding": "Hash",
                    "id": "storage.hash.new",
                    "kind": "syscall",
                    "category": "storage"
                }
            ]
        })
    }

    #[test]
    fn parses_and_validates_ir() {
        let payload = sample_module_value().to_string();
        let parsed = parse_module_ir(&payload).expect("valid ir");

        assert_eq!(parsed.module_name, "sample_token");
        assert_eq!(parsed.functions.len(), 1);
    }

    #[test]
    fn rejects_duplicate_function_names() {
        let mut value = sample_module_value();
        let functions = value
            .get_mut("functions")
            .and_then(Value::as_array_mut)
            .expect("functions array");
        let clone = functions[0].clone();
        functions.push(clone);

        let module: ModuleIr = serde_json::from_value(value).expect("module should deserialize");
        let error = validate_module_ir(&module).expect_err("must fail");
        assert!(error.to_string().contains("duplicate function"));
    }

    #[test]
    fn rejects_unknown_statement_node() {
        let mut value = sample_module_value();
        let functions = value
            .get_mut("functions")
            .and_then(Value::as_array_mut)
            .expect("functions array");
        let body = functions[0]
            .get_mut("body")
            .and_then(Value::as_array_mut)
            .expect("body");
        body[0]["node"] = Value::String("mystery".to_owned());

        let module: ModuleIr = serde_json::from_value(value).expect("module should deserialize");
        let error = validate_module_ir(&module).expect_err("must fail");
        assert!(error.to_string().contains("unsupported statement node"));
    }

    #[test]
    fn validates_explicit_runtime_ops() {
        let value = json!({
            "ir_version": "xian_ir_v1",
            "vm_profile": "xian_vm_v1",
            "host_catalog_version": "xian_vm_v1_host_v1",
            "module_name": "sample_token",
            "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "docstring": null,
            "imports": [
                {
                    "node": "import",
                    "span": {"line": 1, "col": 0, "end_line": 1, "end_col": 15},
                    "module": "currency",
                    "alias": null
                }
            ],
            "global_declarations": [
                {
                    "node": "storage_decl",
                    "span": {"line": 2, "col": 0, "end_line": 2, "end_col": 28},
                    "name": "balances",
                    "storage_type": "Hash",
                    "syscall_id": "storage.hash.new",
                    "args": [],
                    "keywords": []
                },
                {
                    "node": "storage_decl",
                    "span": {"line": 3, "col": 0, "end_line": 3, "end_col": 18},
                    "name": "metadata",
                    "storage_type": "Variable",
                    "syscall_id": "storage.variable.new",
                    "args": [],
                    "keywords": []
                }
            ],
            "functions": [
                {
                    "node": "function",
                    "span": {"line": 5, "col": 0, "end_line": 14, "end_col": 23},
                    "name": "transfer",
                    "visibility": "export",
                    "decorator": {
                        "node": "decorator",
                        "span": {"line": 4, "col": 1, "end_line": 4, "end_col": 7},
                        "name": "export",
                        "args": [],
                        "keywords": []
                    },
                    "docstring": null,
                    "parameters": [
                        {
                            "name": "amount",
                            "kind": "positional_or_keyword",
                            "annotation": "int",
                            "default": null,
                            "span": {"line": 5, "col": 13, "end_line": 5, "end_col": 24}
                        },
                        {
                            "name": "to",
                            "kind": "positional_or_keyword",
                            "annotation": "str",
                            "default": null,
                            "span": {"line": 5, "col": 26, "end_line": 5, "end_col": 33}
                        }
                    ],
                    "returns": null,
                    "body": [
                        {
                            "node": "expr",
                            "span": {"line": 6, "col": 4, "end_line": 6, "end_col": 21},
                            "value": {
                                "node": "call",
                                "span": {"line": 6, "col": 4, "end_line": 6, "end_col": 21},
                                "func": {
                                    "node": "attribute",
                                    "span": {"line": 6, "col": 4, "end_line": 6, "end_col": 16},
                                    "value": {
                                        "node": "name",
                                        "span": {"line": 6, "col": 4, "end_line": 6, "end_col": 12},
                                        "id": "metadata",
                                        "host_binding_id": null
                                    },
                                    "attr": "set",
                                    "path": "metadata.set",
                                    "host_binding_id": null
                                },
                                "args": [
                                    {
                                        "node": "name",
                                        "span": {"line": 6, "col": 17, "end_line": 6, "end_col": 20},
                                        "id": "now",
                                        "host_binding_id": "env.now"
                                    }
                                ],
                                "keywords": [],
                                "syscall_id": "storage.variable.set",
                                "receiver_binding": "metadata",
                                "receiver_type": "Variable",
                                "method": "set"
                            }
                        },
                        {
                            "node": "storage_mutate",
                            "span": {"line": 7, "col": 4, "end_line": 7, "end_col": 26},
                            "binding": "balances",
                            "storage_type": "Hash",
                            "read_syscall_id": "storage.hash.get",
                            "write_syscall_id": "storage.hash.set",
                            "key": {
                                "node": "name",
                                "span": {"line": 7, "col": 13, "end_line": 7, "end_col": 15},
                                "id": "to",
                                "host_binding_id": null
                            },
                            "operator": "add",
                            "value": {
                                "node": "name",
                                "span": {"line": 7, "col": 20, "end_line": 7, "end_col": 26},
                                "id": "amount",
                                "host_binding_id": null
                            }
                        },
                        {
                            "node": "expr",
                            "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 43},
                            "value": {
                                "node": "call",
                                "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 43},
                                "func": {
                                    "node": "attribute",
                                    "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 21},
                                    "value": {
                                        "node": "name",
                                        "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 12},
                                        "id": "currency",
                                        "host_binding_id": null
                                    },
                                    "attr": "transfer",
                                    "path": "currency.transfer",
                                    "host_binding_id": null
                                },
                                "args": [],
                                "keywords": [
                                    {
                                        "arg": "amount",
                                        "span": {"line": 8, "col": 22, "end_line": 8, "end_col": 35},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 8, "col": 29, "end_line": 8, "end_col": 35},
                                            "id": "amount",
                                            "host_binding_id": null
                                        }
                                    },
                                    {
                                        "arg": "to",
                                        "span": {"line": 8, "col": 37, "end_line": 8, "end_col": 42},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 8, "col": 40, "end_line": 8, "end_col": 42},
                                            "id": "to",
                                            "host_binding_id": null
                                        }
                                    }
                                ],
                                "syscall_id": "contract.export_call",
                                "contract_target": {
                                    "kind": "static_import",
                                    "binding": "currency",
                                    "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 12}
                                },
                                "function_name": "transfer"
                            }
                        },
                        {
                            "node": "return",
                            "span": {"line": 9, "col": 4, "end_line": 9, "end_col": 23},
                            "value": {
                                "node": "storage_get",
                                "span": {"line": 9, "col": 11, "end_line": 9, "end_col": 23},
                                "binding": "balances",
                                "storage_type": "Hash",
                                "syscall_id": "storage.hash.get",
                                "key": {
                                    "node": "name",
                                    "span": {"line": 9, "col": 20, "end_line": 9, "end_col": 22},
                                    "id": "to",
                                    "host_binding_id": null
                                }
                            }
                        }
                    ]
                }
            ],
            "module_body": [],
            "host_dependencies": [
                {"binding": "Variable", "id": "storage.variable.new", "kind": "syscall", "category": "storage"},
                {"binding": "Variable.set", "id": "storage.variable.set", "kind": "syscall", "category": "storage"},
                {"binding": "Hash", "id": "storage.hash.new", "kind": "syscall", "category": "storage"},
                {"binding": "Hash.__getitem__", "id": "storage.hash.get", "kind": "syscall", "category": "storage"},
                {"binding": "Hash.__setitem__", "id": "storage.hash.set", "kind": "syscall", "category": "storage"},
                {"binding": "__contract_export__", "id": "contract.export_call", "kind": "syscall", "category": "contract"},
                {"binding": "now", "id": "env.now", "kind": "env_value", "category": "environment"}
            ]
        });

        let module: ModuleIr = serde_json::from_value(value).expect("module should deserialize");
        validate_module_ir(&module).expect("explicit runtime ops should validate");
    }
}
