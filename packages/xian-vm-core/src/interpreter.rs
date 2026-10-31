use crate::{validate_module_ir, FunctionIr, ModuleIr};
use ed25519_dalek::{Signature, VerifyingKey};
use num_bigint::{BigInt, Sign};
use num_traits::{Num, Signed, ToPrimitive, Zero};
use serde_json::{Map, Value};
use sha2::Digest as Sha2Digest;
use sha2::Sha256;
use sha3::Sha3_256;
use std::collections::{HashMap, HashSet};
use std::env;
use std::str::FromStr;

const STORAGE_DELIMITER: &str = ":";
const STORAGE_INDEX_SEPARATOR: &str = ".";
const MAX_HASH_DIMENSIONS: usize = 16;
const MAX_STORAGE_KEY_SIZE: usize = 1024;
pub(crate) const MAX_SEQUENCE_LENGTH: usize = 1024 * 128;
pub(crate) const MAX_BINARY_ALLOCATION_BYTES: usize = 1024 * 128;
pub(crate) const MAX_INTEGER_BITS: u64 = (MAX_BINARY_ALLOCATION_BYTES as u64) * 8;
pub(crate) const MAX_INT_STRING_CHARS: usize = 8192;
pub(crate) const MAX_MODULAR_POW_EXPONENT_BITS: u64 = 8192;
pub(crate) const VM_GAS_CALL_DISPATCH: u64 = 5_000;
const VM_GAS_EVENT_EMIT: u64 = 8_000;
const VM_GAS_VARIABLE_GET: u64 = 1_280;
const VM_GAS_VARIABLE_SET: u64 = 5_120;
const VM_GAS_HASH_SCAN: u64 = 4_096;
const VM_GAS_FUNCTION_ENTRY_COMPLEXITY_FLOOR: u64 = 40;
const VM_GAS_FUNCTION_ENTRY_EXCESS_NODE: u64 = 150;
const VM_GAS_LOOP_ITERATION: u64 = 96;
const VM_GAS_STMT_ASSIGN: u64 = 64;
const VM_GAS_STMT_STORAGE_SET: u64 = 5_120;
const VM_GAS_STMT_STORAGE_MUTATE: u64 = 5_120;
const VM_GAS_STMT_AUG_ASSIGN: u64 = 96;
const VM_GAS_STMT_RETURN: u64 = 32;
const VM_GAS_STMT_EXPR: u64 = 32;
const VM_GAS_STMT_IF: u64 = 96;
const VM_GAS_STMT_WHILE: u64 = 96;
const VM_GAS_STMT_FOR: u64 = 96;
const VM_GAS_STMT_ASSERT: u64 = 96;
const VM_GAS_STMT_RAISE: u64 = 96;
const VM_GAS_STMT_BREAK: u64 = 32;
const VM_GAS_STMT_CONTINUE: u64 = 32;
const VM_GAS_STMT_PASS: u64 = 32;
const VM_GAS_EXPR_NAME: u64 = 64;
const VM_GAS_EXPR_CONSTANT: u64 = 32;
const VM_GAS_EXPR_LIST: u64 = 128;
const VM_GAS_EXPR_LIST_COMP: u64 = 224;
const VM_GAS_EXPR_DICT_COMP: u64 = 288;
const VM_GAS_EXPR_TUPLE: u64 = 128;
const VM_GAS_EXPR_DICT: u64 = 608;
const VM_GAS_EXPR_ATTRIBUTE: u64 = 96;
const VM_GAS_EXPR_SUBSCRIPT: u64 = 96;
const VM_GAS_EXPR_STORAGE_GET: u64 = 1_280;
const VM_GAS_EXPR_COMPARE: u64 = 96;
const VM_GAS_EXPR_BOOL_OP: u64 = 96;
const VM_GAS_EXPR_BINARY_OP: u64 = 96;
const VM_GAS_EXPR_UNARY_OP: u64 = 64;
const VM_GAS_EXPR_IF_EXPR: u64 = 96;
const VM_GAS_EXPR_F_STRING: u64 = 96;
const VM_GAS_EXPR_FORMATTED_VALUE: u64 = 96;

#[path = "builtin_collections.rs"]
mod builtin_collections;
#[path = "builtin_dispatch.rs"]
mod builtin_dispatch;
#[path = "call_dispatch.rs"]
mod call_dispatch;
#[path = "collection_methods.rs"]
mod collection_methods;
#[path = "expression_evaluation.rs"]
mod expression_evaluation;
#[path = "foreign_storage.rs"]
mod foreign_storage;
#[path = "numeric_text.rs"]
mod numeric_text;
#[path = "rounding.rs"]
mod rounding;
#[path = "statement_execution.rs"]
mod statement_execution;
#[path = "storage_access.rs"]
mod storage_access;
#[path = "storage_bulk.rs"]
mod storage_bulk;
#[path = "storage_declarations.rs"]
mod storage_declarations;
#[path = "interpreter_support.rs"]
mod support;
#[path = "syscall_dispatch.rs"]
mod syscall_dispatch;
#[path = "unpacking.rs"]
mod unpacking;
use crate::values::*;
use support::*;

const SUBMISSION_CONTRACT: &str = "submission";
const SUBMISSION_ONLY_SYSCALLS: [&str; 3] = [
    "contract.deploy",
    "contract.set_owner",
    "contract.set_developer",
];

fn vm_trace_enabled(flag: &str) -> bool {
    env::var_os(flag).is_some()
}

#[cfg(feature = "python-extension")]
pub(crate) fn vm_variable_storage_key(contract: &str, binding: &str) -> String {
    variable_storage_key(contract, binding)
}

#[cfg(feature = "python-extension")]
pub(crate) fn vm_hash_storage_key(
    contract: &str,
    binding: &str,
    key: &VmValue,
) -> Result<String, VmExecutionError> {
    hash_storage_key(contract, binding, key)
}

fn vm_statement_gas_cost(
    node: &str,
    _object: &Map<String, Value>,
) -> Result<u64, VmExecutionError> {
    Ok(match node {
        "assign" => VM_GAS_STMT_ASSIGN,
        "storage_set" => VM_GAS_STMT_STORAGE_SET,
        "storage_mutate" => VM_GAS_STMT_STORAGE_MUTATE,
        "aug_assign" => VM_GAS_STMT_AUG_ASSIGN,
        "return" => VM_GAS_STMT_RETURN,
        "expr" => VM_GAS_STMT_EXPR,
        "if" => VM_GAS_STMT_IF,
        "while" => VM_GAS_STMT_WHILE,
        "for" => VM_GAS_STMT_FOR,
        "assert" => VM_GAS_STMT_ASSERT,
        "raise" => VM_GAS_STMT_RAISE,
        "break" => VM_GAS_STMT_BREAK,
        "continue" => VM_GAS_STMT_CONTINUE,
        "pass" => VM_GAS_STMT_PASS,
        other => {
            return Err(VmExecutionError::new(format!(
                "unsupported statement node '{other}'"
            )))
        }
    })
}

fn vm_expression_gas_cost(
    node: &str,
    object: &Map<String, Value>,
) -> Result<u64, VmExecutionError> {
    Ok(match node {
        "name" => VM_GAS_EXPR_NAME,
        "constant" => VM_GAS_EXPR_CONSTANT,
        "list" => VM_GAS_EXPR_LIST,
        "list_comp" => VM_GAS_EXPR_LIST_COMP,
        "dict_comp" => VM_GAS_EXPR_DICT_COMP,
        "tuple" => VM_GAS_EXPR_TUPLE,
        "dict" => VM_GAS_EXPR_DICT,
        "attribute" => VM_GAS_EXPR_ATTRIBUTE,
        "subscript" => VM_GAS_EXPR_SUBSCRIPT,
        "storage_get" => VM_GAS_EXPR_STORAGE_GET,
        "slice" => VM_GAS_EXPR_SUBSCRIPT,
        "call" => VM_GAS_CALL_DISPATCH,
        "compare" => {
            let comparisons = required_array(object, "operators")?.len().max(1) as u64;
            VM_GAS_EXPR_COMPARE * comparisons
        }
        "bool_op" => {
            let branches = required_array(object, "values")?
                .len()
                .saturating_sub(1)
                .max(1) as u64;
            VM_GAS_EXPR_BOOL_OP * branches
        }
        "bin_op" => VM_GAS_EXPR_BINARY_OP,
        "unary_op" => VM_GAS_EXPR_UNARY_OP,
        "if_expr" => VM_GAS_EXPR_IF_EXPR,
        "f_string" => {
            let segments = required_array(object, "values")?.len().max(1) as u64;
            VM_GAS_EXPR_F_STRING * segments
        }
        "formatted_value" => VM_GAS_EXPR_FORMATTED_VALUE,
        other => {
            return Err(VmExecutionError::new(format!(
                "unsupported expression node '{other}'"
            )))
        }
    })
}

fn charge_storage_read(
    host: &mut dyn VmHost,
    key: &str,
    value: &VmValue,
) -> Result<(), VmExecutionError> {
    host.charge_storage_read(key, value)
}

fn collect_target_names(target: &Value, names: &mut Vec<String>) -> Result<(), VmExecutionError> {
    let object = as_object(target, "target")?;
    match required_string(object, "node")? {
        "name" => {
            names.push(required_string(object, "id")?.to_owned());
            Ok(())
        }
        "starred_target" => collect_target_names(required_value(object, "value")?, names),
        "tuple_target" | "list_target" => {
            for element in required_array(object, "elements")? {
                collect_target_names(element, names)?;
            }
            Ok(())
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported comprehension target '{other}'"
        ))),
    }
}

fn capture_target_bindings(
    target: &Value,
    scope: &HashMap<String, VmValue>,
) -> Result<Vec<(String, Option<VmValue>)>, VmExecutionError> {
    let mut names = Vec::new();
    collect_target_names(target, &mut names)?;
    Ok(names
        .into_iter()
        .map(|name| {
            let previous = scope.get(&name).cloned();
            (name, previous)
        })
        .collect())
}

fn restore_target_bindings(
    scope: &mut HashMap<String, VmValue>,
    previous: Vec<(String, Option<VmValue>)>,
) {
    for (name, value) in previous {
        if let Some(value) = value {
            scope.insert(name, value);
        } else {
            scope.remove(&name);
        }
    }
}

fn ir_node_complexity(value: &Value) -> u64 {
    match value {
        Value::Object(object) => {
            let self_cost = if object.contains_key("node") { 1 } else { 0 };
            self_cost + object.values().map(ir_node_complexity).sum::<u64>()
        }
        Value::Array(items) => items.iter().map(ir_node_complexity).sum(),
        _ => 0,
    }
}

fn function_entry_gas_cost(function: &FunctionIr) -> u64 {
    let mut complexity = 0;
    for parameter in &function.parameters {
        if let Some(default) = &parameter.default {
            complexity += ir_node_complexity(default);
        }
    }
    complexity += function.body.iter().map(ir_node_complexity).sum::<u64>();
    complexity
        .saturating_sub(VM_GAS_FUNCTION_ENTRY_COMPLEXITY_FLOOR)
        .saturating_mul(VM_GAS_FUNCTION_ENTRY_EXCESS_NODE)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TypeAnnotation {
    base: String,
    args: Vec<TypeAnnotation>,
}

impl TypeAnnotation {
    fn source(&self) -> String {
        if self.args.is_empty() {
            return self.base.clone();
        }
        format!(
            "{}[{}]",
            self.base,
            self.args
                .iter()
                .map(TypeAnnotation::source)
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn parse_type_annotation(annotation: &str) -> Option<TypeAnnotation> {
    let trimmed = annotation.trim();
    if trimmed.is_empty() {
        return None;
    }

    let Some(open_index) = trimmed.find('[') else {
        if trimmed.contains([']', ',']) {
            return None;
        }
        return Some(TypeAnnotation {
            base: trimmed.to_owned(),
            args: Vec::new(),
        });
    };

    let base = trimmed[..open_index].trim();
    if base.is_empty() {
        return None;
    }

    let mut depth = 0i32;
    let mut close_index = None;
    for (index, ch) in trimmed
        .char_indices()
        .skip_while(|(index, _)| *index < open_index)
    {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
                if depth == 0 {
                    close_index = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }

    let close_index = close_index?;
    if close_index != trimmed.len() - 1 {
        return None;
    }

    let args = split_type_annotation_args(&trimmed[open_index + 1..close_index])?;
    Some(TypeAnnotation {
        base: base.to_owned(),
        args,
    })
}

fn split_type_annotation_args(input: &str) -> Option<Vec<TypeAnnotation>> {
    let mut args = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;

    for (index, ch) in input.char_indices() {
        match ch {
            '[' => depth += 1,
            ']' => {
                depth -= 1;
                if depth < 0 {
                    return None;
                }
            }
            ',' if depth == 0 => {
                args.push(parse_type_annotation(input[start..index].trim())?);
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }

    if depth != 0 {
        return None;
    }

    let tail = input[start..].trim();
    if tail.is_empty() {
        return None;
    }
    args.push(parse_type_annotation(tail)?);
    Some(args)
}

fn export_typecheck_enabled(function: &FunctionIr) -> bool {
    let Some(decorator) = &function.decorator else {
        return false;
    };
    if decorator.name != "export" {
        return false;
    }

    decorator.keywords.iter().any(|keyword| {
        let Some(object) = keyword.as_object() else {
            return false;
        };
        if object.get("arg").and_then(Value::as_str) != Some("typecheck") {
            return false;
        }
        let Some(value) = object.get("value").and_then(Value::as_object) else {
            return false;
        };
        value.get("node").and_then(Value::as_str) == Some("constant")
            && value.get("value_type").and_then(Value::as_str) == Some("bool")
            && value.get("value").and_then(Value::as_bool) == Some(true)
    })
}

fn typecheck_error(label: &str, annotation: &TypeAnnotation, value: &VmValue) -> VmExecutionError {
    let message = format!(
        "{label} must be {}, got {}!",
        annotation_label(annotation),
        value_typecheck_name(value)
    );
    VmExecutionError::new(format!("TypeError({message:?})"))
}

fn annotation_label(annotation: &TypeAnnotation) -> String {
    if !annotation.args.is_empty() {
        return annotation.source();
    }
    match annotation.base.as_str() {
        "Any" => "Any".to_owned(),
        "datetime.datetime" => "datetime.datetime".to_owned(),
        "datetime.timedelta" => "datetime.timedelta".to_owned(),
        "set" => "set".to_owned(),
        "frozenset" => "frozenset".to_owned(),
        "int" => "<class 'int'>".to_owned(),
        "bytes" => "<class 'bytes'>".to_owned(),
        "bytearray" => "<class 'bytearray'>".to_owned(),
        base => format!("<class '{base}'>"),
    }
}

fn value_typecheck_name(value: &VmValue) -> &'static str {
    match value {
        VmValue::None => "NoneType",
        VmValue::Decimal(_) => "ContractingDecimal",
        VmValue::DateTime(_) => "Datetime",
        VmValue::TimeDelta(_) => "Timedelta",
        other => other.type_name(),
    }
}

fn check_function_arguments(
    function: &FunctionIr,
    scope: &HashMap<String, VmValue>,
) -> Result<(), VmExecutionError> {
    for parameter in &function.parameters {
        let Some(annotation) = &parameter.annotation else {
            continue;
        };
        let Some(value) = scope.get(&parameter.name) else {
            continue;
        };
        let parsed = parse_type_annotation(annotation).ok_or_else(|| {
            VmExecutionError::new(format!("unsupported type annotation '{annotation}'"))
        })?;
        check_typed_value(value, &parsed, &format!("Argument '{}'", parameter.name))?;
    }
    Ok(())
}

fn check_function_return(function: &FunctionIr, value: &VmValue) -> Result<(), VmExecutionError> {
    let Some(annotation) = &function.returns else {
        return Ok(());
    };
    let parsed = parse_type_annotation(annotation).ok_or_else(|| {
        VmExecutionError::new(format!("unsupported type annotation '{annotation}'"))
    })?;
    check_typed_value(value, &parsed, "Return value")
}

fn check_typed_value(
    value: &VmValue,
    annotation: &TypeAnnotation,
    label: &str,
) -> Result<(), VmExecutionError> {
    let value = &value.snapshot();
    if annotation.base == "Any" {
        return Ok(());
    }

    match annotation.base.as_str() {
        "list" => {
            let VmValue::List(items) = value else {
                return Err(typecheck_error(label, annotation, value));
            };
            if let Some(item_annotation) = annotation.args.first() {
                for (index, item) in items.iter().enumerate() {
                    check_typed_value(item, item_annotation, &format!("{label}[{index}]"))?;
                }
            }
            Ok(())
        }
        "dict" => {
            let VmValue::Dict(entries) = value else {
                return Err(typecheck_error(label, annotation, value));
            };
            if annotation.args.len() >= 2 {
                let key_annotation = &annotation.args[0];
                let value_annotation = &annotation.args[1];
                for (key, item) in entries {
                    check_typed_value(key, key_annotation, &format!("{label} key"))?;
                    check_typed_value(
                        item,
                        value_annotation,
                        &format!("{label}[{}]", typecheck_dict_key_repr(key)),
                    )?;
                }
            }
            Ok(())
        }
        "set" => {
            let VmValue::Set(items) = value else {
                return Err(typecheck_error(label, annotation, value));
            };
            if let Some(item_annotation) = annotation.args.first() {
                for (index, item) in items.iter().enumerate() {
                    check_typed_value(item, item_annotation, &format!("{label}[{index}]"))?;
                }
            }
            Ok(())
        }
        "frozenset" => {
            let VmValue::FrozenSet(items) = value else {
                return Err(typecheck_error(label, annotation, value));
            };
            if let Some(item_annotation) = annotation.args.first() {
                for (index, item) in items.iter().enumerate() {
                    check_typed_value(item, item_annotation, &format!("{label}[{index}]"))?;
                }
            }
            Ok(())
        }
        "bool" => {
            if matches!(value, VmValue::Bool(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "int" => {
            if matches!(value, VmValue::Int(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "float" => {
            if matches!(
                value,
                VmValue::Int(_) | VmValue::Float(_) | VmValue::Decimal(_)
            ) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "str" => {
            if matches!(value, VmValue::String(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "bytes" => {
            if matches!(value, VmValue::Bytes(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "bytearray" => {
            if matches!(value, VmValue::ByteArray(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "datetime.datetime" => {
            if matches!(value, VmValue::DateTime(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        "datetime.timedelta" => {
            if matches!(value, VmValue::TimeDelta(_)) {
                Ok(())
            } else {
                Err(typecheck_error(label, annotation, value))
            }
        }
        _ => Err(VmExecutionError::new(format!(
            "unsupported type annotation '{}'",
            annotation.source()
        ))),
    }
}

fn typecheck_dict_key_repr(key: &VmValue) -> String {
    match &key.snapshot() {
        VmValue::String(value) => ascii_string_repr(value),
        other => other.python_repr(),
    }
}

pub trait VmHost {
    fn charge_execution_cost(&mut self, _cost: u64) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn charge_storage_read(
        &mut self,
        _key: &str,
        _value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn charge_storage_write(
        &mut self,
        _key: &str,
        _value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn record_storage_write(
        &mut self,
        _key: &str,
        _value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn read_recorded_storage_write(
        &mut self,
        _key: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        Ok(None)
    }

    fn emit_event(&mut self, _event: VmEvent) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn read_variable(
        &mut self,
        _contract: &str,
        _binding: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        Ok(None)
    }

    /// None leaves supplied snapshots intact; Some(None) is an authoritative absence.
    fn read_hash(
        &mut self,
        _contract: &str,
        _binding: &str,
        _key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        Ok(None)
    }

    fn scan_hash_entries(
        &mut self,
        _contract: &str,
        _binding: &str,
        _prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        Ok(Vec::new())
    }

    /// Return canonically ordered entries, charged before they are retained.
    /// Native hosts override this to consume persistent state incrementally.
    fn scan_hash_entries_metered(
        &mut self,
        contract: &str,
        binding: &str,
        prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let mut entries = self.scan_hash_entries(contract, binding, prefix)?;
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut budget = crate::storage_scan::ScanBudget::default();
        for (suffix, value) in &entries {
            let key = hash_storage_key_from_normalized(contract, binding, suffix);
            self.charge_storage_read(&key, value)?;
            budget.observe(&key, value)?;
        }
        Ok(entries)
    }

    fn load_owner(&mut self, _contract: &str) -> Result<Option<String>, VmExecutionError> {
        Ok(None)
    }

    /// Bundle hosts can preserve identity between contracts in one execution.
    /// External hosts receive detached values unless they opt into that model.
    fn call_contract_shared(
        &mut self,
        mut call: VmContractCall,
    ) -> Result<VmValue, VmExecutionError> {
        call.args = call
            .args
            .iter()
            .map(VmValue::detached)
            .collect::<Result<_, _>>()?;
        call.kwargs = call
            .kwargs
            .into_iter()
            .map(|(k, v)| Ok((k, v.detached()?)))
            .collect::<Result<_, VmExecutionError>>()?;
        self.call_contract(call)
    }

    fn call_contract(&mut self, call: VmContractCall) -> Result<VmValue, VmExecutionError> {
        Err(VmExecutionError::unsupported(format!(
            "host does not support contract call {}.{}",
            contract_target_label(&call.target),
            call.function
        )))
    }

    fn handle_syscall(
        &mut self,
        syscall_id: &str,
        _args: Vec<VmValue>,
        _kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        Err(VmExecutionError::unsupported(format!(
            "unsupported host syscall '{syscall_id}'"
        )))
    }
}

#[derive(Debug, Clone, PartialEq)]
struct VariableState {
    value_type: Option<VmValue>,
    default_value: VmValue,
    value: Option<VmValue>,
    foreign_key: Option<String>,
    snapshot_local: bool,
    dirty: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct HashState {
    default_value: VmValue,
    entries: HashMap<String, VmValue>,
    foreign_key: Option<String>,
    snapshot_local: bool,
    dirty_entries: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmVariableSnapshot {
    pub binding: String,
    pub default_value: VmValue,
    pub value: Option<VmValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmHashSnapshot {
    pub binding: String,
    pub default_value: VmValue,
    pub entries: HashMap<String, VmValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmModuleStorageSnapshot {
    pub contract_name: String,
    pub variables: Vec<VmVariableSnapshot>,
    pub hashes: Vec<VmHashSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
enum ControlFlow {
    Next,
    Return(VmValue),
    Break,
    Continue,
}

#[derive(Debug, Clone, PartialEq)]
enum NativeMethodResult {
    Value(VmValue),
    Mutated { receiver: VmValue, value: VmValue },
}

#[derive(Debug, Clone, PartialEq)]
enum ResolvedAssignmentTarget {
    Name(String),
    Subscript {
        parent: Box<ResolvedAssignmentTarget>,
        container: VmValue,
        index: VmValue,
    },
    Unsupported(String),
}

pub struct VmInstance {
    heap: crate::heap::VmHeap,
    module: ModuleIr,
    functions: HashMap<String, FunctionIr>,
    function_defaults: HashMap<(String, String), VmValue>,
    imports: HashMap<String, String>,
    globals: HashMap<String, VmValue>,
    variables: HashMap<String, VariableState>,
    hashes: HashMap<String, HashState>,
    context: VmExecutionContext,
}

impl VmInstance {
    pub fn new(module: ModuleIr, context: VmExecutionContext) -> Result<Self, VmExecutionError> {
        Self::new_with_host(module, context, &mut NoopHost {})
    }

    pub fn new_with_host(
        module: ModuleIr,
        context: VmExecutionContext,
        host: &mut dyn VmHost,
    ) -> Result<Self, VmExecutionError> {
        Self::new_with_heap(module, context, host, crate::heap::VmHeap::default())
    }

    pub(crate) fn new_with_heap(
        module: ModuleIr,
        context: VmExecutionContext,
        host: &mut dyn VmHost,
        heap: crate::heap::VmHeap,
    ) -> Result<Self, VmExecutionError> {
        validate_module_ir(&module).map_err(|err| VmExecutionError::new(err.to_string()))?;

        let imports = module
            .imports
            .iter()
            .map(|import| {
                (
                    import
                        .alias
                        .clone()
                        .unwrap_or_else(|| import.module.clone()),
                    import.module.clone(),
                )
            })
            .collect::<HashMap<_, _>>();

        let mut instance = Self {
            heap,
            module,
            functions: HashMap::new(),
            function_defaults: HashMap::new(),
            imports,
            globals: HashMap::new(),
            variables: HashMap::new(),
            hashes: HashMap::new(),
            context,
        };

        if instance.context.this.is_none() {
            instance.context.this = Some(instance.module.module_name.clone());
        }

        for (binding, module) in instance.imports.clone() {
            instance.globals.insert(
                binding,
                VmValue::ContractHandle(VmContractHandle {
                    module,
                    origin: "static_import".to_owned(),
                }),
            );
        }

        instance.initialize_module(host)?;

        Ok(instance)
    }

    fn initialize_module(&mut self, host: &mut dyn VmHost) -> Result<(), VmExecutionError> {
        // IR groups declarations by kind. Recover source order for eager
        // defaults and module statements, retaining each default's identity.
        let mut steps = Vec::new();
        for (kind, values) in [
            (0, &self.module.global_declarations),
            (2, &self.module.module_body),
        ] {
            for (index, value) in values.iter().enumerate() {
                let span = as_object(
                    required_value(as_object(value, "module statement")?, "span")?,
                    "span",
                )?;
                let line = span.get("line").and_then(Value::as_u64).unwrap_or(0);
                let col = span.get("col").and_then(Value::as_u64).unwrap_or(0);
                steps.push((line, col, kind, index));
            }
        }
        for (index, function) in self.module.functions.iter().enumerate() {
            steps.push((function.span.line, function.span.col, 1, index));
        }
        steps.sort();
        for (_, _, kind, index) in steps {
            match kind {
                0 => self.apply_global_declaration(
                    &self.module.global_declarations[index].clone(),
                    host,
                )?,
                1 => self.define_function(self.module.functions[index].clone(), host)?,
                _ => {
                    let statement = self.module.module_body[index].clone();
                    let mut scope = self.globals.clone();
                    if self.execute_statement(&statement, &mut scope, host)? != ControlFlow::Next {
                        return Err(VmExecutionError::new(
                            "module body cannot return or break execution",
                        ));
                    }
                    self.globals = scope;
                }
            }
        }
        Ok(())
    }

    fn define_function(
        &mut self,
        function: FunctionIr,
        host: &mut dyn VmHost,
    ) -> Result<(), VmExecutionError> {
        for parameter in &function.parameters {
            if let Some(expression) = &parameter.default {
                let value = self.eval_expression(expression, &mut self.globals.clone(), host)?;
                self.function_defaults
                    .insert((function.name.clone(), parameter.name.clone()), value);
            }
        }
        self.functions.insert(function.name.clone(), function);
        Ok(())
    }

    pub fn context(&self) -> &VmExecutionContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut VmExecutionContext {
        &mut self.context
    }

    pub fn has_export(&self, name: &str) -> bool {
        self.functions
            .get(name)
            .map(|function| function.visibility == "export")
            .unwrap_or(false)
    }

    pub fn storage_snapshot(&self) -> VmModuleStorageSnapshot {
        VmModuleStorageSnapshot {
            contract_name: self.module.module_name.clone(),
            variables: self
                .variables
                .iter()
                .filter(|(_, state)| state.snapshot_local && state.dirty)
                .map(|(binding, state)| VmVariableSnapshot {
                    binding: binding.clone(),
                    default_value: state.default_value.clone(),
                    value: state.value.clone(),
                })
                .collect(),
            hashes: self
                .hashes
                .iter()
                .filter(|(_, state)| state.snapshot_local)
                .map(|(binding, state)| VmHashSnapshot {
                    binding: binding.clone(),
                    default_value: state.default_value.clone(),
                    entries: state
                        .entries
                        .iter()
                        .filter(|(key, _)| state.dirty_entries.contains(*key))
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                })
                .filter(|snapshot| !snapshot.entries.is_empty())
                .collect(),
        }
    }

    pub fn apply_foreign_snapshot(&mut self, snapshot: &VmModuleStorageSnapshot) {
        for variable in &snapshot.variables {
            self.variables.insert(
                foreign_storage_key(&snapshot.contract_name, &variable.binding),
                VariableState {
                    value_type: None,
                    default_value: variable.default_value.clone(),
                    value: variable.value.clone(),
                    foreign_key: None,
                    snapshot_local: false,
                    dirty: false,
                },
            );
        }
        for hash in &snapshot.hashes {
            self.hashes.insert(
                foreign_storage_key(&snapshot.contract_name, &hash.binding),
                HashState {
                    default_value: hash.default_value.clone(),
                    entries: hash.entries.clone(),
                    foreign_key: None,
                    snapshot_local: false,
                    dirty_entries: HashSet::new(),
                },
            );
        }
    }

    pub fn set_foreign_variable(
        &mut self,
        foreign_contract: &str,
        foreign_name: &str,
        value: VmValue,
    ) {
        let key = foreign_storage_key(foreign_contract, foreign_name);
        self.variables
            .entry(key)
            .and_modify(|state| state.value = Some(value.clone()))
            .or_insert(VariableState {
                value_type: None,
                default_value: VmValue::None,
                value: Some(value),
                foreign_key: None,
                snapshot_local: false,
                dirty: false,
            });
    }

    pub fn set_foreign_hash_value(
        &mut self,
        foreign_contract: &str,
        foreign_name: &str,
        key: &VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        let storage_key = foreign_storage_key(foreign_contract, foreign_name);
        let normalized = normalize_hash_key(key)?;
        self.hashes
            .entry(storage_key)
            .and_modify(|state| {
                state.entries.insert(normalized.clone(), value.clone());
            })
            .or_insert_with(|| {
                let mut entries = HashMap::new();
                entries.insert(normalized, value);
                HashState {
                    default_value: VmValue::None,
                    entries,
                    foreign_key: None,
                    snapshot_local: false,
                    dirty_entries: HashSet::new(),
                }
            });
        Ok(())
    }

    pub fn get_variable(&self, binding: &str) -> Option<VmValue> {
        self.variables.get(binding).map(|state| {
            state
                .value
                .clone()
                .unwrap_or_else(|| state.default_value.clone())
        })
    }

    pub fn peek_variable_value(&self, binding: &str) -> Option<VmValue> {
        self.variables
            .get(binding)
            .and_then(|state| state.value.clone())
    }

    pub fn get_hash_value(
        &self,
        binding: &str,
        key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let normalized = normalize_hash_key(key)?;
        Ok(self.hashes.get(binding).map(|state| {
            state
                .entries
                .get(&normalized)
                .cloned()
                .unwrap_or_else(|| state.default_value.clone())
        }))
    }

    pub fn peek_hash_entry(
        &self,
        binding: &str,
        key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let normalized = normalize_hash_key(key)?;
        Ok(self
            .hashes
            .get(binding)
            .and_then(|state| state.entries.get(&normalized).cloned()))
    }

    pub fn set_variable_state(
        &mut self,
        binding: &str,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        self.variable_set(binding, value)
    }

    pub fn set_hash_value(
        &mut self,
        binding: &str,
        key: &VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        self.hash_set(binding, key, value)
    }

    pub fn call_function(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        self.call_function_shared(host, name, args, kwargs)?
            .detached()
    }

    pub(crate) fn call_function_shared(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        let args = args
            .into_iter()
            .map(|v| self.heap.capture(v))
            .collect::<Result<_, _>>()?;
        let kwargs = kwargs
            .into_iter()
            .map(|(k, v)| Ok((k, self.heap.capture(v)?)))
            .collect::<Result<_, VmExecutionError>>()?;
        let trace_calls = vm_trace_enabled("XIAN_VM_TRACE_CALLS");
        if trace_calls {
            eprintln!(
                "[vm-call] enter {}.{} caller={} signer={}",
                self.module.module_name,
                name,
                option_string_value(&self.context.caller).python_repr(),
                option_string_value(&self.context.signer).python_repr(),
            );
        }
        let previous_entry = self.context.entry.clone();
        let injected_entry = if self.context.entry.is_none() {
            self.context.entry = Some((self.module.module_name.clone(), name.to_owned()));
            true
        } else {
            false
        };
        let result = self.call_named_function(host, name, args, kwargs);
        if injected_entry {
            self.context.entry = previous_entry;
        }
        if trace_calls {
            match &result {
                Ok(value) => eprintln!(
                    "[vm-call] exit {}.{} -> {} ({})",
                    self.module.module_name,
                    name,
                    value.python_repr(),
                    value.type_name(),
                ),
                Err(err) => eprintln!(
                    "[vm-call] error {}.{} -> {}",
                    self.module.module_name, name, err
                ),
            }
        }
        result
    }

    fn apply_global_declaration(
        &mut self,
        declaration: &Value,
        host: &mut dyn VmHost,
    ) -> Result<(), VmExecutionError> {
        let object = as_object(declaration, "global declaration")?;
        let node = required_string(object, "node")?;
        match node {
            "storage_decl" => {
                let binding = required_string(object, "name")?.to_owned();
                let storage_type = required_string(object, "storage_type")?.to_owned();
                let args = required_array(object, "args")?;
                let keywords = required_array(object, "keywords")?;

                match storage_type.as_str() {
                    "Variable" | "ForeignVariable" => {
                        let state = self.build_variable_state(
                            &binding,
                            &storage_type,
                            args,
                            keywords,
                            host,
                        )?;
                        self.variables.insert(binding.clone(), state);
                    }
                    "Hash" | "ForeignHash" => {
                        let state =
                            self.build_hash_state(&binding, &storage_type, args, keywords, host)?;
                        self.hashes.insert(binding.clone(), state);
                    }
                    other => {
                        return Err(VmExecutionError::new(format!(
                            "unsupported storage declaration type '{other}'"
                        )))
                    }
                }

                self.globals.insert(
                    binding.clone(),
                    VmValue::StorageRef(VmStorageRef {
                        binding,
                        storage_type,
                    }),
                );
                Ok(())
            }
            "event_decl" => {
                let binding = required_string(object, "name")?.to_owned();
                let event_name = required_string(object, "event_name")?.to_owned();
                let params = self.eval_expression(
                    required_value(object, "params")?,
                    &mut self.globals.clone(),
                    host,
                )?;
                self.globals.insert(
                    binding.clone(),
                    VmValue::EventRef(Box::new(VmEventDefinition {
                        binding,
                        event_name,
                        params,
                    })),
                );
                Ok(())
            }
            "binding_decl" => {
                let binding = required_string(object, "name")?.to_owned();
                let value = self.eval_expression(
                    required_value(object, "value")?,
                    &mut self.globals.clone(),
                    host,
                )?;
                self.globals.insert(binding, value);
                Ok(())
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported global declaration node '{other}'"
            ))),
        }
    }

    fn build_variable_state(
        &mut self,
        _binding: &str,
        storage_type: &str,
        args: &[Value],
        keywords: &[Value],
        host: &mut dyn VmHost,
    ) -> Result<VariableState, VmExecutionError> {
        let options = self.storage_options(args, keywords, host)?;
        let foreign_key = if storage_type == "ForeignVariable" {
            Some(storage_declarations::foreign_key(&options)?)
        } else {
            None
        };
        let default_value = options
            .get("default_value")
            .cloned()
            .unwrap_or(VmValue::None);
        Ok(VariableState {
            value_type: options
                .get("t")
                .and_then(storage_declarations::variable_type),
            default_value: default_value.detached()?,
            value: None,
            foreign_key,
            snapshot_local: storage_type == "Variable",
            dirty: false,
        })
    }

    fn build_hash_state(
        &mut self,
        _binding: &str,
        storage_type: &str,
        args: &[Value],
        keywords: &[Value],
        host: &mut dyn VmHost,
    ) -> Result<HashState, VmExecutionError> {
        let options = self.storage_options(args, keywords, host)?;
        let foreign_key = if storage_type == "ForeignHash" {
            Some(storage_declarations::foreign_key(&options)?)
        } else {
            None
        };
        let default_value = options
            .get("default_value")
            .cloned()
            .unwrap_or(VmValue::None);
        Ok(HashState {
            default_value: default_value.detached()?,
            entries: HashMap::new(),
            foreign_key,
            snapshot_local: storage_type == "Hash",
            dirty_entries: HashSet::new(),
        })
    }

    fn call_named_function(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        let function = self
            .functions
            .get(name)
            .cloned()
            .ok_or_else(|| VmExecutionError::new(format!("unknown function '{name}'")))?;
        host.charge_execution_cost(function_entry_gas_cost(&function))?;
        let mut scope = self.bind_function_arguments(&function, args, kwargs, host)?;
        let typecheck = export_typecheck_enabled(&function);
        if typecheck {
            check_function_arguments(&function, &scope)?;
        }
        let result = match self.execute_block(&function.body, &mut scope, host)? {
            ControlFlow::Next => Ok(VmValue::None),
            ControlFlow::Return(value) => Ok(value),
            ControlFlow::Break | ControlFlow::Continue => Err(VmExecutionError::new(format!(
                "function '{name}' leaked loop control"
            ))),
        }?;
        if typecheck {
            check_function_return(&function, &result)?;
        }
        Ok(result)
    }

    fn call_callable_value(
        &mut self,
        host: &mut dyn VmHost,
        callee: VmValue,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        match callee {
            VmValue::Builtin(name) => self.call_builtin(host, &name, args, kwargs),
            VmValue::FunctionRef(name) => self.call_named_function(host, &name, args, kwargs),
            other => Err(VmExecutionError::new(format!(
                "value of type {} is not callable",
                other.type_name()
            ))),
        }
    }

    fn bind_function_arguments(
        &mut self,
        function: &FunctionIr,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        _host: &mut dyn VmHost,
    ) -> Result<HashMap<String, VmValue>, VmExecutionError> {
        let type_error = |message: String| VmExecutionError::new(format!("TypeError({message:?})"));
        let mut remaining_args = args;
        let mut remaining_kwargs = Vec::new();
        for (key, value) in kwargs {
            if remaining_kwargs
                .iter()
                .any(|(existing, _)| existing == &key)
            {
                return Err(type_error(format!(
                    "__{}() got multiple values for keyword argument '{}'",
                    function.name, key
                )));
            }
            remaining_kwargs.push((key, value));
        }
        let mut bound = HashMap::new();
        let mut vararg_name = None;
        let mut kwarg_name = None;

        for parameter in &function.parameters {
            match parameter.kind.as_str() {
                "positional_or_keyword" => {
                    if !remaining_args.is_empty() {
                        if remaining_kwargs
                            .iter()
                            .any(|(key, _)| key == &parameter.name)
                        {
                            return Err(type_error(format!(
                                "__{}() got multiple values for keyword argument '{}'",
                                function.name, parameter.name
                            )));
                        }
                        bound.insert(parameter.name.clone(), remaining_args.remove(0));
                        continue;
                    }
                    if let Some(index) = remaining_kwargs
                        .iter()
                        .position(|(key, _)| key == &parameter.name)
                    {
                        let (_, value) = remaining_kwargs.remove(index);
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    if parameter.default.is_some() {
                        let value = self
                            .function_defaults
                            .get(&(function.name.clone(), parameter.name.clone()))
                            .cloned()
                            .ok_or_else(|| {
                                VmExecutionError::new("function default was not initialized")
                            })?;
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    return Err(type_error(format!(
                        "missing required argument '{}'",
                        parameter.name
                    )));
                }
                "keyword_only" => {
                    if let Some(index) = remaining_kwargs
                        .iter()
                        .position(|(key, _)| key == &parameter.name)
                    {
                        let (_, value) = remaining_kwargs.remove(index);
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    if parameter.default.is_some() {
                        let value = self
                            .function_defaults
                            .get(&(function.name.clone(), parameter.name.clone()))
                            .cloned()
                            .ok_or_else(|| {
                                VmExecutionError::new("function default was not initialized")
                            })?;
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    return Err(type_error(format!(
                        "missing required keyword-only argument '{}'",
                        parameter.name
                    )));
                }
                "vararg" => {
                    vararg_name = Some(parameter.name.clone());
                }
                "kwarg" => {
                    kwarg_name = Some(parameter.name.clone());
                }
                other => {
                    return Err(VmExecutionError::new(format!(
                        "unsupported parameter kind '{other}'"
                    )))
                }
            }
        }

        if let Some(name) = vararg_name {
            bound.insert(name, VmValue::Tuple(remaining_args));
            remaining_args = Vec::new();
        }

        if !remaining_args.is_empty() {
            return Err(type_error(format!(
                "too many positional arguments for '{}'",
                function.name
            )));
        }

        if let Some(name) = kwarg_name {
            let mut entries = Vec::new();
            for (key, value) in remaining_kwargs.drain(..) {
                entries.push((VmValue::String(key), value));
            }
            bound.insert(name, VmValue::Dict(entries));
        } else if let Some(unexpected) = remaining_kwargs.first().map(|(key, _)| key) {
            return Err(type_error(format!(
                "unexpected keyword argument '{unexpected}'"
            )));
        }

        bound
            .into_iter()
            .map(|(k, v)| Ok((k, self.heap.capture(v)?)))
            .collect()
    }
}

struct NoopHost;

impl VmHost for NoopHost {}

fn ir_root_name(value: &Value) -> Result<Option<&str>, VmExecutionError> {
    let object = as_object(value, "expression")?;
    match required_string(object, "node")? {
        "name" => Ok(Some(required_string(object, "id")?)),
        "attribute" | "subscript" => ir_root_name(required_value(object, "value")?),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_module_ir, XIAN_IR_V1, XIAN_VM_HOST_CATALOG_V1, XIAN_VM_V1_PROFILE};
    use serde_json::json;

    #[derive(Default)]
    struct RecordingHost {
        events: Vec<VmEvent>,
        calls: Vec<VmContractCall>,
    }

    #[derive(Default)]
    struct SyscallRecordingHost {
        syscalls: Vec<(String, Vec<VmValue>, Vec<(String, VmValue)>)>,
    }

    #[derive(Default)]
    struct AssignmentMeteringHost {
        budget: Option<u64>,
        raw_cost: u64,
        execution_costs: Vec<u64>,
        hash_reads: Vec<(String, String, VmValue)>,
        storage_reads: Vec<(String, VmValue)>,
    }

    impl VmHost for RecordingHost {
        fn emit_event(&mut self, event: VmEvent) -> Result<(), VmExecutionError> {
            self.events.push(event);
            Ok(())
        }

        fn call_contract(&mut self, call: VmContractCall) -> Result<VmValue, VmExecutionError> {
            self.calls.push(call.clone());
            match call.function.as_str() {
                "transfer" => Ok(VmValue::Bool(true)),
                "balance_of" => Ok(vm_int(77)),
                _ => Ok(VmValue::None),
            }
        }
    }

    impl VmHost for SyscallRecordingHost {
        fn handle_syscall(
            &mut self,
            syscall_id: &str,
            args: Vec<VmValue>,
            kwargs: Vec<(String, VmValue)>,
        ) -> Result<VmValue, VmExecutionError> {
            self.syscalls
                .push((syscall_id.to_owned(), args.clone(), kwargs.clone()));
            match syscall_id {
                "zk.verify_groth16" => Ok(VmValue::Bool(true)),
                "zk.shielded_output_payload_hash" => {
                    Ok(VmValue::String("0x".to_owned() + &"ab".repeat(32)))
                }
                other => Err(VmExecutionError::new(format!(
                    "unexpected syscall '{other}'"
                ))),
            }
        }
    }

    impl VmHost for AssignmentMeteringHost {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
            self.execution_costs.push(cost);
            self.raw_cost = self
                .raw_cost
                .checked_add(cost)
                .ok_or_else(|| VmExecutionError::new("chi metering overflow"))?;
            if self.budget.is_some_and(|budget| self.raw_cost > budget) {
                return Err(VmExecutionError::new("Out of chi."));
            }
            Ok(())
        }

        fn charge_storage_read(
            &mut self,
            key: &str,
            value: &VmValue,
        ) -> Result<(), VmExecutionError> {
            self.storage_reads.push((key.to_owned(), value.clone()));
            Ok(())
        }

        fn read_hash(
            &mut self,
            contract: &str,
            binding: &str,
            key: &VmValue,
        ) -> Result<Option<VmValue>, VmExecutionError> {
            self.hash_reads
                .push((contract.to_owned(), binding.to_owned(), key.clone()));
            Ok(Some(vm_int(1)))
        }
    }

    fn empty_test_instance(module_name: &str) -> VmInstance {
        VmInstance::new(
            ModuleIr {
                ir_version: XIAN_IR_V1.to_owned(),
                vm_profile: XIAN_VM_V1_PROFILE.to_owned(),
                host_catalog_version: XIAN_VM_HOST_CATALOG_V1.to_owned(),
                module_name: module_name.to_owned(),
                source_hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                    .to_owned(),
                docstring: None,
                imports: Vec::new(),
                global_declarations: Vec::new(),
                functions: Vec::new(),
                module_body: Vec::new(),
                host_dependencies: Vec::new(),
            },
            VmExecutionContext::default(),
        )
        .expect("empty test module should instantiate")
    }

    fn test_span() -> Value {
        json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1})
    }

    fn test_name(id: &str) -> Value {
        json!({
            "node": "name",
            "span": test_span(),
            "id": id,
            "host_binding_id": null,
        })
    }

    fn test_int(value: i64) -> Value {
        json!({
            "node": "constant",
            "span": test_span(),
            "value_type": "int",
            "value": value,
        })
    }

    #[test]
    fn eval_name_prefers_scope_over_stale_host_binding() {
        let mut instance = empty_test_instance("host_shadow_probe");
        let mut scope = HashMap::from([("now".to_owned(), vm_int(7))]);
        let mut host = NoopHost;
        let expression = json!({
            "node": "name",
            "span": test_span(),
            "id": "now",
            "host_binding_id": "env.now",
        });

        let result = instance
            .eval_expression(&expression, &mut scope, &mut host)
            .expect("shadowed name should evaluate");

        assert_eq!(result.detached().unwrap(), vm_int(7));
    }

    #[test]
    fn formatted_value_rejects_unsupported_format_spec() {
        let mut instance = empty_test_instance("format_spec_probe");
        let mut scope = HashMap::from([("value".to_owned(), vm_int(7))]);
        let mut host = NoopHost;
        let expression = json!({
            "node": "formatted_value",
            "span": test_span(),
            "value": test_name("value"),
            "conversion": null,
            "format_spec": {
                "node": "f_string",
                "span": test_span(),
                "values": [
                    {
                        "node": "constant",
                        "span": test_span(),
                        "value_type": "str",
                        "value": "04d"
                    }
                ]
            }
        });

        let error = instance
            .eval_expression(&expression, &mut scope, &mut host)
            .expect_err("format spec should fail closed");

        assert!(error
            .to_string()
            .contains("f-string format specifications are not supported"));
    }

    #[test]
    fn subscript_assignment_uses_active_host_for_index_storage_reads() {
        let mut instance = empty_test_instance("assignment_host_probe");
        instance.hashes.insert(
            "indexes".to_owned(),
            HashState {
                default_value: vm_int(0),
                entries: HashMap::new(),
                foreign_key: None,
                snapshot_local: true,
                dirty_entries: HashSet::new(),
            },
        );
        let mut scope = HashMap::from([(
            "values".to_owned(),
            VmValue::List(vec![vm_int(10), vm_int(20)]),
        )]);
        for value in scope.values_mut() {
            *value = instance.heap.capture(value.clone()).unwrap();
        }
        let target = json!({
            "node": "subscript",
            "span": test_span(),
            "value": test_name("values"),
            "slice": {
                "node": "storage_get",
                "span": test_span(),
                "binding": "indexes",
                "storage_type": "Hash",
                "syscall_id": "storage.hash.get",
                "key": {
                    "node": "constant",
                    "span": test_span(),
                    "value_type": "str",
                    "value": "active",
                },
            },
        });
        let mut host = AssignmentMeteringHost::default();

        instance
            .assign_target(&target, vm_int(99), &mut scope, &mut host, false)
            .expect("subscript assignment should use the host-provided index");

        assert_eq!(
            scope.get("values").map(|v| v.detached().unwrap()).as_ref(),
            Some(&VmValue::List(vec![vm_int(10), vm_int(99)]))
        );
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_STORAGE_GET,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
        assert_eq!(
            host.hash_reads,
            vec![(
                "assignment_host_probe".to_owned(),
                "indexes".to_owned(),
                VmValue::String("active".to_owned()),
            )]
        );
        assert_eq!(host.storage_reads.len(), 1);
        assert_eq!(host.storage_reads[0].1, vm_int(1));
    }

    #[test]
    fn nested_subscript_assignment_charges_container_path_once() {
        let mut instance = empty_test_instance("nested_assignment_metering");
        let mut scope = HashMap::from([(
            "matrix".to_owned(),
            VmValue::List(vec![
                VmValue::List(vec![vm_int(1), vm_int(2)]),
                VmValue::List(vec![vm_int(3), vm_int(4)]),
            ]),
        )]);
        for value in scope.values_mut() {
            *value = instance.heap.capture(value.clone()).unwrap();
        }
        let target = json!({
            "node": "subscript",
            "span": test_span(),
            "value": {
                "node": "subscript",
                "span": test_span(),
                "value": test_name("matrix"),
                "slice": test_int(0),
            },
            "slice": test_int(1),
        });
        let mut host = AssignmentMeteringHost::default();

        instance
            .assign_target(&target, vm_int(9), &mut scope, &mut host, false)
            .expect("nested subscript assignment should succeed");

        assert_eq!(
            scope.get("matrix").map(|v| v.detached().unwrap()).as_ref(),
            Some(&VmValue::List(vec![
                VmValue::List(vec![vm_int(1), vm_int(9)]),
                VmValue::List(vec![vm_int(3), vm_int(4)]),
            ]))
        );
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_EXPR_SUBSCRIPT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
    }

    #[test]
    fn augmented_subscript_assignment_charges_target_once() {
        let mut instance = empty_test_instance("augmented_assignment_metering");
        let mut scope = HashMap::from([("values".to_owned(), VmValue::List(vec![vm_int(3)]))]);
        for value in scope.values_mut() {
            *value = instance.heap.capture(value.clone()).unwrap();
        }
        let statement = json!({
            "node": "aug_assign",
            "span": test_span(),
            "operator": "add",
            "target": {
                "node": "subscript",
                "span": test_span(),
                "value": test_name("values"),
                "slice": test_int(0),
            },
            "value": test_int(4),
        });
        let mut host = AssignmentMeteringHost::default();

        instance
            .execute_statement(&statement, &mut scope, &mut host)
            .expect("augmented subscript assignment should succeed");

        assert_eq!(
            scope.get("values").map(|v| v.detached().unwrap()).as_ref(),
            Some(&VmValue::List(vec![vm_int(7)]))
        );
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_STMT_AUG_ASSIGN,
                VM_GAS_EXPR_SUBSCRIPT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
    }

    #[test]
    fn augmented_list_assignment_consumes_iterator_and_preserves_alias() {
        let mut instance = empty_test_instance("augmented_iterator");
        let values = instance
            .heap
            .capture(VmValue::List(vec![vm_int(1)]))
            .unwrap();
        let items =
            crate::iteration::iter(&VmValue::Tuple(vec![vm_int(2), vm_int(3)]), &instance.heap)
                .unwrap();
        let alias = values.clone();
        let mut scope = HashMap::from([
            ("values".to_owned(), values),
            ("items".to_owned(), items.clone()),
        ]);
        let statement = json!({
            "node": "aug_assign",
            "span": test_span(),
            "operator": "add",
            "target": test_name("values"),
            "value": test_name("items"),
        });
        let mut host = AssignmentMeteringHost::default();

        instance
            .execute_statement(&statement, &mut scope, &mut host)
            .unwrap();

        assert!(scope["values"].identical(&alias));
        assert_eq!(
            alias.detached().unwrap(),
            VmValue::List(vec![vm_int(1), vm_int(2), vm_int(3)])
        );
        assert!(instance.next_item(&items, &mut host).unwrap().is_none());
        assert_eq!(
            host.execution_costs,
            vec![VM_GAS_STMT_AUG_ASSIGN, VM_GAS_EXPR_NAME, VM_GAS_EXPR_NAME]
        );
    }

    #[test]
    fn mutable_subscript_receiver_is_evaluated_once() {
        let mut instance = empty_test_instance("mutable_receiver_metering");
        let mut scope = HashMap::from([(
            "values".to_owned(),
            VmValue::List(vec![VmValue::List(vec![vm_int(1)])]),
        )]);
        for value in scope.values_mut() {
            *value = instance.heap.capture(value.clone()).unwrap();
        }
        let statement = json!({
            "node": "expr",
            "span": test_span(),
            "value": {
                "node": "call",
                "span": test_span(),
                "func": {
                    "node": "attribute",
                    "span": test_span(),
                    "value": {
                        "node": "subscript",
                        "span": test_span(),
                        "value": test_name("values"),
                        "slice": test_int(0),
                    },
                    "attr": "append",
                    "path": null,
                    "host_binding_id": null,
                },
                "args": [test_int(2)],
                "keywords": [],
                "syscall_id": null,
            },
        });
        let mut host = AssignmentMeteringHost::default();

        instance
            .execute_statement(&statement, &mut scope, &mut host)
            .expect("nested mutable receiver should be written back");

        assert_eq!(
            scope.get("values").map(|v| v.detached().unwrap()).as_ref(),
            Some(&VmValue::List(vec![VmValue::List(vec![
                vm_int(1),
                vm_int(2),
            ])]))
        );
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_STMT_EXPR,
                VM_GAS_CALL_DISPATCH,
                VM_GAS_EXPR_SUBSCRIPT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
    }

    #[test]
    fn low_chi_during_subscript_target_evaluation_preserves_container() {
        let mut instance = empty_test_instance("assignment_low_chi");
        let original = VmValue::List(vec![vm_int(1), vm_int(2)]);
        let mut scope = HashMap::from([("values".to_owned(), original.clone())]);
        let statement = json!({
            "node": "assign",
            "span": test_span(),
            "targets": [{
                "node": "subscript",
                "span": test_span(),
                "value": test_name("values"),
                "slice": test_int(1),
            }],
            "value": test_int(9),
        });
        let budget = VM_GAS_STMT_ASSIGN + VM_GAS_EXPR_CONSTANT + VM_GAS_EXPR_NAME;
        let mut host = AssignmentMeteringHost {
            budget: Some(budget),
            ..AssignmentMeteringHost::default()
        };

        let error = instance
            .execute_statement(&statement, &mut scope, &mut host)
            .expect_err("index evaluation must exhaust the remaining chi");

        assert_eq!(error.to_string(), "Out of chi.");
        assert_eq!(scope.get("values"), Some(&original));
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_STMT_ASSIGN,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_CONSTANT,
            ]
        );
    }

    #[test]
    fn unsupported_slice_assignment_is_metered_and_preserves_container() {
        let mut instance = empty_test_instance("slice_assignment_metering");
        let original = VmValue::List(vec![vm_int(1), vm_int(2), vm_int(3)]);
        let mut scope = HashMap::from([("values".to_owned(), original.clone())]);
        let statement = json!({
            "node": "assign",
            "span": test_span(),
            "targets": [{
                "node": "subscript",
                "span": test_span(),
                "value": test_name("values"),
                "slice": {
                    "node": "slice",
                    "span": test_span(),
                    "lower": test_int(1),
                    "upper": test_int(2),
                    "step": null,
                },
            }],
            "value": {
                "node": "list",
                "span": test_span(),
                "elements": [test_int(9)],
            },
        });
        let mut host = AssignmentMeteringHost::default();

        let error = instance
            .execute_statement(&statement, &mut scope, &mut host)
            .expect_err("slice assignment remains outside the native VM execution slice");

        assert_eq!(
            error.to_string(),
            "slice expressions are only supported as subscripts"
        );
        assert_eq!(scope.get("values"), Some(&original));
        assert_eq!(
            host.execution_costs,
            vec![
                VM_GAS_STMT_ASSIGN,
                VM_GAS_EXPR_LIST,
                VM_GAS_EXPR_CONSTANT,
                VM_GAS_EXPR_NAME,
                VM_GAS_EXPR_SUBSCRIPT,
            ]
        );
    }

    #[test]
    fn executes_storage_event_and_contract_calls() {
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
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
                        "span": {"line": 2, "col": 0, "end_line": 2, "end_col": 24},
                        "name": "balances",
                        "storage_type": "Hash",
                        "syscall_id": "storage.hash.new",
                        "args": [],
                        "keywords": [
                            {
                                "arg": "default_value",
                                "span": {"line": 2, "col": 16, "end_line": 2, "end_col": 23},
                                "value": {
                                    "node": "constant",
                                    "span": {"line": 2, "col": 23, "end_line": 2, "end_col": 24},
                                    "value_type": "int",
                                    "value": 0
                                }
                            }
                        ]
                    },
                    {
                        "node": "storage_decl",
                        "span": {"line": 3, "col": 0, "end_line": 3, "end_col": 18},
                        "name": "metadata",
                        "storage_type": "Variable",
                        "syscall_id": "storage.variable.new",
                        "args": [],
                        "keywords": []
                    },
                    {
                        "node": "event_decl",
                        "span": {"line": 4, "col": 0, "end_line": 4, "end_col": 10},
                        "name": "TransferEvent",
                        "syscall_id": "event.log.new",
                        "event_name": "Transfer",
                        "params": {
                            "node": "dict",
                            "span": {"line": 4, "col": 0, "end_line": 4, "end_col": 10},
                            "entries": [
                                {
                                    "key": {
                                        "node": "constant",
                                        "span": {"line": 4, "col": 1, "end_line": 4, "end_col": 7},
                                        "value_type": "str",
                                        "value": "from"
                                    },
                                    "value": {
                                        "node": "call",
                                        "span": {"line": 4, "col": 8, "end_line": 4, "end_col": 20},
                                        "func": {
                                            "node": "name",
                                            "span": {"line": 4, "col": 8, "end_line": 4, "end_col": 15},
                                            "id": "indexed",
                                            "host_binding_id": "event.indexed"
                                        },
                                        "args": [
                                            {
                                                "node": "name",
                                                "span": {"line": 4, "col": 16, "end_line": 4, "end_col": 19},
                                                "id": "str",
                                                "host_binding_id": null
                                            }
                                        ],
                                        "keywords": [],
                                        "syscall_id": "event.indexed"
                                    }
                                }
                            ]
                        }
                    }
                ],
                "functions": [
                    {
                        "node": "function",
                        "span": {"line": 6, "col": 0, "end_line": 14, "end_col": 20},
                        "name": "transfer",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "amount",
                                "kind": "positional_or_keyword",
                                "annotation": "int",
                                "default": null,
                                "span": {"line": 6, "col": 13, "end_line": 6, "end_col": 23}
                            },
                            {
                                "name": "to",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 6, "col": 25, "end_line": 6, "end_col": 32}
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "assign",
                                "span": {"line": 7, "col": 4, "end_line": 7, "end_col": 21},
                                "targets": [
                                    {
                                        "node": "name",
                                        "span": {"line": 7, "col": 4, "end_line": 7, "end_col": 10},
                                        "id": "sender",
                                        "host_binding_id": null
                                    }
                                ],
                                "value": {
                                    "node": "attribute",
                                    "span": {"line": 7, "col": 13, "end_line": 7, "end_col": 23},
                                    "value": {
                                        "node": "name",
                                        "span": {"line": 7, "col": 13, "end_line": 7, "end_col": 16},
                                        "id": "ctx",
                                        "host_binding_id": null
                                    },
                                    "attr": "caller",
                                    "path": "ctx.caller",
                                    "host_binding_id": "context.caller"
                                }
                            },
                            {
                                "node": "expr",
                                "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 21},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 21},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 16},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 12},
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
                                            "span": {"line": 8, "col": 17, "end_line": 8, "end_col": 20},
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
                                "span": {"line": 9, "col": 4, "end_line": 9, "end_col": 30},
                                "binding": "balances",
                                "storage_type": "Hash",
                                "read_syscall_id": "storage.hash.get",
                                "write_syscall_id": "storage.hash.set",
                                "key": {
                                    "node": "name",
                                    "span": {"line": 9, "col": 13, "end_line": 9, "end_col": 19},
                                    "id": "sender",
                                    "host_binding_id": null
                                },
                                "operator": "sub",
                                "value": {
                                    "node": "name",
                                    "span": {"line": 9, "col": 24, "end_line": 9, "end_col": 30},
                                    "id": "amount",
                                    "host_binding_id": null
                                }
                            },
                            {
                                "node": "storage_mutate",
                                "span": {"line": 10, "col": 4, "end_line": 10, "end_col": 25},
                                "binding": "balances",
                                "storage_type": "Hash",
                                "read_syscall_id": "storage.hash.get",
                                "write_syscall_id": "storage.hash.set",
                                "key": {
                                    "node": "name",
                                    "span": {"line": 10, "col": 13, "end_line": 10, "end_col": 15},
                                    "id": "to",
                                    "host_binding_id": null
                                },
                                "operator": "add",
                                "value": {
                                    "node": "name",
                                    "span": {"line": 10, "col": 20, "end_line": 10, "end_col": 26},
                                    "id": "amount",
                                    "host_binding_id": null
                                }
                            },
                            {
                                "node": "expr",
                                "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 43},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 43},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 21},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 12},
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
                                            "span": {"line": 11, "col": 22, "end_line": 11, "end_col": 35},
                                            "value": {
                                                "node": "name",
                                                "span": {"line": 11, "col": 29, "end_line": 11, "end_col": 35},
                                                "id": "amount",
                                                "host_binding_id": null
                                            }
                                        },
                                        {
                                            "arg": "to",
                                            "span": {"line": 11, "col": 37, "end_line": 11, "end_col": 42},
                                            "value": {
                                                "node": "name",
                                                "span": {"line": 11, "col": 40, "end_line": 11, "end_col": 42},
                                                "id": "to",
                                                "host_binding_id": null
                                            }
                                        }
                                    ],
                                    "syscall_id": "contract.export_call",
                                    "contract_target": {
                                        "kind": "static_import",
                                        "binding": "currency",
                                        "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 12}
                                    },
                                    "function_name": "transfer"
                                }
                            },
                            {
                                "node": "expr",
                                "span": {"line": 12, "col": 4, "end_line": 12, "end_col": 40},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 12, "col": 4, "end_line": 12, "end_col": 40},
                                    "func": {
                                        "node": "name",
                                        "span": {"line": 12, "col": 4, "end_line": 12, "end_col": 17},
                                        "id": "TransferEvent",
                                        "host_binding_id": null
                                    },
                                    "args": [
                                        {
                                            "node": "dict",
                                            "span": {"line": 12, "col": 18, "end_line": 12, "end_col": 39},
                                            "entries": [
                                                {
                                                    "key": {
                                                        "node": "constant",
                                                        "span": {"line": 12, "col": 19, "end_line": 12, "end_col": 25},
                                                        "value_type": "str",
                                                        "value": "from"
                                                    },
                                                    "value": {
                                                        "node": "name",
                                                        "span": {"line": 12, "col": 27, "end_line": 12, "end_col": 33},
                                                        "id": "sender",
                                                        "host_binding_id": null
                                                    }
                                                }
                                            ]
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "event.log.emit",
                                    "event_binding": "TransferEvent"
                                }
                            },
                            {
                                "node": "return",
                                "span": {"line": 13, "col": 4, "end_line": 13, "end_col": 23},
                                "value": {
                                    "node": "storage_get",
                                    "span": {"line": 13, "col": 11, "end_line": 13, "end_col": 23},
                                    "binding": "balances",
                                    "storage_type": "Hash",
                                    "syscall_id": "storage.hash.get",
                                    "key": {
                                        "node": "name",
                                        "span": {"line": 13, "col": 20, "end_line": 13, "end_col": 22},
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
                    {"binding": "LogEvent", "id": "event.log.new", "kind": "syscall", "category": "event"},
                    {"binding": "LogEvent.__call__", "id": "event.log.emit", "kind": "syscall", "category": "event"},
                    {"binding": "indexed", "id": "event.indexed", "kind": "syscall", "category": "event"},
                    {"binding": "__contract_export__", "id": "contract.export_call", "kind": "syscall", "category": "contract"},
                    {"binding": "ctx.caller", "id": "context.caller", "kind": "context_field", "category": "context"},
                    {"binding": "now", "id": "env.now", "kind": "env_value", "category": "environment"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(
            module,
            VmExecutionContext {
                caller: Some("alice".to_owned()),
                signer: Some("alice".to_owned()),
                now: vm_int(1234),
                ..VmExecutionContext::default()
            },
        )
        .expect("instance should initialize");

        instance
            .hash_set("balances", &VmValue::String("alice".to_owned()), vm_int(20))
            .expect("seed sender balance");

        let mut host = RecordingHost::default();
        let result = instance
            .call_function(
                &mut host,
                "transfer",
                vec![vm_int(5), VmValue::String("bob".to_owned())],
                vec![],
            )
            .expect("transfer should execute");

        assert_eq!(result, vm_int(5));
        assert_eq!(instance.get_variable("metadata"), Some(vm_int(1234)));
        assert_eq!(
            instance
                .get_hash_value("balances", &VmValue::String("alice".to_owned()))
                .expect("alice balance should exist"),
            Some(vm_int(15))
        );
        assert_eq!(
            instance
                .get_hash_value("balances", &VmValue::String("bob".to_owned()))
                .expect("bob balance should exist"),
            Some(vm_int(5))
        );
        assert_eq!(host.events.len(), 1);
        assert_eq!(host.events[0].contract, "sample_token");
        assert_eq!(host.events[0].event, "Transfer");
        assert_eq!(host.events[0].signer, VmValue::String("alice".to_owned()));
        assert_eq!(host.events[0].caller, VmValue::String("alice".to_owned()));
        assert_eq!(
            host.events[0].data_indexed,
            vec![("from".to_owned(), VmValue::String("alice".to_owned()))]
        );
        assert_eq!(host.events[0].data, Vec::<(String, VmValue)>::new());
        assert_eq!(host.calls.len(), 1);
        assert_eq!(contract_target_label(&host.calls[0].target), "currency");
        assert_eq!(host.calls[0].function, "transfer");
    }

    #[test]
    fn resolves_host_bindings_used_as_type_marker_values() {
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "interface_probe",
                "source_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "docstring": null,
                "imports": [],
                "global_declarations": [
                    {
                        "node": "binding_decl",
                        "span": {"line": 1, "col": 0, "end_line": 1, "end_col": 16},
                        "name": "any_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 1, "col": 11, "end_line": 1, "end_col": 14},
                            "id": "Any",
                            "host_binding_id": "typing.any"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 2, "col": 0, "end_line": 2, "end_col": 23},
                        "name": "variable_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 2, "col": 16, "end_line": 2, "end_col": 24},
                            "id": "Variable",
                            "host_binding_id": "storage.variable.new"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 3, "col": 0, "end_line": 3, "end_col": 16},
                        "name": "hash_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 3, "col": 12, "end_line": 3, "end_col": 16},
                            "id": "Hash",
                            "host_binding_id": "storage.hash.new"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 4, "col": 0, "end_line": 4, "end_col": 36},
                        "name": "foreign_variable_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 4, "col": 24, "end_line": 4, "end_col": 39},
                            "id": "ForeignVariable",
                            "host_binding_id": "storage.foreign_variable.new"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 5, "col": 0, "end_line": 5, "end_col": 29},
                        "name": "foreign_hash_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 5, "col": 20, "end_line": 5, "end_col": 31},
                            "id": "ForeignHash",
                            "host_binding_id": "storage.foreign_hash.new"
                        }
                    },
                    {
                        "node": "binding_decl",
                        "span": {"line": 6, "col": 0, "end_line": 6, "end_col": 21},
                        "name": "event_type",
                        "value": {
                            "node": "name",
                            "span": {"line": 6, "col": 13, "end_line": 6, "end_col": 21},
                            "id": "LogEvent",
                            "host_binding_id": "event.log.new"
                        }
                    }
                ],
                "functions": [
                    {
                        "node": "function",
                        "span": {"line": 8, "col": 0, "end_line": 9, "end_col": 94},
                        "name": "get_type_markers",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": {"line": 9, "col": 4, "end_line": 9, "end_col": 94},
                                "value": {
                                    "node": "list",
                                    "span": {"line": 9, "col": 11, "end_line": 9, "end_col": 94},
                                    "elements": [
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 12, "end_line": 9, "end_col": 20},
                                            "id": "any_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 22, "end_line": 9, "end_col": 35},
                                            "id": "variable_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 37, "end_line": 9, "end_col": 46},
                                            "id": "hash_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 48, "end_line": 9, "end_col": 69},
                                            "id": "foreign_variable_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 71, "end_line": 9, "end_col": 88},
                                            "id": "foreign_hash_type",
                                            "host_binding_id": null
                                        },
                                        {
                                            "node": "name",
                                            "span": {"line": 9, "col": 90, "end_line": 9, "end_col": 100},
                                            "id": "event_type",
                                            "host_binding_id": null
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "Any", "id": "typing.any", "kind": "type_marker", "category": "typing"},
                    {"binding": "Variable", "id": "storage.variable.new", "kind": "syscall", "category": "storage"},
                    {"binding": "Hash", "id": "storage.hash.new", "kind": "syscall", "category": "storage"},
                    {"binding": "ForeignVariable", "id": "storage.foreign_variable.new", "kind": "syscall", "category": "storage"},
                    {"binding": "ForeignHash", "id": "storage.foreign_hash.new", "kind": "syscall", "category": "storage"},
                    {"binding": "LogEvent", "id": "event.log.new", "kind": "syscall", "category": "event"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = NoopHost;

        let result = instance
            .call_function(&mut host, "get_type_markers", vec![], vec![])
            .expect("type markers should resolve");

        assert_eq!(
            result,
            VmValue::List(vec![
                VmValue::TypeMarker("Any".to_owned()),
                VmValue::TypeMarker("Variable".to_owned()),
                VmValue::TypeMarker("Hash".to_owned()),
                VmValue::TypeMarker("ForeignVariable".to_owned()),
                VmValue::TypeMarker("ForeignHash".to_owned()),
                VmValue::TypeMarker("LogEvent".to_owned()),
            ])
        );
    }

    #[test]
    fn resolves_dynamic_imports_and_factory_calls() {
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "adapter",
                "source_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": {"line": 1, "col": 0, "end_line": 2, "end_col": 24},
                        "name": "load_token",
                        "visibility": "private",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "token",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 1, "col": 14, "end_line": 1, "end_col": 24}
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": {"line": 2, "col": 4, "end_line": 2, "end_col": 24},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 2, "col": 11, "end_line": 2, "end_col": 24},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 2, "col": 11, "end_line": 2, "end_col": 23},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 2, "col": 11, "end_line": 2, "end_col": 20},
                                            "id": "importlib",
                                            "host_binding_id": null
                                        },
                                        "attr": "import_module",
                                        "path": "importlib.import_module",
                                        "host_binding_id": "contract.import"
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": {"line": 2, "col": 21, "end_line": 2, "end_col": 24},
                                            "id": "token",
                                            "host_binding_id": null
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "contract.import"
                                }
                            }
                        ]
                    },
                    {
                        "node": "function",
                        "span": {"line": 4, "col": 0, "end_line": 5, "end_col": 40},
                        "name": "balance_of_token",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "token",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 4, "col": 20, "end_line": 4, "end_col": 30}
                            },
                            {
                                "name": "account",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 4, "col": 32, "end_line": 4, "end_col": 44}
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": {"line": 5, "col": 4, "end_line": 5, "end_col": 40},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 40},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 29},
                                        "value": {
                                            "node": "call",
                                            "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 28},
                                            "func": {
                                                "node": "name",
                                                "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 21},
                                                "id": "load_token",
                                                "host_binding_id": null
                                            },
                                            "args": [
                                                {
                                                    "node": "name",
                                                    "span": {"line": 5, "col": 22, "end_line": 5, "end_col": 27},
                                                    "id": "token",
                                                    "host_binding_id": null
                                                }
                                            ],
                                            "keywords": []
                                        },
                                        "attr": "balance_of",
                                        "path": "load_token.balance_of",
                                        "host_binding_id": null
                                    },
                                    "args": [],
                                    "keywords": [
                                        {
                                            "arg": "account",
                                            "span": {"line": 5, "col": 30, "end_line": 5, "end_col": 39},
                                            "value": {
                                                "node": "name",
                                                "span": {"line": 5, "col": 38, "end_line": 5, "end_col": 45},
                                                "id": "account",
                                                "host_binding_id": null
                                            }
                                        }
                                    ],
                                    "syscall_id": "contract.export_call",
                                    "contract_target": {
                                        "kind": "factory_call",
                                        "factory": "load_token",
                                        "source": {
                                            "node": "call",
                                            "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 28},
                                            "func": {
                                                "node": "name",
                                                "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 21},
                                                "id": "load_token",
                                                "host_binding_id": null
                                            },
                                            "args": [
                                                {
                                                    "node": "name",
                                                    "span": {"line": 5, "col": 22, "end_line": 5, "end_col": 27},
                                                    "id": "token",
                                                    "host_binding_id": null
                                                }
                                            ],
                                            "keywords": []
                                        },
                                        "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 28}
                                    },
                                    "function_name": "balance_of"
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "importlib.import_module", "id": "contract.import", "kind": "syscall", "category": "import"},
                    {"binding": "__contract_export__", "id": "contract.export_call", "kind": "syscall", "category": "contract"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "balance_of_token",
                vec![
                    VmValue::String("shielded_note".to_owned()),
                    VmValue::String("alice".to_owned()),
                ],
                vec![],
            )
            .expect("call should execute");

        assert_eq!(result, vm_int(77));
        assert_eq!(host.calls.len(), 1);
        match &host.calls[0].target {
            VmContractTarget::FactoryCall { factory, module } => {
                assert_eq!(factory, "load_token");
                assert_eq!(module, "shielded_note");
            }
            other => panic!("unexpected contract target: {other:?}"),
        }
        assert_eq!(host.calls[0].function, "balance_of");
    }

    #[test]
    fn supports_string_replace_with_optional_count() {
        let replaced = call_native_method(
            VmValue::String("foo-foo-foo".to_owned()),
            "replace",
            vec![
                VmValue::String("foo".to_owned()),
                VmValue::String("bar".to_owned()),
            ],
            vec![],
        )
        .expect("replace should succeed");
        match replaced {
            NativeMethodResult::Value(VmValue::String(value)) => {
                assert_eq!(value, "bar-bar-bar".to_owned());
            }
            _ => panic!("unexpected replace result"),
        }

        let limited = call_native_method(
            VmValue::String("foo-foo-foo".to_owned()),
            "replace",
            vec![
                VmValue::String("foo".to_owned()),
                VmValue::String("bar".to_owned()),
                vm_int(2),
            ],
            vec![],
        )
        .expect("replace with count should succeed");
        match limited {
            NativeMethodResult::Value(VmValue::String(value)) => {
                assert_eq!(value, "bar-bar-foo".to_owned());
            }
            _ => panic!("unexpected replace result with count"),
        }

        let negative = call_native_method(
            VmValue::String("foo-foo".to_owned()),
            "replace",
            vec![
                VmValue::String("foo".to_owned()),
                VmValue::String("bar".to_owned()),
                vm_int(-1),
            ],
            vec![],
        )
        .expect("replace with negative count should replace all");
        match negative {
            NativeMethodResult::Value(VmValue::String(value)) => {
                assert_eq!(value, "bar-bar".to_owned());
            }
            _ => panic!("unexpected replace result with negative count"),
        }
    }

    #[test]
    fn supports_common_string_helper_methods() {
        let upper = call_native_method(
            VmValue::String("Alpha beta".to_owned()),
            "upper",
            vec![],
            vec![],
        )
        .expect("upper should succeed");
        assert_eq!(
            upper,
            NativeMethodResult::Value(VmValue::String("ALPHA BETA".to_owned()))
        );

        let strip = call_native_method(
            VmValue::String("  Alpha  ".to_owned()),
            "strip",
            vec![],
            vec![],
        )
        .expect("strip should succeed");
        assert_eq!(
            strip,
            NativeMethodResult::Value(VmValue::String("Alpha".to_owned()))
        );

        let endswith = call_native_method(
            VmValue::String("Alpha beta ALPHA".to_owned()),
            "endswith",
            vec![
                VmValue::Tuple(vec![
                    VmValue::String("nope".to_owned()),
                    VmValue::String("ALPHA".to_owned()),
                ]),
                vm_int(0),
                vm_int(16),
            ],
            vec![],
        )
        .expect("endswith should succeed");
        assert_eq!(endswith, NativeMethodResult::Value(VmValue::Bool(true)));

        let split = call_native_method(
            VmValue::String(" a  b c ".to_owned()),
            "split",
            vec![VmValue::None, vm_int(1)],
            vec![],
        )
        .expect("split should succeed");
        assert_eq!(
            split,
            NativeMethodResult::Value(VmValue::List(vec![
                VmValue::String("a".to_owned()),
                VmValue::String("b c ".to_owned()),
            ]))
        );
    }

    #[test]
    fn supports_list_and_dict_helper_methods() {
        let index = call_native_method(
            VmValue::List(vec![vm_int(1), vm_int(2), vm_int(2), vm_int(3)]),
            "index",
            vec![vm_int(2), vm_int(2)],
            vec![],
        )
        .expect("list.index should succeed");
        assert_eq!(index, NativeMethodResult::Value(vm_int(2)));

        let copied = call_native_method(
            VmValue::List(vec![vm_int(1), vm_int(2)]),
            "copy",
            vec![],
            vec![],
        )
        .expect("list.copy should succeed");
        assert_eq!(
            copied,
            NativeMethodResult::Value(VmValue::List(vec![vm_int(1), vm_int(2)]))
        );

        let popped = call_native_method(
            VmValue::Dict(vec![
                (VmValue::String("alpha".to_owned()), vm_int(1)),
                (VmValue::String("beta".to_owned()), vm_int(2)),
            ]),
            "pop",
            vec![VmValue::String("beta".to_owned())],
            vec![],
        )
        .expect("dict.pop should succeed");
        assert_eq!(
            popped,
            NativeMethodResult::Mutated {
                receiver: VmValue::Dict(vec![(VmValue::String("alpha".to_owned()), vm_int(1))]),
                value: vm_int(2),
            }
        );

        let cleared = call_native_method(
            VmValue::Dict(vec![(VmValue::String("alpha".to_owned()), vm_int(1))]),
            "clear",
            vec![],
            vec![],
        )
        .expect("dict.clear should succeed");
        assert_eq!(
            cleared,
            NativeMethodResult::Mutated {
                receiver: VmValue::Dict(Vec::new()),
                value: VmValue::None,
            }
        );
    }

    #[test]
    fn supports_decimal_pow_for_integer_and_square_root_exponents() {
        let nine = VmDecimal::from_str_literal("9").expect("decimal literal should parse");
        let square_root = nine
            .pow(&VmDecimal::from_str_literal("0.5").expect("decimal exponent should parse"))
            .expect("square root exponent should succeed");
        assert_eq!(
            square_root,
            VmDecimal::from_str_literal("3").expect("expected decimal should parse")
        );

        let fractional = VmDecimal::from_str_literal("0.1").expect("decimal literal should parse");
        let cubic = fractional
            .pow(&VmDecimal::from_str_literal("3.0").expect("decimal exponent should parse"))
            .expect("integer-like decimal exponent should succeed");
        assert_eq!(
            cubic,
            VmDecimal::from_str_literal("0.001").expect("expected decimal should parse")
        );
    }

    #[test]
    fn hash_syscalls_separate_text_and_hex_inputs() {
        let text = hash_sha3_256_text(vec![VmValue::String("68656c6c6f".to_owned())], vec![])
            .expect("text hash should succeed");
        let decoded = hash_sha3_256_hex(vec![VmValue::String("68656c6c6f".to_owned())], vec![])
            .expect("hex hash should succeed");

        assert_eq!(
            text,
            VmValue::String(hex::encode(Sha3_256::digest("68656c6c6f".as_bytes())))
        );
        assert_eq!(
            decoded,
            VmValue::String(hex::encode(Sha3_256::digest(b"hello")))
        );
        assert_ne!(text, decoded);

        let error = hash_sha3_256_hex(vec![VmValue::String("68 65".to_owned())], vec![])
            .expect_err("hex mode should reject whitespace");
        assert!(error.to_string().contains("hash hex input"));
    }

    #[test]
    fn integer_arithmetic_rejects_oversized_results() {
        let huge = BigInt::from(1u8) << (MAX_INTEGER_BITS as usize);
        let mul_error = apply_binary_operator("mul", VmValue::Int(huge), vm_int(2))
            .expect_err("oversized multiplication should fail");
        assert!(mul_error
            .to_string()
            .contains("integer multiplication exceeds"));

        let pow_error = apply_binary_operator("pow", vm_int(2), vm_int(MAX_INTEGER_BITS))
            .expect_err("oversized exponentiation should fail");
        assert!(pow_error
            .to_string()
            .contains("integer exponentiation exceeds"));

        let shift_error = apply_binary_operator("lshift", vm_int(1), vm_int(MAX_INTEGER_BITS))
            .expect_err("oversized left shift should fail");
        assert!(shift_error.to_string().contains("left shift exceeds"));
    }

    #[test]
    fn int_input_size_guard_rejects_oversized_strings() {
        let value = "9".repeat(MAX_INT_STRING_CHARS + 1);
        let error = ensure_int_input_size(&value).expect_err("oversized int input should fail");
        assert!(error.to_string().contains("int() input exceeds"));
    }

    #[test]
    fn delegates_zk_syscalls_to_host() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "zk_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "probe",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "payload",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "assign",
                                "span": span.clone(),
                                "targets": [
                                    {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "verified",
                                        "host_binding_id": null
                                    }
                                ],
                                "value": {
                                    "node": "call",
                                    "span": span.clone(),
                                    "func": {
                                        "node": "attribute",
                                        "span": span.clone(),
                                        "value": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "zk",
                                            "host_binding_id": null
                                        },
                                        "attr": "verify_groth16",
                                        "path": "zk.verify_groth16",
                                        "host_binding_id": "zk.verify_groth16"
                                    },
                                    "args": [
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "str",
                                            "value": "vk-main"
                                        },
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "str",
                                            "value": "proof-main"
                                        },
                                        {
                                            "node": "list",
                                            "span": span.clone(),
                                            "elements": [
                                                {
                                                    "node": "name",
                                                    "span": span.clone(),
                                                    "id": "payload",
                                                    "host_binding_id": null
                                                },
                                                {
                                                    "node": "constant",
                                                    "span": span.clone(),
                                                    "value_type": "str",
                                                    "value": "42"
                                                }
                                            ]
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "zk.verify_groth16"
                                }
                            },
                            {
                                "node": "assign",
                                "span": span.clone(),
                                "targets": [
                                    {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "digest",
                                        "host_binding_id": null
                                    }
                                ],
                                "value": {
                                    "node": "call",
                                    "span": span.clone(),
                                    "func": {
                                        "node": "attribute",
                                        "span": span.clone(),
                                        "value": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "zk",
                                            "host_binding_id": null
                                        },
                                        "attr": "shielded_output_payload_hash",
                                        "path": "zk.shielded_output_payload_hash",
                                        "host_binding_id": "zk.shielded_output_payload_hash"
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "payload",
                                            "host_binding_id": null
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "zk.shielded_output_payload_hash"
                                }
                            },
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "dict",
                                    "span": span.clone(),
                                    "entries": [
                                        {
                                            "key": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "verified"
                                            },
                                            "value": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "verified",
                                                "host_binding_id": null
                                            }
                                        },
                                        {
                                            "key": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "digest"
                                            },
                                            "value": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "digest",
                                                "host_binding_id": null
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "zk.verify_groth16", "id": "zk.verify_groth16", "kind": "syscall", "category": "zk"},
                    {"binding": "zk.shielded_output_payload_hash", "id": "zk.shielded_output_payload_hash", "kind": "syscall", "category": "zk"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = SyscallRecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "probe",
                vec![VmValue::String("0x1234".to_owned())],
                vec![],
            )
            .expect("call should execute");

        let VmValue::Dict(entries) = result else {
            panic!("expected dict result");
        };
        assert_eq!(
            dict_get(&entries, &VmValue::String("verified".to_owned())).unwrap(),
            Some(VmValue::Bool(true))
        );
        assert_eq!(
            dict_get(&entries, &VmValue::String("digest".to_owned())).unwrap(),
            Some(VmValue::String("0x".to_owned() + &"ab".repeat(32)))
        );
        assert_eq!(host.syscalls.len(), 2);
        assert_eq!(host.syscalls[0].0, "zk.verify_groth16");
        assert_eq!(
            host.syscalls[0].1,
            vec![
                VmValue::String("vk-main".to_owned()),
                VmValue::String("proof-main".to_owned()),
                VmValue::List(vec![
                    VmValue::String("0x1234".to_owned()),
                    VmValue::String("42".to_owned()),
                ]),
            ]
        );
        assert_eq!(host.syscalls[1].0, "zk.shielded_output_payload_hash");
        assert_eq!(
            host.syscalls[1].1,
            vec![VmValue::String("0x1234".to_owned())]
        );
    }

    #[test]
    fn evaluates_list_comprehensions() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "list_comp_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "positives",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "values",
                                "kind": "positional_or_keyword",
                                "annotation": "list[int]",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "list_comp",
                                    "span": span.clone(),
                                    "element": {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "value",
                                        "host_binding_id": null
                                    },
                                    "generators": [
                                        {
                                            "target": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            },
                                            "iter": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "values",
                                                "host_binding_id": null
                                            },
                                            "ifs": [
                                                {
                                                    "node": "compare",
                                                    "span": span.clone(),
                                                    "left": {
                                                        "node": "name",
                                                        "span": span.clone(),
                                                        "id": "value",
                                                        "host_binding_id": null
                                                    },
                                                    "operators": ["gt"],
                                                    "comparators": [
                                                        {
                                                            "node": "constant",
                                                            "span": span.clone(),
                                                            "value_type": "int",
                                                            "value": 0
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "positives",
                vec![VmValue::List(vec![
                    vm_int(-2),
                    vm_int(0),
                    vm_int(3),
                    vm_int(5),
                ])],
                vec![],
            )
            .expect("call should execute");

        assert_eq!(result, VmValue::List(vec![vm_int(3), vm_int(5)]));
    }

    #[test]
    fn evaluates_dict_comprehensions() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "dict_comp_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "prices",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "values",
                                "kind": "positional_or_keyword",
                                "annotation": "list[int]",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "dict_comp",
                                    "span": span.clone(),
                                    "key": {
                                        "node": "call",
                                        "span": span.clone(),
                                        "func": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "str",
                                            "host_binding_id": null
                                        },
                                        "args": [
                                            {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            }
                                        ],
                                        "keywords": []
                                    },
                                    "value": {
                                        "node": "bin_op",
                                        "span": span.clone(),
                                        "operator": "mul",
                                        "left": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "value",
                                            "host_binding_id": null
                                        },
                                        "right": {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "int",
                                            "value": 2
                                        }
                                    },
                                    "generators": [
                                        {
                                            "target": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            },
                                            "iter": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "values",
                                                "host_binding_id": null
                                            },
                                            "ifs": [
                                                {
                                                    "node": "compare",
                                                    "span": span.clone(),
                                                    "left": {
                                                        "node": "name",
                                                        "span": span.clone(),
                                                        "id": "value",
                                                        "host_binding_id": null
                                                    },
                                                    "operators": ["gt"],
                                                    "comparators": [
                                                        {
                                                            "node": "constant",
                                                            "span": span.clone(),
                                                            "value_type": "int",
                                                            "value": 0
                                                        }
                                                    ]
                                                }
                                            ]
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "prices",
                vec![VmValue::List(vec![
                    vm_int(-2),
                    vm_int(0),
                    vm_int(3),
                    vm_int(5),
                ])],
                vec![],
            )
            .expect("call should execute");

        let VmValue::Dict(entries) = result else {
            panic!("expected dict result");
        };
        assert_eq!(
            dict_get(&entries, &VmValue::String("3".to_owned())).unwrap(),
            Some(vm_int(6))
        );
        assert_eq!(
            dict_get(&entries, &VmValue::String("5".to_owned())).unwrap(),
            Some(vm_int(10))
        );
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn evaluates_dict_unpacking() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "dict_unpack_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "payload",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "base",
                                "kind": "positional_or_keyword",
                                "annotation": "dict",
                                "default": null,
                                "span": span.clone()
                            },
                            {
                                "name": "override",
                                "kind": "positional_or_keyword",
                                "annotation": "dict",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "dict",
                                    "span": span.clone(),
                                    "entries": [
                                        {
                                            "unpack": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "base",
                                                "host_binding_id": null
                                            }
                                        },
                                        {
                                            "key": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "kind"
                                            },
                                            "value": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "price"
                                            }
                                        },
                                        {
                                            "unpack": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "override",
                                                "host_binding_id": null
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "payload",
                vec![
                    VmValue::Dict(vec![
                        (
                            VmValue::String("symbol".to_owned()),
                            VmValue::String("XIAN".to_owned()),
                        ),
                        (VmValue::String("value".to_owned()), vm_int(42)),
                    ]),
                    VmValue::Dict(vec![(VmValue::String("value".to_owned()), vm_int(77))]),
                ],
                vec![],
            )
            .expect("call should execute");

        assert_eq!(
            result,
            VmValue::Dict(vec![
                (
                    VmValue::String("symbol".to_owned()),
                    VmValue::String("XIAN".to_owned())
                ),
                (VmValue::String("value".to_owned()), vm_int(77)),
                (
                    VmValue::String("kind".to_owned()),
                    VmValue::String("price".to_owned())
                ),
            ])
        );
    }

    #[test]
    fn executes_while_loops() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "while_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "countdown",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "value",
                                "kind": "positional_or_keyword",
                                "annotation": "int",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "while",
                                "span": span.clone(),
                                "test": {
                                    "node": "compare",
                                    "span": span.clone(),
                                    "left": {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "value",
                                        "host_binding_id": null
                                    },
                                    "operators": ["gt"],
                                    "comparators": [
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "int",
                                            "value": 0
                                        }
                                    ]
                                },
                                "body": [
                                    {
                                        "node": "assign",
                                        "span": span.clone(),
                                        "targets": [
                                            {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            }
                                        ],
                                        "value": {
                                            "node": "bin_op",
                                            "span": span.clone(),
                                            "operator": "sub",
                                            "left": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "value",
                                                "host_binding_id": null
                                            },
                                            "right": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "int",
                                                "value": 1
                                            }
                                        }
                                    }
                                ],
                                "orelse": []
                            },
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "name",
                                    "span": span.clone(),
                                    "id": "value",
                                    "host_binding_id": null
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(&mut host, "countdown", vec![vm_int(4)], vec![])
            .expect("call should execute");

        assert_eq!(result, vm_int(0));
    }

    #[test]
    fn formats_assert_failures_like_python_repr() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "assert_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "must_be_positive",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "value",
                                "kind": "positional_or_keyword",
                                "annotation": "int",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "assert",
                                "span": span.clone(),
                                "test": {
                                    "node": "compare",
                                    "span": span.clone(),
                                    "left": {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "value",
                                        "host_binding_id": null
                                    },
                                    "operators": ["gt"],
                                    "comparators": [
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "int",
                                            "value": 0
                                        }
                                    ]
                                },
                                "message": {
                                    "node": "constant",
                                    "span": span.clone(),
                                    "value_type": "str",
                                    "value": "value must be positive"
                                }
                            },
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "name",
                                    "span": span.clone(),
                                    "id": "value",
                                    "host_binding_id": null
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let error = instance
            .call_function(&mut host, "must_be_positive", vec![vm_int(-1)], vec![])
            .expect_err("call should fail");

        assert_eq!(
            error.to_string(),
            "AssertionError('value must be positive')"
        );
    }

    #[test]
    fn supports_ord_builtin() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "ord_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "ascii_code",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "value",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "call",
                                    "span": span.clone(),
                                    "func": {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "ord",
                                        "host_binding_id": null
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "value",
                                            "host_binding_id": null
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": null,
                                    "event_binding": null
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "ascii_code",
                vec![VmValue::String("A".to_owned())],
                vec![],
            )
            .expect("call should execute");

        assert_eq!(result, vm_int(65));
    }
}
