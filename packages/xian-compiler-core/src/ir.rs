use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};

use crate::artifact::{build_contract_artifact, ContractArtifact};
use crate::compiler::CompileOptions;
use crate::constants::{validate_profile, XIAN_IR_V1, XIAN_VM_HOST_CATALOG_V1};
use crate::diagnostic::{CompilerDiagnostic, SourceRange};
use crate::frontend::parse_source;
use crate::handle_inference::{
    infer_contract_handles, sweep_bindings, FunctionHandleFacts, HandleArgument, HandleSource,
    InferenceError, Readiness,
};
use crate::limits::{
    compile_work_message, ir_json_bytes_message, validate_ir_json_limits, WorkBudget, WorkExceeded,
    COMPILE_WORK_CODE, IR_JSON_BYTES_CODE, MAX_CONTRACT_HANDLE_INFERENCE_PASSES, MAX_IR_JSON_BYTES,
};
use crate::lint::lint_syntax;
use crate::normalize::{
    format_expression as format_syntax_expression, format_float, normalize_source, normalize_syntax,
};
use crate::source::SourceUnit;
use crate::syntax::{
    build_syntax_tree, SyntaxBinaryOperator, SyntaxBoolOperator, SyntaxCompareOperator,
    SyntaxComprehension, SyntaxConstant, SyntaxDictEntry, SyntaxExpression,
    SyntaxExpressionContext, SyntaxImportAlias, SyntaxKeyword, SyntaxModule, SyntaxParameter,
    SyntaxParameterKind, SyntaxStatement, SyntaxUnaryOperator,
};

/// A JSON object of IR fields. Unlike `json!`, which serializes each field
/// value again (copying every nested subtree once per nesting level, work
/// times the depth), the field values move in.
macro_rules! ir_object {
    ($($key:literal : $value:expr),* $(,)?) => {{
        let mut fields = serde_json::Map::new();
        $( fields.insert($key.to_owned(), IrField::into_field($value)); )*
        Value::Object(fields)
    }};
}

/// An IR field value: a lowered `Value` moves in, anything else is
/// serialized as `json!` serializes it.
trait IrField {
    fn into_field(self) -> Value;
}

impl IrField for Value {
    fn into_field(self) -> Value {
        self
    }
}

macro_rules! serialized_ir_fields {
    ($($field:ty),* $(,)?) => {$(
        impl IrField for $field {
            fn into_field(self) -> Value {
                serde_json::to_value(self).expect("IR fields serialize")
            }
        }
    )*};
}

serialized_ir_fields!(
    &str,
    &String,
    String,
    &bool,
    bool,
    u32,
    usize,
    i64,
    &Option<String>,
    Option<&str>,
    Option<String>,
    Vec<Value>,
    Vec<&str>,
    Option<Value>,
);

const STORAGE_CONSTRUCTORS: &[(&str, &str)] = &[
    ("Variable", "storage.variable.new"),
    ("Hash", "storage.hash.new"),
    ("ForeignVariable", "storage.foreign_variable.new"),
    ("ForeignHash", "storage.foreign_hash.new"),
];

const STORAGE_METHOD_SYSCALLS: &[(&str, &str, &str)] = &[
    ("Variable", "get", "storage.variable.get"),
    ("Variable", "set", "storage.variable.set"),
    ("ForeignVariable", "get", "storage.foreign_variable.get"),
    ("Hash", "all", "storage.hash.all"),
    ("ForeignHash", "all", "storage.foreign_hash.all"),
];

const STORAGE_SUBSCRIPT_READ_SYSCALLS: &[(&str, &str)] = &[
    ("Hash", "storage.hash.get"),
    ("ForeignHash", "storage.foreign_hash.get"),
];

const STORAGE_SUBSCRIPT_WRITE_SYSCALLS: &[(&str, &str)] = &[("Hash", "storage.hash.set")];

const EVENT_CONSTRUCTOR: &str = "LogEvent";
const CONTRACT_EXPORT_SYSCALL: &str = "contract.export_call";

const HOST_MODULE_BINDINGS: &[&str] =
    &["importlib", "hashlib", "crypto", "datetime", "random", "zk"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostBinding {
    pub binding: &'static str,
    pub id: &'static str,
    pub kind: &'static str,
    pub category: &'static str,
}

const fn host_binding(
    binding: &'static str,
    id: &'static str,
    kind: &'static str,
    category: &'static str,
) -> HostBinding {
    HostBinding {
        binding,
        id,
        kind,
        category,
    }
}

pub const HOST_BINDINGS: &[HostBinding] = &[
    host_binding("Any", "typing.any", "type_marker", "typing"),
    host_binding("Variable", "storage.variable.new", "syscall", "storage"),
    host_binding("Variable.get", "storage.variable.get", "syscall", "storage"),
    host_binding("Variable.set", "storage.variable.set", "syscall", "storage"),
    host_binding("Hash", "storage.hash.new", "syscall", "storage"),
    host_binding("Hash.__getitem__", "storage.hash.get", "syscall", "storage"),
    host_binding("Hash.all", "storage.hash.all", "syscall", "storage"),
    host_binding("Hash.__setitem__", "storage.hash.set", "syscall", "storage"),
    host_binding(
        "ForeignVariable",
        "storage.foreign_variable.new",
        "syscall",
        "storage",
    ),
    host_binding(
        "ForeignVariable.get",
        "storage.foreign_variable.get",
        "syscall",
        "storage",
    ),
    host_binding(
        "ForeignHash",
        "storage.foreign_hash.new",
        "syscall",
        "storage",
    ),
    host_binding(
        "ForeignHash.__getitem__",
        "storage.foreign_hash.get",
        "syscall",
        "storage",
    ),
    host_binding(
        "ForeignHash.all",
        "storage.foreign_hash.all",
        "syscall",
        "storage",
    ),
    host_binding("LogEvent", "event.log.new", "syscall", "event"),
    host_binding("LogEvent.__call__", "event.log.emit", "syscall", "event"),
    host_binding("indexed", "event.indexed", "syscall", "event"),
    host_binding("__Contract", "contract.handle.new", "syscall", "contract"),
    host_binding("Contract.deploy", "contract.deploy", "syscall", "contract"),
    host_binding("Contract.get_info", "contract.info", "syscall", "contract"),
    host_binding(
        "Contract.set_owner",
        "contract.set_owner",
        "syscall",
        "contract",
    ),
    host_binding(
        "Contract.set_developer",
        "contract.set_developer",
        "syscall",
        "contract",
    ),
    host_binding("decimal", "numeric.decimal.new", "syscall", "numeric"),
    host_binding("datetime.datetime", "time.datetime.new", "syscall", "time"),
    host_binding(
        "datetime.timedelta",
        "time.timedelta.new",
        "syscall",
        "time",
    ),
    host_binding(
        "datetime.datetime.strptime",
        "time.datetime.strptime",
        "syscall",
        "time",
    ),
    host_binding("datetime.SECONDS", "time.seconds", "value", "time"),
    host_binding("datetime.MINUTES", "time.minutes", "value", "time"),
    host_binding("datetime.HOURS", "time.hours", "value", "time"),
    host_binding("datetime.DAYS", "time.days", "value", "time"),
    host_binding("datetime.WEEKS", "time.weeks", "value", "time"),
    host_binding("hashlib.sha3", "hash.sha3_256_legacy", "syscall", "hashing"),
    host_binding("hashlib.sha256", "hash.sha256_legacy", "syscall", "hashing"),
    host_binding(
        "hashlib.sha3_text",
        "hash.sha3_256_text",
        "syscall",
        "hashing",
    ),
    host_binding(
        "hashlib.sha3_hex",
        "hash.sha3_256_hex",
        "syscall",
        "hashing",
    ),
    host_binding(
        "hashlib.sha256_text",
        "hash.sha256_text",
        "syscall",
        "hashing",
    ),
    host_binding(
        "hashlib.sha256_hex",
        "hash.sha256_hex",
        "syscall",
        "hashing",
    ),
    host_binding(
        "crypto.verify",
        "crypto.ed25519_verify",
        "syscall",
        "crypto",
    ),
    host_binding(
        "crypto.key_is_valid",
        "crypto.key_is_valid",
        "syscall",
        "crypto",
    ),
    host_binding("importlib", "module.importlib", "value", "import"),
    host_binding(
        "importlib.import_module",
        "contract.import",
        "syscall",
        "import",
    ),
    host_binding("importlib.exists", "contract.exists", "syscall", "import"),
    host_binding(
        "importlib.has_export",
        "contract.has_export",
        "syscall",
        "import",
    ),
    host_binding("importlib.call", "contract.call", "syscall", "import"),
    host_binding(
        "importlib.enforce_interface",
        "contract.enforce_interface",
        "syscall",
        "import",
    ),
    host_binding(
        "importlib.owner_of",
        "contract.owner_of",
        "syscall",
        "import",
    ),
    host_binding(
        "importlib.contract_info",
        "contract.info",
        "syscall",
        "import",
    ),
    host_binding(
        "importlib.code_hash",
        "contract.code_hash",
        "syscall",
        "import",
    ),
    host_binding(
        "importlib.Func",
        "contract.interface.func",
        "syscall",
        "import",
    ),
    host_binding(
        "importlib.Var",
        "contract.interface.var",
        "syscall",
        "import",
    ),
    host_binding("hashlib", "module.hashlib", "value", "hashing"),
    host_binding("crypto", "module.crypto", "value", "crypto"),
    host_binding("datetime", "module.datetime", "value", "time"),
    host_binding("random", "module.random", "value", "random"),
    host_binding("zk", "module.zk", "value", "zk"),
    host_binding(
        "__contract_export__",
        "contract.export_call",
        "syscall",
        "contract",
    ),
    host_binding("random.seed", "random.seed", "syscall", "random"),
    host_binding("random.random", "random.random", "syscall", "random"),
    host_binding("random.shuffle", "random.shuffle", "syscall", "random"),
    host_binding(
        "random.getrandbits",
        "random.getrandbits",
        "syscall",
        "random",
    ),
    host_binding("random.randrange", "random.randrange", "syscall", "random"),
    host_binding("random.randint", "random.randint", "syscall", "random"),
    host_binding("random.choice", "random.choice", "syscall", "random"),
    host_binding("random.choices", "random.choices", "syscall", "random"),
    host_binding("zk.is_available", "zk.is_available", "syscall", "zk"),
    host_binding(
        "zk.has_verifying_key",
        "zk.has_verifying_key",
        "syscall",
        "zk",
    ),
    host_binding("zk.get_vk_info", "zk.get_vk_info", "syscall", "zk"),
    host_binding(
        "zk.verify_groth16_bn254",
        "zk.verify_groth16_bn254",
        "syscall",
        "zk",
    ),
    host_binding("zk.verify_groth16", "zk.verify_groth16", "syscall", "zk"),
    host_binding(
        "zk.clear_prepared_vk_cache",
        "zk.clear_prepared_vk_cache",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.clear_verified_proof_cache",
        "zk.clear_verified_proof_cache",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.warm_verified_proofs",
        "zk.warm_verified_proofs",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_note_append_commitments",
        "zk.shielded_note_append_commitments",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_command_nullifier_digest",
        "zk.shielded_command_nullifier_digest",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_command_binding",
        "zk.shielded_command_binding",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_command_execution_tag",
        "zk.shielded_command_execution_tag",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_command_public_inputs",
        "zk.shielded_command_public_inputs",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_deposit_public_inputs",
        "zk.shielded_deposit_public_inputs",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_output_payload_hashes",
        "zk.shielded_output_payload_hashes",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_output_payload_hash",
        "zk.shielded_output_payload_hash",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_transfer_public_inputs",
        "zk.shielded_transfer_public_inputs",
        "syscall",
        "zk",
    ),
    host_binding(
        "zk.shielded_withdraw_public_inputs",
        "zk.shielded_withdraw_public_inputs",
        "syscall",
        "zk",
    ),
    host_binding("ctx.caller", "context.caller", "context_field", "context"),
    host_binding("ctx.signer", "context.signer", "context_field", "context"),
    host_binding("ctx.this", "context.this", "context_field", "context"),
    host_binding("ctx.owner", "context.owner", "context_field", "context"),
    host_binding("ctx.entry", "context.entry", "context_field", "context"),
    host_binding(
        "ctx.submission_name",
        "context.submission_name",
        "context_field",
        "context",
    ),
    host_binding("now", "env.now", "env_value", "environment"),
    host_binding("block_num", "env.block_num", "env_value", "environment"),
    host_binding("block_hash", "env.block_hash", "env_value", "environment"),
    host_binding("chain_id", "env.chain_id", "env_value", "environment"),
];

pub fn describe_vm_host_surface() -> Value {
    ir_object!(
        "catalog_version": XIAN_VM_HOST_CATALOG_V1,
        "bindings": HOST_BINDINGS.iter().map(host_binding_value).collect::<Vec<_>>(),
    )
}

pub fn lower_source_to_ir(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Result<Value, Vec<CompilerDiagnostic>> {
    let (ir, _) = lower_source_to_checked_ir(module_name, source, options)?;
    Ok(ir)
}

pub fn lower_source_to_ir_json(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Result<String, Vec<CompilerDiagnostic>> {
    lower_source_to_checked_ir(module_name, source, options).map(|(_, payload)| payload)
}

/// The IR of `source` and its canonical JSON, within the IR size limit.
fn lower_source_to_checked_ir(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Result<(Value, String), Vec<CompilerDiagnostic>> {
    let (_, syntax) = normalize_and_build_syntax(module_name, source, options)?;
    let ir = lower_syntax_to_ir(&syntax, &options.vm_profile)
        .map_err(|error| vec![error.into_diagnostic()])?;
    let payload = to_python_canonical_json(&ir);
    validate_ir_json_limits(&payload).map_err(|error| vec![error])?;
    Ok((ir, payload))
}

pub fn compile_contract_artifact(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Result<ContractArtifact, Vec<CompilerDiagnostic>> {
    let (normalized_source, syntax) = normalize_and_build_syntax(module_name, source, options)?;
    let ir = lower_syntax_to_ir(&syntax, &options.vm_profile)
        .map_err(|error| vec![error.into_diagnostic()])?;
    let vm_ir_json = to_python_canonical_json(&ir);
    validate_ir_json_limits(&vm_ir_json).map_err(|error| vec![error])?;
    build_contract_artifact(module_name, source, &normalized_source, &vm_ir_json).map_err(|error| {
        vec![CompilerDiagnostic::error(
            "xian.artifact.invalid",
            error.to_string(),
        )]
    })
}

/// A contract as a node deploys submitted source: the normalized (linted)
/// source and the canonical IR lowered from that source. For accepted source
/// it is the artifact's `source` and `vm_ir_json`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledSource {
    pub source: String,
    pub vm_ir_json: String,
}

pub fn compile_contract_source(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Result<CompiledSource, Vec<CompilerDiagnostic>> {
    let normalized_source = normalize_source(module_name, source, options)?;
    let vm_ir_json = lower_source_to_ir_json(module_name, &normalized_source, options)?;
    Ok(CompiledSource {
        source: normalized_source,
        vm_ir_json,
    })
}

/// `json.dumps(value, sort_keys=True, ensure_ascii=False)` with Python's
/// float text, written into one buffer.
fn to_python_canonical_json(value: &Value) -> String {
    let mut output = String::new();
    write_python_canonical_json(value, &mut output);
    output
}

fn write_python_canonical_json(value: &Value, output: &mut String) {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => write_number(value, output),
        Value::String(value) => write_json_string(value, output),
        Value::Array(values) => {
            write_separated(output, ('[', ']'), values, write_python_canonical_json);
        }
        Value::Object(values) => {
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by_key(|(key, _)| *key);
            write_separated(output, ('{', '}'), &entries, write_entry);
        }
    }
}

/// A float as Python writes it; an integer as is.
fn write_number(value: &Number, output: &mut String) {
    match value.as_f64() {
        Some(float) if value.is_f64() => output.push_str(&format_float(float)),
        _ => output.push_str(&value.to_string()),
    }
}

fn write_entry((key, value): &(&String, &Value), output: &mut String) {
    write_json_string(key, output);
    output.push_str(": ");
    write_python_canonical_json(value, output);
}

/// `items` between `open` and `close`, separated by `", "`.
fn write_separated<T>(
    output: &mut String,
    (open, close): (char, char),
    items: &[T],
    write: impl Fn(&T, &mut String),
) {
    output.push(open);
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        write(item, output);
    }
    output.push(close);
}

fn write_json_string(value: &str, output: &mut String) {
    output
        .push_str(&serde_json::to_string(value).expect("serializing JSON string should not fail"));
}

pub fn lower_syntax_to_ir(
    module: &SyntaxModule,
    vm_profile: &str,
) -> Result<Value, IrLoweringError> {
    if validate_profile(vm_profile).is_err() || vm_profile != module.vm_profile {
        return Err(IrLoweringError::new(
            format!("unsupported vm_profile '{vm_profile}'"),
            None,
        ));
    }
    IrLowerer::new(module, vm_profile).lower()
}

fn normalize_and_build_syntax(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Result<(String, SyntaxModule), Vec<CompilerDiagnostic>> {
    let unit = match SourceUnit::with_profile(module_name, source, &options.vm_profile) {
        Ok(unit) => unit,
        Err(error) => {
            return Err(vec![CompilerDiagnostic::error(
                "xian.source.invalid",
                error.to_string(),
            )])
        }
    };
    let parsed = parse_source(&unit)?;
    let initial_syntax = build_syntax_tree(&parsed)?;
    let diagnostics = lint_syntax(&initial_syntax);
    if !diagnostics.is_empty() {
        return Err(diagnostics);
    }
    let normalized_source = normalize_syntax(&initial_syntax);
    let normalized_unit =
        SourceUnit::with_profile(module_name, &normalized_source, &options.vm_profile).map_err(
            |error| {
                vec![CompilerDiagnostic::error(
                    "xian.source.invalid",
                    error.to_string(),
                )]
            },
        )?;
    let normalized_parsed = parse_source(&normalized_unit)?;
    let normalized_syntax = build_syntax_tree(&normalized_parsed)?;
    Ok((normalized_source, normalized_syntax))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrLoweringError {
    pub code: &'static str,
    pub message: String,
    pub range: Option<SourceRange>,
}

impl IrLoweringError {
    fn new(message: impl Into<String>, range: Option<SourceRange>) -> Self {
        Self {
            code: "xian.ir.lowering_error",
            message: message.into(),
            range,
        }
    }

    /// A compiler limit the lowering reached.
    fn limit(code: &'static str, message: String) -> Self {
        Self {
            code,
            message,
            range: None,
        }
    }

    fn into_diagnostic(self) -> CompilerDiagnostic {
        let diagnostic = CompilerDiagnostic::error(self.code, self.message);
        if let Some(range) = self.range {
            diagnostic.with_range(range)
        } else {
            diagnostic
        }
    }
}

impl From<WorkExceeded> for IrLoweringError {
    fn from(_: WorkExceeded) -> Self {
        Self::limit(COMPILE_WORK_CODE, compile_work_message())
    }
}

/// A module's lowered parts, in source order.
#[derive(Default)]
struct LoweredModule {
    imports: Vec<Value>,
    global_declarations: Vec<Value>,
    functions: Vec<Value>,
    module_body: Vec<Value>,
}

/// Whether a module assignment to `targets` declares a global: one name not
/// declared before. Later ordinary assignments are executable initialization
/// steps, ordered by source span.
fn declares_global(targets: &[SyntaxExpression], declared: &mut HashSet<String>) -> bool {
    match targets {
        [target] => name_id(target).is_some_and(|name| declared.insert(name.to_owned())),
        _ => false,
    }
}

struct IrLowerer<'a> {
    module: &'a SyntaxModule,
    vm_profile: &'a str,
    host_dependencies: BTreeMap<String, HostBinding>,
    event_bindings: HashSet<String>,
    storage_bindings: HashMap<String, String>,
    static_import_bindings: HashSet<String>,
    global_bindings: HashSet<String>,
    local_binding_stack: Vec<HashSet<String>>,
    host_module_aliases: HashMap<String, String>,
    contract_handle_factories: HashSet<String>,
    contract_handle_parameters: HashMap<String, HashSet<String>>,
    local_contract_handles: HashMap<String, SyntaxExpression>,
    work: WorkBudget,
    /// The IR bytes of the handle sources lowered at each use so far.
    handle_source_bytes: usize,
}

impl<'a> IrLowerer<'a> {
    fn new(module: &'a SyntaxModule, vm_profile: &'a str) -> Self {
        Self {
            module,
            vm_profile,
            host_dependencies: BTreeMap::new(),
            event_bindings: HashSet::new(),
            storage_bindings: HashMap::new(),
            static_import_bindings: HashSet::new(),
            global_bindings: HashSet::new(),
            local_binding_stack: Vec::new(),
            host_module_aliases: HashMap::new(),
            contract_handle_factories: HashSet::new(),
            contract_handle_parameters: HashMap::new(),
            local_contract_handles: HashMap::new(),
            work: WorkBudget::default(),
            handle_source_bytes: 0,
        }
    }

    fn lower(&mut self) -> Result<Value, IrLoweringError> {
        let (docstring, body) = split_docstring(&self.module.body);
        self.analyze_module(body)?;
        let lowered = self.lower_module_body(body)?;
        Ok(ir_object!(
            "ir_version": XIAN_IR_V1,
            "vm_profile": self.vm_profile,
            "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
            "module_name": &self.module.module_name,
            "source_hash": &self.module.source_sha256,
            "docstring": docstring,
            "imports": lowered.imports,
            "global_declarations": lowered.global_declarations,
            "functions": lowered.functions,
            "module_body": lowered.module_body,
            "host_dependencies": self.host_dependencies.values().map(host_binding_value).collect::<Vec<_>>(),
        ))
    }

    /// The module's bindings, checked unique, and its contract handles.
    fn analyze_module(&mut self, body: &'a [SyntaxStatement]) -> Result<(), IrLoweringError> {
        self.inspect_module_bindings(body)?;
        let fixed_bindings = self
            .storage_bindings
            .keys()
            .chain(self.event_bindings.iter())
            .chain(self.host_module_aliases.keys())
            .cloned()
            .collect();
        validate_unique_module_bindings(body, &fixed_bindings)?;
        let functions = body
            .iter()
            .filter(|statement| matches!(statement, SyntaxStatement::FunctionDef { .. }))
            .collect::<Vec<_>>();
        self.refresh_contract_handle_inference(&functions)
    }

    fn lower_module_body(
        &mut self,
        body: &[SyntaxStatement],
    ) -> Result<LoweredModule, IrLoweringError> {
        let mut lowered = LoweredModule::default();
        let mut declared = HashSet::new();
        for statement in body {
            self.lower_module_statement(statement, &mut lowered, &mut declared)?;
        }
        Ok(lowered)
    }

    fn lower_module_statement(
        &mut self,
        statement: &SyntaxStatement,
        lowered: &mut LoweredModule,
        declared: &mut HashSet<String>,
    ) -> Result<(), IrLoweringError> {
        match statement {
            SyntaxStatement::Import { .. } => lowered.imports.extend(self.lower_import(statement)?),
            SyntaxStatement::Assign { targets, .. } if declares_global(targets, declared) => {
                let declaration = self.lower_global_declaration(statement)?;
                lowered.global_declarations.push(declaration);
            }
            SyntaxStatement::FunctionDef { .. } => {
                let function = self.lower_function(statement)?;
                lowered.functions.push(function);
            }
            _ => lowered.module_body.push(self.lower_statement(statement)?),
        }
        Ok(())
    }

    fn inspect_module_bindings(&mut self, body: &[SyntaxStatement]) -> Result<(), IrLoweringError> {
        self.discover_host_module_aliases(body)?;
        for statement in body {
            match statement {
                SyntaxStatement::Import { names, .. } => {
                    for alias in names {
                        let binding = alias.alias.clone().unwrap_or_else(|| alias.name.clone());
                        self.static_import_bindings.insert(binding);
                    }
                }
                SyntaxStatement::Assign { targets, value, .. } => {
                    if targets.len() != 1 || name_id(&targets[0]).is_none() {
                        for target in targets {
                            collect_target_binding_names(target, &mut self.global_bindings);
                        }
                    }
                    if targets.len() != 1 {
                        continue;
                    }
                    let Some(target) = name_id(&targets[0]) else {
                        continue;
                    };
                    if !self.host_module_aliases.contains_key(target) {
                        self.global_bindings.insert(target.to_string());
                    }
                    let SyntaxExpression::Call { func, .. } = value else {
                        continue;
                    };
                    let Some(path) = dotted_path(func) else {
                        continue;
                    };
                    if storage_constructor_syscall(&path).is_some() {
                        self.storage_bindings.insert(target.to_string(), path);
                    } else if path == EVENT_CONSTRUCTOR {
                        self.event_bindings.insert(target.to_string());
                    }
                }
                SyntaxStatement::FunctionDef { name, .. } => {
                    self.global_bindings.insert(name.to_string());
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Module names bound to host modules (`h = hashlib`, `g = h`) and the
    /// module each stands for, as repeated in-order sweeps over the module's
    /// single-name assignments bind them.
    fn discover_host_module_aliases(
        &mut self,
        body: &[SyntaxStatement],
    ) -> Result<(), IrLoweringError> {
        let assignments = body
            .iter()
            .filter_map(|statement| match statement {
                SyntaxStatement::Assign { targets, value, .. } if targets.len() == 1 => {
                    name_id(&targets[0]).map(|target| (target, name_id(value)))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let entries = assignments
            .iter()
            .map(|&(target, value)| {
                let readiness = match value {
                    Some(value) if HOST_MODULE_BINDINGS.contains(&value) => Readiness::Now,
                    Some(value) => Readiness::After(value),
                    None => Readiness::Never,
                };
                (target, readiness)
            })
            .collect::<Vec<_>>();
        for index in sweep_bindings(&entries, &HashSet::new(), &mut self.work)? {
            let (target, Some(value)) = assignments[index] else {
                continue;
            };
            let module = self
                .host_module_aliases
                .get(value)
                .cloned()
                .unwrap_or_else(|| value.to_owned());
            self.host_module_aliases.insert(target.to_owned(), module);
        }
        Ok(())
    }

    fn refresh_contract_handle_inference(
        &mut self,
        functions: &[&'a SyntaxStatement],
    ) -> Result<(), IrLoweringError> {
        let functions_by_name = functions
            .iter()
            .filter_map(|function| match function {
                SyntaxStatement::FunctionDef { name, .. } => Some((name.as_str(), *function)),
                _ => None,
            })
            .collect::<HashMap<_, _>>();
        let facts = functions
            .iter()
            .map(|function| self.function_handle_facts(function, &functions_by_name))
            .collect::<Vec<_>>();
        let handles = infer_contract_handles(&facts, &mut self.work).map_err(|error| match error {
            InferenceError::TooManyPasses => IrLoweringError::new(
                format!(
                    "contract handle inference exceeded the maximum of {MAX_CONTRACT_HANDLE_INFERENCE_PASSES} passes"
                ),
                None,
            ),
            InferenceError::Work(exceeded) => exceeded.into(),
        })?;
        self.contract_handle_factories = handles.factories;
        self.contract_handle_parameters = handles.parameters;
        Ok(())
    }

    /// The returns, single-name assignments and module-function call
    /// arguments of `function`, each as the handle it may be.
    fn function_handle_facts(
        &self,
        function: &'a SyntaxStatement,
        functions_by_name: &HashMap<&str, &'a SyntaxStatement>,
    ) -> FunctionHandleFacts<'a> {
        let SyntaxStatement::FunctionDef {
            name,
            parameters,
            body,
            ..
        } = function
        else {
            return FunctionHandleFacts::default();
        };
        let local_names = collect_function_local_bindings(parameters, body);
        let source = |expression| self.handle_source(expression, &local_names);
        let mut returns = Vec::new();
        collect_return_values(body, &mut returns);
        let mut assignments = Vec::new();
        collect_named_assignments(body, &mut assignments);
        let mut calls = Vec::new();
        collect_call_expressions(body, &mut calls);
        let mut arguments = Vec::new();
        for call in calls {
            let SyntaxExpression::Call {
                func,
                args,
                keywords,
                ..
            } = call
            else {
                continue;
            };
            let Some(callee_name) = name_id(func) else {
                continue;
            };
            let Some(callee) = functions_by_name.get(callee_name) else {
                continue;
            };
            for (parameter, argument) in call_parameter_arguments(callee, args, keywords) {
                arguments.push(HandleArgument {
                    callee: callee_name,
                    parameter,
                    source: source(argument),
                });
            }
        }
        FunctionHandleFacts {
            name,
            parameters: parameters
                .iter()
                .map(|parameter| parameter.name.as_str())
                .collect(),
            returns: returns.into_iter().map(source).collect(),
            assignments: assignments
                .into_iter()
                .map(|(target, value)| (target, source(value)))
                .collect(),
            arguments,
        }
    }

    /// When `expression`, in a function with `local_names`, is a handle.
    fn handle_source<'e>(
        &self,
        expression: &'e SyntaxExpression,
        local_names: &HashSet<String>,
    ) -> HandleSource<'e> {
        if let Some(name) = name_id(expression) {
            if local_names.contains(name) {
                return HandleSource::Local(name);
            }
            if self.static_import_bindings.contains(name) && !self.global_bindings.contains(name) {
                return HandleSource::Always;
            }
            return HandleSource::Never;
        }
        if let SyntaxExpression::Call { func, .. } = expression {
            if self.is_importlib_import_call_in_scope(expression, local_names) {
                return HandleSource::Always;
            }
            if let Some(name) = name_id(func) {
                return HandleSource::Factory(name);
            }
        }
        HandleSource::Never
    }

    fn parameter_contract_handle_bindings(
        &self,
        function: &SyntaxStatement,
        parameter_handles: &HashSet<String>,
    ) -> HashMap<String, SyntaxExpression> {
        let SyntaxStatement::FunctionDef { parameters, .. } = function else {
            return HashMap::new();
        };

        parameters
            .iter()
            .filter(|parameter| parameter_handles.contains(&parameter.name))
            .map(|parameter| {
                (
                    parameter.name.clone(),
                    SyntaxExpression::Name {
                        span: parameter.span,
                        id: parameter.name.clone(),
                        context: SyntaxExpressionContext::Load,
                    },
                )
            })
            .collect()
    }

    /// The function's locals that hold a handle, each with the expression
    /// that bound it: the handle parameters, then the first ready assignment
    /// of repeated in-order sweeps over the function's assignments.
    fn local_contract_handles(
        &mut self,
        body: &[SyntaxStatement],
        mut bindings: HashMap<String, SyntaxExpression>,
        local_names: &HashSet<String>,
    ) -> Result<HashMap<String, SyntaxExpression>, IrLoweringError> {
        let mut assignments = Vec::new();
        collect_named_assignments(body, &mut assignments);
        let entries = assignments
            .iter()
            .map(|(target, value)| {
                let readiness = match self.handle_source(value, local_names) {
                    HandleSource::Always => Readiness::Now,
                    HandleSource::Factory(name)
                        if self.contract_handle_factories.contains(name) =>
                    {
                        Readiness::Now
                    }
                    HandleSource::Local(name) => Readiness::After(name),
                    HandleSource::Factory(_) | HandleSource::Never => Readiness::Never,
                };
                (*target, readiness)
            })
            .collect::<Vec<_>>();
        let order = {
            let bound = bindings.keys().map(String::as_str).collect();
            sweep_bindings(&entries, &bound, &mut self.work)?
        };
        for index in order {
            let (target, value) = assignments[index];
            bindings.insert(target.to_owned(), value.clone());
        }
        Ok(bindings)
    }

    fn is_importlib_import_call_in_scope(
        &self,
        expression: &SyntaxExpression,
        local_names: &HashSet<String>,
    ) -> bool {
        let SyntaxExpression::Call { func, .. } = expression else {
            return false;
        };
        let Some(root) = root_name(func) else {
            return false;
        };
        if local_names.contains(root) || self.global_bindings.contains(root) {
            return false;
        }
        self.canonical_dotted_path(func).as_deref() == Some("importlib.import_module")
    }

    fn is_importlib_import_call(&self, expression: &SyntaxExpression) -> bool {
        let SyntaxExpression::Call { func, .. } = expression else {
            return false;
        };
        if self.root_name_is_host_shadowed(func) {
            return false;
        }
        self.canonical_dotted_path(func).as_deref() == Some("importlib.import_module")
    }

    fn contract_target_for_expression(
        &mut self,
        expression: &SyntaxExpression,
        allow_local: bool,
    ) -> Result<Option<Value>, IrLoweringError> {
        if let Some(name) = name_id(expression) {
            if self.static_import_bindings.contains(name) && !self.is_host_shadowed(name) {
                return Ok(Some(ir_object!(
                    "kind": "static_import",
                    "binding": name,
                    "span": span_value(expression_span(expression)),
                )));
            }
            if allow_local {
                if let Some(source_expression) = self.local_contract_handles.get(name).cloned() {
                    return Ok(Some(ir_object!(
                        "kind": "local_handle",
                        "binding": name,
                        "source": self.lower_handle_source(&source_expression)?,
                        "span": span_value(expression_span(expression)),
                    )));
                }
            }
            return Ok(None);
        }

        if let SyntaxExpression::Call { func, .. } = expression {
            if self.is_importlib_import_call(expression) {
                return Ok(Some(ir_object!(
                    "kind": "dynamic_import",
                    "source": self.lower_expression(expression)?,
                    "span": span_value(expression_span(expression)),
                )));
            }
            if let Some(name) = name_id(func) {
                if self.contract_handle_factories.contains(name) {
                    return Ok(Some(ir_object!(
                        "kind": "factory_call",
                        "factory": name,
                        "source": self.lower_expression(expression)?,
                        "span": span_value(expression_span(expression)),
                    )));
                }
            }
        }
        Ok(None)
    }

    /// A local handle's source, lowered again at each use of the handle.
    /// Every copy is part of the IR, so once the copies alone exceed the IR
    /// limit the IR does too: refused as it would be when finished, before
    /// the copies grow with uses x source size.
    fn lower_handle_source(&mut self, source: &SyntaxExpression) -> Result<Value, IrLoweringError> {
        let lowered = self.lower_expression(source)?;
        self.handle_source_bytes += to_python_canonical_json(&lowered).len();
        if self.handle_source_bytes > MAX_IR_JSON_BYTES {
            return Err(IrLoweringError::limit(
                IR_JSON_BYTES_CODE,
                ir_json_bytes_message(),
            ));
        }
        Ok(lowered)
    }

    fn canonical_dotted_path(&self, expression: &SyntaxExpression) -> Option<String> {
        let path = dotted_path(expression)?;
        let (root, remainder) = match path.split_once('.') {
            Some((root, remainder)) => (root, Some(remainder)),
            None => (path.as_str(), None),
        };
        let canonical_root = self
            .host_module_aliases
            .get(root)
            .map(String::as_str)
            .unwrap_or(root);
        Some(match remainder {
            Some(remainder) => format!("{canonical_root}.{remainder}"),
            None => canonical_root.to_string(),
        })
    }

    fn root_name_is_host_shadowed(&self, expression: &SyntaxExpression) -> bool {
        root_name(expression).is_some_and(|name| self.is_host_shadowed(name))
    }

    fn is_locally_shadowed(&self, name: &str) -> bool {
        self.local_binding_stack
            .iter()
            .any(|bindings| bindings.contains(name))
    }

    fn is_host_shadowed(&self, name: &str) -> bool {
        self.is_locally_shadowed(name) || self.global_bindings.contains(name)
    }

    fn record_host_dependency(&mut self, expression: &SyntaxExpression) -> Option<HostBinding> {
        if self.root_name_is_host_shadowed(expression) {
            return None;
        }
        let path = self.canonical_dotted_path(expression)?;
        let spec = resolve_host_binding(&path)?;
        self.host_dependencies.insert(spec.id.to_string(), spec);
        Some(spec)
    }

    fn record_host_dependency_id(&mut self, identifier: &str) -> Option<HostBinding> {
        let spec = resolve_host_binding_id(identifier)?;
        self.host_dependencies.insert(spec.id.to_string(), spec);
        Some(spec)
    }

    fn lower_import(&self, statement: &SyntaxStatement) -> Result<Vec<Value>, IrLoweringError> {
        let SyntaxStatement::Import { span, names } = statement else {
            return Err(self.unsupported_statement(statement, "expected import statement"));
        };
        Ok(names
            .iter()
            .map(|alias| self.lower_import_alias(alias, *span))
            .collect())
    }

    fn lower_import_alias(&self, alias: &SyntaxImportAlias, span: SourceRange) -> Value {
        ir_object!(
            "node": "import",
            "span": span_value(span),
            "module": &alias.name,
            "alias": &alias.alias,
        )
    }

    fn lower_global_declaration(
        &mut self,
        statement: &SyntaxStatement,
    ) -> Result<Value, IrLoweringError> {
        let SyntaxStatement::Assign {
            span,
            targets,
            value,
        } = statement
        else {
            return Err(self.unsupported_statement(statement, "expected assignment statement"));
        };

        if targets.len() != 1 {
            return Err(IrLoweringError::new(
                "multi-target module assignments are not supported in Xian IR",
                Some(*span),
            ));
        }
        let Some(target) = name_id(&targets[0]) else {
            return Err(IrLoweringError::new(
                "module-level declarations must assign into a named binding",
                Some(expression_span(&targets[0])),
            ));
        };

        if let SyntaxExpression::Call {
            func,
            args,
            keywords,
            ..
        } = value
        {
            if let Some(callee_path) = dotted_path(func) {
                if let Some(syscall_id) = storage_constructor_syscall(&callee_path) {
                    self.record_host_dependency(func);
                    return Ok(ir_object!(
                        "node": "storage_decl",
                        "span": span_value(*span),
                        "name": target,
                        "storage_type": callee_path,
                        "syscall_id": syscall_id,
                        "args": self.lower_expanded_expressions(args)?,
                        "keywords": self.lower_keywords(keywords)?,
                    ));
                }
                if callee_path == EVENT_CONSTRUCTOR {
                    self.record_host_dependency(func);
                    self.event_bindings.insert(target.to_string());
                    let (event_name, params) = self.extract_log_event_parts(value)?;
                    return Ok(ir_object!(
                        "node": "event_decl",
                        "span": span_value(*span),
                        "name": target,
                        "syscall_id": "event.log.new",
                        "event_name": event_name,
                        "params": self.lower_expression(params)?,
                    ));
                }
            }
        }

        Ok(ir_object!(
            "node": "binding_decl",
            "span": span_value(*span),
            "name": target,
            "value": self.lower_expression(value)?,
        ))
    }

    fn extract_log_event_parts<'b>(
        &self,
        expression: &'b SyntaxExpression,
    ) -> Result<(&'b str, &'b SyntaxExpression), IrLoweringError> {
        let SyntaxExpression::Call {
            span,
            args,
            keywords,
            ..
        } = expression
        else {
            return Err(IrLoweringError::new(
                "LogEvent declarations must be calls",
                Some(expression_span(expression)),
            ));
        };

        let (event_node, params_node) = if args.len() >= 2 {
            (Some(&args[0]), Some(&args[1]))
        } else {
            let event_node = keywords
                .iter()
                .find(|keyword| keyword.arg.as_deref() == Some("event"))
                .map(|keyword| &keyword.value);
            let params_node = keywords
                .iter()
                .find(|keyword| keyword.arg.as_deref() == Some("params"))
                .map(|keyword| &keyword.value);
            (event_node, params_node)
        };

        let Some(SyntaxExpression::Constant {
            value: SyntaxConstant::Str(event_name),
            ..
        }) = event_node
        else {
            return Err(IrLoweringError::new(
                "LogEvent declarations must use a constant string event name",
                Some(*span),
            ));
        };
        let Some(params_node) = params_node else {
            return Err(IrLoweringError::new(
                "LogEvent declarations must include a params schema",
                Some(*span),
            ));
        };
        Ok((event_name, params_node))
    }

    fn lower_function(&mut self, statement: &SyntaxStatement) -> Result<Value, IrLoweringError> {
        let SyntaxStatement::FunctionDef {
            span,
            name,
            parameters,
            returns,
            body,
            ..
        } = statement
        else {
            return Err(self.unsupported_statement(statement, "expected function statement"));
        };
        let (docstring, body) = split_docstring(body);
        let decorator = self.lower_decorator(statement)?;
        let initial_handles = self
            .contract_handle_parameters
            .get(name)
            .map(|handles| self.parameter_contract_handle_bindings(statement, handles))
            .unwrap_or_default();
        let local_bindings = collect_function_local_bindings(parameters, body);
        let local_handles = self.local_contract_handles(body, initial_handles, &local_bindings)?;
        let previous_local_handles =
            std::mem::replace(&mut self.local_contract_handles, local_handles);
        self.local_binding_stack.push(local_bindings);
        let lowered_body = body
            .iter()
            .map(|statement| self.lower_statement(statement))
            .collect::<Result<Vec<_>, _>>();
        self.local_binding_stack.pop();
        self.local_contract_handles = previous_local_handles;

        Ok(ir_object!(
            "node": "function",
            "span": span_value(*span),
            "name": name,
            "visibility": decorator.visibility,
            "decorator": decorator.decorator,
            "docstring": docstring,
            "parameters": self.lower_parameters(parameters)?,
            "returns": self.lower_annotation(returns.as_ref()),
            "body": lowered_body?,
        ))
    }

    fn lower_decorator(
        &mut self,
        statement: &SyntaxStatement,
    ) -> Result<LoweredDecorator, IrLoweringError> {
        let SyntaxStatement::FunctionDef { decorators, .. } = statement else {
            return Err(self.unsupported_statement(statement, "expected function statement"));
        };
        if decorators.is_empty() {
            return Ok(LoweredDecorator {
                visibility: "private".to_string(),
                decorator: Value::Null,
            });
        }
        let decorator = &decorators[0];
        if let Some(name) = name_id(decorator) {
            return Ok(LoweredDecorator {
                visibility: name.to_string(),
                decorator: ir_object!(
                    "node": "decorator",
                    "span": span_value(expression_span(decorator)),
                    "name": name,
                    "args": Vec::<Value>::new(),
                    "keywords": Vec::<Value>::new(),
                ),
            });
        }
        if let SyntaxExpression::Call {
            func,
            args,
            keywords,
            ..
        } = decorator
        {
            if let Some(name) = name_id(func) {
                return Ok(LoweredDecorator {
                    visibility: name.to_string(),
                    decorator: ir_object!(
                        "node": "decorator",
                        "span": span_value(expression_span(decorator)),
                        "name": name,
                        "args": self.lower_expanded_expressions(args)?,
                        "keywords": self.lower_keywords(keywords)?,
                    ),
                });
            }
        }

        Err(IrLoweringError::new(
            "complex decorators are not supported in Xian IR",
            Some(expression_span(decorator)),
        ))
    }

    fn lower_parameters(
        &mut self,
        parameters: &[SyntaxParameter],
    ) -> Result<Vec<Value>, IrLoweringError> {
        parameters
            .iter()
            .map(|parameter| self.lower_parameter(parameter))
            .collect()
    }

    fn lower_parameter(&mut self, parameter: &SyntaxParameter) -> Result<Value, IrLoweringError> {
        if parameter.kind == SyntaxParameterKind::PositionalOnly {
            return Err(IrLoweringError::new(
                "positional-only arguments are not supported in Xian IR",
                Some(parameter.span),
            ));
        }
        Ok(ir_object!(
            "name": &parameter.name,
            "kind": parameter_kind_name(parameter.kind),
            "annotation": self.lower_annotation(parameter.annotation.as_ref()),
            "default": match &parameter.default {
                Some(default) => self.lower_expression(default)?,
                None => Value::Null,
            },
            "span": span_value(parameter.span),
        ))
    }

    fn lower_annotation(&mut self, annotation: Option<&SyntaxExpression>) -> Value {
        let Some(annotation) = annotation else {
            return Value::Null;
        };
        self.record_host_dependency(annotation);
        Value::String(format_syntax_expression(annotation))
    }

    fn lower_keyword(&mut self, keyword: &SyntaxKeyword) -> Result<Value, IrLoweringError> {
        match &keyword.arg {
            Some(arg) => Ok(ir_object!(
                "node": "keyword",
                "span": span_value(keyword.span),
                "arg": arg,
                "value": self.lower_expression(&keyword.value)?,
            )),
            None => Ok(ir_object!(
                "node": "keyword_unpack",
                "span": span_value(keyword.span),
                "value": self.lower_expression(&keyword.value)?,
            )),
        }
    }

    fn lower_keywords(
        &mut self,
        keywords: &[SyntaxKeyword],
    ) -> Result<Vec<Value>, IrLoweringError> {
        keywords
            .iter()
            .map(|keyword| self.lower_keyword(keyword))
            .collect()
    }

    fn lower_statement(&mut self, statement: &SyntaxStatement) -> Result<Value, IrLoweringError> {
        match statement {
            SyntaxStatement::Assign {
                span,
                targets,
                value,
            } => {
                if targets.len() == 1 {
                    if let SyntaxExpression::Subscript {
                        value: target_value,
                        slice,
                        ..
                    } = &targets[0]
                    {
                        if let Some(storage_meta) =
                            self.storage_subscript_metadata(target_value.as_ref())
                        {
                            if let Some(write_syscall_id) = storage_meta.write_syscall_id {
                                self.record_host_dependency_id(write_syscall_id);
                                if let Some(read_syscall_id) = storage_meta.read_syscall_id {
                                    self.record_host_dependency_id(read_syscall_id);
                                }
                                return Ok(ir_object!(
                                    "node": "storage_set",
                                    "span": span_value(*span),
                                    "binding": storage_meta.binding,
                                    "storage_type": storage_meta.storage_type,
                                    "syscall_id": write_syscall_id,
                                    "key": self.lower_subscript_slice(slice)?,
                                    "value": self.lower_expression(value)?,
                                ));
                            }
                        }
                    }
                }
                Ok(ir_object!(
                    "node": "assign",
                    "span": span_value(*span),
                    "targets": targets.iter().map(|target| self.lower_target(target)).collect::<Result<Vec<_>, _>>()?,
                    "value": self.lower_expression(value)?,
                ))
            }
            SyntaxStatement::AugAssign {
                span,
                target,
                operator,
                value,
            } => {
                if let SyntaxExpression::Subscript {
                    value: target_value,
                    slice,
                    ..
                } = target
                {
                    if let Some(storage_meta) = self.storage_subscript_metadata(target_value) {
                        if let Some(write_syscall_id) = storage_meta.write_syscall_id {
                            self.record_host_dependency_id(write_syscall_id);
                            if let Some(read_syscall_id) = storage_meta.read_syscall_id {
                                self.record_host_dependency_id(read_syscall_id);
                            }
                            return Ok(ir_object!(
                                "node": "storage_mutate",
                                "span": span_value(*span),
                                "binding": storage_meta.binding,
                                "storage_type": storage_meta.storage_type,
                                "read_syscall_id": storage_meta.read_syscall_id,
                                "write_syscall_id": write_syscall_id,
                                "key": self.lower_subscript_slice(slice)?,
                                "operator": binary_operator_name(*operator),
                                "value": self.lower_expression(value)?,
                            ));
                        }
                    }
                }
                Ok(ir_object!(
                    "node": "aug_assign",
                    "span": span_value(*span),
                    "operator": binary_operator_name(*operator),
                    "target": self.lower_target(target)?,
                    "value": self.lower_expression(value)?,
                ))
            }
            SyntaxStatement::Return { span, value } => Ok(ir_object!(
                "node": "return",
                "span": span_value(*span),
                "value": match value {
                    Some(value) => self.lower_expression(value)?,
                    None => Value::Null,
                },
            )),
            SyntaxStatement::Expr { span, value } => Ok(ir_object!(
                "node": "expr",
                "span": span_value(*span),
                "value": self.lower_expression(value)?,
            )),
            SyntaxStatement::If {
                span,
                test,
                body,
                orelse,
            } => Ok(ir_object!(
                "node": "if",
                "span": span_value(*span),
                "test": self.lower_expression(test)?,
                "body": self.lower_statement_list(body)?,
                "orelse": self.lower_statement_list(orelse)?,
            )),
            SyntaxStatement::For {
                span,
                target,
                iter,
                body,
                orelse,
            } => Ok(ir_object!(
                "node": "for",
                "span": span_value(*span),
                "target": self.lower_target(target)?,
                "iter": self.lower_expression(iter)?,
                "body": self.lower_statement_list(body)?,
                "orelse": self.lower_statement_list(orelse)?,
            )),
            SyntaxStatement::While {
                span,
                test,
                body,
                orelse,
            } => Ok(ir_object!(
                "node": "while",
                "span": span_value(*span),
                "test": self.lower_expression(test)?,
                "body": self.lower_statement_list(body)?,
                "orelse": self.lower_statement_list(orelse)?,
            )),
            SyntaxStatement::Assert {
                span,
                test,
                message,
            } => Ok(ir_object!(
                "node": "assert",
                "span": span_value(*span),
                "test": self.lower_expression(test)?,
                "message": match message {
                    Some(message) => self.lower_expression(message)?,
                    None => Value::Null,
                },
            )),
            SyntaxStatement::Raise {
                span,
                exception,
                cause,
            } => Ok(ir_object!(
                "node": "raise",
                "span": span_value(*span),
                "exception": match exception {
                    Some(exception) => self.lower_expression(exception)?,
                    None => Value::Null,
                },
                "cause": match cause {
                    Some(cause) => self.lower_expression(cause)?,
                    None => Value::Null,
                },
            )),
            SyntaxStatement::Break { span } => Ok(ir_object!(
                "node": "break",
                "span": span_value(*span),
            )),
            SyntaxStatement::Continue { span } => Ok(ir_object!(
                "node": "continue",
                "span": span_value(*span),
            )),
            SyntaxStatement::Pass { span } => Ok(ir_object!(
                "node": "pass",
                "span": span_value(*span),
            )),
            SyntaxStatement::Import { .. } | SyntaxStatement::FunctionDef { .. } => {
                Err(self
                    .unsupported_statement(statement, "unsupported statement position in Xian IR"))
            }
        }
    }

    fn lower_statement_list(
        &mut self,
        statements: &[SyntaxStatement],
    ) -> Result<Vec<Value>, IrLoweringError> {
        statements
            .iter()
            .map(|statement| self.lower_statement(statement))
            .collect()
    }

    fn lower_sequence_targets(
        &mut self,
        elements: &[SyntaxExpression],
    ) -> Result<Vec<Value>, IrLoweringError> {
        let mut starred = false;
        elements.iter().map(|element| match element {
            SyntaxExpression::Starred { span, value, .. } => {
                if starred { return Err(IrLoweringError::new("multiple starred assignment targets", Some(*span))); }
                starred = true;
                Ok(ir_object!("node":"starred_target", "span":span_value(*span), "value":self.lower_target(value)?))
            }
            other => self.lower_target(other),
        }).collect()
    }

    fn lower_target(&mut self, expression: &SyntaxExpression) -> Result<Value, IrLoweringError> {
        match expression {
            SyntaxExpression::Starred { span, .. } => Err(IrLoweringError::new(
                "starred target requires a list or tuple target",
                Some(*span),
            )),
            SyntaxExpression::Tuple { span, elements, .. } => Ok(ir_object!(
                "node": "tuple_target",
                "span": span_value(*span),
                "elements": self.lower_sequence_targets(elements)?,
            )),
            SyntaxExpression::List { span, elements, .. } => Ok(ir_object!(
                "node": "list_target",
                "span": span_value(*span),
                "elements": self.lower_sequence_targets(elements)?,
            )),
            SyntaxExpression::Name { span, id, .. } => {
                let host = self.record_host_dependency(expression);
                Ok(ir_object!(
                    "node": "name",
                    "span": span_value(*span),
                    "id": id,
                    "host_binding_id": host.map(|spec| spec.id),
                ))
            }
            SyntaxExpression::Attribute {
                span, value, attr, ..
            } => {
                let host = self.record_host_dependency(expression);
                Ok(ir_object!(
                    "node": "attribute",
                    "span": span_value(*span),
                    "value": self.lower_expression(value)?,
                    "attr": attr,
                    "path": dotted_path(expression),
                    "host_binding_id": host.map(|spec| spec.id),
                ))
            }
            SyntaxExpression::Subscript {
                span, value, slice, ..
            } => Ok(ir_object!(
                "node": "subscript",
                "span": span_value(*span),
                "value": self.lower_expression(value)?,
                "slice": self.lower_subscript_slice(slice)?,
            )),
            _ => Err(IrLoweringError::new(
                format!(
                    "unsupported assignment target '{}' in Xian IR",
                    expression_node_name(expression)
                ),
                Some(expression_span(expression)),
            )),
        }
    }

    fn lower_expression(
        &mut self,
        expression: &SyntaxExpression,
    ) -> Result<Value, IrLoweringError> {
        match expression {
            SyntaxExpression::Name { span, id, .. } => {
                let host = self.record_host_dependency(expression);
                Ok(ir_object!(
                    "node": "name",
                    "span": span_value(*span),
                    "id": id,
                    "host_binding_id": host.map(|spec| spec.id),
                ))
            }
            SyntaxExpression::Starred { span, .. } => Err(IrLoweringError::new(
                "starred expression requires a call or collection",
                Some(*span),
            )),
            SyntaxExpression::Constant { span, value } => Ok(lower_constant(*span, value)),
            SyntaxExpression::List { span, elements, .. } => Ok(ir_object!(
                "node": "list",
                "span": span_value(*span),
                "elements": self.lower_expanded_expressions(elements)?,
            )),
            SyntaxExpression::ListComp {
                span,
                element,
                generators,
            } => self.lower_comprehension(*span, Some(element), None, generators),
            SyntaxExpression::DictComp {
                span,
                key,
                value,
                generators,
            } => self.lower_comprehension(*span, None, Some((key, value)), generators),
            SyntaxExpression::Tuple { span, elements, .. } => Ok(ir_object!(
                "node": "tuple",
                "span": span_value(*span),
                "elements": self.lower_expanded_expressions(elements)?,
            )),
            SyntaxExpression::Dict { span, entries } => Ok(ir_object!(
                "node": "dict",
                "span": span_value(*span),
                "entries": self.lower_dict_entries(entries)?,
            )),
            SyntaxExpression::Attribute {
                span, value, attr, ..
            } => {
                let host = self.record_host_dependency(expression);
                Ok(ir_object!(
                    "node": "attribute",
                    "span": span_value(*span),
                    "value": self.lower_expression(value)?,
                    "attr": attr,
                    "path": dotted_path(expression),
                    "host_binding_id": host.map(|spec| spec.id),
                ))
            }
            SyntaxExpression::Subscript {
                span, value, slice, ..
            } => {
                if let Some(storage_meta) = self.storage_subscript_metadata(value) {
                    if let Some(read_syscall_id) = storage_meta.read_syscall_id {
                        self.record_host_dependency_id(read_syscall_id);
                        return Ok(ir_object!(
                            "node": "storage_get",
                            "span": span_value(*span),
                            "binding": storage_meta.binding,
                            "storage_type": storage_meta.storage_type,
                            "syscall_id": read_syscall_id,
                            "key": self.lower_subscript_slice(slice)?,
                        ));
                    }
                }
                Ok(ir_object!(
                    "node": "subscript",
                    "span": span_value(*span),
                    "value": self.lower_expression(value)?,
                    "slice": self.lower_subscript_slice(slice)?,
                ))
            }
            SyntaxExpression::Slice {
                span,
                lower,
                upper,
                step,
            } => Ok(ir_object!(
                "node": "slice",
                "span": span_value(*span),
                "lower": match lower {
                    Some(lower) => self.lower_expression(lower)?,
                    None => Value::Null,
                },
                "upper": match upper {
                    Some(upper) => self.lower_expression(upper)?,
                    None => Value::Null,
                },
                "step": match step {
                    Some(step) => self.lower_expression(step)?,
                    None => Value::Null,
                },
            )),
            SyntaxExpression::Call {
                span,
                func,
                args,
                keywords,
            } => self.lower_call(*span, func, args, keywords),
            SyntaxExpression::Compare {
                span,
                left,
                operators,
                comparators,
            } => Ok(ir_object!(
                "node": "compare",
                "span": span_value(*span),
                "left": self.lower_expression(left)?,
                "operators": operators.iter().copied().map(compare_operator_name).collect::<Vec<_>>(),
                "comparators": self.lower_expression_list(comparators)?,
            )),
            SyntaxExpression::BoolOp {
                span,
                operator,
                values,
            } => Ok(ir_object!(
                "node": "bool_op",
                "span": span_value(*span),
                "operator": bool_operator_name(*operator),
                "values": self.lower_expression_list(values)?,
            )),
            SyntaxExpression::BinOp {
                span,
                operator,
                left,
                right,
            } => Ok(ir_object!(
                "node": "bin_op",
                "span": span_value(*span),
                "operator": binary_operator_name(*operator),
                "left": self.lower_expression(left)?,
                "right": self.lower_expression(right)?,
            )),
            SyntaxExpression::UnaryOp {
                span,
                operator,
                operand,
            } => Ok(ir_object!(
                "node": "unary_op",
                "span": span_value(*span),
                "operator": unary_operator_name(*operator),
                "operand": self.lower_expression(operand)?,
            )),
            SyntaxExpression::IfExpr {
                span,
                test,
                body,
                orelse,
            } => Ok(ir_object!(
                "node": "if_expr",
                "span": span_value(*span),
                "test": self.lower_expression(test)?,
                "body": self.lower_expression(body)?,
                "orelse": self.lower_expression(orelse)?,
            )),
            SyntaxExpression::FString { span, values } => Ok(ir_object!(
                "node": "f_string",
                "span": span_value(*span),
                "values": self.lower_expression_list(values)?,
            )),
            SyntaxExpression::FormattedValue {
                span,
                value,
                conversion,
                format_spec,
            } => Ok(ir_object!(
                "node": "formatted_value",
                "span": span_value(*span),
                "value": self.lower_expression(value)?,
                "conversion": conversion.map(|value| value.to_string()),
                "format_spec": format_spec.as_ref().map(|spec| self.lower_expression(spec)).transpose()?,
            )),
        }
    }

    fn lower_call(
        &mut self,
        span: SourceRange,
        func: &SyntaxExpression,
        args: &[SyntaxExpression],
        keywords: &[SyntaxKeyword],
    ) -> Result<Value, IrLoweringError> {
        if let SyntaxExpression::Attribute { value, attr, .. } = func {
            if let Some((binding, storage_type)) = self.storage_metadata_for_name(value) {
                if let Some(syscall_id) = storage_method_syscall(&storage_type, attr) {
                    self.record_host_dependency_id(syscall_id);
                    return Ok(ir_object!(
                        "node": "call",
                        "span": span_value(span),
                        "func": self.lower_expression(func)?,
                        "args": self.lower_expanded_expressions(args)?,
                        "keywords": self.lower_keywords(keywords)?,
                        "syscall_id": syscall_id,
                        "receiver_binding": binding,
                        "receiver_type": storage_type,
                        "method": attr,
                    ));
                }
            }

            if let Some(contract_target) = self.contract_target_for_expression(value, true)? {
                self.record_host_dependency_id(CONTRACT_EXPORT_SYSCALL);
                return Ok(ir_object!(
                    "node": "call",
                    "span": span_value(span),
                    "func": self.lower_expression(func)?,
                    "args": self.lower_expanded_expressions(args)?,
                    "keywords": self.lower_keywords(keywords)?,
                    "syscall_id": CONTRACT_EXPORT_SYSCALL,
                    "contract_target": contract_target,
                    "function_name": attr,
                ));
            }
        }

        let host = self.record_host_dependency(func);
        let event_emit = if host.is_none() {
            if let Some(name) = name_id(func) {
                if self.event_bindings.contains(name) && !self.is_locally_shadowed(name) {
                    let spec = resolve_host_binding("LogEvent.__call__");
                    if let Some(spec) = spec {
                        self.host_dependencies.insert(spec.id.to_string(), spec);
                    }
                    spec
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let syscall_id = host
            .filter(|spec| spec.kind == "syscall")
            .map(|spec| spec.id)
            .or_else(|| event_emit.map(|spec| spec.id));
        Ok(ir_object!(
            "node": "call",
            "span": span_value(span),
            "func": self.lower_expression(func)?,
            "args": self.lower_expanded_expressions(args)?,
            "keywords": self.lower_keywords(keywords)?,
            "syscall_id": syscall_id,
            "event_binding": event_emit.and_then(|_| name_id(func).map(str::to_string)),
        ))
    }

    fn lower_expanded_expressions(
        &mut self,
        expressions: &[SyntaxExpression],
    ) -> Result<Vec<Value>, IrLoweringError> {
        expressions.iter().map(|expression| match expression {
            SyntaxExpression::Starred { span, value, .. } => Ok(ir_object!("node":"starred", "span":span_value(*span), "value":self.lower_expression(value)?)),
            other => self.lower_expression(other),
        }).collect()
    }

    fn lower_expression_list(
        &mut self,
        expressions: &[SyntaxExpression],
    ) -> Result<Vec<Value>, IrLoweringError> {
        expressions
            .iter()
            .map(|expression| self.lower_expression(expression))
            .collect()
    }

    fn lower_dict_entries(
        &mut self,
        entries: &[SyntaxDictEntry],
    ) -> Result<Vec<Value>, IrLoweringError> {
        entries
            .iter()
            .map(|entry| match &entry.key {
                Some(key) => Ok(ir_object!(
                    "key": self.lower_expression(key)?,
                    "value": self.lower_expression(&entry.value)?,
                )),
                None => Ok(ir_object!(
                    "unpack": self.lower_expression(&entry.value)?,
                )),
            })
            .collect()
    }

    fn lower_comprehension(
        &mut self,
        span: SourceRange,
        element: Option<&SyntaxExpression>,
        pair: Option<(&SyntaxExpression, &SyntaxExpression)>,
        generators: &[SyntaxComprehension],
    ) -> Result<Value, IrLoweringError> {
        let first = generators
            .first()
            .ok_or_else(|| IrLoweringError::new("missing comprehension generator", Some(span)))?;
        let first_iter = self.lower_expression(&first.iter)?;
        let mut bindings = HashSet::new();
        for generator in generators {
            collect_target_binding_names(&generator.target, &mut bindings);
        }
        self.local_binding_stack.push(bindings);
        let result = (|| {
            let generators = self.lower_comprehension_generators(generators, first_iter)?;
            if let Some(element) = element {
                return Ok(
                    ir_object!("node": "list_comp", "span": span_value(span), "element": self.lower_expression(element)?, "generators": generators),
                );
            }
            let (key, value) = pair.expect("dictionary comprehension pair");
            Ok(
                ir_object!("node": "dict_comp", "span": span_value(span), "key": self.lower_expression(key)?, "value": self.lower_expression(value)?, "generators": generators),
            )
        })();
        self.local_binding_stack.pop();
        result
    }

    fn lower_comprehension_generators(
        &mut self,
        generators: &[SyntaxComprehension],
        first_iter: Value,
    ) -> Result<Vec<Value>, IrLoweringError> {
        generators
            .iter()
            .enumerate()
            .map(|(index, generator)| {
                if generator.is_async {
                    return Err(IrLoweringError::new(
                        "async comprehensions are not supported in Xian IR",
                        Some(generator.span),
                    ));
                }
                Ok(ir_object!(
                    "target": self.lower_target(&generator.target)?,
                    "iter": if index == 0 { first_iter.clone() } else { self.lower_expression(&generator.iter)? },
                    "ifs": self.lower_expression_list(&generator.ifs)?,
                ))
            })
            .collect()
    }

    fn lower_subscript_slice(
        &mut self,
        expression: &SyntaxExpression,
    ) -> Result<Value, IrLoweringError> {
        self.lower_expression(expression)
    }

    fn storage_metadata_for_name(&self, expression: &SyntaxExpression) -> Option<(String, String)> {
        let name = name_id(expression)?;
        if self.is_locally_shadowed(name) {
            return None;
        }
        let storage_type = self.storage_bindings.get(name)?;
        Some((name.to_string(), storage_type.clone()))
    }

    fn storage_subscript_metadata(
        &self,
        expression: &SyntaxExpression,
    ) -> Option<StorageSubscriptMetadata> {
        let (binding, storage_type) = self.storage_metadata_for_name(expression)?;
        let read_syscall_id = storage_subscript_read_syscall(&storage_type);
        let write_syscall_id = storage_subscript_write_syscall(&storage_type);
        if read_syscall_id.is_none() && write_syscall_id.is_none() {
            return None;
        }
        Some(StorageSubscriptMetadata {
            binding,
            storage_type,
            read_syscall_id,
            write_syscall_id,
        })
    }

    fn unsupported_statement(&self, statement: &SyntaxStatement, message: &str) -> IrLoweringError {
        IrLoweringError::new(message, Some(statement_span(statement)))
    }
}

struct LoweredDecorator {
    visibility: String,
    decorator: Value,
}

struct StorageSubscriptMetadata {
    binding: String,
    storage_type: String,
    read_syscall_id: Option<&'static str>,
    write_syscall_id: Option<&'static str>,
}

fn split_docstring(statements: &[SyntaxStatement]) -> (Option<String>, &[SyntaxStatement]) {
    if let Some(SyntaxStatement::Expr {
        value:
            SyntaxExpression::Constant {
                value: SyntaxConstant::Str(value),
                ..
            },
        ..
    }) = statements.first()
    {
        (Some(value.clone()), &statements[1..])
    } else {
        (None, statements)
    }
}

fn validate_unique_module_bindings(
    statements: &[SyntaxStatement],
    fixed_bindings: &HashSet<String>,
) -> Result<(), IrLoweringError> {
    let mut imports = HashSet::new();
    let mut globals = HashSet::new();
    let mut functions = HashSet::new();

    for statement in statements {
        match statement {
            SyntaxStatement::Import { names, .. } => {
                for alias in names {
                    let binding = alias.alias.as_deref().unwrap_or(&alias.name);
                    if !imports.insert(binding.to_owned()) {
                        return Err(IrLoweringError::new(
                            format!("duplicate import binding '{binding}'"),
                            Some(alias.span),
                        ));
                    }
                }
            }
            SyntaxStatement::Assign { targets, span, .. } => {
                let mut assigned = HashSet::new();
                for target in targets {
                    collect_target_binding_names(target, &mut assigned);
                }
                let mut assigned: Vec<_> = assigned.into_iter().collect();
                assigned.sort();
                for name in assigned {
                    if !globals.insert(name.clone()) && fixed_bindings.contains(&name) {
                        return Err(IrLoweringError::new(
                            format!("duplicate global declaration '{name}'"),
                            Some(*span),
                        ));
                    }
                }
            }
            SyntaxStatement::FunctionDef { name, span, .. } => {
                if !functions.insert(name.to_owned()) {
                    return Err(IrLoweringError::new(
                        format!("duplicate function '{name}'"),
                        Some(*span),
                    ));
                }
            }
            _ => {}
        }
    }

    if let Some(name) = globals
        .iter()
        .find(|name| imports.contains(*name) || functions.contains(*name))
        .or_else(|| imports.iter().find(|name| functions.contains(*name)))
    {
        return Err(IrLoweringError::new(
            format!("conflicting module binding '{name}'"),
            None,
        ));
    }

    Ok(())
}

fn collect_function_local_bindings(
    parameters: &[SyntaxParameter],
    body: &[SyntaxStatement],
) -> HashSet<String> {
    let mut bindings = parameters
        .iter()
        .map(|parameter| parameter.name.clone())
        .collect::<HashSet<_>>();
    collect_statement_binding_names(body, &mut bindings);
    bindings
}

fn collect_statement_binding_names(statements: &[SyntaxStatement], output: &mut HashSet<String>) {
    for statement in statements {
        match statement {
            SyntaxStatement::Assign { targets, .. } => {
                for target in targets {
                    collect_target_binding_names(target, output);
                }
            }
            SyntaxStatement::AugAssign { target, .. } => {
                if matches!(target, SyntaxExpression::Name { .. }) {
                    collect_target_binding_names(target, output);
                }
            }
            SyntaxStatement::For {
                target,
                body,
                orelse,
                ..
            } => {
                collect_target_binding_names(target, output);
                collect_statement_binding_names(body, output);
                collect_statement_binding_names(orelse, output);
            }
            SyntaxStatement::While { body, orelse, .. }
            | SyntaxStatement::If { body, orelse, .. } => {
                collect_statement_binding_names(body, output);
                collect_statement_binding_names(orelse, output);
            }
            SyntaxStatement::Import { names, .. } => {
                for alias in names {
                    output.insert(alias.alias.clone().unwrap_or_else(|| alias.name.clone()));
                }
            }
            SyntaxStatement::FunctionDef { .. }
            | SyntaxStatement::Return { .. }
            | SyntaxStatement::Assert { .. }
            | SyntaxStatement::Raise { .. }
            | SyntaxStatement::Expr { .. }
            | SyntaxStatement::Pass { .. }
            | SyntaxStatement::Break { .. }
            | SyntaxStatement::Continue { .. } => {}
        }
    }
}

fn collect_target_binding_names(expression: &SyntaxExpression, output: &mut HashSet<String>) {
    match expression {
        SyntaxExpression::Name { id, .. } => {
            output.insert(id.clone());
        }
        SyntaxExpression::Tuple { elements, .. } | SyntaxExpression::List { elements, .. } => {
            for element in elements {
                collect_target_binding_names(element, output);
            }
        }
        SyntaxExpression::Starred { value, .. } => collect_target_binding_names(value, output),
        SyntaxExpression::Subscript { .. } | SyntaxExpression::Attribute { .. } => {}
        _ => {}
    }
}

fn collect_return_values<'a>(
    statements: &'a [SyntaxStatement],
    output: &mut Vec<&'a SyntaxExpression>,
) {
    for statement in statements {
        match statement {
            SyntaxStatement::Return {
                value: Some(value), ..
            } => output.push(value),
            SyntaxStatement::FunctionDef { .. } => {}
            SyntaxStatement::For { body, orelse, .. }
            | SyntaxStatement::While { body, orelse, .. }
            | SyntaxStatement::If { body, orelse, .. } => {
                collect_return_values(body, output);
                collect_return_values(orelse, output);
            }
            _ => {}
        }
    }
}

fn collect_named_assignments<'a>(
    statements: &'a [SyntaxStatement],
    output: &mut Vec<(&'a str, &'a SyntaxExpression)>,
) {
    for statement in statements {
        match statement {
            SyntaxStatement::Assign { targets, value, .. } if targets.len() == 1 => {
                if let Some(name) = name_id(&targets[0]) {
                    output.push((name, value));
                }
            }
            SyntaxStatement::FunctionDef { .. } => {}
            SyntaxStatement::For { body, orelse, .. }
            | SyntaxStatement::While { body, orelse, .. }
            | SyntaxStatement::If { body, orelse, .. } => {
                collect_named_assignments(body, output);
                collect_named_assignments(orelse, output);
            }
            _ => {}
        }
    }
}

fn collect_call_expressions<'a>(
    statements: &'a [SyntaxStatement],
    output: &mut Vec<&'a SyntaxExpression>,
) {
    for statement in statements {
        match statement {
            SyntaxStatement::FunctionDef { .. } => {}
            SyntaxStatement::Return {
                value: Some(value), ..
            }
            | SyntaxStatement::Expr { value, .. } => collect_calls_from_expression(value, output),
            SyntaxStatement::Assign { targets, value, .. } => {
                for target in targets {
                    collect_calls_from_expression(target, output);
                }
                collect_calls_from_expression(value, output);
            }
            SyntaxStatement::AugAssign { target, value, .. } => {
                collect_calls_from_expression(target, output);
                collect_calls_from_expression(value, output);
            }
            SyntaxStatement::For {
                target,
                iter,
                body,
                orelse,
                ..
            } => {
                collect_calls_from_expression(target, output);
                collect_calls_from_expression(iter, output);
                collect_call_expressions(body, output);
                collect_call_expressions(orelse, output);
            }
            SyntaxStatement::While {
                test, body, orelse, ..
            }
            | SyntaxStatement::If {
                test, body, orelse, ..
            } => {
                collect_calls_from_expression(test, output);
                collect_call_expressions(body, output);
                collect_call_expressions(orelse, output);
            }
            SyntaxStatement::Assert { test, message, .. } => {
                collect_calls_from_expression(test, output);
                if let Some(message) = message {
                    collect_calls_from_expression(message, output);
                }
            }
            SyntaxStatement::Raise {
                exception, cause, ..
            } => {
                if let Some(exception) = exception {
                    collect_calls_from_expression(exception, output);
                }
                if let Some(cause) = cause {
                    collect_calls_from_expression(cause, output);
                }
            }
            SyntaxStatement::Import { .. }
            | SyntaxStatement::Pass { .. }
            | SyntaxStatement::Break { .. }
            | SyntaxStatement::Continue { .. }
            | SyntaxStatement::Return { value: None, .. } => {}
        }
    }
}

fn collect_calls_from_expression<'a>(
    expression: &'a SyntaxExpression,
    output: &mut Vec<&'a SyntaxExpression>,
) {
    if let SyntaxExpression::Call { .. } = expression {
        output.push(expression);
    }

    match expression {
        SyntaxExpression::Name { .. } | SyntaxExpression::Constant { .. } => {}
        SyntaxExpression::Starred { value, .. } => collect_calls_from_expression(value, output),
        SyntaxExpression::List { elements, .. } | SyntaxExpression::Tuple { elements, .. } => {
            for element in elements {
                collect_calls_from_expression(element, output);
            }
        }
        SyntaxExpression::ListComp {
            element,
            generators,
            ..
        } => {
            collect_calls_from_expression(element, output);
            collect_calls_from_comprehensions(generators, output);
        }
        SyntaxExpression::DictComp {
            key,
            value,
            generators,
            ..
        } => {
            collect_calls_from_expression(key, output);
            collect_calls_from_expression(value, output);
            collect_calls_from_comprehensions(generators, output);
        }
        SyntaxExpression::Dict { entries, .. } => {
            for entry in entries {
                if let Some(key) = &entry.key {
                    collect_calls_from_expression(key, output);
                }
                collect_calls_from_expression(&entry.value, output);
            }
        }
        SyntaxExpression::Attribute { value, .. } => {
            collect_calls_from_expression(value, output);
        }
        SyntaxExpression::Subscript { value, slice, .. } => {
            collect_calls_from_expression(value, output);
            collect_calls_from_expression(slice, output);
        }
        SyntaxExpression::Slice {
            lower, upper, step, ..
        } => {
            if let Some(lower) = lower {
                collect_calls_from_expression(lower, output);
            }
            if let Some(upper) = upper {
                collect_calls_from_expression(upper, output);
            }
            if let Some(step) = step {
                collect_calls_from_expression(step, output);
            }
        }
        SyntaxExpression::Call {
            func,
            args,
            keywords,
            ..
        } => {
            collect_calls_from_expression(func, output);
            for arg in args {
                collect_calls_from_expression(arg, output);
            }
            for keyword in keywords {
                collect_calls_from_expression(&keyword.value, output);
            }
        }
        SyntaxExpression::Compare {
            left, comparators, ..
        } => {
            collect_calls_from_expression(left, output);
            for comparator in comparators {
                collect_calls_from_expression(comparator, output);
            }
        }
        SyntaxExpression::BoolOp { values, .. } | SyntaxExpression::FString { values, .. } => {
            for value in values {
                collect_calls_from_expression(value, output);
            }
        }
        SyntaxExpression::BinOp { left, right, .. } => {
            collect_calls_from_expression(left, output);
            collect_calls_from_expression(right, output);
        }
        SyntaxExpression::UnaryOp { operand, .. } => {
            collect_calls_from_expression(operand, output);
        }
        SyntaxExpression::IfExpr {
            test, body, orelse, ..
        } => {
            collect_calls_from_expression(test, output);
            collect_calls_from_expression(body, output);
            collect_calls_from_expression(orelse, output);
        }
        SyntaxExpression::FormattedValue {
            value, format_spec, ..
        } => {
            collect_calls_from_expression(value, output);
            if let Some(format_spec) = format_spec {
                collect_calls_from_expression(format_spec, output);
            }
        }
    }
}

fn collect_calls_from_comprehensions<'a>(
    generators: &'a [SyntaxComprehension],
    output: &mut Vec<&'a SyntaxExpression>,
) {
    for generator in generators {
        collect_calls_from_expression(&generator.target, output);
        collect_calls_from_expression(&generator.iter, output);
        for condition in &generator.ifs {
            collect_calls_from_expression(condition, output);
        }
    }
}

fn call_parameter_arguments<'a>(
    callee: &'a SyntaxStatement,
    args: &'a [SyntaxExpression],
    keywords: &'a [SyntaxKeyword],
) -> Vec<(&'a str, &'a SyntaxExpression)> {
    let SyntaxStatement::FunctionDef { parameters, .. } = callee else {
        return Vec::new();
    };
    let positional = parameters.iter().filter(|parameter| {
        matches!(
            parameter.kind,
            SyntaxParameterKind::PositionalOnly | SyntaxParameterKind::PositionalOrKeyword
        )
    });
    let named_parameters = parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect::<HashSet<_>>();

    let mut output = positional
        .zip(args)
        .map(|(parameter, argument)| (parameter.name.as_str(), argument))
        .collect::<Vec<_>>();
    for keyword in keywords {
        if let Some(arg) = keyword
            .arg
            .as_deref()
            .filter(|arg| named_parameters.contains(arg))
        {
            output.push((arg, &keyword.value));
        }
    }
    output
}

fn host_binding_value(binding: &HostBinding) -> Value {
    ir_object!(
        "binding": binding.binding,
        "id": binding.id,
        "kind": binding.kind,
        "category": binding.category,
    )
}

fn resolve_host_binding(path: &str) -> Option<HostBinding> {
    host_binding_index().by_binding.get(path).copied()
}

fn resolve_host_binding_id(identifier: &str) -> Option<HostBinding> {
    host_binding_index().by_id.get(identifier).copied()
}

/// The host bindings by binding path and by id, the first of each (as a
/// scan of `HOST_BINDINGS` finds it), built once.
struct HostBindingIndex {
    by_binding: HashMap<&'static str, HostBinding>,
    by_id: HashMap<&'static str, HostBinding>,
}

fn host_binding_index() -> &'static HostBindingIndex {
    static INDEX: OnceLock<HostBindingIndex> = OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index = HostBindingIndex {
            by_binding: HashMap::new(),
            by_id: HashMap::new(),
        };
        for binding in HOST_BINDINGS {
            index.by_binding.entry(binding.binding).or_insert(*binding);
            index.by_id.entry(binding.id).or_insert(*binding);
        }
        index
    })
}

fn span_value(span: SourceRange) -> Value {
    ir_object!(
        "line": span.start_line,
        "col": span.start_column,
        "end_line": span.end_line,
        "end_col": span.end_column,
    )
}

fn statement_span(statement: &SyntaxStatement) -> SourceRange {
    match statement {
        SyntaxStatement::FunctionDef { span, .. }
        | SyntaxStatement::Return { span, .. }
        | SyntaxStatement::Assign { span, .. }
        | SyntaxStatement::AugAssign { span, .. }
        | SyntaxStatement::For { span, .. }
        | SyntaxStatement::While { span, .. }
        | SyntaxStatement::If { span, .. }
        | SyntaxStatement::Assert { span, .. }
        | SyntaxStatement::Raise { span, .. }
        | SyntaxStatement::Import { span, .. }
        | SyntaxStatement::Expr { span, .. }
        | SyntaxStatement::Pass { span }
        | SyntaxStatement::Break { span }
        | SyntaxStatement::Continue { span } => *span,
    }
}

fn expression_span(expression: &SyntaxExpression) -> SourceRange {
    match expression {
        SyntaxExpression::Name { span, .. }
        | SyntaxExpression::Constant { span, .. }
        | SyntaxExpression::Starred { span, .. }
        | SyntaxExpression::List { span, .. }
        | SyntaxExpression::ListComp { span, .. }
        | SyntaxExpression::DictComp { span, .. }
        | SyntaxExpression::Tuple { span, .. }
        | SyntaxExpression::Dict { span, .. }
        | SyntaxExpression::Attribute { span, .. }
        | SyntaxExpression::Subscript { span, .. }
        | SyntaxExpression::Slice { span, .. }
        | SyntaxExpression::Call { span, .. }
        | SyntaxExpression::Compare { span, .. }
        | SyntaxExpression::BoolOp { span, .. }
        | SyntaxExpression::BinOp { span, .. }
        | SyntaxExpression::UnaryOp { span, .. }
        | SyntaxExpression::IfExpr { span, .. }
        | SyntaxExpression::FString { span, .. }
        | SyntaxExpression::FormattedValue { span, .. } => *span,
    }
}

fn name_id(expression: &SyntaxExpression) -> Option<&str> {
    match expression {
        SyntaxExpression::Name { id, .. } => Some(id.as_str()),
        _ => None,
    }
}

fn root_name(expression: &SyntaxExpression) -> Option<&str> {
    match expression {
        SyntaxExpression::Name { id, .. } => Some(id.as_str()),
        SyntaxExpression::Attribute { value, .. } | SyntaxExpression::Subscript { value, .. } => {
            root_name(value)
        }
        _ => None,
    }
}

/// `a.b.c` of a name and its attributes, built once (not once per level).
fn dotted_path(expression: &SyntaxExpression) -> Option<String> {
    let mut parts = Vec::new();
    let mut current = expression;
    loop {
        match current {
            SyntaxExpression::Name { id, .. } => {
                parts.push(id.as_str());
                break;
            }
            SyntaxExpression::Attribute { value, attr, .. } => {
                parts.push(attr.as_str());
                current = value;
            }
            _ => return None,
        }
    }
    parts.reverse();
    Some(parts.join("."))
}

fn storage_constructor_syscall(callee_path: &str) -> Option<&'static str> {
    STORAGE_CONSTRUCTORS
        .iter()
        .find_map(|(name, syscall)| (*name == callee_path).then_some(*syscall))
}

fn storage_method_syscall(storage_type: &str, method: &str) -> Option<&'static str> {
    STORAGE_METHOD_SYSCALLS
        .iter()
        .find_map(|(receiver, candidate, syscall)| {
            (*receiver == storage_type && *candidate == method).then_some(*syscall)
        })
}

fn storage_subscript_read_syscall(storage_type: &str) -> Option<&'static str> {
    STORAGE_SUBSCRIPT_READ_SYSCALLS
        .iter()
        .find_map(|(receiver, syscall)| (*receiver == storage_type).then_some(*syscall))
}

fn storage_subscript_write_syscall(storage_type: &str) -> Option<&'static str> {
    STORAGE_SUBSCRIPT_WRITE_SYSCALLS
        .iter()
        .find_map(|(receiver, syscall)| (*receiver == storage_type).then_some(*syscall))
}

fn lower_constant(span: SourceRange, constant: &SyntaxConstant) -> Value {
    match constant {
        SyntaxConstant::None => ir_object!(
            "node": "constant",
            "span": span_value(span),
            "value_type": "none",
            "value": Value::Null,
        ),
        SyntaxConstant::Bool(value) => ir_object!(
            "node": "constant",
            "span": span_value(span),
            "value_type": "bool",
            "value": value,
        ),
        SyntaxConstant::Int(value) => {
            let value = value
                .parse::<i64>()
                .map(Value::from)
                .unwrap_or_else(|_| Value::String(value.clone()));
            ir_object!(
                "node": "constant",
                "span": span_value(span),
                "value_type": "int",
                "value": value,
            )
        }
        SyntaxConstant::Decimal(value) => ir_object!(
            "node": "constant",
            "span": span_value(span),
            "value_type": "decimal",
            "value": value,
        ),
        SyntaxConstant::Float(value) => ir_object!(
            "node": "constant",
            "span": span_value(span),
            "value_type": "float",
            "value": Number::from_f64(*value).map(Value::Number).unwrap_or(Value::Null),
            "literal": format_float(*value),
        ),
        SyntaxConstant::Str(value) => ir_object!(
            "node": "constant",
            "span": span_value(span),
            "value_type": "str",
            "value": value,
        ),
        SyntaxConstant::Bytes(value) => ir_object!(
            "node": "constant",
            "span": span_value(span),
            "value_type": "bytes",
            "value": value,
        ),
        SyntaxConstant::Tuple(values) => ir_object!(
            "node": "constant",
            "span": span_value(span),
            "value_type": "tuple",
            "value": values.iter().map(lower_constant_without_span).collect::<Vec<_>>(),
        ),
    }
}

fn lower_constant_without_span(constant: &SyntaxConstant) -> Value {
    match constant {
        SyntaxConstant::None => Value::Null,
        SyntaxConstant::Bool(value) => Value::Bool(*value),
        SyntaxConstant::Int(value) => value
            .parse::<i64>()
            .map(Value::from)
            .unwrap_or_else(|_| Value::String(value.clone())),
        SyntaxConstant::Decimal(value) => ir_object!("__fixed__": value),
        SyntaxConstant::Float(value) => Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        SyntaxConstant::Str(value) | SyntaxConstant::Bytes(value) => Value::String(value.clone()),
        SyntaxConstant::Tuple(values) => {
            Value::Array(values.iter().map(lower_constant_without_span).collect())
        }
    }
}

fn bool_operator_name(operator: SyntaxBoolOperator) -> &'static str {
    match operator {
        SyntaxBoolOperator::And => "and",
        SyntaxBoolOperator::Or => "or",
    }
}

fn binary_operator_name(operator: SyntaxBinaryOperator) -> &'static str {
    match operator {
        SyntaxBinaryOperator::Add => "add",
        SyntaxBinaryOperator::Sub => "sub",
        SyntaxBinaryOperator::Mult => "mul",
        SyntaxBinaryOperator::Div => "div",
        SyntaxBinaryOperator::FloorDiv => "floordiv",
        SyntaxBinaryOperator::Mod => "mod",
        SyntaxBinaryOperator::Pow => "pow",
        SyntaxBinaryOperator::BitAnd => "bitand",
        SyntaxBinaryOperator::BitOr => "bitor",
        SyntaxBinaryOperator::BitXor => "bitxor",
        SyntaxBinaryOperator::LShift => "lshift",
        SyntaxBinaryOperator::RShift => "rshift",
    }
}

fn unary_operator_name(operator: SyntaxUnaryOperator) -> &'static str {
    match operator {
        SyntaxUnaryOperator::Not => "not",
        SyntaxUnaryOperator::Neg => "neg",
        SyntaxUnaryOperator::Pos => "pos",
        SyntaxUnaryOperator::Invert => "invert",
    }
}

fn compare_operator_name(operator: SyntaxCompareOperator) -> &'static str {
    match operator {
        SyntaxCompareOperator::Eq => "eq",
        SyntaxCompareOperator::NotEq => "not_eq",
        SyntaxCompareOperator::Gt => "gt",
        SyntaxCompareOperator::GtE => "gt_e",
        SyntaxCompareOperator::Lt => "lt",
        SyntaxCompareOperator::LtE => "lt_e",
        SyntaxCompareOperator::In => "in",
        SyntaxCompareOperator::NotIn => "not_in",
        SyntaxCompareOperator::Is => "is",
        SyntaxCompareOperator::IsNot => "is_not",
    }
}

fn parameter_kind_name(kind: SyntaxParameterKind) -> &'static str {
    match kind {
        SyntaxParameterKind::PositionalOnly => "positional_only",
        SyntaxParameterKind::PositionalOrKeyword => "positional_or_keyword",
        SyntaxParameterKind::Vararg => "vararg",
        SyntaxParameterKind::KeywordOnly => "keyword_only",
        SyntaxParameterKind::Kwarg => "kwarg",
    }
}

fn expression_node_name(expression: &SyntaxExpression) -> &'static str {
    match expression {
        SyntaxExpression::Name { .. } => "Name",
        SyntaxExpression::Constant { .. } => "Constant",
        SyntaxExpression::Starred { .. } => "Starred",
        SyntaxExpression::List { .. } => "List",
        SyntaxExpression::ListComp { .. } => "ListComp",
        SyntaxExpression::DictComp { .. } => "DictComp",
        SyntaxExpression::Tuple { .. } => "Tuple",
        SyntaxExpression::Dict { .. } => "Dict",
        SyntaxExpression::Attribute { .. } => "Attribute",
        SyntaxExpression::Subscript { .. } => "Subscript",
        SyntaxExpression::Slice { .. } => "Slice",
        SyntaxExpression::Call { .. } => "Call",
        SyntaxExpression::Compare { .. } => "Compare",
        SyntaxExpression::BoolOp { .. } => "BoolOp",
        SyntaxExpression::BinOp { .. } => "BinOp",
        SyntaxExpression::UnaryOp { .. } => "UnaryOp",
        SyntaxExpression::IfExpr { .. } => "IfExp",
        SyntaxExpression::FString { .. } => "JoinedStr",
        SyntaxExpression::FormattedValue { .. } => "FormattedValue",
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use serde_json::Value;

    use crate::compiler::CompileOptions;
    use crate::ir::{
        compile_contract_artifact, describe_vm_host_surface, lower_source_to_ir,
        lower_source_to_ir_json, normalize_and_build_syntax, IrLowerer,
    };
    use crate::limits::{MAX_COMPILE_WORK, MAX_SOURCE_BYTES};

    /// The work units lowering `source` spends, when it compiles.
    fn compile_work(source: &str) -> Option<usize> {
        let options = CompileOptions::default();
        let (_, syntax) = normalize_and_build_syntax("con_work", source, &options).ok()?;
        let mut lowerer = IrLowerer::new(&syntax, &options.vm_profile);
        lowerer.lower().ok()?;
        Some(MAX_COMPILE_WORK - lowerer.work.remaining())
    }

    fn alias_chain(links: usize) -> String {
        let chain: String = (2..=links)
            .rev()
            .map(|index| format!(" a{index}=a{}\n", index - 1))
            .collect();
        format!(
            "import con_token\n@export\ndef go():\n{chain} a1=con_token\n return a{links}.f()\n"
        )
    }

    fn mutual(count: usize) -> String {
        let functions: String = (0..count)
            .map(|index| {
                format!(
                    "def f{index}(h,g):\n if g:\n  return f{}(g,h)\n return f{}(h,h)\n",
                    (index + 1) % count,
                    (index + count - 1) % count
                )
            })
            .collect();
        format!("import con_token\n{functions}@export\ndef go():\n return f0(con_token,con_token).f()\n")
    }

    fn module_aliases(count: usize) -> String {
        let aliases: String = (1..=count)
            .rev()
            .map(|index| format!("m{index}=m{}\n", index - 1))
            .collect();
        format!("{aliases}m0=hashlib\n@export\ndef go():\n return 1\n")
    }

    fn many_locals(count: usize) -> String {
        let body: String = (2..=40)
            .rev()
            .map(|index| format!(" a{index}=a{}\n", index - 1))
            .collect();
        let functions: String = (0..count)
            .map(|index| format!("def f{index}(h):\n{body} a1=h\n return a40\n"))
            .collect();
        format!("import con_token\n{functions}@export\ndef go():\n return f0(con_token).f()\n")
    }

    /// The largest `make(n)` that compiles.
    fn largest(make: fn(usize) -> String) -> (String, usize) {
        let (mut low, mut high) = (1, 2);
        while make(high).len() <= MAX_SOURCE_BYTES && compile_work(&make(high)).is_some() {
            (low, high) = (high, high * 2);
        }
        while high - low > 1 {
            let middle = (low + high) / 2;
            if make(middle).len() <= MAX_SOURCE_BYTES && compile_work(&make(middle)).is_some() {
                low = middle;
            } else {
                high = middle;
            }
        }
        let source = make(low);
        let work = compile_work(&source).expect("compiles");
        (source, work)
    }

    #[test]
    fn lowering_past_the_work_budget_is_refused_as_a_compile_limit() {
        let options = CompileOptions::default();
        let (_, syntax) =
            normalize_and_build_syntax("con_work", &alias_chain(3), &options).expect("parses");
        let mut lowerer = IrLowerer::new(&syntax, &options.vm_profile);
        lowerer.work = crate::limits::WorkBudget::with_limit(3);
        let diagnostic = lowerer.lower().expect_err("over budget").into_diagnostic();
        assert_eq!(diagnostic.code, "xian.limit.compile_work");
        assert_eq!(
            diagnostic.message,
            "contract compilation exceeds the maximum of 1000000 work units"
        );
    }

    #[test]
    fn the_largest_pathological_contracts_spend_a_fraction_of_the_work_ceiling() {
        for make in [alias_chain, mutual, module_aliases, many_locals] {
            let (source, work) = largest(make);
            assert!(
                work * 4 < MAX_COMPILE_WORK,
                "{work} units for {} bytes",
                source.len()
            );
            assert!(
                work < 16 * source.len(),
                "{work} units for {} bytes",
                source.len()
            );
        }
    }

    #[test]
    fn lower_source_matches_checked_in_fixture_ir() {
        let fixture_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let mut checked = 0;
        for entry in fs::read_dir(fixture_dir).expect("fixture directory should read") {
            let path = entry.expect("fixture entry should read").path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let fixture: Value =
                serde_json::from_str(&fs::read_to_string(&path).expect("fixture should read"))
                    .unwrap_or_else(|error| panic!("{} should parse: {error}", path.display()));
            if fixture["expected"]["accepted"] != true {
                continue;
            }
            let source = fixture["input_source"]
                .as_str()
                .expect("fixture source should exist");
            let module_name = fixture["module_name"]
                .as_str()
                .expect("fixture module_name should exist");

            let options = CompileOptions {
                vm_profile: fixture["vm_profile"].as_str().unwrap().to_owned(),
                ..CompileOptions::default()
            };
            let lowered = lower_source_to_ir(module_name, source, &options)
                .unwrap_or_else(|error| panic!("{} should lower: {error:?}", path.display()));

            assert_eq!(lowered, fixture["vm_ir"], "{} IR mismatch", path.display());
            checked += 1;
        }
        assert!(checked > 0, "expected at least one accepted fixture");
    }

    #[test]
    fn lower_source_to_ir_json_returns_valid_canonical_json() {
        let source = "@export\ndef ping():\n    return 'pong'\n";
        let payload = lower_source_to_ir_json("con_ping", source, &CompileOptions::default())
            .expect("source should lower");
        let decoded: Value = serde_json::from_str(&payload).expect("IR JSON should parse");

        assert_eq!(decoded["module_name"], "con_ping");
        assert_eq!(decoded["ir_version"], "xian_ir_v1");
    }

    #[test]
    fn lowering_respects_function_local_host_shadowing() {
        let source = "@export\ndef probe():\n    now = 7\n    return now\n";
        let ir =
            lower_source_to_ir("con_shadow", source, &CompileOptions::default()).expect("source");
        let returned = &ir["functions"][0]["body"][1]["value"];

        assert_eq!(returned["node"], "name");
        assert_eq!(returned["id"], "now");
        assert!(returned["host_binding_id"].is_null());
        assert!(!ir["host_dependencies"]
            .as_array()
            .expect("dependencies")
            .iter()
            .any(|dependency| dependency["id"] == "env.now"));
    }

    #[test]
    fn lowering_respects_function_local_storage_shadowing() {
        let source = "balances = Hash(default_value=0)\n\n@export\ndef probe():\n    balances = {\"alice\": 7}\n    return balances[\"alice\"]\n";
        let ir =
            lower_source_to_ir("con_shadow", source, &CompileOptions::default()).expect("source");
        let returned = &ir["functions"][0]["body"][1]["value"];

        assert_eq!(returned["node"], "subscript");
        assert_eq!(returned["value"]["node"], "name");
        assert_eq!(returned["value"]["id"], "balances");
    }

    #[test]
    fn lowering_preserves_fstring_conversions_and_nested_specs() {
        let source = "@export\ndef probe():\n    value = 7\n    return f'{value!r:>{4}}'\n";
        let ir = lower_source_to_ir("con_format", source, &CompileOptions::default()).unwrap();
        let value = &ir["functions"][0]["body"][1]["value"]["values"][0];
        assert_eq!(value["node"], "formatted_value");
        assert_eq!(value["conversion"], "r");
        assert_eq!(value["format_spec"]["node"], "f_string");
        assert_eq!(value["format_spec"]["values"][1]["node"], "formatted_value");
    }

    #[test]
    fn ordinary_reassignment_is_an_ordered_module_statement() {
        let source = "x=1\nx=x+1\n@export\ndef probe():\n    return x\n";
        let ir = lower_source_to_ir_json("con_rebind", source, &CompileOptions::default()).unwrap();
        let module: Value = serde_json::from_str(&ir).unwrap();
        assert_eq!(module["global_declarations"].as_array().unwrap().len(), 1);
        assert_eq!(module["module_body"][0]["node"], "assign");
        assert_eq!(module["module_body"][0]["span"]["line"], 2);
    }

    #[test]
    fn fixed_module_bindings_cannot_be_reassigned() {
        for prefix in [
            "x=Hash()\nx=Hash()",
            "x=Hash()\nx=1",
            "x=1\nx=Variable()",
            "import con_x as x\nx=1",
            "x=hashlib\nx=1",
            "x=1\ndef x():\n    return 1",
        ] {
            let source = format!("{prefix}\n@export\ndef probe():\n    return 1\n");
            assert!(
                lower_source_to_ir_json("con_rebind", &source, &CompileOptions::default()).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn lowering_rejects_duplicate_module_bindings() {
        let source = "@export\ndef ping():\n    return 1\n\n@export\ndef ping():\n    return 2\n";
        let diagnostics =
            lower_source_to_ir_json("con_duplicate", source, &CompileOptions::default())
                .expect_err("duplicate functions should fail");

        assert_eq!(diagnostics[0].code, "xian.ir.lowering_error");
        assert!(diagnostics[0].message.contains("duplicate function 'ping'"));
    }

    #[test]
    fn compile_contract_artifact_builds_hash_checked_artifact() {
        let source = "@export\ndef ping():\n    return 'pong'\n";
        let artifact = compile_contract_artifact("con_ping", source, &CompileOptions::default())
            .expect("artifact should compile");

        assert_eq!(artifact.format, "xian_contract_artifact_v1");
        assert_eq!(artifact.module_name, "con_ping");
        assert!(artifact
            .vm_ir_json
            .contains("\"ir_version\": \"xian_ir_v1\""));
    }

    #[test]
    fn host_surface_contains_catalog_metadata() {
        let surface = describe_vm_host_surface();

        assert_eq!(surface["catalog_version"], "xian_vm_v1_host_v1");
        assert!(surface["bindings"]
            .as_array()
            .expect("bindings should be array")
            .iter()
            .any(|binding| binding["id"] == "storage.variable.get"));
    }
}
