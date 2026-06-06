use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Number, Value};

use crate::artifact::{build_contract_artifact, ContractArtifact};
use crate::compiler::CompileOptions;
use crate::constants::{XIAN_IR_V1, XIAN_VM_HOST_CATALOG_V1, XIAN_VM_V1_PROFILE};
use crate::diagnostic::{CompilerDiagnostic, SourceRange};
use crate::frontend::parse_source;
use crate::lint::lint_syntax;
use crate::normalize::{
    format_expression as format_syntax_expression, format_float, normalize_syntax,
};
use crate::source::SourceUnit;
use crate::syntax::{
    build_syntax_tree, SyntaxBinaryOperator, SyntaxBoolOperator, SyntaxCompareOperator,
    SyntaxComprehension, SyntaxConstant, SyntaxDictEntry, SyntaxExpression,
    SyntaxExpressionContext, SyntaxImportAlias, SyntaxKeyword, SyntaxModule, SyntaxParameter,
    SyntaxParameterKind, SyntaxStatement, SyntaxUnaryOperator,
};

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
    json!({
        "catalog_version": XIAN_VM_HOST_CATALOG_V1,
        "bindings": HOST_BINDINGS.iter().map(host_binding_value).collect::<Vec<_>>(),
    })
}

pub fn lower_source_to_ir(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Result<Value, Vec<CompilerDiagnostic>> {
    let (_, syntax) = normalize_and_build_syntax(module_name, source, options)?;
    lower_syntax_to_ir(&syntax, &options.vm_profile).map_err(|error| vec![error.into_diagnostic()])
}

pub fn lower_source_to_ir_json(
    module_name: &str,
    source: &str,
    options: &CompileOptions,
) -> Result<String, Vec<CompilerDiagnostic>> {
    let ir = lower_source_to_ir(module_name, source, options)?;
    Ok(to_python_canonical_json(&ir))
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
    build_contract_artifact(module_name, source, &normalized_source, &vm_ir_json).map_err(|error| {
        vec![CompilerDiagnostic::error(
            "xian.artifact.invalid",
            error.to_string(),
        )]
    })
}

fn to_python_canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => match value.as_f64() {
            Some(float) if value.is_f64() => format_float(float),
            _ => value.to_string(),
        },
        Value::String(value) => {
            serde_json::to_string(value).expect("serializing JSON string should not fail")
        }
        Value::Array(values) => {
            let rendered = values
                .iter()
                .map(to_python_canonical_json)
                .collect::<Vec<_>>()
                .join(", ");
            format!("[{rendered}]")
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            let rendered = keys
                .into_iter()
                .map(|key| {
                    let rendered_key =
                        serde_json::to_string(key).expect("serializing JSON key should not fail");
                    let rendered_value = to_python_canonical_json(&values[key]);
                    format!("{rendered_key}: {rendered_value}")
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{{rendered}}}")
        }
    }
}

pub fn lower_syntax_to_ir(
    module: &SyntaxModule,
    vm_profile: &str,
) -> Result<Value, IrLoweringError> {
    if vm_profile != XIAN_VM_V1_PROFILE {
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
    pub message: String,
    pub range: Option<SourceRange>,
}

impl IrLoweringError {
    fn new(message: impl Into<String>, range: Option<SourceRange>) -> Self {
        Self {
            message: message.into(),
            range,
        }
    }

    fn into_diagnostic(self) -> CompilerDiagnostic {
        let diagnostic = CompilerDiagnostic::error("xian.ir.lowering_error", self.message);
        if let Some(range) = self.range {
            diagnostic.with_range(range)
        } else {
            diagnostic
        }
    }
}

struct IrLowerer<'a> {
    module: &'a SyntaxModule,
    vm_profile: &'a str,
    host_dependencies: BTreeMap<String, HostBinding>,
    event_bindings: HashSet<String>,
    storage_bindings: HashMap<String, String>,
    static_import_bindings: HashSet<String>,
    host_module_aliases: HashMap<String, String>,
    contract_handle_factories: HashSet<String>,
    contract_handle_parameters: HashMap<String, HashSet<String>>,
    local_contract_handles: HashMap<String, SyntaxExpression>,
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
            host_module_aliases: HashMap::new(),
            contract_handle_factories: HashSet::new(),
            contract_handle_parameters: HashMap::new(),
            local_contract_handles: HashMap::new(),
        }
    }

    fn lower(mut self) -> Result<Value, IrLoweringError> {
        let (docstring, body) = split_docstring(&self.module.body);
        self.inspect_module_bindings(body);
        let functions = body
            .iter()
            .filter_map(|statement| match statement {
                SyntaxStatement::FunctionDef { .. } => Some(statement),
                _ => None,
            })
            .collect::<Vec<_>>();
        self.refresh_contract_handle_inference(&functions);

        let mut imports = Vec::new();
        let mut global_declarations = Vec::new();
        let mut lowered_functions = Vec::new();
        let mut module_body = Vec::new();

        for statement in body {
            match statement {
                SyntaxStatement::Import { .. } => imports.extend(self.lower_import(statement)?),
                SyntaxStatement::Assign { .. } => {
                    global_declarations.push(self.lower_global_declaration(statement)?);
                }
                SyntaxStatement::FunctionDef { .. } => {
                    lowered_functions.push(self.lower_function(statement)?);
                }
                _ => module_body.push(self.lower_statement(statement)?),
            }
        }

        Ok(json!({
            "ir_version": XIAN_IR_V1,
            "vm_profile": self.vm_profile,
            "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
            "module_name": self.module.module_name,
            "source_hash": self.module.source_sha256,
            "docstring": docstring,
            "imports": imports,
            "global_declarations": global_declarations,
            "functions": lowered_functions,
            "module_body": module_body,
            "host_dependencies": self.host_dependencies.values().map(host_binding_value).collect::<Vec<_>>(),
        }))
    }

    fn inspect_module_bindings(&mut self, body: &[SyntaxStatement]) {
        self.discover_host_module_aliases(body);
        for statement in body {
            match statement {
                SyntaxStatement::Import { names, .. } => {
                    for alias in names {
                        self.static_import_bindings
                            .insert(alias.alias.clone().unwrap_or_else(|| alias.name.clone()));
                    }
                }
                SyntaxStatement::Assign { targets, value, .. } => {
                    if targets.len() != 1 {
                        continue;
                    }
                    let Some(target) = name_id(&targets[0]) else {
                        continue;
                    };
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
                _ => {}
            }
        }
    }

    fn discover_host_module_aliases(&mut self, body: &[SyntaxStatement]) {
        let pending = body
            .iter()
            .filter_map(|statement| match statement {
                SyntaxStatement::Assign { targets, value, .. } if targets.len() == 1 => {
                    name_id(&targets[0]).map(|target| (target.to_string(), value.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        let mut changed = true;
        while changed {
            changed = false;
            for (target, value) in &pending {
                if self.host_module_aliases.contains_key(target) {
                    continue;
                }
                let Some(value_name) = name_id(value) else {
                    continue;
                };
                let canonical = self
                    .host_module_aliases
                    .get(value_name)
                    .map(String::as_str)
                    .unwrap_or(value_name);
                if HOST_MODULE_BINDINGS.contains(&canonical) {
                    self.host_module_aliases
                        .insert(target.clone(), canonical.to_string());
                    changed = true;
                }
            }
        }
    }

    fn refresh_contract_handle_inference(&mut self, functions: &[&SyntaxStatement]) {
        let mut factories = HashSet::new();
        let mut parameters: HashMap<String, HashSet<String>> = HashMap::new();

        loop {
            let next_factories = self.discover_contract_handle_factories(functions, &parameters);
            let next_parameters =
                self.discover_contract_handle_parameters(functions, &next_factories, &parameters);

            if next_factories == factories && next_parameters == parameters {
                self.contract_handle_factories = next_factories;
                self.contract_handle_parameters = next_parameters;
                return;
            }

            factories = next_factories;
            parameters = next_parameters;
        }
    }

    fn discover_contract_handle_factories(
        &self,
        functions: &[&SyntaxStatement],
        parameter_handles: &HashMap<String, HashSet<String>>,
    ) -> HashSet<String> {
        let mut discovered = HashSet::new();
        let mut changed = true;
        while changed {
            changed = false;
            for function in functions {
                let SyntaxStatement::FunctionDef { name, .. } = function else {
                    continue;
                };
                if discovered.contains(name) {
                    continue;
                }
                if self.function_returns_contract_handle(function, &discovered, parameter_handles) {
                    discovered.insert(name.clone());
                    changed = true;
                }
            }
        }
        discovered
    }

    fn function_returns_contract_handle(
        &self,
        function: &SyntaxStatement,
        known_factories: &HashSet<String>,
        parameter_handles: &HashMap<String, HashSet<String>>,
    ) -> bool {
        let SyntaxStatement::FunctionDef { name, body, .. } = function else {
            return false;
        };
        let initial_bindings = parameter_handles
            .get(name)
            .map(|handles| self.parameter_contract_handle_bindings(function, handles))
            .unwrap_or_default();
        let local_bindings =
            self.collect_local_contract_handle_bindings(body, known_factories, initial_bindings);
        let mut returns = Vec::new();
        collect_return_values(body, &mut returns);
        !returns.is_empty()
            && returns.iter().all(|value| {
                self.expression_is_contract_handle(value, &local_bindings, known_factories)
            })
    }

    fn discover_contract_handle_parameters(
        &self,
        functions: &[&SyntaxStatement],
        known_factories: &HashSet<String>,
        initial: &HashMap<String, HashSet<String>>,
    ) -> HashMap<String, HashSet<String>> {
        let functions_by_name = functions
            .iter()
            .filter_map(|function| match function {
                SyntaxStatement::FunctionDef { name, .. } => Some((name.as_str(), *function)),
                _ => None,
            })
            .collect::<HashMap<_, _>>();
        let mut discovered = initial.clone();
        let mut changed = true;

        while changed {
            changed = false;
            let mut evidence: HashMap<String, HashMap<String, Vec<bool>>> = HashMap::new();

            for caller in functions {
                let SyntaxStatement::FunctionDef {
                    name: caller_name,
                    body,
                    ..
                } = caller
                else {
                    continue;
                };
                let initial_bindings = discovered
                    .get(caller_name)
                    .map(|handles| self.parameter_contract_handle_bindings(caller, handles))
                    .unwrap_or_default();
                let caller_bindings = self.collect_local_contract_handle_bindings(
                    body,
                    known_factories,
                    initial_bindings,
                );
                let mut calls = Vec::new();
                collect_call_expressions(body, &mut calls);

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

                    for (parameter_name, argument) in
                        call_parameter_arguments(callee, args, keywords)
                    {
                        let is_handle = self.expression_is_contract_handle(
                            argument,
                            &caller_bindings,
                            known_factories,
                        );
                        evidence
                            .entry(callee_name.to_string())
                            .or_default()
                            .entry(parameter_name)
                            .or_default()
                            .push(is_handle);
                    }
                }
            }

            for (function_name, parameters) in evidence {
                let current = discovered.entry(function_name).or_default();
                for (parameter_name, values) in parameters {
                    if !values.is_empty()
                        && values.iter().all(|is_handle| *is_handle)
                        && !current.contains(&parameter_name)
                    {
                        current.insert(parameter_name);
                        changed = true;
                    }
                }
            }
        }

        discovered
            .into_iter()
            .filter(|(_, values)| !values.is_empty())
            .collect()
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

    fn collect_local_contract_handle_bindings(
        &self,
        body: &[SyntaxStatement],
        known_factories: &HashSet<String>,
        initial_bindings: HashMap<String, SyntaxExpression>,
    ) -> HashMap<String, SyntaxExpression> {
        let mut bindings = initial_bindings;
        let mut pending = Vec::new();
        collect_named_assignments(body, &mut pending);

        let mut changed = true;
        while changed {
            changed = false;
            for (name, value) in &pending {
                if bindings.contains_key(name) {
                    continue;
                }
                if self.expression_is_contract_handle(value, &bindings, known_factories) {
                    bindings.insert(name.clone(), value.clone());
                    changed = true;
                }
            }
        }
        bindings
    }

    fn expression_is_contract_handle(
        &self,
        expression: &SyntaxExpression,
        local_bindings: &HashMap<String, SyntaxExpression>,
        known_factories: &HashSet<String>,
    ) -> bool {
        if let Some(name) = name_id(expression) {
            return self.static_import_bindings.contains(name) || local_bindings.contains_key(name);
        }
        if let SyntaxExpression::Call { func, .. } = expression {
            if self.is_importlib_import_call(expression) {
                return true;
            }
            if let Some(name) = name_id(func) {
                return known_factories.contains(name);
            }
        }
        false
    }

    fn is_importlib_import_call(&self, expression: &SyntaxExpression) -> bool {
        let SyntaxExpression::Call { func, .. } = expression else {
            return false;
        };
        self.canonical_dotted_path(func).as_deref() == Some("importlib.import_module")
    }

    fn contract_target_for_expression(
        &mut self,
        expression: &SyntaxExpression,
        allow_local: bool,
    ) -> Result<Option<Value>, IrLoweringError> {
        if let Some(name) = name_id(expression) {
            if self.static_import_bindings.contains(name) {
                return Ok(Some(json!({
                    "kind": "static_import",
                    "binding": name,
                    "span": span_value(expression_span(expression)),
                })));
            }
            if allow_local {
                if let Some(source_expression) = self.local_contract_handles.get(name).cloned() {
                    return Ok(Some(json!({
                        "kind": "local_handle",
                        "binding": name,
                        "source": self.lower_expression(&source_expression)?,
                        "span": span_value(expression_span(expression)),
                    })));
                }
            }
            return Ok(None);
        }

        if let SyntaxExpression::Call { func, .. } = expression {
            if self.is_importlib_import_call(expression) {
                return Ok(Some(json!({
                    "kind": "dynamic_import",
                    "source": self.lower_expression(expression)?,
                    "span": span_value(expression_span(expression)),
                })));
            }
            if let Some(name) = name_id(func) {
                if self.contract_handle_factories.contains(name) {
                    return Ok(Some(json!({
                        "kind": "factory_call",
                        "factory": name,
                        "source": self.lower_expression(expression)?,
                        "span": span_value(expression_span(expression)),
                    })));
                }
            }
        }
        Ok(None)
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

    fn record_host_dependency(&mut self, expression: &SyntaxExpression) -> Option<HostBinding> {
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
        json!({
            "node": "import",
            "span": span_value(span),
            "module": alias.name,
            "alias": alias.alias,
        })
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
                    return Ok(json!({
                        "node": "storage_decl",
                        "span": span_value(*span),
                        "name": target,
                        "storage_type": callee_path,
                        "syscall_id": syscall_id,
                        "args": self.lower_expression_list(args)?,
                        "keywords": self.lower_keywords(keywords)?,
                    }));
                }
                if callee_path == EVENT_CONSTRUCTOR {
                    self.record_host_dependency(func);
                    self.event_bindings.insert(target.to_string());
                    let (event_name, params) = self.extract_log_event_parts(value)?;
                    return Ok(json!({
                        "node": "event_decl",
                        "span": span_value(*span),
                        "name": target,
                        "syscall_id": "event.log.new",
                        "event_name": event_name,
                        "params": self.lower_expression(params)?,
                    }));
                }
            }
        }

        Ok(json!({
            "node": "binding_decl",
            "span": span_value(*span),
            "name": target,
            "value": self.lower_expression(value)?,
        }))
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
        let local_handles = self.collect_local_contract_handle_bindings(
            body,
            &self.contract_handle_factories,
            initial_handles,
        );
        let previous_local_handles =
            std::mem::replace(&mut self.local_contract_handles, local_handles);
        let lowered_body = body
            .iter()
            .map(|statement| self.lower_statement(statement))
            .collect::<Result<Vec<_>, _>>();
        self.local_contract_handles = previous_local_handles;

        Ok(json!({
            "node": "function",
            "span": span_value(*span),
            "name": name,
            "visibility": decorator.visibility,
            "decorator": decorator.decorator,
            "docstring": docstring,
            "parameters": self.lower_parameters(parameters)?,
            "returns": self.lower_annotation(returns.as_ref()),
            "body": lowered_body?,
        }))
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
                decorator: json!({
                    "node": "decorator",
                    "span": span_value(expression_span(decorator)),
                    "name": name,
                    "args": [],
                    "keywords": [],
                }),
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
                    decorator: json!({
                        "node": "decorator",
                        "span": span_value(expression_span(decorator)),
                        "name": name,
                        "args": self.lower_expression_list(args)?,
                        "keywords": self.lower_keywords(keywords)?,
                    }),
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
        Ok(json!({
            "name": parameter.name,
            "kind": parameter_kind_name(parameter.kind),
            "annotation": self.lower_annotation(parameter.annotation.as_ref()),
            "default": match &parameter.default {
                Some(default) => self.lower_expression(default)?,
                None => Value::Null,
            },
            "span": span_value(parameter.span),
        }))
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
            Some(arg) => Ok(json!({
                "node": "keyword",
                "span": span_value(keyword.span),
                "arg": arg,
                "value": self.lower_expression(&keyword.value)?,
            })),
            None => Ok(json!({
                "node": "keyword_unpack",
                "span": span_value(keyword.span),
                "value": self.lower_expression(&keyword.value)?,
            })),
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
                                return Ok(json!({
                                    "node": "storage_set",
                                    "span": span_value(*span),
                                    "binding": storage_meta.binding,
                                    "storage_type": storage_meta.storage_type,
                                    "syscall_id": write_syscall_id,
                                    "key": self.lower_subscript_slice(slice)?,
                                    "value": self.lower_expression(value)?,
                                }));
                            }
                        }
                    }
                }
                Ok(json!({
                    "node": "assign",
                    "span": span_value(*span),
                    "targets": targets.iter().map(|target| self.lower_target(target)).collect::<Result<Vec<_>, _>>()?,
                    "value": self.lower_expression(value)?,
                }))
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
                            return Ok(json!({
                                "node": "storage_mutate",
                                "span": span_value(*span),
                                "binding": storage_meta.binding,
                                "storage_type": storage_meta.storage_type,
                                "read_syscall_id": storage_meta.read_syscall_id,
                                "write_syscall_id": write_syscall_id,
                                "key": self.lower_subscript_slice(slice)?,
                                "operator": binary_operator_name(*operator),
                                "value": self.lower_expression(value)?,
                            }));
                        }
                    }
                }
                Ok(json!({
                    "node": "aug_assign",
                    "span": span_value(*span),
                    "operator": binary_operator_name(*operator),
                    "target": self.lower_target(target)?,
                    "value": self.lower_expression(value)?,
                }))
            }
            SyntaxStatement::Return { span, value } => Ok(json!({
                "node": "return",
                "span": span_value(*span),
                "value": match value {
                    Some(value) => self.lower_expression(value)?,
                    None => Value::Null,
                },
            })),
            SyntaxStatement::Expr { span, value } => Ok(json!({
                "node": "expr",
                "span": span_value(*span),
                "value": self.lower_expression(value)?,
            })),
            SyntaxStatement::If {
                span,
                test,
                body,
                orelse,
            } => Ok(json!({
                "node": "if",
                "span": span_value(*span),
                "test": self.lower_expression(test)?,
                "body": self.lower_statement_list(body)?,
                "orelse": self.lower_statement_list(orelse)?,
            })),
            SyntaxStatement::For {
                span,
                target,
                iter,
                body,
                orelse,
            } => Ok(json!({
                "node": "for",
                "span": span_value(*span),
                "target": self.lower_target(target)?,
                "iter": self.lower_expression(iter)?,
                "body": self.lower_statement_list(body)?,
                "orelse": self.lower_statement_list(orelse)?,
            })),
            SyntaxStatement::While {
                span,
                test,
                body,
                orelse,
            } => Ok(json!({
                "node": "while",
                "span": span_value(*span),
                "test": self.lower_expression(test)?,
                "body": self.lower_statement_list(body)?,
                "orelse": self.lower_statement_list(orelse)?,
            })),
            SyntaxStatement::Assert {
                span,
                test,
                message,
            } => Ok(json!({
                "node": "assert",
                "span": span_value(*span),
                "test": self.lower_expression(test)?,
                "message": match message {
                    Some(message) => self.lower_expression(message)?,
                    None => Value::Null,
                },
            })),
            SyntaxStatement::Raise {
                span,
                exception,
                cause,
            } => Ok(json!({
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
            })),
            SyntaxStatement::Break { span } => Ok(json!({
                "node": "break",
                "span": span_value(*span),
            })),
            SyntaxStatement::Continue { span } => Ok(json!({
                "node": "continue",
                "span": span_value(*span),
            })),
            SyntaxStatement::Pass { span } => Ok(json!({
                "node": "pass",
                "span": span_value(*span),
            })),
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

    fn lower_target(&mut self, expression: &SyntaxExpression) -> Result<Value, IrLoweringError> {
        match expression {
            SyntaxExpression::Tuple { span, elements, .. } => Ok(json!({
                "node": "tuple_target",
                "span": span_value(*span),
                "elements": elements.iter().map(|element| self.lower_target(element)).collect::<Result<Vec<_>, _>>()?,
            })),
            SyntaxExpression::List { span, elements, .. } => Ok(json!({
                "node": "list_target",
                "span": span_value(*span),
                "elements": elements.iter().map(|element| self.lower_target(element)).collect::<Result<Vec<_>, _>>()?,
            })),
            SyntaxExpression::Name { span, id, .. } => {
                let host = self.record_host_dependency(expression);
                Ok(json!({
                    "node": "name",
                    "span": span_value(*span),
                    "id": id,
                    "host_binding_id": host.map(|spec| spec.id),
                }))
            }
            SyntaxExpression::Attribute {
                span, value, attr, ..
            } => {
                let host = self.record_host_dependency(expression);
                Ok(json!({
                    "node": "attribute",
                    "span": span_value(*span),
                    "value": self.lower_expression(value)?,
                    "attr": attr,
                    "path": dotted_path(expression),
                    "host_binding_id": host.map(|spec| spec.id),
                }))
            }
            SyntaxExpression::Subscript {
                span, value, slice, ..
            } => Ok(json!({
                "node": "subscript",
                "span": span_value(*span),
                "value": self.lower_expression(value)?,
                "slice": self.lower_subscript_slice(slice)?,
            })),
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
                Ok(json!({
                    "node": "name",
                    "span": span_value(*span),
                    "id": id,
                    "host_binding_id": host.map(|spec| spec.id),
                }))
            }
            SyntaxExpression::Constant { span, value } => Ok(lower_constant(*span, value)),
            SyntaxExpression::List { span, elements, .. } => Ok(json!({
                "node": "list",
                "span": span_value(*span),
                "elements": self.lower_expression_list(elements)?,
            })),
            SyntaxExpression::ListComp {
                span,
                element,
                generators,
            } => Ok(json!({
                "node": "list_comp",
                "span": span_value(*span),
                "element": self.lower_expression(element)?,
                "generators": self.lower_comprehension_generators(generators)?,
            })),
            SyntaxExpression::DictComp {
                span,
                key,
                value,
                generators,
            } => Ok(json!({
                "node": "dict_comp",
                "span": span_value(*span),
                "key": self.lower_expression(key)?,
                "value": self.lower_expression(value)?,
                "generators": self.lower_comprehension_generators(generators)?,
            })),
            SyntaxExpression::Tuple { span, elements, .. } => Ok(json!({
                "node": "tuple",
                "span": span_value(*span),
                "elements": self.lower_expression_list(elements)?,
            })),
            SyntaxExpression::Dict { span, entries } => Ok(json!({
                "node": "dict",
                "span": span_value(*span),
                "entries": self.lower_dict_entries(entries)?,
            })),
            SyntaxExpression::Attribute {
                span, value, attr, ..
            } => {
                let host = self.record_host_dependency(expression);
                Ok(json!({
                    "node": "attribute",
                    "span": span_value(*span),
                    "value": self.lower_expression(value)?,
                    "attr": attr,
                    "path": dotted_path(expression),
                    "host_binding_id": host.map(|spec| spec.id),
                }))
            }
            SyntaxExpression::Subscript {
                span, value, slice, ..
            } => {
                if let Some(storage_meta) = self.storage_subscript_metadata(value) {
                    if let Some(read_syscall_id) = storage_meta.read_syscall_id {
                        self.record_host_dependency_id(read_syscall_id);
                        return Ok(json!({
                            "node": "storage_get",
                            "span": span_value(*span),
                            "binding": storage_meta.binding,
                            "storage_type": storage_meta.storage_type,
                            "syscall_id": read_syscall_id,
                            "key": self.lower_subscript_slice(slice)?,
                        }));
                    }
                }
                Ok(json!({
                    "node": "subscript",
                    "span": span_value(*span),
                    "value": self.lower_expression(value)?,
                    "slice": self.lower_subscript_slice(slice)?,
                }))
            }
            SyntaxExpression::Slice {
                span,
                lower,
                upper,
                step,
            } => Ok(json!({
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
            })),
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
            } => Ok(json!({
                "node": "compare",
                "span": span_value(*span),
                "left": self.lower_expression(left)?,
                "operators": operators.iter().copied().map(compare_operator_name).collect::<Vec<_>>(),
                "comparators": self.lower_expression_list(comparators)?,
            })),
            SyntaxExpression::BoolOp {
                span,
                operator,
                values,
            } => Ok(json!({
                "node": "bool_op",
                "span": span_value(*span),
                "operator": bool_operator_name(*operator),
                "values": self.lower_expression_list(values)?,
            })),
            SyntaxExpression::BinOp {
                span,
                operator,
                left,
                right,
            } => Ok(json!({
                "node": "bin_op",
                "span": span_value(*span),
                "operator": binary_operator_name(*operator),
                "left": self.lower_expression(left)?,
                "right": self.lower_expression(right)?,
            })),
            SyntaxExpression::UnaryOp {
                span,
                operator,
                operand,
            } => Ok(json!({
                "node": "unary_op",
                "span": span_value(*span),
                "operator": unary_operator_name(*operator),
                "operand": self.lower_expression(operand)?,
            })),
            SyntaxExpression::IfExpr {
                span,
                test,
                body,
                orelse,
            } => Ok(json!({
                "node": "if_expr",
                "span": span_value(*span),
                "test": self.lower_expression(test)?,
                "body": self.lower_expression(body)?,
                "orelse": self.lower_expression(orelse)?,
            })),
            SyntaxExpression::FString { span, values } => Ok(json!({
                "node": "f_string",
                "span": span_value(*span),
                "values": self.lower_expression_list(values)?,
            })),
            SyntaxExpression::FormattedValue {
                span,
                value,
                conversion,
                format_spec,
            } => Ok(json!({
                "node": "formatted_value",
                "span": span_value(*span),
                "value": self.lower_expression(value)?,
                "conversion": conversion.map(|value| value.to_string()),
                "format_spec": match format_spec {
                    Some(format_spec) => self.lower_expression(format_spec)?,
                    None => Value::Null,
                },
            })),
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
                    return Ok(json!({
                        "node": "call",
                        "span": span_value(span),
                        "func": self.lower_expression(func)?,
                        "args": self.lower_expression_list(args)?,
                        "keywords": self.lower_keywords(keywords)?,
                        "syscall_id": syscall_id,
                        "receiver_binding": binding,
                        "receiver_type": storage_type,
                        "method": attr,
                    }));
                }
            }

            if let Some(contract_target) = self.contract_target_for_expression(value, true)? {
                self.record_host_dependency_id(CONTRACT_EXPORT_SYSCALL);
                return Ok(json!({
                    "node": "call",
                    "span": span_value(span),
                    "func": self.lower_expression(func)?,
                    "args": self.lower_expression_list(args)?,
                    "keywords": self.lower_keywords(keywords)?,
                    "syscall_id": CONTRACT_EXPORT_SYSCALL,
                    "contract_target": contract_target,
                    "function_name": attr,
                }));
            }
        }

        let host = self.record_host_dependency(func);
        let event_emit = if host.is_none() {
            if let Some(name) = name_id(func) {
                if self.event_bindings.contains(name) {
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
        Ok(json!({
            "node": "call",
            "span": span_value(span),
            "func": self.lower_expression(func)?,
            "args": self.lower_expression_list(args)?,
            "keywords": self.lower_keywords(keywords)?,
            "syscall_id": syscall_id,
            "event_binding": event_emit.and_then(|_| name_id(func).map(str::to_string)),
        }))
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
                Some(key) => Ok(json!({
                    "key": self.lower_expression(key)?,
                    "value": self.lower_expression(&entry.value)?,
                })),
                None => Ok(json!({
                    "unpack": self.lower_expression(&entry.value)?,
                })),
            })
            .collect()
    }

    fn lower_comprehension_generators(
        &mut self,
        generators: &[SyntaxComprehension],
    ) -> Result<Vec<Value>, IrLoweringError> {
        generators
            .iter()
            .map(|generator| {
                if generator.is_async {
                    return Err(IrLoweringError::new(
                        "async comprehensions are not supported in Xian IR",
                        Some(generator.span),
                    ));
                }
                Ok(json!({
                    "target": self.lower_target(&generator.target)?,
                    "iter": self.lower_expression(&generator.iter)?,
                    "ifs": self.lower_expression_list(&generator.ifs)?,
                }))
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

fn collect_named_assignments(
    statements: &[SyntaxStatement],
    output: &mut Vec<(String, SyntaxExpression)>,
) {
    for statement in statements {
        match statement {
            SyntaxStatement::Assign { targets, value, .. } if targets.len() == 1 => {
                if let Some(name) = name_id(&targets[0]) {
                    output.push((name.to_string(), value.clone()));
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
    callee: &SyntaxStatement,
    args: &'a [SyntaxExpression],
    keywords: &'a [SyntaxKeyword],
) -> Vec<(String, &'a SyntaxExpression)> {
    let SyntaxStatement::FunctionDef { parameters, .. } = callee else {
        return Vec::new();
    };
    let positional = parameters
        .iter()
        .filter(|parameter| {
            matches!(
                parameter.kind,
                SyntaxParameterKind::PositionalOnly | SyntaxParameterKind::PositionalOrKeyword
            )
        })
        .collect::<Vec<_>>();
    let named_parameters = parameters
        .iter()
        .map(|parameter| parameter.name.as_str())
        .collect::<HashSet<_>>();

    let mut output = Vec::new();
    for (index, argument) in args.iter().enumerate() {
        if let Some(parameter) = positional.get(index) {
            output.push((parameter.name.clone(), argument));
        }
    }
    for keyword in keywords {
        let Some(arg) = &keyword.arg else {
            continue;
        };
        if named_parameters.contains(arg.as_str()) {
            output.push((arg.clone(), &keyword.value));
        }
    }
    output
}

fn host_binding_value(binding: &HostBinding) -> Value {
    json!({
        "binding": binding.binding,
        "id": binding.id,
        "kind": binding.kind,
        "category": binding.category,
    })
}

fn resolve_host_binding(path: &str) -> Option<HostBinding> {
    HOST_BINDINGS
        .iter()
        .copied()
        .find(|binding| binding.binding == path)
}

fn resolve_host_binding_id(identifier: &str) -> Option<HostBinding> {
    HOST_BINDINGS
        .iter()
        .copied()
        .find(|binding| binding.id == identifier)
}

fn span_value(span: SourceRange) -> Value {
    json!({
        "line": span.start_line,
        "col": span.start_column,
        "end_line": span.end_line,
        "end_col": span.end_column,
    })
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

fn dotted_path(expression: &SyntaxExpression) -> Option<String> {
    match expression {
        SyntaxExpression::Name { id, .. } => Some(id.clone()),
        SyntaxExpression::Attribute { value, attr, .. } => {
            let base = dotted_path(value)?;
            Some(format!("{base}.{attr}"))
        }
        _ => None,
    }
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
        SyntaxConstant::None => json!({
            "node": "constant",
            "span": span_value(span),
            "value_type": "none",
            "value": Value::Null,
        }),
        SyntaxConstant::Bool(value) => json!({
            "node": "constant",
            "span": span_value(span),
            "value_type": "bool",
            "value": value,
        }),
        SyntaxConstant::Int(value) => {
            let value = value
                .parse::<i64>()
                .map(Value::from)
                .unwrap_or_else(|_| Value::String(value.clone()));
            json!({
                "node": "constant",
                "span": span_value(span),
                "value_type": "int",
                "value": value,
            })
        }
        SyntaxConstant::Float(value) => json!({
            "node": "constant",
            "span": span_value(span),
            "value_type": "float",
            "value": Number::from_f64(*value).map(Value::Number).unwrap_or(Value::Null),
            "literal": format_float(*value),
        }),
        SyntaxConstant::Str(value) => json!({
            "node": "constant",
            "span": span_value(span),
            "value_type": "str",
            "value": value,
        }),
        SyntaxConstant::Bytes(value) => json!({
            "node": "constant",
            "span": span_value(span),
            "value_type": "bytes",
            "value": value,
        }),
        SyntaxConstant::Tuple(values) => json!({
            "node": "constant",
            "span": span_value(span),
            "value_type": "tuple",
            "value": values.iter().map(|value| lower_constant_without_span(value)).collect::<Vec<_>>(),
        }),
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
        lower_source_to_ir_json,
    };

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

            let lowered = lower_source_to_ir(module_name, source, &CompileOptions::default())
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
