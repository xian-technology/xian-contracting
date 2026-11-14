//! Contract deployment (`NativeVmHost._stage_contract_deploy` for
//! `contract.deploy`, which only submission may call): the source is
//! compiled with the linked compiler as `compile_contract_source` compiles
//! it, the module checked, its constructor run in a nested execution over
//! this host and the transaction's budget, and the contract's metadata and
//! the constructor's effects staged. Every failure reads as the Python
//! host's; an argument the Python host would convert in a way not ported
//! here is handed back.
use super::charges::host_runtime_error;
use super::modules::{uses_zk, Ir};
use super::{BlockHost, DEVELOPER_KEY, IR_KEY, OWNER_KEY, SOURCE_KEY};
use crate::bundle_executor::{validate_bundle_module, BundleExecutor, ExecutionOutcome};
use crate::module_cache::shared_module;
use crate::set_member_codec::is_reserved_tag;
use crate::{
    ValidatedModuleIr, VmEvent, VmException, VmExecutionContext, VmExecutionError, VmMeterConfig,
    VmValue, XIAN_VM_V2_PROFILE,
};
use std::collections::{BTreeMap, HashMap};
use xian_compiler_core::{
    compiler_error_message, lower_source_to_ir_json, normalize_source, CompileOptions,
    CompilerDiagnostic,
};

/// `contracting.constants.DEPLOYMENT_BASE_COST` and
/// `DEPLOYMENT_COST_PER_SOURCE_BYTE`: the raw cost of a deployment.
const DEPLOYMENT_BASE_COST: u64 = 5_000;
const DEPLOYMENT_COST_PER_SOURCE_BYTE: u64 = 1;
/// `contracting.names.MAX_CONTRACT_NAME_LENGTH`.
const MAX_CONTRACT_NAME_LENGTH: usize = 64;
const TIME_KEY: &str = "__submitted__";
const DEPLOYER_KEY: &str = "__deployer__";
const INITIATOR_KEY: &str = "__initiator__";
/// The nesting a constructor argument may have to pass the Python host's
/// wire round trip unchanged (its traversal limit is 128).
const MAX_ARGUMENT_DEPTH: usize = 64;

/// `contract.deploy`'s arguments as `NativeVmHost.handle_syscall` reads them.
struct Deployment {
    name: VmValue,
    code: VmValue,
    owner: VmValue,
    constructor_args: VmValue,
    developer: VmValue,
    deployer: VmValue,
    initiator: VmValue,
    artifacts: VmValue,
}

impl Deployment {
    fn of(args: &[VmValue], kwargs: &[(String, VmValue)]) -> Self {
        let keyword = |name: &str| kwargs.iter().find(|(key, _)| key == name).map(|(_, v)| v);
        let positional = |index: usize| args.get(index).cloned().unwrap_or(VmValue::None);
        // kwargs.get(name, args[i]) for the name and code; the keyword, or
        // the argument when it is None, for the owner and constructor args.
        let either = |name: &str, index: usize| keyword(name).cloned().unwrap_or(positional(index));
        let or_argument = |name: &str, index: usize| match keyword(name) {
            Some(value) if !matches!(value, VmValue::None) => value.clone(),
            _ => positional(index),
        };
        let only_keyword = |name: &str| keyword(name).cloned().unwrap_or(VmValue::None);
        Self {
            name: either("name", 0),
            code: either("code", 1),
            owner: or_argument("owner", 2),
            constructor_args: or_argument("constructor_args", 3),
            developer: only_keyword("developer"),
            deployer: only_keyword("deployer"),
            initiator: only_keyword("initiator"),
            artifacts: only_keyword("deployment_artifacts"),
        }
    }
}

/// The compiled contract (`_deployment_artifacts`).
struct Artifacts {
    name: String,
    source: String,
    ir: String,
    module: ValidatedModuleIr,
    construct: Option<String>,
}

/// The deployment's actors and time (`_stage_contract_deploy`): the given
/// ones, else the transaction's caller and signer.
struct Actors {
    developer: VmValue,
    deployer: VmValue,
    initiator: VmValue,
    now: VmValue,
}

/// `contract.deploy`, or `None` for another syscall.
pub(super) fn deploy(
    host: &mut BlockHost<'_>,
    syscall_id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Option<Result<VmValue, VmExecutionError>> {
    (syscall_id == "contract.deploy").then(|| host.deploy(Deployment::of(args, kwargs)))
}

impl BlockHost<'_> {
    fn deploy(&mut self, deployment: Deployment) -> Result<VmValue, VmExecutionError> {
        if !matches!(deployment.artifacts, VmValue::None) {
            return Err(host_runtime_error(
                "native contract deployment accepts source code only",
            ));
        }
        let artifacts = self.deployment_artifacts(&deployment.name, &deployment.code)?;
        let actors = self.actors(&deployment)?;
        let (writes, events) = self.run_constructor(&artifacts, &deployment, &actors)?;
        self.stage_deployment(&artifacts, &deployment.owner, actors, writes, events)?;
        Ok(VmValue::None)
    }

    /// `_deployment_artifacts`: a safe and unused name, then the compiled
    /// and checked module.
    fn deployment_artifacts(
        &mut self,
        name: &VmValue,
        code: &VmValue,
    ) -> Result<Artifacts, VmExecutionError> {
        let name = self.contract_name(name)?;
        if self.contract_exists(&name)? {
            return Err(host_runtime_error("Contract already exists."));
        }
        let (source, ir) = compile(&name, source_code(code)?)?;
        let module = self.checked_module(&name, &ir)?;
        let construct = module
            .functions
            .iter()
            .find(|function| function.visibility == "construct")
            .map(|function| function.name.clone());
        Ok(Artifacts {
            name,
            source,
            ir,
            module,
            construct,
        })
    }

    /// The compiled module, validated (`validate_module_ir`) and allowed by
    /// the chain's runtime features.
    fn checked_module(
        &mut self,
        name: &str,
        ir: &str,
    ) -> Result<ValidatedModuleIr, VmExecutionError> {
        let module = shared_module(name, ir)
            .map_err(|error| VmExecutionError::new(format!("VmIrValidationError: {error}")))?;
        if uses_zk(&module) {
            self.require_zk(name)?;
        }
        Ok(module)
    }

    /// `assert_safe_contract_name`.
    fn contract_name(&mut self, name: &VmValue) -> Result<String, VmExecutionError> {
        let name = match name {
            VmValue::String(name) if !name.is_empty() => name,
            VmValue::String(_)
            | VmValue::None
            | VmValue::Bool(_)
            | VmValue::Int(_)
            | VmValue::Decimal(_)
            | VmValue::List(_)
            | VmValue::Dict(_) => {
                return Err(assertion("Contract name must be a non-empty string."))
            }
            _ => return self.back("contract name the Python host may read as a string"),
        };
        if name.chars().count() > MAX_CONTRACT_NAME_LENGTH {
            return Err(assertion(&format!(
                "Contract name length exceeds {MAX_CONTRACT_NAME_LENGTH} characters!"
            )));
        }
        if !safe_contract_name(name) {
            return Err(assertion(
                "Contract name must start with a lowercase ASCII letter and contain only \
                 lowercase ASCII letters, digits, and underscores.",
            ));
        }
        Ok(name.clone())
    }

    /// The developer, deployer and initiator (the transaction's caller and
    /// signer when not given) and the deployment time.
    fn actors(&self, deployment: &Deployment) -> Result<Actors, VmExecutionError> {
        let context = &self.tx.context;
        let given_or = |value: &VmValue, fallback: &Option<String>| match value {
            VmValue::None => fallback.clone().map_or(VmValue::None, VmValue::String),
            value => value.clone(),
        };
        if matches!(context.now, VmValue::None) {
            return Err(host_runtime_error(
                "native contract deployment requires deterministic now context",
            ));
        }
        Ok(Actors {
            developer: given_or(&deployment.developer, &context.caller),
            deployer: given_or(&deployment.deployer, &context.caller),
            initiator: given_or(&deployment.initiator, &context.signer),
            now: context.now.clone(),
        })
    }

    /// `_run_constructor`: the constructor's writes and events. While it
    /// runs, the new module is the contract's IR for every module load
    /// (not for `contract.exists` or `code_hash`); a failure takes it back.
    fn run_constructor(
        &mut self,
        artifacts: &Artifacts,
        deployment: &Deployment,
        actors: &Actors,
    ) -> Result<(BTreeMap<String, VmValue>, Vec<VmEvent>), VmExecutionError> {
        let Some(construct) = &artifacts.construct else {
            return Ok((BTreeMap::new(), Vec::new()));
        };
        let kwargs = self.constructor_kwargs(&deployment.constructor_args)?;
        let context = self.constructor_context(artifacts, deployment, actors)?;
        validate_bundle_module(&artifacts.module, &artifacts.name, XIAN_VM_V2_PROFILE)
            .map_err(host_runtime_error)?;
        self.constructing.insert(
            artifacts.name.clone(),
            Ir::of(Some(VmValue::String(artifacts.ir.clone()))),
        );
        let outcome = self.execute_constructor(artifacts, construct, kwargs, context);
        self.constructing.remove(&artifacts.name);
        self.constructor_outcome(outcome)
    }

    /// `_execute_constructor`: a nested execution over this host that
    /// charges the transaction's budget.
    fn execute_constructor(
        &mut self,
        artifacts: &Artifacts,
        construct: &str,
        kwargs: Vec<(String, VmValue)>,
        context: VmExecutionContext,
    ) -> ExecutionOutcome {
        let config = VmMeterConfig {
            enabled: self.charges.metered(),
            chi_budget_raw: 0,
            transaction_size_bytes: 0,
        };
        let budget = self.charges.budget();
        let bundle = HashMap::from([(artifacts.name.clone(), artifacts.module.clone())]);
        let mut executor = BundleExecutor::with_modules(
            &mut *self,
            bundle,
            config,
            Some(budget),
            XIAN_VM_V2_PROFILE,
        );
        executor.execute_entry(&artifacts.name, construct, Vec::new(), kwargs, context)
    }

    /// The constructor's cost counts for the transaction whatever its
    /// outcome; a failure fails the deployment with the constructor's
    /// exception.
    fn constructor_outcome(
        &mut self,
        mut outcome: ExecutionOutcome,
    ) -> Result<(BTreeMap<String, VmValue>, Vec<VmEvent>), VmExecutionError> {
        self.charges.add_raw(outcome.stats.raw_cost);
        self.charges.add_costs(&outcome.stats.contract_costs);
        if outcome.status_code == 0 {
            let writes = outcome.take_writes();
            return Ok((writes, outcome.events));
        }
        let text = match &outcome.result {
            VmValue::String(text) => text.clone(),
            other => other.python_repr(),
        };
        let error = host_runtime_error(format!("contract constructor failed: {text}"));
        let Some(exception) = outcome.exception else {
            return Err(error);
        };
        // The host carries the exception through Python (`__xian_exception__`).
        match plain_arguments(&exception.args) {
            Some(args) => Err(error.with_exception(VmException {
                name: exception.name,
                args,
            })),
            None => self.back("constructor exception arguments the host would convert"),
        }
    }

    /// `coerce_call_kwargs(dict(constructor_args or {}))`: arguments that
    /// pass the Python host's wire round trip unchanged; others are handed
    /// back.
    fn constructor_kwargs(
        &mut self,
        arguments: &VmValue,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let entries = match arguments {
            VmValue::None => return Ok(Vec::new()),
            VmValue::Dict(entries) => entries,
            _ => return self.back("constructor arguments that are not a dict"),
        };
        let mut kwargs = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            match key {
                VmValue::String(key) if wire_stable(value, 1) && !is_reserved_tag(key) => {
                    kwargs.push((key.clone(), value.clone()));
                }
                _ => return self.back("constructor arguments the wire round trip changes"),
            }
        }
        Ok(kwargs)
    }

    /// The constructor's context: signed by the initiator, called by the
    /// deployer, owned by the owner, as the new contract.
    fn constructor_context(
        &mut self,
        artifacts: &Artifacts,
        deployment: &Deployment,
        actors: &Actors,
    ) -> Result<VmExecutionContext, VmExecutionError> {
        let context = &self.tx.context;
        let (entry, block_num, block_hash, chain_id) = (
            context.entry.clone(),
            context.block_num.clone(),
            context.block_hash.clone(),
            context.chain_id.clone(),
        );
        Ok(VmExecutionContext {
            this: Some(artifacts.name.clone()),
            caller: self.optional_text(&actors.deployer)?,
            signer: self.optional_text(&actors.initiator)?,
            owner: self.optional_text(&deployment.owner)?,
            entry,
            submission_name: Some(artifacts.name.clone()),
            now: actors.now.clone(),
            block_num,
            block_hash,
            chain_id,
            // `_stage_contract_deploy`'s context has no `__input_hash`.
            input_hash: VmValue::None,
        })
    }

    /// A context string as `context_from_py` reads it; anything else is
    /// handed back.
    fn optional_text(&mut self, value: &VmValue) -> Result<Option<String>, VmExecutionError> {
        match value {
            VmValue::None => Ok(None),
            VmValue::String(text) => Ok(Some(text.clone())),
            _ => self.back("constructor context value that is not a string"),
        }
    }

    /// The constructor's effects, then the contract's metadata, each
    /// charged when metered; then the deployment's own cost.
    fn stage_deployment(
        &mut self,
        artifacts: &Artifacts,
        owner: &VmValue,
        actors: Actors,
        writes: BTreeMap<String, VmValue>,
        events: Vec<VmEvent>,
    ) -> Result<(), VmExecutionError> {
        for (key, value) in writes {
            self.writes.stage(&key, value);
        }
        let metadata = [
            (SOURCE_KEY, VmValue::String(artifacts.source.clone())),
            (IR_KEY, VmValue::String(artifacts.ir.clone())),
            (OWNER_KEY, owner.clone()),
            (TIME_KEY, actors.now),
            (DEVELOPER_KEY, actors.developer),
            (DEPLOYER_KEY, actors.deployer),
            (INITIATOR_KEY, actors.initiator),
        ];
        for (variable, value) in metadata {
            let key = format!("{}.{variable}", artifacts.name);
            self.writes.stage(&key, value.clone());
            if !matches!(value, VmValue::None) {
                self.charge_host_write(&key, &value)?;
            }
        }
        for event in events {
            self.writes.emit(event);
        }
        let source_bytes = artifacts.source.len() as u64;
        self.charges
            .record(DEPLOYMENT_BASE_COST + source_bytes * DEPLOYMENT_COST_PER_SOURCE_BYTE)
    }
}

/// The source code a deployment needs: a non-empty string.
fn source_code(code: &VmValue) -> Result<&str, VmExecutionError> {
    match code {
        VmValue::String(code) if !code.is_empty() => Ok(code),
        _ => Err(host_runtime_error(
            "native contract deployment requires non-empty source code",
        )),
    }
}

/// `compile_contract_source`: the normalized source (linted) and its IR
/// (compiled from that source without the lint).
fn compile(name: &str, code: &str) -> Result<(String, String), VmExecutionError> {
    let linted = CompileOptions {
        vm_profile: XIAN_VM_V2_PROFILE.to_owned(),
        lint: true,
    };
    let source = normalize_source(name, code, &linted).map_err(compiler_failure)?;
    let canonical = CompileOptions {
        lint: false,
        ..linted
    };
    let ir = lower_source_to_ir_json(name, &source, &canonical).map_err(compiler_failure)?;
    Ok((source, ir))
}

/// The compiler's `CompilerError` as the VM reports a host failure.
fn compiler_failure(diagnostics: Vec<CompilerDiagnostic>) -> VmExecutionError {
    VmExecutionError::new(format!(
        "CompilerError: {}",
        compiler_error_message(&diagnostics)
    ))
}

fn assertion(message: &str) -> VmExecutionError {
    VmExecutionError::described(
        "AssertionError",
        format!("AssertionError: {message}"),
        message,
    )
}

/// `contracting.names.is_safe_contract_name`: `[a-z][a-z0-9_]{0,63}`.
fn safe_contract_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|char| char.is_ascii_lowercase() || char.is_ascii_digit() || char == '_')
}

/// Whether `normalize_wire_numbers` then `decode_wire_numbers` gives
/// `value` back unchanged: strings, booleans, integers of at most 512 bits,
/// exact decimals whose fixed text has at most 93 characters, and lists and
/// string-keyed dicts of those.
fn wire_stable(value: &VmValue, depth: usize) -> bool {
    if depth > MAX_ARGUMENT_DEPTH {
        return false;
    }
    match value {
        VmValue::None | VmValue::Bool(_) | VmValue::String(_) => true,
        VmValue::Int(number) => number.bits() <= 512,
        VmValue::Decimal(number) => number.to_string().len() <= 93,
        VmValue::List(items) => items.iter().all(|item| wire_stable(item, depth + 1)),
        VmValue::Dict(entries) => entries.iter().all(|(key, item)| {
            matches!(key, VmValue::String(key) if !is_reserved_tag(key))
                && wire_stable(item, depth + 1)
        }),
        _ => false,
    }
}

/// Exception arguments as the Python host's round trip returns them
/// (detached from the heap), when they are plain values it keeps.
fn plain_arguments(args: &[VmValue]) -> Option<Vec<VmValue>> {
    args.iter()
        .map(|arg| {
            let value = arg.detached().ok()?;
            matches!(
                value,
                VmValue::None | VmValue::Bool(_) | VmValue::Int(_) | VmValue::String(_)
            )
            .then_some(value)
        })
        .collect()
}
