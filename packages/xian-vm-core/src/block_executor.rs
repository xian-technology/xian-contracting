//! A block's transactions executed in Rust over the block overlay.
//!
//! This is the node's per-transaction path (`xian.processor.TxProcessor.
//! process_tx` with `xian.execution_engine.execute_vm_transaction` and
//! `xian_vm_core.execute_contract`) for metered transactions whose contract
//! needs nothing from Python: fee reservation, contract preparation, VM
//! execution, the failure charge, refund or failure metering, fee rewards
//! and staging the writes. Every outcome is byte-identical to that path.
//!
//! A transaction the port does not cover stops with `Stop::Handback` before
//! any of its effects reach the overlay; the node then runs it through the
//! Python path, in block order. That covers contract submission, contracts
//! using zk host syscalls, host syscalls other than the contract metadata
//! reads, hash scans, preparation and entry rejections, and any value the
//! Python checks could refuse. A storage fault stops with `Stop::Fault`.
use crate::block_state::lock;
use crate::bundle_executor::{
    validate_bundle_module, BundleExecutor, ExecutionOutcome, HostServices,
};
use crate::lmdb_env::storage_key_error;
use crate::metering::VM_TRANSACTION_BASE_CHI as TRANSACTION_BASE_CHI;
use crate::module_cache::shared_module;
use crate::settlement::{self, handback, Balance, Reservation, Settled, Stop};
use crate::state_view::StateView;
use crate::stored_value_encoder::encode_stored_value;
use crate::tx_rewards::{chain_chi_rate, tx_reward_outputs, RewardState, TxRewards};
use crate::{
    ValidatedModuleIr, VmBudget, VmEvent, VmException, VmExecutionContext, VmExecutionError,
    VmMeterConfig, VmValue, XIAN_VM_V2_PROFILE,
};
use num_bigint::BigInt;
use num_traits::Zero;
use std::cell::{OnceCell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::sync::Arc;

const IR_KEY: &str = "__xian_ir_v1__";
const SOURCE_KEY: &str = "__source__";
const OWNER_KEY: &str = "__owner__";
const INSUFFICIENT_BALANCE: &str = "Sender does not have enough chi for the submitted budget.";

/// The chain fee policy of the block (`xian.fee_policy.TxFeePolicy`).
#[derive(Clone, Debug)]
pub(crate) struct BlockPolicy {
    pub(crate) charge_fees: bool,
    pub(crate) distribute_fee_rewards: bool,
    /// Keys contract effects may not write (the execution policy).
    pub(crate) protected_keys: Vec<String>,
}

/// One transaction's inputs, converted as the Python path converts them.
pub(crate) struct PreparedTx {
    pub(crate) sender: String,
    pub(crate) contract: String,
    pub(crate) function: String,
    pub(crate) kwargs: Vec<(String, VmValue)>,
    /// signer, caller, this, entry, submission name and block context; the
    /// owner is read here.
    pub(crate) context: VmExecutionContext,
    pub(crate) chi_budget: BigInt,
    pub(crate) size_bytes: usize,
}

/// What the receipt of an executed transaction is built from.
pub(crate) struct TxOutcome {
    pub(crate) status: i32,
    /// The return value, or the failure text.
    pub(crate) result: VmValue,
    pub(crate) exception: Option<VmException>,
    /// The staged writes in key order.
    pub(crate) writes: Vec<(String, VmValue)>,
    pub(crate) events: Vec<VmEvent>,
    pub(crate) chi_used: BigInt,
    /// `None` when rewards were not computed.
    pub(crate) rewards: Option<TxRewards>,
}

fn fault(error: String) -> Stop {
    Stop::Fault(error)
}

/// What a contract's IR key holds.
#[derive(Clone)]
enum Ir {
    /// Missing (or null).
    Absent,
    /// A value that is not a non-empty string: no runnable module.
    Other,
    Text(Rc<CachedModule>),
}

/// A contract's IR text and, once needed, its validated module.
struct CachedModule {
    text: String,
    validated: OnceCell<Result<ValidatedModuleIr, String>>,
}

impl CachedModule {
    fn validated(&self, name: &str) -> Result<ValidatedModuleIr, String> {
        self.validated
            .get_or_init(|| shared_module(name, &self.text).map_err(|error| error.to_string()))
            .clone()
    }
}

/// The IR of the contracts one run read, by contract name, so a large IR is
/// decoded and validated once per run. Only a write to an IR key changes
/// it: the run's own staging forgets such keys, and every run starts empty
/// (the Python path writes between runs).
#[derive(Default)]
pub(crate) struct Modules(RefCell<HashMap<String, Ir>>);

impl Modules {
    pub(crate) fn clear(&self) {
        self.0.borrow_mut().clear();
    }

    fn forget(&self, key: &str) {
        if let Some(name) = key.strip_suffix(&format!(".{IR_KEY}")) {
            self.0.borrow_mut().remove(name);
        }
    }

    /// The IR of `name`, read as `Driver.get` reads it (booked as read).
    fn ir(&self, view: &StateView, name: &str) -> Result<Ir, String> {
        let key = format!("{name}.{IR_KEY}");
        if let Some(ir) = self.0.borrow().get(name) {
            view.record_read(&key);
            return Ok(ir.clone());
        }
        let ir = match view.get(&key, true)? {
            None | Some(VmValue::None) => Ir::Absent,
            Some(VmValue::String(text)) if !text.is_empty() => Ir::Text(Rc::new(CachedModule {
                text,
                validated: OnceCell::new(),
            })),
            Some(_) => Ir::Other,
        };
        self.0.borrow_mut().insert(name.to_owned(), ir.clone());
        Ok(ir)
    }
}

/// The VM host of a block transaction: state from the overlay and LMDB; a
/// request it cannot serve marks the transaction for the Python path.
struct BlockHost<'a> {
    view: StateView,
    modules: &'a Modules,
    stop: Option<Stop>,
}

impl BlockHost<'_> {
    fn ir(&mut self, name: &str) -> Result<Ir, VmExecutionError> {
        self.modules
            .ir(&self.view, name)
            .map_err(|error| self.halt(fault(error)))
    }

    fn halt(&mut self, stop: Stop) -> VmExecutionError {
        let message = match &stop {
            Stop::Handback(reason) => format!("handed back to the Python path: {reason}"),
            Stop::Fault(reason) => format!("host fault: {reason}"),
        };
        self.stop.get_or_insert(stop);
        VmExecutionError::new(message)
    }

    fn get(&mut self, key: &str) -> Result<Option<VmValue>, VmExecutionError> {
        match self.view.get(key, true) {
            Ok(value) => Ok(value.filter(|value| !matches!(value, VmValue::None))),
            Err(error) => Err(self.halt(fault(error))),
        }
    }

    fn back<T>(&mut self, reason: impl Into<String>) -> Result<T, VmExecutionError> {
        Err(self.halt(Stop::Handback(reason.into())))
    }

    fn string_arg(&mut self, args: &[VmValue], index: usize) -> Result<String, VmExecutionError> {
        match args.get(index) {
            Some(VmValue::String(value)) => Ok(value.clone()),
            _ => self.back("syscall argument is not a string"),
        }
    }

    /// `NativeVmHost._contract_exists`.
    fn contract_exists(&mut self, contract: &str) -> Result<bool, VmExecutionError> {
        if !matches!(self.ir(contract)?, Ir::Absent) {
            return Ok(true);
        }
        Ok(self.get(&format!("{contract}.{SOURCE_KEY}"))?.is_some())
    }

    /// `NativeVmHost._contract_has_export`.
    fn contract_has_export(
        &mut self,
        contract: &str,
        export: &str,
    ) -> Result<bool, VmExecutionError> {
        let Ir::Text(module) = self.ir(contract)? else {
            return Ok(false);
        };
        match runnable(contract, &module) {
            Ok(module) => Ok(exports(&module, export)),
            Err(Stop::Handback(reason)) => self.back(reason),
            Err(stop) => Err(self.halt(stop)),
        }
    }
}

impl HostServices for BlockHost<'_> {
    fn module_ir_json(&mut self, module: &str) -> Result<Option<String>, VmExecutionError> {
        match self.ir(module)? {
            Ir::Text(cached) => Ok(Some(cached.text.clone())),
            _ => Ok(None),
        }
    }

    fn module(
        &mut self,
        module: &str,
        profile: &str,
    ) -> Result<Option<ValidatedModuleIr>, VmExecutionError> {
        let Ir::Text(cached) = self.ir(module)? else {
            return Ok(None);
        };
        let validated = cached.validated(module).map_err(VmExecutionError::new)?;
        validate_bundle_module(&validated, module, profile)?;
        Ok(Some(validated))
    }

    fn read_variable(
        &mut self,
        _contract: &str,
        _binding: &str,
        storage_key: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        self.get(storage_key)
    }

    fn read_hash(
        &mut self,
        _contract: &str,
        _binding: &str,
        _key: &VmValue,
        storage_key: &str,
    ) -> Result<VmValue, VmExecutionError> {
        Ok(self.get(storage_key)?.unwrap_or(VmValue::None))
    }

    fn scan_hash_entries(
        &mut self,
        _contract: &str,
        _binding: &str,
        _prefix: &str,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        self.back("hash scan")
    }

    fn visit_hash_entries(
        &mut self,
        _contract: &str,
        _binding: &str,
        _prefix: &str,
        _visit: &mut dyn FnMut(String, VmValue) -> Result<(), VmExecutionError>,
    ) -> Result<(), VmExecutionError> {
        self.back("hash scan")
    }

    fn owner(&mut self, contract: &str) -> Result<Option<String>, VmExecutionError> {
        match self.get(&format!("{contract}.{OWNER_KEY}"))? {
            None => Ok(None),
            Some(VmValue::String(owner)) => Ok(Some(owner)),
            Some(_) => self.back("contract owner is not a string"),
        }
    }

    fn syscall(
        &mut self,
        syscall_id: &str,
        args: Vec<VmValue>,
        _kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        match syscall_id {
            "contract.exists" if args.len() == 1 => {
                let contract = self.string_arg(&args, 0)?;
                Ok(VmValue::Bool(self.contract_exists(&contract)?))
            }
            "contract.has_export" if args.len() == 2 => {
                let contract = self.string_arg(&args, 0)?;
                let export = self.string_arg(&args, 1)?;
                Ok(VmValue::Bool(self.contract_has_export(&contract, &export)?))
            }
            "contract.owner_of" if args.len() == 1 => {
                let contract = self.string_arg(&args, 0)?;
                Ok(self
                    .get(&format!("{contract}.{OWNER_KEY}"))?
                    .unwrap_or(VmValue::None))
            }
            other => self.back(format!("host syscall {other}")),
        }
    }
}

/// The module `name` as the node prepares it; a module the Python path
/// would refuse or that uses zk host syscalls is left to Python.
fn runnable(name: &str, cached: &CachedModule) -> Settled<ValidatedModuleIr> {
    let module = cached.validated(name).map_err(Stop::Handback)?;
    if module.vm_profile != XIAN_VM_V2_PROFILE {
        return handback("module does not target xian_vm_v2");
    }
    let uses_zk = module.host_dependencies.iter().any(|dependency| {
        dependency.category == "zk"
            || dependency.id.starts_with("zk.")
            || dependency.binding.starts_with("zk.")
    });
    if uses_zk {
        return handback("module uses zk host syscalls");
    }
    Ok(module)
}

fn exports(module: &ValidatedModuleIr, function: &str) -> bool {
    module
        .functions
        .iter()
        .any(|candidate| candidate.visibility == "export" && candidate.name == function)
}

struct UntrackedState<'a>(&'a StateView);

impl RewardState for UntrackedState<'_> {
    fn get(&mut self, key: &str) -> Settled<Option<VmValue>> {
        self.0.get(key, false).map_err(fault)
    }
}

/// What the VM part of a transaction produced, before settlement.
struct Execution {
    reservation: Option<Reservation>,
    status: i32,
    result: VmValue,
    exception: Option<VmException>,
    writes: BTreeMap<String, VmValue>,
    events: Vec<VmEvent>,
    chi_used: BigInt,
    contract_costs: Vec<(String, BigInt)>,
}

impl Execution {
    fn insufficient_balance() -> Self {
        Self {
            reservation: None,
            status: 1,
            result: VmValue::String(INSUFFICIENT_BALANCE.to_owned()),
            exception: Some(VmException {
                name: "AssertionError".to_owned(),
                args: vec![VmValue::String(INSUFFICIENT_BALANCE.to_owned())],
            }),
            writes: BTreeMap::new(),
            events: Vec::new(),
            chi_used: BigInt::zero(),
            contract_costs: Vec::new(),
        }
    }
}

pub(crate) struct BlockExecutor {
    view: StateView,
    policy: BlockPolicy,
    modules: Modules,
}

impl BlockExecutor {
    pub(crate) fn new(view: StateView, policy: BlockPolicy) -> Self {
        Self {
            view,
            policy,
            modules: Modules::default(),
        }
    }

    /// Start a run: the Python path may have changed state since the last.
    pub(crate) fn begin_run(&self) {
        self.modules.clear();
    }

    fn ir(&self, name: &str) -> Settled<Ir> {
        self.modules.ir(&self.view, name).map_err(fault)
    }

    fn get(&self, key: &str) -> Settled<Option<VmValue>> {
        self.view.get(key, true).map_err(fault)
    }

    fn stage(&self, key: &str, value: Option<&VmValue>) -> Settled<()> {
        self.stage_all(&[(key.to_owned(), value.cloned().unwrap_or(VmValue::None))])
    }

    /// Validate and encode every write, then write them all (`apply_writes`).
    fn stage_all(&self, writes: &[(String, VmValue)]) -> Settled<()> {
        let mut encoded = Vec::with_capacity(writes.len());
        for (key, value) in writes {
            if let Some(error) = storage_key_error(key) {
                return handback(error);
            }
            let stored = match value {
                VmValue::None => None,
                value => Some(Arc::<[u8]>::from(
                    encode_stored_value(value)
                        .map_err(|error| Stop::Handback(error.to_string()))?,
                )),
            };
            encoded.push((key, stored));
        }
        let mut overlay = lock(self.view.overlay());
        for (key, stored) in encoded {
            self.modules.forget(key);
            overlay.write(key, stored);
        }
        Ok(())
    }

    /// The transaction, executed and staged.
    pub(crate) fn execute(&self, tx: &PreparedTx) -> Settled<TxOutcome> {
        if tx.contract == "submission" {
            return handback("contract submission");
        }
        let rate = if self.policy.charge_fees {
            Some(chain_chi_rate(
                self.view.get("chi_cost.S:value", false).map_err(fault)?,
            )?)
        } else {
            None
        };
        let balance_key = format!("currency.balances:{}", tx.sender);
        if let Some(error) = storage_key_error(&balance_key) {
            return handback(error);
        }
        lock(self.view.overlay())
            .begin_discarding()
            .map_err(|error| fault(error.to_string()))?;
        let execution = self.execute_in_scope(tx, rate.as_ref(), &balance_key);
        lock(self.view.overlay())
            .discard()
            .map_err(|error| fault(error.to_string()))?;
        let mut execution = execution?;
        if execution.status != 0 {
            execution.chi_used = settlement::failed_transaction_chi(
                &execution.chi_used,
                &tx.chi_budget,
                TRANSACTION_BASE_CHI,
            );
        }
        self.settle(tx, execution, rate.as_ref(), &balance_key)
    }

    /// Reservation, preparation and VM execution, inside the discarding scope.
    fn execute_in_scope(
        &self,
        tx: &PreparedTx,
        rate: Option<&BigInt>,
        balance_key: &str,
    ) -> Settled<Execution> {
        let reservation = match rate {
            None => None,
            Some(rate) => match self.reserve(tx, rate, balance_key)? {
                Some(reservation) => Some(reservation),
                None => return Ok(Execution::insufficient_balance()),
            },
        };
        let entry = self.prepare(&tx.contract)?;
        let context = self.entry_context(tx, &entry)?;
        let outcome = self.run_vm(tx, entry, context)?;
        Ok(execution_of(outcome, reservation))
    }

    /// `_reserve_vm_fee_budget`: the budget reserved from the sender's
    /// balance and the spendable rest staged; `None` when it cannot pay.
    fn reserve(
        &self,
        tx: &PreparedTx,
        rate: &BigInt,
        balance_key: &str,
    ) -> Settled<Option<Reservation>> {
        let balance = Balance::of(self.get(balance_key)?.as_ref())?;
        let Some(reservation) = settlement::reserve(&balance, &tx.chi_budget, rate)? else {
            return Ok(None);
        };
        self.stage(
            balance_key,
            Some(&VmValue::Decimal(reservation.spendable.clone())),
        )?;
        Ok(Some(reservation))
    }

    /// The execution context of an entry call that passes
    /// `execute_contract`'s checks.
    fn entry_context(
        &self,
        tx: &PreparedTx,
        entry: &ValidatedModuleIr,
    ) -> Settled<VmExecutionContext> {
        // execute_contract's own load of the entry module.
        self.ir(&tx.contract)?;
        let owner = match self.get(&format!("{}.{OWNER_KEY}", tx.contract))? {
            None => None,
            Some(VmValue::String(owner)) => Some(owner),
            Some(_) => return handback("contract owner is not a string"),
        };
        // execute_contract's entry checks: only the owner may call an owned
        // contract (an empty owner too), and only exported functions.
        if owner
            .as_deref()
            .is_some_and(|owner| Some(owner) != tx.context.caller.as_deref())
        {
            return handback("caller is not the owner");
        }
        let mut context = tx.context.clone();
        // Driver.get_owner: an empty owner is no owner.
        context.owner = owner.filter(|owner| !owner.is_empty());
        if !exports(entry, &tx.function) {
            return handback("function is not exported");
        }
        Ok(context)
    }

    /// `_prepare_vm_contract_bundle`: the import graph of `contract` must
    /// be acyclic and every module in it runnable; returns the entry module.
    fn prepare(&self, contract: &str) -> Settled<ValidatedModuleIr> {
        let mut prepared = BTreeMap::new();
        self.prepare_module(contract, &mut Vec::new(), &mut prepared)?;
        Ok(prepared
            .remove(contract)
            .expect("the entry module was prepared"))
    }

    fn prepare_module(
        &self,
        name: &str,
        stack: &mut Vec<String>,
        prepared: &mut BTreeMap<String, ValidatedModuleIr>,
    ) -> Settled<()> {
        if stack.iter().any(|entry| entry == name) {
            return handback("import graph contains a cycle");
        }
        if prepared.contains_key(name) {
            return Ok(());
        }
        let Ir::Text(cached) = self.ir(name)? else {
            return handback("contract has no persisted IR");
        };
        let module = runnable(name, &cached)?;
        let imports: std::collections::BTreeSet<String> = module
            .imports
            .iter()
            .map(|import| import.module.clone())
            .filter(|module| !module.is_empty())
            .collect();
        stack.push(name.to_owned());
        for import in imports {
            self.prepare_module(&import, stack, prepared)?;
        }
        stack.pop();
        prepared.insert(name.to_owned(), module);
        Ok(())
    }

    fn run_vm(
        &self,
        tx: &PreparedTx,
        entry: ValidatedModuleIr,
        context: VmExecutionContext,
    ) -> Settled<ExecutionOutcome> {
        let budget_raw = chi_budget_raw(&tx.chi_budget)?;
        let budget = VmBudget::new(budget_raw, XIAN_VM_V2_PROFILE);
        let host = BlockHost {
            view: self.view.clone(),
            modules: &self.modules,
            stop: None,
        };
        validate_bundle_module(&entry, &tx.contract, XIAN_VM_V2_PROFILE)
            .map_err(|error| Stop::Handback(error.to_string()))?;
        let bundle = HashMap::from([(tx.contract.clone(), entry)]);
        let config = VmMeterConfig {
            enabled: true,
            chi_budget_raw: budget_raw,
            transaction_size_bytes: tx.size_bytes,
        };
        let limit = budget.limit();
        let mut executor =
            BundleExecutor::with_modules(host, bundle, config, Some(budget), XIAN_VM_V2_PROFILE);
        let mut outcome = executor.execute_entry(
            &tx.contract,
            &tx.function,
            Vec::new(),
            tx.kwargs.clone(),
            context,
        );
        if let Some(stop) = executor.host.stop.take() {
            return Err(stop);
        }
        // _combined_chi_used: the base charge plus measured work, within the budget.
        let combined = (outcome.stats.raw_cost / 1_000 + TRANSACTION_BASE_CHI).min(limit / 1_000);
        outcome.stats.chi_used = combined.max(outcome.stats.chi_used);
        Ok(outcome)
    }

    /// Fee settlement, rewards and staging after the scope closed.
    fn settle(
        &self,
        tx: &PreparedTx,
        execution: Execution,
        rate: Option<&BigInt>,
        balance_key: &str,
    ) -> Settled<TxOutcome> {
        let mut writes = if execution.status == 0 {
            self.validated(&execution)?;
            execution.writes.clone()
        } else {
            BTreeMap::new()
        };
        if let Some(rate) = rate {
            if let Some(balance) = self.charged_balance(&execution, rate, balance_key)? {
                writes.insert(balance_key.to_owned(), balance);
            }
        }
        let rewards = if execution.status == 0 && self.policy.distribute_fee_rewards {
            Some(tx_reward_outputs(
                &mut UntrackedState(&self.view),
                &execution.chi_used,
                &tx.contract,
                &execution.contract_costs,
            )?)
        } else {
            None
        };
        if let Some(rewards) = &rewards {
            self.add_deltas(&mut writes, rewards)?;
        }
        let writes: Vec<(String, VmValue)> = writes.into_iter().collect();
        self.stage_all(&writes)?;
        Ok(TxOutcome {
            status: execution.status,
            result: execution.result,
            exception: execution.exception,
            writes,
            events: execution.events,
            chi_used: execution.chi_used,
            rewards,
        })
    }

    /// The sender's balance after the fee: refunded against the reservation
    /// after a success, metered from the balance before the transaction
    /// after a failure (`None`: no write).
    fn charged_balance(
        &self,
        execution: &Execution,
        rate: &BigInt,
        balance_key: &str,
    ) -> Settled<Option<VmValue>> {
        if execution.status != 0 {
            let balance = Balance::of(self.get(balance_key)?.as_ref())?;
            return settlement::metered_balance(&balance, &execution.chi_used, rate);
        }
        let reservation = execution
            .reservation
            .as_ref()
            .expect("a charged success reserved its budget");
        let after = match execution.writes.get(balance_key) {
            Some(value) => Balance::of(Some(value))?,
            None => Balance::Fixed(reservation.spendable.clone()),
        };
        let refunded = settlement::refund(reservation, &after, &execution.chi_used, rate)?;
        Ok(Some(VmValue::Decimal(refunded)))
    }

    /// `materialize_writes`: each reward delta added to the written or
    /// current balance (a missing balance is 0).
    fn add_deltas(
        &self,
        writes: &mut BTreeMap<String, VmValue>,
        rewards: &TxRewards,
    ) -> Settled<()> {
        for (key, delta) in &rewards.deltas {
            let current = match writes.get(key) {
                Some(VmValue::None) => return handback("reward delta on a deleted balance"),
                Some(value) => Balance::of(Some(value))?,
                None => Balance::of(self.view.get(key, false).map_err(fault)?.as_ref())?,
            };
            writes.insert(key.clone(), VmValue::Decimal(current.plus(delta)?));
        }
        Ok(())
    }

    /// `_validated_vm_result`: what the Python checks would refuse is left
    /// to Python. The writes and events are encoded as one document, as
    /// `validate_persistent_value((writes, events))` traverses them.
    fn validated(&self, execution: &Execution) -> Settled<()> {
        for key in execution.writes.keys() {
            if self.policy.protected_keys.contains(key) {
                return handback("contract effects write a protected key");
            }
            if let Some(error) = storage_key_error(key) {
                return handback(error);
            }
        }
        let writes = VmValue::Dict(
            execution
                .writes
                .iter()
                .map(|(key, value)| (VmValue::String(key.clone()), value.clone()))
                .collect(),
        );
        let events = VmValue::List(execution.events.iter().map(event_value).collect());
        let document = VmValue::List(vec![writes, events]);
        if !receipt_encodable(&document) {
            return handback("a value the receipt encoding refuses");
        }
        encode_stored_value(&document).map_err(|error| Stop::Handback(error.to_string()))?;
        Ok(())
    }
}

/// Whether `encode_abci_json` takes `value`: it has no form for a bytearray
/// or a timedelta; raw decimals and floats (whose conversion can refuse) are
/// also left to Python.
fn receipt_encodable(value: &VmValue) -> bool {
    match value {
        VmValue::ByteArray(_)
        | VmValue::TimeDelta(_)
        | VmValue::RawDecimal(_)
        | VmValue::DecimalTuple(_)
        | VmValue::Float(_)
        | VmValue::Reference(_) => false,
        VmValue::List(items)
        | VmValue::Tuple(items)
        | VmValue::Set(items)
        | VmValue::FrozenSet(items) => items.iter().all(receipt_encodable),
        VmValue::Dict(entries) => entries
            .iter()
            .all(|(key, value)| receipt_encodable(key) && receipt_encodable(value)),
        _ => true,
    }
}

/// An event as the Python path's event dictionary.
pub(crate) fn event_value(event: &VmEvent) -> VmValue {
    let text = |value: &str| VmValue::String(value.to_owned());
    let pairs = |pairs: &[(String, VmValue)]| {
        VmValue::Dict(
            pairs
                .iter()
                .map(|(key, value)| (text(key), value.clone()))
                .collect(),
        )
    };
    VmValue::Dict(vec![
        (text("contract"), text(&event.contract)),
        (text("event"), text(&event.event)),
        (text("signer"), event.signer.clone()),
        (text("caller"), event.caller.clone()),
        (text("data_indexed"), pairs(&event.data_indexed)),
        (text("data"), pairs(&event.data)),
    ])
}

fn chi_budget_raw(chi_budget: &BigInt) -> Settled<u64> {
    let budget = if chi_budget < &BigInt::zero() {
        BigInt::zero()
    } else {
        chi_budget.clone()
    };
    u64::try_from(budget * 1_000).map_err(|_| Stop::Handback("chi budget out of range".to_owned()))
}

/// The VM outcome as `execute_contract` reports it: writes from the module
/// snapshots, then the recorded storage writes, in key order.
fn execution_of(outcome: ExecutionOutcome, reservation: Option<Reservation>) -> Execution {
    let mut writes = BTreeMap::new();
    for snapshot in outcome.snapshots {
        for variable in snapshot.variables {
            writes.insert(
                format!("{}.{}", snapshot.contract_name, variable.binding),
                variable.value.unwrap_or(VmValue::None),
            );
        }
        for hash in snapshot.hashes {
            for (key, value) in hash.entries {
                writes.insert(
                    format!("{}.{}:{}", snapshot.contract_name, hash.binding, key),
                    value,
                );
            }
        }
    }
    writes.extend(outcome.storage_writes);
    let mut contract_costs: Vec<(String, BigInt)> = outcome
        .stats
        .contract_costs
        .into_iter()
        .map(|(name, cost)| (name, BigInt::from(cost)))
        .collect();
    contract_costs.sort();
    Execution {
        reservation,
        status: outcome.status_code,
        result: outcome.result,
        exception: outcome.exception,
        writes,
        events: outcome.events,
        chi_used: BigInt::from(outcome.stats.chi_used),
        contract_costs,
    }
}
