//! A block's transactions executed in Rust over the block overlay.
//!
//! This is the node's only transaction engine (blocks through
//! `xian.processor.TxProcessor.process_block`, single calls through
//! `execute_tx`): fee reservation, contract preparation, VM execution, the
//! failure charge, refund or failure metering, fee rewards and staging the
//! writes. The outcomes and texts are those of the former Python
//! per-transaction path (deleted in increment 9 of the single-engine plan),
//! pinned by xian-abci's golden corpora.
//!
//! Every transaction gets a receipt here; revision 14 gives the inputs the
//! former Python path halted on or decided by its own quirks explicit rules: a
//! sender balance that is not a number cannot pay (`INVALID_BALANCE`, no
//! charge), a failure charge never raises a negative balance, and an invalid
//! reward input pays no rewards (`tx_rewards`). The VM's host (`block_host`)
//! reads the overlay and LMDB, hash scans included, and serves every host
//! syscall. Only a host fault (unreadable state, or a chain chi rate the
//! node refuses to price with) stops a transaction (`Stop::Fault`): the
//! node halts.
use crate::block_host::features::{zk_disabled, zk_enabled, Unread};
use crate::block_host::modules::{exports, runnable, uses_zk};
use crate::block_host::{
    fault, text, BlockHost, HostCharges, HostWrites, Ir, Modules, TxInputs, OWNER_KEY,
};
use crate::block_state::lock;
use crate::bundle_executor::{validate_bundle_module, BundleExecutor, ExecutionOutcome};
use crate::interpreter::numeric_v2;
use crate::lmdb_env::storage_key_error;
use crate::metering::VM_TRANSACTION_BASE_CHI as TRANSACTION_BASE_CHI;
use crate::python_decimal::PyDecimal;
use crate::settlement::{self, Balance, InvalidBalance, Reservation, Settled, Stop};
use crate::state_view::StateView;
use crate::stored_value_encoder::encode_stored_value;
use crate::tx_rewards::{chain_chi_rate, tx_reward_outputs, RewardState, TxRewards, CHI_RATE_KEY};
use crate::{
    ValidatedModuleIr, VmBudget, VmEvent, VmException, VmExecutionContext, VmExecutionStats,
    VmMeterConfig, VmValue, XIAN_VM_V2_PROFILE,
};
use num_bigint::BigInt;
use num_traits::Zero;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

const INSUFFICIENT_BALANCE: &str = "Sender does not have enough chi for the submitted budget.";
/// `vm_contract_source_error("submission", "submit_contract")`.
const MISSING_SOURCE: &str = "xian_vm_v2 requires source code for submission.submit_contract";
/// `canonical_failure`'s text for a failure outside the VM's own errors.
const HOST_FAILURE: &str = "Transaction failed in the host runtime.";
/// A sender whose balance is not a number (revision 14): it cannot pay.
pub(crate) const INVALID_BALANCE: &str = "Sender balance is not a number.";
/// `_validated_vm_result`'s refusal of effects consensus cannot store.
const UNENCODABLE: &str = "Contract writes or events cannot be encoded for consensus.";
/// `_external_entry_error`'s refusals.
const NOT_OWNER: &str = "Caller is not the owner!";

/// The chain fee policy of the block (`xian.fee_policy.TxFeePolicy`).
#[derive(Clone, Debug)]
pub(crate) struct BlockPolicy {
    /// Chain policies meter execution; system transactions (epoch
    /// rebalance, evidence penalties) run unmetered: the VM meter is off and
    /// a failure is not charged.
    pub(crate) meter_execution: bool,
    pub(crate) charge_fees: bool,
    pub(crate) distribute_fee_rewards: bool,
    /// The zk runtime feature when chain state does not set it (the
    /// features installed on the node's driver).
    pub(crate) zk_enabled_without_state: bool,
    /// Keys contract effects may not write (the execution policy).
    pub(crate) protected_keys: Vec<String>,
}

/// How a transaction's fee is settled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FeeMode {
    /// A transaction with a submitted budget: the budget is reserved from
    /// the sender's balance before execution and a success is refunded
    /// against it (`execute_vm_transaction`).
    Reserved,
    /// A dry run (the simulator; decision 2 of the single-engine plan): no
    /// budget is reserved, so a small balance still gets an estimate, and
    /// the fee is metered from the balance the run leaves, success or
    /// failure (`reserve_fee_budget=False`, `apply_metering_on_success_only=False`).
    /// In the receipt, a fee write the run did not already make comes last.
    Estimated,
}

/// One transaction's inputs, read from its wire bytes.
pub(crate) use crate::transaction_inputs::PreparedTx;

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
    /// The chi rate the fee was priced at (`None`: no fees charged).
    pub(crate) chi_rate: Option<BigInt>,
    /// How many writes `execute_vm_transaction` reports for the transaction:
    /// a success's writes and fee refund before reward deltas; none for a
    /// failure, whose fee is metered after it.
    pub(crate) output_writes: usize,
    /// The raw cost per contract (VM and host), in contract order.
    pub(crate) contract_costs: Vec<(String, BigInt)>,
    /// Whether the transaction failed because its contract cannot run in
    /// current chain state (`ContractPreparationError`).
    pub(crate) unprepared: bool,
}

struct ViewRewardState<'a>(&'a StateView);

impl RewardState for ViewRewardState<'_> {
    fn get(&mut self, key: &str) -> Settled<Option<VmValue>> {
        self.0.get(key).map_err(fault)
    }
}

/// A contract that cannot run in current chain state: the exception
/// `_prepared_contract_failure` records for it.
struct Unprepared {
    name: &'static str,
    message: String,
    /// The import graph's preparation refused it (not a missing source).
    preparation: bool,
}

impl Unprepared {
    /// A failure before the VM that is no preparation error (an entry
    /// rejection, a submission without source).
    fn new(name: &'static str, message: String) -> Self {
        Self {
            name,
            message,
            preparation: false,
        }
    }

    /// `ContractPreparationError` (a `ValueError` in the receipt).
    fn prepare_error(message: String) -> Self {
        Self {
            preparation: true,
            ..Self::new("ValueError", message)
        }
    }
}

/// Why a contract's preparation stopped.
enum PrepareStop {
    Stop(Stop),
    Unprepared(Unprepared),
}

impl From<Stop> for PrepareStop {
    fn from(stop: Stop) -> Self {
        Self::Stop(stop)
    }
}

/// A transaction's writes after its fee, and the chi whose fee was paid.
type SettledWrites = (BTreeMap<String, VmValue>, PyDecimal);

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
    unprepared: bool,
}

impl Execution {
    /// A transaction that failed before the VM ran: `_failed_vm_result`
    /// with the exception `name(message)`.
    fn reserved(self, reservation: Option<Reservation>) -> Self {
        Self {
            reservation,
            ..self
        }
    }

    /// The failure `name(message)` in place of what the VM produced: its
    /// effects are dropped, its chi and costs stay.
    fn refused(self, name: &str, message: &str) -> Self {
        Self {
            chi_used: self.chi_used,
            contract_costs: self.contract_costs,
            ..Self::failed(self.reservation, name, message)
        }
    }

    fn failed(reservation: Option<Reservation>, name: &str, message: &str) -> Self {
        Self {
            reservation,
            status: 1,
            result: VmValue::String(message.to_owned()),
            exception: Some(VmException {
                name: name.to_owned(),
                args: vec![VmValue::String(message.to_owned())],
            }),
            writes: BTreeMap::new(),
            events: Vec::new(),
            chi_used: BigInt::zero(),
            contract_costs: Vec::new(),
            unprepared: false,
        }
    }

    /// A contract that cannot run: failed before the VM.
    fn unprepared(reservation: Option<Reservation>, unprepared: Unprepared) -> Self {
        Self {
            unprepared: unprepared.preparation,
            ..Self::failed(reservation, unprepared.name, &unprepared.message)
        }
    }
}

pub(crate) struct BlockExecutor {
    view: StateView,
    policy: BlockPolicy,
    fee_mode: FeeMode,
    modules: Modules,
}

impl BlockExecutor {
    /// The executor of a block's transactions: fees are reserved.
    pub(crate) fn new(view: StateView, policy: BlockPolicy) -> Self {
        Self::settling(view, policy, FeeMode::Reserved)
    }

    /// An executor that settles fees as `fee_mode` says.
    pub(crate) fn settling(view: StateView, policy: BlockPolicy, fee_mode: FeeMode) -> Self {
        Self {
            view,
            policy,
            fee_mode,
            modules: Modules::default(),
        }
    }

    /// Start a run: the node may have changed state since the last.
    pub(crate) fn begin_run(&self) {
        self.modules.clear();
    }

    fn ir(&self, name: &str) -> Settled<Ir> {
        self.modules.ir(&self.view, name).map_err(fault)
    }

    fn get(&self, key: &str) -> Settled<Option<VmValue>> {
        self.view.get(key).map_err(fault)
    }

    fn stage(&self, key: &str, value: Option<&VmValue>) -> Settled<()> {
        self.stage_all(&[(key.to_owned(), value.cloned().unwrap_or(VmValue::None))])
    }

    /// Validate and encode every write, then write them all (`apply_writes`).
    fn stage_all(&self, writes: &[(String, VmValue)]) -> Settled<()> {
        let mut encoded = Vec::with_capacity(writes.len());
        for (key, value) in writes {
            // Every staged key and value was checked before (the balance
            // key, `validated`, `tx_rewards`): a refusal here is a bug.
            if let Some(error) = storage_key_error(key) {
                return Err(fault(error));
            }
            let stored = match value {
                VmValue::None => None,
                value => Some(Arc::<[u8]>::from(
                    encode_stored_value(value).map_err(|error| fault(error.to_string()))?,
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
        let rate = self.chi_rate()?;
        // Admission takes only 64-hex senders: the key is always storable.
        let balance_key = format!("currency.balances:{}", tx.sender);
        let execution =
            self.discarding(|| self.execute_in_scope(tx, rate.as_ref(), &balance_key))?;
        let execution = self.charge_failure(self.validated(execution), tx);
        self.settle(tx, execution, rate.as_ref(), &balance_key)
    }

    /// The chain's chi rate when the policy charges fees.
    fn chi_rate(&self) -> Settled<Option<BigInt>> {
        if !self.policy.charge_fees {
            return Ok(None);
        }
        Ok(Some(chain_chi_rate(self.get(CHI_RATE_KEY)?)?))
    }

    /// `run` inside the overlay's discarding scope: what it stages (the
    /// reservation) is undone before settlement.
    fn discarding<T>(&self, run: impl FnOnce() -> Settled<T>) -> Settled<T> {
        lock(self.view.overlay())
            .begin_discarding()
            .map_err(|error| fault(error.to_string()))?;
        let result = run();
        lock(self.view.overlay())
            .discard()
            .map_err(|error| fault(error.to_string()))?;
        result
    }

    /// `_charge_failure`: a failed metered transaction is charged at least
    /// the base chi and at most its budget; unmetered execution is not.
    fn charge_failure(&self, mut execution: Execution, tx: &PreparedTx) -> Execution {
        if execution.status != 0 && self.policy.meter_execution {
            execution.chi_used = settlement::failed_transaction_chi(
                &execution.chi_used,
                &tx.chi_budget,
                TRANSACTION_BASE_CHI,
            );
        }
        execution
    }

    /// Reservation, preparation and VM execution, inside the discarding scope.
    fn execute_in_scope(
        &self,
        tx: &PreparedTx,
        rate: Option<&BigInt>,
        balance_key: &str,
    ) -> Settled<Execution> {
        let rate = rate.filter(|_| self.fee_mode == FeeMode::Reserved);
        let reservation = match self.reservation(tx, rate, balance_key)? {
            Ok(reservation) => reservation,
            Err(unpaid) => return Ok(unpaid),
        };
        let (entry, context) = match self.entry_call(tx)? {
            Ok(call) => call,
            Err(refused) => return Ok(refused.reserved(reservation)),
        };
        // The raw budget is a u64: a larger one is a failure in the host
        // runtime.
        let Some(budget_raw) = chi_budget_raw(&tx.chi_budget) else {
            return Ok(Execution::failed(reservation, "RuntimeError", HOST_FAILURE));
        };
        let (outcome, host_writes) = self.run_vm(tx, entry, context, budget_raw)?;
        Ok(execution_of(outcome, host_writes, reservation))
    }

    /// The entry module and its call's context, or the failure of a
    /// transaction whose entry cannot run (before its reservation is set).
    fn entry_call(
        &self,
        tx: &PreparedTx,
    ) -> Settled<Result<(ValidatedModuleIr, VmExecutionContext), Execution>> {
        let entry = match self.entry(tx)? {
            Ok(entry) => entry,
            Err(refused) => return Ok(Err(Execution::unprepared(None, refused))),
        };
        Ok(match self.entry_context(tx, &entry)? {
            Ok(context) => Ok((entry, context)),
            // `_rejected_entry` reports the base chi, metered or not.
            Err(refused) => Err(Execution {
                chi_used: BigInt::from(TRANSACTION_BASE_CHI),
                ..Execution::unprepared(None, refused)
            }),
        })
    }

    /// The prepared entry module, or why the transaction fails without
    /// running: a contract the chain does not let run, or a submission
    /// without source code.
    fn entry(&self, tx: &PreparedTx) -> Settled<Result<ValidatedModuleIr, Unprepared>> {
        let entry = self.prepare(&tx.contract)?;
        if entry.is_ok() && missing_source(tx) {
            return Ok(Err(Unprepared {
                name: "ValueError",
                message: MISSING_SOURCE.to_owned(),
                preparation: false,
            }));
        }
        Ok(entry)
    }

    /// The reservation of a charged transaction (`None` without fees), or
    /// its failure when the sender cannot pay the budget.
    fn reservation(
        &self,
        tx: &PreparedTx,
        rate: Option<&BigInt>,
        balance_key: &str,
    ) -> Settled<Result<Option<Reservation>, Execution>> {
        let Some(rate) = rate else {
            return Ok(Ok(None));
        };
        Ok(match self.reserve(tx, rate, balance_key)? {
            Ok(Some(reservation)) => Ok(Some(reservation)),
            Ok(None) => Err(Execution::failed(
                None,
                "AssertionError",
                INSUFFICIENT_BALANCE,
            )),
            Err(InvalidBalance) => Err(Execution::failed(None, "AssertionError", INVALID_BALANCE)),
        })
    }

    /// `_reserve_vm_fee_budget`: the budget reserved from the sender's
    /// balance and the spendable rest staged; `None` when it cannot pay.
    fn reserve(
        &self,
        tx: &PreparedTx,
        rate: &BigInt,
        balance_key: &str,
    ) -> Settled<Result<Option<Reservation>, InvalidBalance>> {
        let reservation = Balance::of(self.get(balance_key)?.as_ref())
            .and_then(|balance| settlement::reserve(&balance, &tx.chi_budget, rate));
        let Ok(Some(reservation)) = reservation else {
            return Ok(reservation);
        };
        self.stage(
            balance_key,
            Some(&VmValue::Decimal(reservation.spendable.clone())),
        )?;
        Ok(Ok(Some(reservation)))
    }

    /// The execution context of an entry call that passes the entry checks.
    fn entry_context(
        &self,
        tx: &PreparedTx,
        entry: &ValidatedModuleIr,
    ) -> Settled<Result<VmExecutionContext, Unprepared>> {
        // The entry module must load.
        self.ir(&tx.contract)?;
        // The entry checks: only the owner may call an owned
        // contract (an empty owner too, and an owner that is not a string
        // no caller is), and only exported functions.
        let owner = match self.get(&format!("{}.{OWNER_KEY}", tx.contract))? {
            None | Some(VmValue::None) => None,
            Some(VmValue::String(owner))
                if Some(owner.as_str()) == tx.context.caller.as_deref() =>
            {
                Some(owner)
            }
            Some(_) => return Ok(Err(Unprepared::new("Exception", NOT_OWNER.to_owned()))),
        };
        if !exports(entry, &tx.function) {
            let message = format!(
                "Function '{}' is not exported by contract '{}'.",
                tx.function, tx.contract
            );
            return Ok(Err(Unprepared::new("RuntimeError", message)));
        }
        let mut context = tx.context.clone();
        // Driver.get_owner: an empty owner is no owner.
        context.owner = owner.filter(|owner| !owner.is_empty());
        Ok(Ok(context))
    }

    /// `_prepare_vm_contract_bundle`: the import graph of `contract` must
    /// be acyclic and every module in it runnable; returns the entry module,
    /// or why the chain does not let the contract run.
    fn prepare(&self, contract: &str) -> Settled<Result<ValidatedModuleIr, Unprepared>> {
        let mut prepared = BTreeMap::new();
        match self.prepare_module(contract, &mut Vec::new(), &mut prepared) {
            Ok(()) => {
                let entry = prepared
                    .remove(contract)
                    .expect("the entry module was prepared");
                Ok(validate_bundle_module(&entry, contract, XIAN_VM_V2_PROFILE)
                    .map(|()| entry)
                    .map_err(|_| invalid_ir(contract)))
            }
            Err(PrepareStop::Unprepared(unprepared)) => Ok(Err(unprepared)),
            Err(PrepareStop::Stop(stop)) => Err(stop),
        }
    }

    fn prepare_module(
        &self,
        name: &str,
        stack: &mut Vec<String>,
        prepared: &mut BTreeMap<String, ValidatedModuleIr>,
    ) -> Result<(), PrepareStop> {
        if stack.iter().any(|entry| entry == name) {
            let path = [stack.as_slice(), &[name.to_owned()]].concat().join(" -> ");
            return Err(PrepareStop::Unprepared(Unprepared::prepare_error(format!(
                "xian_vm_v2 import graph contains a cycle: {path}"
            ))));
        }
        if prepared.contains_key(name) {
            return Ok(());
        }
        let Ir::Text(cached) = self.ir(name)? else {
            return Err(PrepareStop::Unprepared(Unprepared::prepare_error(
                missing_ir(name),
            )));
        };
        let module =
            runnable(name, &cached).ok_or_else(|| PrepareStop::Unprepared(invalid_ir(name)))?;
        if uses_zk(&module) {
            self.require_zk(name)?;
        }
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

    /// `_reject_disabled_zk_feature` for `name`, which uses zk host
    /// syscalls: a disabled feature is a `ContractPreparationError`, a value
    /// the feature check refuses a failure in the host runtime.
    fn require_zk(&self, name: &str) -> Result<(), PrepareStop> {
        let unprepared = |name, message| {
            Err(PrepareStop::Unprepared(Unprepared {
                name,
                message,
                preparation: true,
            }))
        };
        match zk_enabled(&self.view, self.policy.zk_enabled_without_state).map_err(fault)? {
            Ok(true) => Ok(()),
            Ok(false) => unprepared("ValueError", zk_disabled(name)),
            Err(Unread) => unprepared("RuntimeError", HOST_FAILURE.to_owned()),
        }
    }

    fn run_vm(
        &self,
        tx: &PreparedTx,
        entry: ValidatedModuleIr,
        context: VmExecutionContext,
        budget_raw: u64,
    ) -> Settled<(ExecutionOutcome, HostWrites)> {
        // `execute_bundle` runs the whole bundle in its profile's semantics,
        // the charge for the entry's result included.
        let _scope = numeric_v2::Scope::enter(XIAN_VM_V2_PROFILE);
        let budget = VmBudget::new(budget_raw, XIAN_VM_V2_PROFILE);
        let limit = budget.limit();
        let charges = HostCharges::new(budget.clone(), self.policy.meter_execution, &tx.contract);
        let inputs = TxInputs {
            context: context.clone(),
            zk_enabled_without_state: self.policy.zk_enabled_without_state,
        };
        let host = BlockHost::new(self.view.clone(), &self.modules, charges, inputs);
        let bundle = HashMap::from([(tx.contract.clone(), entry)]);
        let config = VmMeterConfig {
            enabled: self.policy.meter_execution,
            chi_budget_raw: budget_raw,
            transaction_size_bytes: tx.size_bytes,
        };
        let mut executor =
            BundleExecutor::with_modules(host, bundle, config, Some(budget), XIAN_VM_V2_PROFILE);
        let mut outcome = executor.execute_entry(
            &tx.contract,
            &tx.function,
            Vec::new(),
            tx.kwargs.clone(),
            context,
        );
        let (host_writes, charges) = executor.host.finish()?;
        add_host_charges(&mut outcome.stats, &charges, limit);
        Ok((outcome, host_writes))
    }

    /// Fee settlement, rewards and staging after the scope closed.
    fn settle(
        &self,
        tx: &PreparedTx,
        execution: Execution,
        rate: Option<&BigInt>,
        balance_key: &str,
    ) -> Settled<TxOutcome> {
        let (execution, (mut writes, paid_chi)) =
            self.settled_writes(execution, rate, balance_key)?;
        let output_writes = if execution.status == 0 {
            writes.len()
        } else {
            0
        };
        let rewards = if self.policy.distribute_fee_rewards {
            // A failed call earns no developer reward.
            Some(tx_reward_outputs(
                &mut ViewRewardState(&self.view),
                &paid_chi,
                &tx.contract,
                &execution.contract_costs,
                execution.status == 0,
            )?)
        } else {
            None
        };
        let rewards = match rewards {
            Some(rewards) => self.paid(&mut writes, rewards)?,
            None => None,
        };
        let writes = self.receipt_order(writes, &execution, balance_key);
        self.stage_all(&writes)?;
        Ok(TxOutcome {
            status: execution.status,
            result: execution.result,
            exception: execution.exception,
            writes,
            events: execution.events,
            chi_used: execution.chi_used,
            rewards,
            chi_rate: rate.cloned(),
            output_writes,
            contract_costs: execution.contract_costs,
            unprepared: execution.unprepared,
        })
    }

    /// `determine_writes_from_output`: a success's writes with its refunded
    /// fee and its chi used, or a failure's fee charge alone (nothing when
    /// no fee is charged) and the chi it paid.
    fn settled_writes(
        &self,
        execution: Execution,
        rate: Option<&BigInt>,
        balance_key: &str,
    ) -> Settled<(Execution, SettledWrites)> {
        let execution = if execution.status == 0 {
            match self.success_writes(&execution, rate, balance_key)? {
                Ok(writes) => return Ok((execution, writes)),
                // What execution left at the sender's balance cannot be
                // refunded: the transaction fails with its chi.
                Err(InvalidBalance) => execution.refused("AssertionError", INVALID_BALANCE),
            }
        } else {
            execution
        };
        let charge = match rate {
            None => None,
            // Metered from the balance before the transaction; a balance
            // that is not a number pays nothing.
            Some(rate) => Balance::of(self.get(balance_key)?.as_ref())
                .and_then(|balance| settlement::failure_charge(&balance, &execution.chi_used, rate))
                .unwrap_or(None),
        };
        let writes = match charge {
            None => (BTreeMap::new(), PyDecimal::int(0)),
            Some(charge) => (
                BTreeMap::from([(balance_key.to_owned(), charge.balance)]),
                charge.paid_chi,
            ),
        };
        Ok((execution, writes))
    }

    /// A success's writes with its refunded fee, and its chi used.
    fn success_writes(
        &self,
        execution: &Execution,
        rate: Option<&BigInt>,
        balance_key: &str,
    ) -> Settled<Result<SettledWrites, InvalidBalance>> {
        let mut writes = execution.writes.clone();
        if let Some(rate) = rate {
            let balance = match self.fee_mode {
                FeeMode::Reserved => refunded_balance(execution, rate, balance_key).map(Some),
                FeeMode::Estimated => self.metered_balance(execution, rate, balance_key)?,
            };
            match balance {
                Ok(Some(balance)) => {
                    writes.insert(balance_key.to_owned(), balance);
                }
                Ok(None) => {}
                Err(invalid) => return Ok(Err(invalid)),
            }
        }
        Ok(Ok((writes, PyDecimal::int(execution.chi_used.clone()))))
    }

    /// The sender's balance after an estimated success: the fee metered
    /// from the balance the run left (`vm_metering_writes`); `None` when
    /// nothing was used.
    fn metered_balance(
        &self,
        execution: &Execution,
        rate: &BigInt,
        balance_key: &str,
    ) -> Settled<Result<Option<VmValue>, InvalidBalance>> {
        let balance = match execution.writes.get(balance_key) {
            Some(value) => Balance::of(Some(value)),
            None => Balance::of(self.get(balance_key)?.as_ref()),
        };
        Ok(balance
            .and_then(|balance| settlement::failure_charge(&balance, &execution.chi_used, rate))
            .map(|charge| charge.map(|charge| charge.balance)))
    }

    /// The writes in receipt order: key order, except that an estimate
    /// lists a fee write its run did not make last (the Python dictionary
    /// it reproduces gained that key after the run's writes).
    fn receipt_order(
        &self,
        mut writes: BTreeMap<String, VmValue>,
        execution: &Execution,
        balance_key: &str,
    ) -> Vec<(String, VmValue)> {
        let appended = self.fee_mode == FeeMode::Estimated
            && execution.status == 0
            && !execution.writes.contains_key(balance_key);
        let fee = appended.then(|| writes.remove_entry(balance_key)).flatten();
        writes.into_iter().chain(fee).collect()
    }

    /// The rewards a transaction pays, their deltas added to `writes`
    /// (`materialize_writes`: to the written or current balance; a missing
    /// or deleted balance is 0). A recipient whose balance is not a number
    /// voids the payout (revision 14): no rewards, the fee is burned.
    fn paid(
        &self,
        writes: &mut BTreeMap<String, VmValue>,
        rewards: TxRewards,
    ) -> Settled<Option<TxRewards>> {
        let mut credited = Vec::with_capacity(rewards.deltas.len());
        for (key, delta) in &rewards.deltas {
            let current = match writes.get(key) {
                Some(value) => Balance::of(Some(value)),
                None => Balance::of(self.view.get(key).map_err(fault)?.as_ref()),
            };
            match current.and_then(|current| current.plus(delta)) {
                Ok(balance) => credited.push((key.clone(), VmValue::Decimal(balance))),
                Err(InvalidBalance) => return Ok(None),
            }
        }
        writes.extend(credited);
        Ok(Some(rewards))
    }

    /// `_validated_vm_result`: a success whose effects write the protected
    /// execution policy, a key LMDB cannot store, or a value the stored-value
    /// encoding refuses fails with its chi. The writes and events are encoded
    /// as one document, as `validate_persistent_value((writes, events))`
    /// traverses them.
    fn validated(&self, execution: Execution) -> Execution {
        if execution.status != 0 || self.storable(&execution) {
            return execution;
        }
        execution.refused("ValueError", UNENCODABLE)
    }

    fn storable(&self, execution: &Execution) -> bool {
        let keys_ok = execution.writes.keys().all(|key| {
            !self.policy.protected_keys.contains(key) && storage_key_error(key).is_none()
        });
        let writes = VmValue::Dict(
            execution
                .writes
                .iter()
                .map(|(key, value)| (VmValue::String(key.clone()), value.clone()))
                .collect(),
        );
        let events = VmValue::List(execution.events.iter().map(event_value).collect());
        keys_ok && encode_stored_value(&VmValue::List(vec![writes, events])).is_ok()
    }
}

/// The sender's balance after a success: refunded against the reservation.
fn refunded_balance(
    execution: &Execution,
    rate: &BigInt,
    balance_key: &str,
) -> Result<VmValue, InvalidBalance> {
    let reservation = execution
        .reservation
        .as_ref()
        .expect("a charged success reserved its budget");
    let after = match execution.writes.get(balance_key) {
        Some(value) => Balance::of(Some(value))?,
        None => Balance::Fixed(reservation.spendable.clone()),
    };
    settlement::refund(reservation, &after, &execution.chi_used, rate).map(VmValue::Decimal)
}

/// An event as the receipt's event dictionary.
pub(crate) fn event_value(event: &VmEvent) -> VmValue {
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

/// `vm_requires_contract_source`: a contract submission without source
/// code (`code` missing, not a string or empty).
fn missing_source(tx: &PreparedTx) -> bool {
    tx.contract == "submission"
        && tx.function == "submit_contract"
        && !tx.kwargs.iter().any(|(name, code)| {
            name == "code" && matches!(code, VmValue::String(code) if !code.is_empty())
        })
}

/// The accounting of what the host syscalls cost: the raw cost of the VM
/// and the host makes the chi used (the base charge plus measured work,
/// within the budget), and the host's costs join the VM's per-contract costs.
fn add_host_charges(stats: &mut VmExecutionStats, charges: &HostCharges, limit: u64) {
    stats.raw_cost = stats.raw_cost.saturating_add(charges.raw_cost());
    let combined = (stats.raw_cost / 1_000 + TRANSACTION_BASE_CHI).min(limit / 1_000);
    stats.chi_used = combined.max(stats.chi_used);
    charges.add_contract_costs(&mut stats.contract_costs);
}

/// The raw budget, `max(chi_budget, 0) * 1000`.
fn chi_budget_raw(chi_budget: &BigInt) -> Option<u64> {
    let budget = if chi_budget < &BigInt::zero() {
        BigInt::zero()
    } else {
        chi_budget.clone()
    };
    u64::try_from(budget * 1_000).ok()
}

/// `_load_vm_module_ir_json`'s refusal.
fn missing_ir(name: &str) -> String {
    format!(
        "xian_vm_v2 requires persisted __xian_ir_v1__ for contract '{name}'; \
         stored source is inspection-only"
    )
}

/// A persisted IR that is not a valid xian_vm_v2 module (revision 14: one
/// text whatever the IR's defect).
fn invalid_ir(name: &str) -> Unprepared {
    Unprepared::prepare_error(format!("contract '{name}' has invalid persisted VM IR"))
}

/// The VM outcome: writes from the module
/// snapshots, then the recorded storage writes, then a success's host
/// writes, in key order; a success's host events before the VM's events.
fn execution_of(
    mut outcome: ExecutionOutcome,
    host_writes: HostWrites,
    reservation: Option<Reservation>,
) -> Execution {
    let mut writes = outcome.take_writes();
    let mut events = outcome.events;
    host_writes.settle(outcome.status_code, &mut writes, &mut events);
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
        events,
        chi_used: BigInt::from(outcome.stats.chi_used),
        contract_costs,
        unprepared: false,
    }
}
