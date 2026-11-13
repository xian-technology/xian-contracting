//! A block's transactions executed in Rust over the block overlay.
//!
//! This is the node's per-transaction path (`xian.processor.TxProcessor.
//! process_tx` with `xian.execution_engine.execute_vm_transaction` and
//! `xian_vm_core.execute_contract`) for chain and system transactions whose contract
//! needs nothing from Python: fee reservation, contract preparation, VM
//! execution, the failure charge, refund or failure metering, fee rewards
//! and staging the writes. Every outcome is byte-identical to that path.
//!
//! A transaction the port does not cover stops with `Stop::Handback` before
//! any of its effects reach the overlay; the node then runs it through the
//! Python path, in block order. That covers contract submission
//! (`submission.submit_contract`), contracts using zk host syscalls, host
//! syscalls other than the contract metadata reads and changes (random,
//! deploy), preparation and entry rejections, and any value the Python
//! checks could refuse. The VM's host
//! (`block_host`) reads the overlay and LMDB, hash scans included. A storage
//! fault stops with `Stop::Fault`.
use crate::block_host::modules::{exports, runnable};
use crate::block_host::{fault, text, BlockHost, HostCharges, HostWrites, Ir, Modules, OWNER_KEY};
use crate::block_state::lock;
use crate::bundle_executor::{validate_bundle_module, BundleExecutor, ExecutionOutcome};
use crate::lmdb_env::storage_key_error;
use crate::metering::VM_TRANSACTION_BASE_CHI as TRANSACTION_BASE_CHI;
use crate::python_decimal::PyDecimal;
use crate::settlement::{self, handback, Balance, Reservation, Settled, Stop};
use crate::state_view::StateView;
use crate::stored_value_encoder::encode_stored_value;
use crate::tx_rewards::{chain_chi_rate, tx_reward_outputs, RewardState, TxRewards};
use crate::{
    ValidatedModuleIr, VmBudget, VmEvent, VmException, VmExecutionContext, VmExecutionStats,
    VmMeterConfig, VmValue, XIAN_VM_V2_PROFILE,
};
use num_bigint::BigInt;
use num_traits::Zero;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

const INSUFFICIENT_BALANCE: &str = "Sender does not have enough chi for the submitted budget.";

/// The chain fee policy of the block (`xian.fee_policy.TxFeePolicy`).
#[derive(Clone, Debug)]
pub(crate) struct BlockPolicy {
    /// Chain policies meter execution; system transactions (epoch
    /// rebalance, evidence penalties) run unmetered: the VM meter is off and
    /// a failure is not charged.
    pub(crate) meter_execution: bool,
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
    /// The chi rate the fee was priced at (`None`: no fees charged).
    pub(crate) chi_rate: Option<BigInt>,
    /// How many writes `execute_vm_transaction` reports for the transaction:
    /// a success's writes and fee refund before reward deltas; none for a
    /// failure, whose fee is metered after it.
    pub(crate) output_writes: usize,
}

struct ViewRewardState<'a>(&'a StateView);

impl RewardState for ViewRewardState<'_> {
    fn get(&mut self, key: &str) -> Settled<Option<VmValue>> {
        self.0.get(key).map_err(fault)
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
        self.view.get(key).map_err(fault)
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
        if tx.contract == "submission" && tx.function == "submit_contract" {
            return handback("contract submission");
        }
        let rate = self.chi_rate()?;
        let balance_key = format!("currency.balances:{}", tx.sender);
        if let Some(error) = storage_key_error(&balance_key) {
            return handback(error);
        }
        let execution =
            self.discarding(|| self.execute_in_scope(tx, rate.as_ref(), &balance_key))?;
        let execution = self.charge_failure(execution, tx);
        self.settle(tx, execution, rate.as_ref(), &balance_key)
    }

    /// The chain's chi rate when the policy charges fees.
    fn chi_rate(&self) -> Settled<Option<BigInt>> {
        if !self.policy.charge_fees {
            return Ok(None);
        }
        Ok(Some(chain_chi_rate(self.get("chi_cost.S:value")?)?))
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
        let reservation = match rate {
            None => None,
            Some(rate) => match self.reserve(tx, rate, balance_key)? {
                Some(reservation) => Some(reservation),
                None => return Ok(Execution::insufficient_balance()),
            },
        };
        let entry = self.prepare(&tx.contract)?;
        let context = self.entry_context(tx, &entry)?;
        let (outcome, host_writes) = self.run_vm(tx, entry, context)?;
        Ok(execution_of(outcome, host_writes, reservation))
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
    ) -> Settled<(ExecutionOutcome, HostWrites)> {
        let budget_raw = chi_budget_raw(&tx.chi_budget)?;
        let budget = VmBudget::new(budget_raw, XIAN_VM_V2_PROFILE);
        let limit = budget.limit();
        let charges = HostCharges::new(budget.clone(), self.policy.meter_execution, &tx.contract);
        let host = BlockHost::new(self.view.clone(), &self.modules, charges);
        validate_bundle_module(&entry, &tx.contract, XIAN_VM_V2_PROFILE)
            .map_err(|error| Stop::Handback(error.to_string()))?;
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
        let (mut writes, paid_chi) = self.settled_writes(&execution, rate, balance_key)?;
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
            chi_rate: rate.cloned(),
            output_writes,
        })
    }

    /// `determine_writes_from_output`: a success's writes with its refunded
    /// fee and its chi used, or a failure's fee charge alone (nothing when
    /// no fee is charged) and the chi it paid.
    fn settled_writes(
        &self,
        execution: &Execution,
        rate: Option<&BigInt>,
        balance_key: &str,
    ) -> Settled<(BTreeMap<String, VmValue>, PyDecimal)> {
        if execution.status == 0 {
            return self.success_writes(execution, rate, balance_key);
        }
        let charge = match rate {
            None => None,
            Some(rate) => {
                // Metered from the balance before the transaction.
                let balance = Balance::of(self.get(balance_key)?.as_ref())?;
                settlement::failure_charge(&balance, &execution.chi_used, rate)?
            }
        };
        Ok(match charge {
            None => (BTreeMap::new(), PyDecimal::int(0)),
            Some(charge) => (
                BTreeMap::from([(balance_key.to_owned(), charge.balance)]),
                charge.paid_chi,
            ),
        })
    }

    /// A success's writes with its refunded fee, and its chi used.
    fn success_writes(
        &self,
        execution: &Execution,
        rate: Option<&BigInt>,
        balance_key: &str,
    ) -> Settled<(BTreeMap<String, VmValue>, PyDecimal)> {
        self.validated(execution)?;
        let mut writes = execution.writes.clone();
        if let Some(rate) = rate {
            let balance = self.refunded_balance(execution, rate, balance_key)?;
            writes.insert(balance_key.to_owned(), balance);
        }
        Ok((writes, PyDecimal::int(execution.chi_used.clone())))
    }

    /// The sender's balance after a success: refunded against the
    /// reservation.
    fn refunded_balance(
        &self,
        execution: &Execution,
        rate: &BigInt,
        balance_key: &str,
    ) -> Settled<VmValue> {
        let reservation = execution
            .reservation
            .as_ref()
            .expect("a charged success reserved its budget");
        let after = match execution.writes.get(balance_key) {
            Some(value) => Balance::of(Some(value))?,
            None => Balance::Fixed(reservation.spendable.clone()),
        };
        let refunded = settlement::refund(reservation, &after, &execution.chi_used, rate)?;
        Ok(VmValue::Decimal(refunded))
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
                None => Balance::of(self.view.get(key).map_err(fault)?.as_ref())?,
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

/// Whether `encode_abci_json` takes `value` as it is: raw decimals and floats
/// (whose conversion can refuse) are left to Python.
fn receipt_encodable(value: &VmValue) -> bool {
    match value {
        VmValue::RawDecimal(_)
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

/// `execute_contract`'s accounting of what the host syscalls cost: the raw
/// cost of the VM and the host makes the chi used (`_combined_chi_used`: the
/// base charge plus measured work, within the budget), and the host's costs
/// join the VM's per-contract costs.
fn add_host_charges(stats: &mut VmExecutionStats, charges: &HostCharges, limit: u64) {
    stats.raw_cost = stats.raw_cost.saturating_add(charges.raw_cost());
    let combined = (stats.raw_cost / 1_000 + TRANSACTION_BASE_CHI).min(limit / 1_000);
    stats.chi_used = combined.max(stats.chi_used);
    charges.add_contract_costs(&mut stats.contract_costs);
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
/// snapshots, then the recorded storage writes, then a success's host
/// writes, in key order; a success's host events before the VM's events.
fn execution_of(
    outcome: ExecutionOutcome,
    host_writes: HostWrites,
    reservation: Option<Reservation>,
) -> Execution {
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
    }
}
