//! What a transaction's host syscalls cost.
//!
//! The raw cost is recorded beside the VM's own (`extra_raw_cost`) and
//! attributed to the transaction's entry contract (`extra_contract_costs`);
//! metered execution also charges it to the budget the VM charges, so the
//! host can run a transaction out of chi. Unmetered execution charges no
//! host writes.
use crate::{VmBudget, VmExecutionError};
use std::collections::HashMap;

/// `contracting.constants.WRITE_COST_PER_BYTE`: the raw cost of one encoded
/// byte (key and value) a host syscall writes. Host writes have no write cap
/// and do not count towards the VM meter's written bytes.
pub(crate) const HOST_WRITE_COST_PER_BYTE: u64 = 25;

/// A host failure, reported as `VmRuntimeExecutionError`.
pub(crate) fn host_runtime_error(message: impl std::fmt::Display) -> VmExecutionError {
    VmExecutionError::new(format!("VmRuntimeExecutionError: {message}"))
}

#[derive(Debug)]
pub(crate) struct HostCharges {
    budget: VmBudget,
    metered: bool,
    entry: String,
    raw_cost: u64,
    contract_costs: HashMap<String, u64>,
}

impl HostCharges {
    /// The charges of a transaction to `entry` that shares `budget` with
    /// its VM execution.
    pub(crate) fn new(budget: VmBudget, metered: bool, entry: &str) -> Self {
        Self {
            budget,
            metered,
            entry: entry.to_owned(),
            raw_cost: 0,
            contract_costs: HashMap::new(),
        }
    }

    pub(crate) fn metered(&self) -> bool {
        self.metered
    }

    /// The budget the transaction's executions share.
    pub(crate) fn budget(&self) -> VmBudget {
        self.budget.clone()
    }

    /// `_record_raw_cost`: record `raw_cost` for the entry contract and, when
    /// metered, charge it to the shared budget (recorded even when the
    /// budget refuses it).
    pub(crate) fn record(&mut self, raw_cost: u64) -> Result<(), VmExecutionError> {
        if raw_cost == 0 {
            return Ok(());
        }
        self.raw_cost = self.raw_cost.saturating_add(raw_cost);
        let attributed = self.contract_costs.entry(self.entry.clone()).or_insert(0);
        *attributed = attributed.saturating_add(raw_cost);
        if self.metered {
            self.budget.charge(raw_cost).map_err(host_runtime_error)?;
        }
        Ok(())
    }

    /// `_add_raw_cost`: raw cost already charged to the budget (a nested
    /// execution's), recorded without attribution.
    pub(crate) fn add_raw(&mut self, raw_cost: u64) {
        self.raw_cost = self.raw_cost.saturating_add(raw_cost);
    }

    /// `_merge_contract_costs` of a nested execution's per-contract costs
    /// into the recorded ones.
    pub(crate) fn add_costs(&mut self, costs: &HashMap<String, u64>) {
        merge_costs(&mut self.contract_costs, costs);
    }

    /// The recorded raw cost (`extra_raw_cost`).
    pub(crate) fn raw_cost(&self) -> u64 {
        self.raw_cost
    }

    /// `_merge_contract_costs`: the recorded costs added to the VM's.
    pub(crate) fn add_contract_costs(&self, costs: &mut HashMap<String, u64>) {
        merge_costs(costs, &self.contract_costs);
    }
}

fn merge_costs(into: &mut HashMap<String, u64>, costs: &HashMap<String, u64>) {
    for (contract, raw_cost) in costs {
        let total = into.entry(contract.clone()).or_insert(0);
        *total = total.saturating_add(*raw_cost);
    }
}
