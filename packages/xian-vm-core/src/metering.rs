#![cfg_attr(not(feature = "python-extension"), allow(dead_code))]

use crate::{VmExecutionError, VmValue};
use num_traits::ToPrimitive;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const VM_READ_COST_PER_BYTE: u64 = 2;
const VM_WRITE_COST_PER_BYTE: u64 = 25;
const VM_TRANSACTION_BYTES_COST_PER_BYTE: u64 = 1;
const VM_RETURN_VALUE_COST_PER_BYTE: u64 = 1;
const VM_TRANSACTION_BASE_CHI: u64 = 5;
const VM_TRANSACTION_BASE_CHI_RAW: u64 = VM_TRANSACTION_BASE_CHI * 1_000;
const VM_MAX_RAW_CHI: u64 = 50_000_000_000;
const VM_WRITE_MAX_BYTES: usize = 1024 * 128;

pub(crate) const VM_GAS_CROSS_CONTRACT_CALL_BASE: u64 = 10_000;
pub(crate) const VM_GAS_CROSS_CONTRACT_CALL_REPEAT: u64 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmMeterConfig {
    pub enabled: bool,
    pub chi_budget_raw: u64,
    pub transaction_size_bytes: usize,
}

impl Default for VmMeterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            chi_budget_raw: 0,
            transaction_size_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmExecutionStats {
    pub raw_cost: u64,
    pub chi_used: u64,
    pub contract_costs: HashMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContractMeterFrame {
    contract: String,
    start_cost: u64,
    child_cost: u64,
}

/// One budget spans every executor and host operation in a transaction.
#[derive(Debug, Clone)]
pub(crate) struct VmBudget {
    raw_cost: Arc<AtomicU64>,
    limit: u64,
}

impl VmBudget {
    pub(crate) fn new(chi_budget_raw: u64) -> Self {
        Self {
            raw_cost: Arc::new(AtomicU64::new(0)),
            limit: match chi_budget_raw {
                0 => VM_MAX_RAW_CHI,
                budget => budget.min(VM_MAX_RAW_CHI),
            },
        }
    }

    pub(crate) fn limit(&self) -> u64 {
        self.limit
    }

    pub(crate) fn charge(&self, cost: u64) -> Result<(), VmExecutionError> {
        let previous = self
            .raw_cost
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |raw| {
                raw.checked_add(cost)
            })
            .map_err(|_| VmExecutionError::new("chi metering overflow"))?;
        if previous + cost > self.limit {
            return Err(VmExecutionError::new("Out of chi."));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VmMeter {
    enabled: bool,
    budget: VmBudget,
    transaction_size_bytes: usize,
    raw_cost: u64,
    written_bytes: usize,
    contract_meter_frames: Vec<ContractMeterFrame>,
    contract_meter_markers: Vec<bool>,
    contract_costs: HashMap<String, u64>,
}

impl VmMeter {
    pub(crate) fn new(config: VmMeterConfig) -> Self {
        let budget = VmBudget::new(config.chi_budget_raw);
        Self::with_budget(config, budget)
    }

    pub(crate) fn with_budget(config: VmMeterConfig, budget: VmBudget) -> Self {
        Self {
            enabled: config.enabled,
            budget,
            transaction_size_bytes: config.transaction_size_bytes,
            raw_cost: 0,
            written_bytes: 0,
            contract_meter_frames: Vec::new(),
            contract_meter_markers: Vec::new(),
            contract_costs: HashMap::new(),
        }
    }

    pub(crate) fn charge_transaction_bytes(&mut self) -> Result<(), VmExecutionError> {
        if !self.enabled || self.transaction_size_bytes == 0 {
            return Ok(());
        }
        self.charge(self.transaction_size_bytes as u64 * VM_TRANSACTION_BYTES_COST_PER_BYTE)
    }

    pub(crate) fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
        self.charge(cost)
    }

    pub(crate) fn charge_read(
        &mut self,
        key: &str,
        value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        if !self.enabled {
            return Ok(());
        }
        let encoded = encode_vm_value(value)?;
        let read = key.len() + encoded.len();
        self.charge((read as u64) * VM_READ_COST_PER_BYTE)
    }

    pub(crate) fn charge_write(
        &mut self,
        key: &str,
        value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        if !self.enabled {
            return Ok(());
        }
        let encoded = encode_vm_value(value)?;
        let written = key.len() + encoded.len();
        self.written_bytes = self.written_bytes.checked_add(written).ok_or_else(|| {
            VmExecutionError::new("You have exceeded the maximum write capacity per transaction!")
        })?;
        if self.written_bytes >= VM_WRITE_MAX_BYTES {
            return Err(VmExecutionError::new(
                "You have exceeded the maximum write capacity per transaction!",
            ));
        }
        self.charge((written as u64) * VM_WRITE_COST_PER_BYTE)
    }

    pub(crate) fn charge_return_value(&mut self, value: &VmValue) -> Result<(), VmExecutionError> {
        if !self.enabled {
            return Ok(());
        }
        let encoded = encode_vm_value(value)?;
        self.charge((encoded.len() as u64) * VM_RETURN_VALUE_COST_PER_BYTE)
    }

    pub(crate) fn begin_contract_metering(&mut self, contract: &str) {
        if !self.enabled {
            return;
        }
        self.contract_meter_frames = vec![ContractMeterFrame {
            contract: contract.to_owned(),
            start_cost: self.raw_cost,
            child_cost: 0,
        }];
        self.contract_meter_markers.clear();
        self.contract_costs.clear();
    }

    pub(crate) fn enter_contract_metering(&mut self, contract: &str) {
        if !self.enabled {
            return;
        }
        if self.contract_meter_frames.is_empty() {
            self.contract_meter_frames.push(ContractMeterFrame {
                contract: contract.to_owned(),
                start_cost: self.raw_cost,
                child_cost: 0,
            });
            self.contract_meter_markers.push(true);
            return;
        }

        let pushed = self
            .contract_meter_frames
            .last()
            .map(|frame| frame.contract != contract)
            .unwrap_or(true);
        if pushed {
            self.contract_meter_frames.push(ContractMeterFrame {
                contract: contract.to_owned(),
                start_cost: self.raw_cost,
                child_cost: 0,
            });
        }
        self.contract_meter_markers.push(pushed);
    }

    pub(crate) fn exit_contract_metering(&mut self) {
        if !self.enabled {
            return;
        }
        if self.contract_meter_markers.pop().unwrap_or(false) {
            self.finalize_contract_meter_frame();
        }
    }

    pub(crate) fn finalize_contracts(
        &mut self,
        fixed_overhead_contract: Option<&str>,
    ) -> HashMap<String, u64> {
        while !self.contract_meter_frames.is_empty() {
            self.finalize_contract_meter_frame();
        }
        if let Some(contract) = fixed_overhead_contract {
            *self.contract_costs.entry(contract.to_owned()).or_insert(0) +=
                VM_TRANSACTION_BASE_CHI_RAW;
        }
        let result = self.contract_costs.clone();
        self.contract_meter_markers.clear();
        self.contract_costs.clear();
        result
    }

    pub(crate) fn execution_stats(&self, contract_costs: HashMap<String, u64>) -> VmExecutionStats {
        let chi_used =
            ((self.raw_cost / 1_000) + VM_TRANSACTION_BASE_CHI).min(self.budget.limit() / 1_000);
        VmExecutionStats {
            raw_cost: self.raw_cost,
            chi_used,
            contract_costs,
        }
    }

    fn charge(&mut self, cost: u64) -> Result<(), VmExecutionError> {
        if !self.enabled || cost == 0 {
            return Ok(());
        }
        self.raw_cost = self
            .raw_cost
            .checked_add(cost)
            .ok_or_else(|| VmExecutionError::new("chi metering overflow"))?;
        self.budget.charge(cost)
    }

    fn finalize_contract_meter_frame(&mut self) {
        let Some(frame) = self.contract_meter_frames.pop() else {
            return;
        };
        let contract_total = self
            .raw_cost
            .saturating_sub(frame.start_cost)
            .saturating_sub(frame.child_cost);
        *self.contract_costs.entry(frame.contract).or_insert(0) += contract_total;
        if let Some(parent) = self.contract_meter_frames.last_mut() {
            parent.child_cost = parent.child_cost.saturating_add(contract_total);
        }
    }
}

pub(crate) fn encode_vm_value(value: &VmValue) -> Result<Vec<u8>, VmExecutionError> {
    serde_json::to_vec(&vm_value_to_json(value)?)
        .map_err(|error| VmExecutionError::new(error.to_string()))
}

fn vm_value_to_json(value: &VmValue) -> Result<Value, VmExecutionError> {
    Ok(match value {
        VmValue::None => Value::Null,
        VmValue::Bool(value) => Value::Bool(*value),
        VmValue::Int(value) => {
            if let Some(number) = value.to_i64() {
                Value::Number(number.into())
            } else {
                let mut object = Map::new();
                object.insert("__big_int__".to_owned(), Value::String(value.to_string()));
                Value::Object(object)
            }
        }
        VmValue::Float(value) => Value::Number(
            serde_json::Number::from_f64(*value)
                .ok_or_else(|| VmExecutionError::new("cannot encode non-finite float"))?,
        ),
        VmValue::Decimal(value) => {
            let mut object = Map::new();
            object.insert("__fixed__".to_owned(), Value::String(value.to_string()));
            Value::Object(object)
        }
        VmValue::DateTime(value) => {
            let mut object = Map::new();
            object.insert(
                "__time__".to_owned(),
                Value::Array(vec![
                    Value::Number(value.year().into()),
                    Value::Number(value.month().into()),
                    Value::Number(value.day().into()),
                    Value::Number(value.hour().into()),
                    Value::Number(value.minute().into()),
                    Value::Number(value.second().into()),
                    Value::Number(value.microsecond().into()),
                ]),
            );
            Value::Object(object)
        }
        VmValue::TimeDelta(value) => {
            let (days, seconds) = python_timedelta_parts(value.seconds());
            let mut object = Map::new();
            object.insert(
                "__delta__".to_owned(),
                Value::Array(vec![
                    Value::Number(days.into()),
                    Value::Number(seconds.into()),
                ]),
            );
            Value::Object(object)
        }
        VmValue::String(value) => Value::String(value.clone()),
        VmValue::Bytes(value) => {
            let mut object = Map::new();
            object.insert("__bytes__".to_owned(), Value::String(hex::encode(value)));
            Value::Object(object)
        }
        VmValue::ByteArray(value) => {
            let mut object = Map::new();
            object.insert(
                "__bytearray__".to_owned(),
                Value::String(hex::encode(value)),
            );
            Value::Object(object)
        }
        VmValue::Set(values) => {
            let mut object = Map::new();
            object.insert(
                "__set__".to_owned(),
                Value::Array(
                    values
                        .iter()
                        .map(vm_value_to_json)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            );
            Value::Object(object)
        }
        VmValue::FrozenSet(values) => {
            let mut object = Map::new();
            object.insert(
                "__frozenset__".to_owned(),
                Value::Array(
                    values
                        .iter()
                        .map(vm_value_to_json)
                        .collect::<Result<Vec<_>, _>>()?,
                ),
            );
            Value::Object(object)
        }
        VmValue::List(values) | VmValue::Tuple(values) => Value::Array(
            values
                .iter()
                .map(vm_value_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        VmValue::Dict(entries) => {
            let mut object = Map::new();
            for (key, value) in entries {
                object.insert(vm_json_object_key(key)?, vm_value_to_json(value)?);
            }
            Value::Object(object)
        }
        other => {
            return Err(VmExecutionError::new(format!(
                "unsupported metering encode value '{}'",
                other.type_name()
            )))
        }
    })
}

fn vm_json_object_key(value: &VmValue) -> Result<String, VmExecutionError> {
    Ok(match value {
        VmValue::String(value) => value.clone(),
        VmValue::Bool(value) => {
            if *value {
                "true".to_owned()
            } else {
                "false".to_owned()
            }
        }
        VmValue::None => "null".to_owned(),
        VmValue::Int(value) => value.to_string(),
        VmValue::Float(value) => value.to_string(),
        VmValue::Decimal(value) => value.to_string(),
        VmValue::DateTime(value) => value.to_string(),
        VmValue::TimeDelta(value) => value.to_string(),
        other => other.python_repr(),
    })
}

fn python_timedelta_parts(raw_seconds: i64) -> (i64, i64) {
    let days = raw_seconds.div_euclid(86_400);
    let seconds = raw_seconds.rem_euclid(86_400);
    (days, seconds)
}

#[cfg(test)]
mod tests {
    use super::{
        VmBudget, VmMeter, VmMeterConfig, VM_GAS_CROSS_CONTRACT_CALL_BASE,
        VM_GAS_CROSS_CONTRACT_CALL_REPEAT, VM_MAX_RAW_CHI, VM_TRANSACTION_BASE_CHI,
        VM_TRANSACTION_BASE_CHI_RAW,
    };

    #[test]
    fn disabled_meter_still_reports_base_chi_and_fixed_overhead() {
        let mut meter = VmMeter::new(VmMeterConfig {
            enabled: false,
            chi_budget_raw: 25_000,
            transaction_size_bytes: 0,
        });

        let contract_costs = meter.finalize_contracts(Some("currency"));
        let stats = meter.execution_stats(contract_costs.clone());

        assert_eq!(stats.raw_cost, 0);
        assert_eq!(stats.chi_used, VM_TRANSACTION_BASE_CHI);
        assert_eq!(
            contract_costs.get("currency"),
            Some(&VM_TRANSACTION_BASE_CHI_RAW)
        );
        assert_eq!(
            stats.contract_costs.get("currency"),
            Some(&VM_TRANSACTION_BASE_CHI_RAW)
        );
    }

    #[test]
    fn cross_contract_dispatch_keeps_fixed_cost_without_repeat_surcharge() {
        assert_eq!(VM_GAS_CROSS_CONTRACT_CALL_BASE, 10_000);
        assert_eq!(VM_GAS_CROSS_CONTRACT_CALL_REPEAT, 0);
    }

    #[test]
    fn zero_and_oversized_budgets_enforce_the_vm_maximum() {
        for supplied in [0, VM_MAX_RAW_CHI * 2] {
            let mut meter = VmMeter::new(VmMeterConfig {
                enabled: true,
                chi_budget_raw: supplied,
                transaction_size_bytes: 0,
            });
            assert!(meter.charge(VM_MAX_RAW_CHI).is_ok());
            assert!(meter.charge(1).is_err());
            assert_eq!(
                meter.execution_stats(Default::default()).chi_used,
                VM_MAX_RAW_CHI / 1000
            );
        }
    }

    #[test]
    fn nested_meters_and_host_costs_share_one_budget() {
        let budget = VmBudget::new(25_000);
        let config = VmMeterConfig {
            enabled: true,
            chi_budget_raw: 25_000,
            transaction_size_bytes: 0,
        };
        let mut parent = VmMeter::with_budget(config.clone(), budget.clone());
        let mut child = VmMeter::with_budget(config, budget.clone());
        parent.charge(10_000).unwrap();
        child.charge(10_000).unwrap();
        budget.charge(5_000).unwrap();
        assert!(parent.charge(1).is_err());
        assert_eq!(parent.raw_cost, 10_001);
        assert_eq!(child.raw_cost, 10_000);
    }

    #[test]
    fn budget_overflow_is_rejected() {
        let budget = VmBudget::new(0);
        assert!(budget.charge(u64::MAX).is_err());
        assert_eq!(
            budget.charge(1).unwrap_err().to_string(),
            "chi metering overflow"
        );
    }
}
