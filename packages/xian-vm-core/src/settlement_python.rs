//! Python access to the Rust fee settlement and reward port: the node's
//! reward computation over its own state, and debug hooks the differential
//! tests drive with explicit inputs.
use super::{py_to_vm, vm_to_py};
use crate::block_state_python::PyBlockState;
use crate::lmdb_python::{LmdbStorageError, PyLmdbEnvironment};
use crate::python_decimal::PyDecimal;
use crate::settlement::{self, Balance, Paid, Settled, Stop};
use crate::state_view::StateView;
use crate::tx_rewards::{tx_reward_outputs, RewardRecord, RewardState, TxRewards};
use crate::{VmDecimal, VmValue};
use num_bigint::BigInt;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use std::collections::HashMap;

fn to_vm(value: Bound<'_, PyAny>) -> PyResult<VmValue> {
    py_to_vm(value).map_err(|error| PyValueError::new_err(error.to_string()))
}

fn int_arg(value: Bound<'_, PyAny>) -> PyResult<BigInt> {
    match to_vm(value)? {
        VmValue::Int(value) => Ok(value),
        other => Err(PyValueError::new_err(format!(
            "expected an int, got {}",
            other.type_name()
        ))),
    }
}

/// The chi whose fee is paid out: an int, or a `ContractingDecimal` (a
/// failed transaction that paid its whole balance).
fn chi_arg(value: Bound<'_, PyAny>) -> PyResult<PyDecimal> {
    match to_vm(value)? {
        VmValue::Int(value) => Ok(PyDecimal::int(value)),
        VmValue::Decimal(value) => Ok(PyDecimal::fixed(&value)),
        other => Err(PyValueError::new_err(format!(
            "expected an int or a decimal, got {}",
            other.type_name()
        ))),
    }
}

fn fixed_to_py(py: Python<'_>, value: &VmDecimal) -> PyResult<Py<PyAny>> {
    vm_to_py(py, &VmValue::Decimal(value.clone()))
}

fn credits_to_py<'py>(
    py: Python<'py>,
    credits: &[(String, VmDecimal)],
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (key, value) in credits {
        dict.set_item(key, fixed_to_py(py, value)?)?;
    }
    Ok(dict)
}

fn record_to_py<'py>(py: Python<'py>, record: &RewardRecord) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    dict.set_item("type", record.kind.name())?;
    dict.set_item("recipient_key", &record.recipient_key)?;
    dict.set_item("source_contract", &record.source_contract)?;
    dict.set_item("value", fixed_to_py(py, &record.value)?)?;
    if let Some(validator) = &record.validator_key {
        dict.set_item("validator_key", validator)?;
    }
    if let Some(delegator) = &record.delegator_key {
        dict.set_item("delegator_key", delegator)?;
    }
    Ok(dict)
}

/// `(rewards, deltas, records)` as `RewardsHandler.build_tx_reward_outputs`
/// returns them.
pub(super) fn rewards_to_py(py: Python<'_>, outputs: &TxRewards) -> PyResult<Py<PyAny>> {
    let rewards = match &outputs.rewards {
        None => py.None(),
        Some(buckets) => {
            let dict = PyDict::new(py);
            for (kind, credits) in buckets {
                dict.set_item(kind.name(), credits_to_py(py, credits)?)?;
            }
            dict.into_any().unbind()
        }
    };
    let records = PyList::empty(py);
    for record in &outputs.records {
        records.append(record_to_py(py, record)?)?;
    }
    Ok((rewards, credits_to_py(py, &outputs.deltas)?, records)
        .into_pyobject(py)?
        .into_any()
        .unbind())
}

/// A fault is raised as `LmdbStorageError`.
fn settled_to_py<T>(
    py: Python<'_>,
    outcome: Settled<T>,
    convert: impl FnOnce(Python<'_>, T) -> PyResult<Py<PyAny>>,
) -> PyResult<Py<PyAny>> {
    match outcome {
        Ok(value) => convert(py, value),
        Err(Stop::Fault(fault)) => Err(LmdbStorageError::new_err(fault)),
    }
}

/// `None` for a balance that cannot pay (`InvalidBalance`).
fn paid_to_py<T>(
    py: Python<'_>,
    outcome: Paid<T>,
    convert: impl FnOnce(Python<'_>, T) -> PyResult<Py<PyAny>>,
) -> PyResult<Py<PyAny>> {
    match outcome {
        Ok(value) => convert(py, value),
        Err(settlement::InvalidBalance) => Ok(py.None()),
    }
}

fn contract_costs(costs: Option<Bound<'_, PyDict>>) -> PyResult<Vec<(String, BigInt)>> {
    let mut costs = match costs {
        None => Vec::new(),
        Some(costs) => costs
            .iter()
            .map(|(name, cost)| Ok((name.extract::<String>()?, int_arg(cost)?)))
            .collect::<PyResult<Vec<_>>>()?,
    };
    costs.sort();
    Ok(costs)
}

struct ViewState(StateView);

impl RewardState for ViewState {
    fn get(&mut self, key: &str) -> Settled<Option<VmValue>> {
        self.0.get(key).map_err(Stop::Fault)
    }
}

/// The fee rewards of a transaction over the node's state (block overlay,
/// then LMDB).
#[pyfunction]
#[pyo3(signature = (environment, overlay, total_chi, contract, contract_costs=None, *, pay_developers=true))]
pub(super) fn tx_rewards(
    py: Python<'_>,
    environment: PyRef<'_, PyLmdbEnvironment>,
    overlay: PyRef<'_, PyBlockState>,
    total_chi: Bound<'_, PyAny>,
    contract: &str,
    contract_costs: Option<Bound<'_, PyDict>>,
    pay_developers: bool,
) -> PyResult<Py<PyAny>> {
    let total_chi = chi_arg(total_chi)?;
    let costs = self::contract_costs(contract_costs)?;
    let mut state = ViewState(StateView::new(environment.env().clone(), overlay.shared()));
    let outcome =
        py.detach(|| tx_reward_outputs(&mut state, &total_chi, contract, &costs, pay_developers));
    settled_to_py(py, outcome, |py, outputs| rewards_to_py(py, &outputs))
}

struct MapState(HashMap<String, VmValue>);

impl RewardState for MapState {
    fn get(&mut self, key: &str) -> Settled<Option<VmValue>> {
        Ok(self.0.get(key).cloned())
    }
}

/// `tx_rewards` over a `{key: value}` state, for differential tests.
#[pyfunction]
#[pyo3(signature = (state, total_chi, contract, contract_costs=None, *, pay_developers=true))]
pub(super) fn _tx_rewards_debug(
    py: Python<'_>,
    state: Bound<'_, PyDict>,
    total_chi: Bound<'_, PyAny>,
    contract: &str,
    contract_costs: Option<Bound<'_, PyDict>>,
    pay_developers: bool,
) -> PyResult<Py<PyAny>> {
    let mut values = HashMap::new();
    for (key, value) in state.iter() {
        values.insert(key.extract::<String>()?, to_vm(value)?);
    }
    let total_chi = chi_arg(total_chi)?;
    let costs = self::contract_costs(contract_costs)?;
    let outcome = tx_reward_outputs(
        &mut MapState(values),
        &total_chi,
        contract,
        &costs,
        pay_developers,
    );
    settled_to_py(py, outcome, |py, outputs| rewards_to_py(py, &outputs))
}

fn tuple_to_py(py: Python<'_>, items: Vec<Py<PyAny>>) -> PyResult<Py<PyAny>> {
    Ok(pyo3::types::PyTuple::new(py, items)?.into_any().unbind())
}

/// `_reserve_vm_fee_budget`, for differential tests: `(amount, spendable)`,
/// `("insufficient",)`, or `None` for a balance that cannot pay.
#[pyfunction]
pub(super) fn _fee_reserve_debug(
    py: Python<'_>,
    balance: Bound<'_, PyAny>,
    budget: Bound<'_, PyAny>,
    rate: Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    let balance = to_vm(balance)?;
    let (budget, rate) = (int_arg(budget)?, int_arg(rate)?);
    let outcome = Balance::of(Some(&balance))
        .and_then(|balance| settlement::reserve(&balance, &budget, &rate));
    paid_to_py(
        py,
        outcome,
        |py, reservation: Option<settlement::Reservation>| match reservation {
            None => tuple_to_py(
                py,
                vec!["insufficient".into_pyobject(py)?.into_any().unbind()],
            ),
            Some(reservation) => tuple_to_py(
                py,
                vec![
                    fixed_to_py(py, &reservation.amount)?,
                    fixed_to_py(py, &reservation.spendable)?,
                ],
            ),
        },
    )
}

/// `_VmFeeReservation.refund_writes`, for differential tests: the refunded
/// balance, or `None` for a balance that cannot pay. `written` is what execution left at
/// the balance key; without `has_written` the spendable balance is used.
#[pyfunction]
#[pyo3(signature = (amount, spendable, chi_used, rate, written=None, has_written=false))]
pub(super) fn _fee_refund_debug(
    py: Python<'_>,
    amount: Bound<'_, PyAny>,
    spendable: Bound<'_, PyAny>,
    chi_used: Bound<'_, PyAny>,
    rate: Bound<'_, PyAny>,
    written: Option<Bound<'_, PyAny>>,
    has_written: bool,
) -> PyResult<Py<PyAny>> {
    let fixed = |value| match to_vm(value)? {
        VmValue::Decimal(value) => Ok(value),
        other => Err(PyValueError::new_err(format!(
            "expected a decimal, got {}",
            other.type_name()
        ))),
    };
    let reservation = settlement::Reservation {
        amount: fixed(amount)?,
        spendable: fixed(spendable)?,
    };
    let (chi_used, rate) = (int_arg(chi_used)?, int_arg(rate)?);
    let after = match written {
        Some(value) if has_written => Some(to_vm(value)?),
        _ if has_written => Some(VmValue::None),
        _ => Some(VmValue::Decimal(reservation.spendable.clone())),
    };
    let outcome = Balance::of(after.as_ref())
        .and_then(|after| settlement::refund(&reservation, &after, &chi_used, &rate));
    paid_to_py(py, outcome, |py, value| fixed_to_py(py, &value))
}

/// `vm_failure_charge`, for differential tests: `("write", balance, paid
/// chi as decimal text)`, `("unchanged",)`, or `None` for a balance that
/// cannot pay.
#[pyfunction]
pub(super) fn _fee_metered_debug(
    py: Python<'_>,
    balance: Bound<'_, PyAny>,
    chi_used: Bound<'_, PyAny>,
    rate: Bound<'_, PyAny>,
) -> PyResult<Py<PyAny>> {
    let balance = to_vm(balance)?;
    let (chi_used, rate) = (int_arg(chi_used)?, int_arg(rate)?);
    let outcome = Balance::of(Some(&balance))
        .and_then(|balance| settlement::failure_charge(&balance, &chi_used, &rate));
    paid_to_py(
        py,
        outcome,
        |py, charge: Option<settlement::FailureCharge>| match charge {
            None => tuple_to_py(py, vec!["unchanged".into_pyobject(py)?.into_any().unbind()]),
            Some(charge) => tuple_to_py(
                py,
                vec![
                    "write".into_pyobject(py)?.into_any().unbind(),
                    vm_to_py(py, &charge.balance)?,
                    charge
                        .paid_chi
                        .to_string()
                        .into_pyobject(py)?
                        .into_any()
                        .unbind(),
                ],
            ),
        },
    )
}

pub(super) fn register(module: &Bound<'_, pyo3::types::PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(tx_rewards, module)?)?;
    module.add_function(wrap_pyfunction!(_tx_rewards_debug, module)?)?;
    module.add_function(wrap_pyfunction!(_fee_reserve_debug, module)?)?;
    module.add_function(wrap_pyfunction!(_fee_refund_debug, module)?)?;
    module.add_function(wrap_pyfunction!(_fee_metered_debug, module)?)?;
    Ok(())
}
