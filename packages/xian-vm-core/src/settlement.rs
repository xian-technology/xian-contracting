//! Fee reservation, refunds and metering of a transaction, as
//! `xian.execution_engine` and `xian.processor` compute them in Python.
//!
//! Balances and amounts are `ContractingDecimal` values (30 fractional
//! digits; division truncates toward zero; 91 digits at most). Anything the
//! Python code would raise on, or an input this port does not cover, stops
//! with `Stop::Handback` so the Python path decides it.
use crate::python_decimal::{DecimalSignal, PyDecimal};
use crate::{VmDecimal, VmValue};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};

/// Why the Rust path stops on a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// Left to the Python path, which reproduces the reference behaviour
    /// (including the cases where it raises).
    Handback(String),
    /// A host fault (unreadable state): the node halts, as on the Python path.
    Fault(String),
}

impl From<DecimalSignal> for Stop {
    fn from(signal: DecimalSignal) -> Self {
        Stop::Handback(signal.0)
    }
}

pub(crate) type Settled<T> = Result<T, Stop>;

pub(crate) fn handback<T>(reason: impl Into<String>) -> Settled<T> {
    Err(Stop::Handback(reason.into()))
}

/// A `ContractingDecimal` result; out of range (Python raises) is left to Python.
pub(crate) fn checked(value: Result<VmDecimal, crate::VmExecutionError>) -> Settled<VmDecimal> {
    value.map_err(|error| Stop::Handback(error.to_string()))
}

/// `left + right` of two `ContractingDecimal` values.
pub(crate) fn checked_add(left: &VmDecimal, right: &VmDecimal) -> Settled<VmDecimal> {
    checked(left.add(right))
}

/// `ContractingDecimal(n)`.
pub(crate) fn fixed_int(value: &BigInt) -> Settled<VmDecimal> {
    checked(VmDecimal::from_scaled(value * scale()))
}

fn scale() -> BigInt {
    BigInt::from(10u8).pow(30)
}

/// `ContractingDecimal(chi) / ContractingDecimal(rate)`: chi priced in tokens.
pub(crate) fn chi_to_tokens(chi: &BigInt, rate: &BigInt) -> Settled<VmDecimal> {
    let rate = fixed_int(rate)?;
    if rate.is_zero() {
        return handback("division by zero");
    }
    checked(fixed_int(chi)?.div(&rate))
}

/// A balance as `_coerce_balance_value` returns it: a missing balance is the
/// integer 0; other value types are left to Python.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Balance {
    Int(BigInt),
    Fixed(VmDecimal),
}

impl Balance {
    pub(crate) fn of(value: Option<&VmValue>) -> Settled<Self> {
        match value {
            None | Some(VmValue::None) => Ok(Self::Int(BigInt::zero())),
            Some(VmValue::Int(value)) => Ok(Self::Int(value.clone())),
            Some(VmValue::Decimal(value)) => Ok(Self::Fixed(value.clone())),
            Some(other) => handback(format!("{} balance", other.type_name())),
        }
    }

    /// The balance as a `ContractingDecimal` operand (`_coerce_scaled`).
    fn fixed(&self) -> Settled<VmDecimal> {
        match self {
            Self::Int(value) => fixed_int(value),
            Self::Fixed(value) => Ok(value.clone()),
        }
    }

    /// `self + amount` (an integer balance takes `ContractingDecimal.__radd__`).
    pub(crate) fn plus(&self, amount: &VmDecimal) -> Settled<VmDecimal> {
        checked(self.fixed()?.add(amount))
    }

    /// `self - amount`.
    pub(crate) fn minus(&self, amount: &VmDecimal) -> Settled<VmDecimal> {
        checked(self.fixed()?.sub(amount))
    }

    /// The exact value as a fraction with denominator 10**30.
    fn scaled(&self) -> BigInt {
        match self {
            Self::Int(value) => value * scale(),
            Self::Fixed(value) => value.scaled.clone(),
        }
    }
}

/// A fee budget reserved from the sender's balance before execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reservation {
    pub(crate) amount: VmDecimal,
    pub(crate) spendable: VmDecimal,
}

/// `_reserve_vm_fee_budget`: `None` when the balance cannot pay `budget` chi
/// at `rate` chi per token (compared exactly, before any truncation).
pub(crate) fn reserve(
    balance: &Balance,
    budget: &BigInt,
    rate: &BigInt,
) -> Settled<Option<Reservation>> {
    if !rate.is_positive() {
        return handback("chi rate is not positive");
    }
    if !budget.is_positive() || balance.scaled() * rate < budget * scale() {
        return Ok(None);
    }
    let amount = chi_to_tokens(budget, rate)?;
    let spendable = balance.minus(&amount)?;
    Ok(Some(Reservation { amount, spendable }))
}

/// `_VmFeeReservation.refund_writes`: the sender's balance after a
/// successful transaction (`balance` is what execution left, or the
/// spendable balance) once `chi_used` is charged against the reservation.
pub(crate) fn refund(
    reservation: &Reservation,
    balance: &Balance,
    chi_used: &BigInt,
    rate: &BigInt,
) -> Settled<VmDecimal> {
    let fee = chi_to_tokens(chi_used, rate)?;
    let unused = checked(reservation.amount.sub(&fee))?;
    balance.plus(&unused)
}

/// What a failed transaction pays for its fee.
#[derive(Clone, Debug)]
pub(crate) struct FailureCharge {
    /// The sender's balance after the fee.
    pub(crate) balance: VmValue,
    /// The chi whose fee was paid, as `decimal.Decimal`.
    pub(crate) paid_chi: PyDecimal,
}

/// `vm_failure_charge`: the fee is `chi_used / rate`; a balance that cannot
/// cover it is taken whole (the integer 0 remains) and pays its own worth
/// in chi. `None` (no write) when nothing was used.
pub(crate) fn failure_charge(
    balance: &Balance,
    chi_used: &BigInt,
    rate: &BigInt,
) -> Settled<Option<FailureCharge>> {
    if !chi_used.is_positive() {
        return Ok(None);
    }
    let remaining = balance.minus(&chi_to_tokens(chi_used, rate)?)?;
    Ok(Some(if remaining.scaled.is_negative() {
        FailureCharge {
            balance: VmValue::Int(BigInt::zero()),
            paid_chi: whole_balance_chi(balance, rate)?,
        }
    } else {
        FailureCharge {
            balance: VmValue::Decimal(remaining),
            paid_chi: PyDecimal::int(chi_used.clone()),
        }
    }))
}

/// `max(balance, 0) * rate`: a whole balance priced in chi (an integer
/// balance stays an integer).
fn whole_balance_chi(balance: &Balance, rate: &BigInt) -> Settled<PyDecimal> {
    Ok(match balance {
        _ if !balance.scaled().is_positive() => PyDecimal::int(0),
        Balance::Int(value) => PyDecimal::int(value * rate),
        Balance::Fixed(value) => PyDecimal::fixed(&checked(value.mul(&fixed_int(rate)?))?),
    })
}

/// `failed_transaction_chi`: chi charged for a failed metered transaction,
/// at least the base charge and at most the budget.
pub(crate) fn failed_transaction_chi(chi_used: &BigInt, budget: &BigInt, base: u64) -> BigInt {
    let floor = chi_used.max(&BigInt::from(base)).clone();
    floor.min(budget.max(&BigInt::zero()).clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(text: &str) -> VmDecimal {
        VmDecimal::from_str_literal(text).unwrap()
    }

    #[test]
    fn reservation_compares_exactly_and_truncates_the_amount() {
        let rate = BigInt::from(3);
        let enough = Balance::Fixed(fixed("33.333333333333333333333333333334"));
        let reservation = reserve(&enough, &BigInt::from(100), &rate)
            .unwrap()
            .unwrap();
        assert_eq!(
            reservation.amount.to_string(),
            "33.333333333333333333333333333333"
        );
        assert_eq!(
            reservation.spendable.to_string(),
            "0.000000000000000000000000000001"
        );
        let short = Balance::Fixed(fixed("33.333333333333333333333333333333"));
        assert_eq!(reserve(&short, &BigInt::from(100), &rate).unwrap(), None);
        assert_eq!(
            reserve(&Balance::Int(BigInt::zero()), &BigInt::from(1), &rate).unwrap(),
            None
        );
        assert_eq!(
            reserve(&Balance::Int(BigInt::from(5)), &BigInt::zero(), &rate).unwrap(),
            None
        );
    }

    #[test]
    fn refund_charges_against_the_reserved_amount() {
        let rate = BigInt::from(20);
        let reservation = reserve(&Balance::Int(BigInt::from(10)), &BigInt::from(100), &rate)
            .unwrap()
            .unwrap();
        assert_eq!(reservation.spendable.to_string(), "5");
        let balance = Balance::Fixed(reservation.spendable.clone());
        let refunded = refund(&reservation, &balance, &BigInt::from(213), &rate).unwrap();
        assert_eq!(refunded.to_string(), "-0.65");
    }

    fn charge(balance: Balance, chi_used: i64) -> Option<(VmValue, String)> {
        failure_charge(&balance, &BigInt::from(chi_used), &BigInt::from(20))
            .unwrap()
            .map(|charge| (charge.balance, charge.paid_chi.to_string()))
    }

    #[test]
    fn metering_floors_at_integer_zero() {
        let int = |value: i64| Balance::Int(BigInt::from(value));
        assert_eq!(charge(int(1), 40).unwrap().0, VmValue::Int(BigInt::zero()));
        assert_eq!(
            charge(int(2), 40).unwrap().0,
            VmValue::Decimal(VmDecimal::zero())
        );
        assert_eq!(charge(int(2), 0), None);
    }

    #[test]
    fn a_failure_pays_its_chi_or_its_whole_balance_in_chi() {
        let int = |value: i64| Balance::Int(BigInt::from(value));
        // Covered (exactly, too): the fee of chi_used is paid.
        assert_eq!(charge(int(3), 40).unwrap().1, "40");
        assert_eq!(charge(int(2), 40).unwrap().1, "40");
        // Not covered: the whole balance, priced in chi at the rate.
        assert_eq!(charge(int(1), 40).unwrap().1, "20");
        assert_eq!(
            charge(Balance::Fixed(fixed("0.0003")), 5).unwrap().1,
            "0.006"
        );
        assert_eq!(
            charge(Balance::Fixed(fixed("0.123456789012345678901234567891")), 5)
                .unwrap()
                .1,
            "2.46913578024691357802469135782"
        );
        // Nothing to take.
        assert_eq!(charge(int(0), 40).unwrap().1, "0");
        assert_eq!(charge(Balance::Fixed(fixed("-1")), 40).unwrap().1, "0");
    }

    #[test]
    fn other_balance_types_are_left_to_python() {
        assert!(matches!(
            Balance::of(Some(&VmValue::String("5".into()))),
            Err(Stop::Handback(_))
        ));
        assert!(matches!(
            Balance::of(Some(&VmValue::Bool(true))),
            Err(Stop::Handback(_))
        ));
        assert_eq!(Balance::of(None).unwrap(), Balance::Int(BigInt::zero()));
    }

    #[test]
    fn failed_chi_is_clamped_between_base_and_budget() {
        assert_eq!(
            failed_transaction_chi(&BigInt::from(3), &BigInt::from(1000), 5),
            BigInt::from(5)
        );
        assert_eq!(
            failed_transaction_chi(&BigInt::from(3000), &BigInt::from(1000), 5),
            BigInt::from(1000)
        );
        assert_eq!(
            failed_transaction_chi(&BigInt::from(30), &BigInt::from(-1), 5),
            BigInt::zero()
        );
    }
}
