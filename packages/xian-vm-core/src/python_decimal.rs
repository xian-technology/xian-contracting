//! `decimal.Decimal` arithmetic as the node's Python fee and reward code does
//! it: CPython's default context (28 significant digits, ROUND_HALF_EVEN),
//! through the pinned libmpdec. Values are carried as their exact
//! scientific text; every result depends only on the operand values.
use crate::decimal_backend::python_calculate;
use crate::VmDecimal;
use num_bigint::BigInt;
use std::cmp::Ordering;

/// A `decimal.Decimal` value.
#[derive(Clone, Debug)]
pub(crate) struct PyDecimal(String);

/// A signal CPython would raise (InvalidOperation, DivisionByZero, Overflow),
/// a backend resource limit, or a value `ContractingDecimal` refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DecimalSignal(pub(crate) String);

type Result<T> = std::result::Result<T, DecimalSignal>;

const FIXED_SCALE: i64 = 30;
const FIXED_MAX_ADJUSTED: i64 = 61;

impl PyDecimal {
    /// `Decimal(n)`: exact.
    pub(crate) fn int(value: impl Into<BigInt>) -> Self {
        Self(value.into().to_string())
    }

    /// `Decimal(str(value))` of a `ContractingDecimal`: exact.
    pub(crate) fn fixed(value: &VmDecimal) -> Self {
        Self(value.to_string())
    }

    fn calculate(operation: &str, args: &[&str]) -> Result<Self> {
        python_calculate(operation, args)
            .map(Self)
            .map_err(|error| DecimalSignal(error.to_string()))
    }

    pub(crate) fn add(&self, other: &Self) -> Result<Self> {
        Self::calculate("add", &[&self.0, &other.0])
    }

    pub(crate) fn sub(&self, other: &Self) -> Result<Self> {
        Self::calculate("sub", &[&self.0, &other.0])
    }

    pub(crate) fn mul(&self, other: &Self) -> Result<Self> {
        Self::calculate("mul", &[&self.0, &other.0])
    }

    pub(crate) fn div(&self, other: &Self) -> Result<Self> {
        Self::calculate("div", &[&self.0, &other.0])
    }

    /// `round(self, places)`: quantize to `10**-places` in the context's
    /// rounding.
    pub(crate) fn round(&self, places: u32) -> Result<Self> {
        Self::calculate("quantize", &[&self.0, &format!("1E-{places}")])
    }

    pub(crate) fn compare(&self, other: &Self) -> Result<Ordering> {
        match Self::calculate("compare", &[&self.0, &other.0])?.0.as_str() {
            "-1" => Ok(Ordering::Less),
            "0" => Ok(Ordering::Equal),
            "1" => Ok(Ordering::Greater),
            other => Err(DecimalSignal(format!("unordered comparison {other}"))),
        }
    }

    pub(crate) fn sign(&self) -> Result<Ordering> {
        self.compare(&Self::int(0))
    }

    /// `(negative, coefficient digits without leading zeros, exponent)` of
    /// a finite value; `None` for Infinity and NaN.
    fn parts(&self) -> Option<(bool, &str, i64)> {
        let (negative, unsigned) = match self.0.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, self.0.as_str()),
        };
        let (mantissa, exponent) = match unsigned.split_once('E') {
            Some((mantissa, exponent)) => (mantissa, exponent.parse::<i64>().ok()?),
            None => (unsigned, 0),
        };
        let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let digits_only = |text: &str| text.bytes().all(|byte| byte.is_ascii_digit());
        if whole.is_empty() || !digits_only(whole) || !digits_only(fraction) {
            return None;
        }
        // libmpdec writes either a plain coefficient or one digit before the
        // point; both concatenate to the coefficient.
        let start = mantissa.len() - mantissa.trim_start_matches(['0', '.']).len();
        let digits = &mantissa[start..];
        let exponent = exponent - fraction.len() as i64;
        Some((negative, digits, exponent))
    }

    /// `ContractingDecimal(str(self))`: truncated to 30 fractional digits;
    /// a non-finite value or one of 61 or more integer digits is refused, as
    /// `xian_runtime_types.decimal._decimal_to_scaled` refuses it.
    pub(crate) fn to_fixed(&self) -> Result<VmDecimal> {
        let refused = || {
            DecimalSignal(format!(
                "Value {} exceeds the supported decimal range.",
                self.0
            ))
        };
        let (negative, digits, exponent) = self.parts().ok_or_else(refused)?;
        let digits = digits.replace('.', "");
        if digits.is_empty() {
            return Ok(VmDecimal::zero());
        }
        if exponent + digits.len() as i64 - 1 >= FIXED_MAX_ADJUSTED {
            return Err(refused());
        }
        let shift = exponent + FIXED_SCALE;
        let scaled = if shift >= 0 {
            format!("{digits}{}", "0".repeat(shift as usize))
        } else {
            let keep = digits.len() as i64 + shift;
            if keep <= 0 {
                return Ok(VmDecimal::zero());
            }
            digits[..keep as usize].to_owned()
        };
        let scaled: BigInt = scaled.parse().map_err(|_| refused())?;
        VmDecimal::from_scaled(if negative { -scaled } else { scaled }).map_err(|_| refused())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(text: &str) -> PyDecimal {
        PyDecimal(text.to_owned())
    }

    #[test]
    fn arithmetic_rounds_to_28_digits_half_even() {
        assert_eq!(
            dec("1").div(&dec("3")).unwrap().0,
            "0.3333333333333333333333333333"
        );
        assert_eq!(
            dec("2").div(&dec("3")).unwrap().0,
            "0.6666666666666666666666666667"
        );
        // 0 + x rounds x to the context, as Python's sum() does.
        let long = "0.333333333333333333333333333333";
        assert_eq!(
            dec("0").add(&dec(long)).unwrap().0,
            "0.3333333333333333333333333333"
        );
        assert_eq!(
            dec("1000000")
                .mul(&dec("3.14159265358979323846264338327"))
                .unwrap()
                .0,
            "3141592.653589793238462643383"
        );
    }

    #[test]
    fn round_is_half_even_and_refuses_too_many_digits() {
        assert_eq!(dec("0.000000025").round(8).unwrap().0, "2E-8");
        assert_eq!(dec("0.000000035").round(8).unwrap().0, "4E-8");
        assert_eq!(dec("12.5").round(8).unwrap().0, "12.50000000");
        assert!(dec("1E+20").round(8).is_err());
    }

    #[test]
    fn signals_python_traps() {
        assert!(dec("1").div(&dec("0")).is_err());
        assert!(dec("0").div(&dec("0")).is_err());
    }

    #[test]
    fn converts_to_contracting_decimal_by_truncation() {
        let fixed = |text: &str| dec(text).to_fixed().map(|value| value.to_string());
        assert_eq!(
            fixed("0.3333333333333333333333333333").unwrap(),
            "0.3333333333333333333333333333"
        );
        assert_eq!(
            fixed("-1.2345678901234567890123456789012345").unwrap(),
            "-1.234567890123456789012345678901"
        );
        assert_eq!(fixed("1.5E+3").unwrap(), "1500");
        assert_eq!(fixed("2E-8").unwrap(), "0.00000002");
        assert_eq!(fixed("1E-31").unwrap(), "0");
        assert_eq!(fixed("-0E-8").unwrap(), "0");
        assert_eq!(
            fixed(&format!("{}", "9".repeat(61))).unwrap(),
            "9".repeat(61)
        );
        assert!(fixed(&format!("1{}", "0".repeat(61))).is_err());
        assert!(fixed("Infinity").is_err());
        assert!(fixed("NaN").is_err());
    }

    #[test]
    fn compares_values() {
        assert_eq!(dec("1.0").compare(&dec("1")).unwrap(), Ordering::Equal);
        assert_eq!(dec("-3").sign().unwrap(), Ordering::Less);
        assert_eq!(
            PyDecimal::int(10_000).compare(&dec("12000")).unwrap(),
            Ordering::Less
        );
    }
}
