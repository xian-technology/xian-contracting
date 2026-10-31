//! Raw decimal results use the contract Decimal context (91 digits, ROUND_DOWN).
//! Quantum and signed zero are observable; ContractingDecimal remains fixed-scale.
use crate::{VmDecimal, VmExecutionError, VmValue};
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, ToPrimitive, Zero};
#[cfg(any(feature = "python-extension", test))]
use std::str::FromStr;
use std::{cmp::Ordering, fmt};

#[path = "raw_decimal_format.rs"]
mod formatting;

type Result<T> = std::result::Result<T, VmExecutionError>;
const PRECISION: i32 = 91;
const ETINY: i32 = -190;
const EMAX: i32 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmRawDecimal {
    pub(crate) coefficient: BigInt,
    pub(crate) exponent: i32,
    negative_zero: bool,
}

fn error() -> VmExecutionError {
    VmExecutionError::new("invalid decimal operation or range")
}
fn ten(power: u32) -> BigInt {
    BigInt::from(10u8).pow(power)
}
fn digits(value: &BigInt) -> i32 {
    value.abs().to_str_radix(10).len() as i32
}

impl VmRawDecimal {
    fn new(coefficient: BigInt, exponent: i32, negative: bool) -> Self {
        let negative_zero = coefficient.is_zero() && negative;
        Self {
            coefficient,
            exponent,
            negative_zero,
        }
    }

    #[cfg(any(feature = "python-extension", test))]
    pub(crate) fn parse(text: &str) -> Result<Self> {
        if text.len() > 512 {
            return Err(error());
        }
        let (mantissa, exp) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
        let exp: i32 = exp.parse().map_err(|_| error())?;
        let places = mantissa
            .split_once('.')
            .map_or(0, |(_, fraction)| fraction.len() as i32);
        let coefficient = BigInt::from_str(&mantissa.replace('.', "")).map_err(|_| error())?;
        let exponent = exp.checked_sub(places).ok_or_else(error)?;
        let value = Self::new(coefficient, exponent, text.starts_with('-'));
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if !(ETINY..=EMAX).contains(&self.exponent)
            || digits(&self.coefficient) > PRECISION
            || (!self.is_zero() && self.adjusted() > EMAX)
        {
            return Err(error());
        }
        Ok(())
    }

    pub(crate) fn from_fixed(value: &VmDecimal) -> Self {
        let mut coefficient = value.scaled.clone();
        let mut exponent = -30;
        if coefficient.is_zero() {
            exponent = 0;
        } else {
            while (&coefficient % 10u8).is_zero() {
                coefficient /= 10u8;
                exponent += 1;
            }
        }
        Self::new(coefficient, exponent, false)
    }

    pub(crate) fn from_value(value: &VmValue) -> Result<Self> {
        match value.snapshot() {
            VmValue::RawDecimal(value) => Ok(value),
            VmValue::Decimal(value) => Ok(Self::from_fixed(&value)),
            VmValue::Int(value) => Ok(Self::new(value, 0, false)),
            VmValue::Bool(value) => Ok(Self::new(BigInt::from(u8::from(value)), 0, false)),
            _ => Err(VmExecutionError::new(
                "raw Decimal arithmetic requires decimal or integer operands",
            )),
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.coefficient.is_zero()
    }
    fn negative(&self) -> bool {
        self.coefficient.sign() == Sign::Minus || self.negative_zero
    }
    fn adjusted(&self) -> i32 {
        self.exponent + digits(&self.coefficient) - 1
    }
    pub(crate) fn to_fixed(&self) -> Result<VmDecimal> {
        VmDecimal::from_str_literal(&self.to_string())
    }
    pub(crate) fn engineering(&self) -> String {
        if self.exponent <= 0 && self.adjusted() >= -6 {
            return self.to_string();
        }
        let sign = if self.negative() { "-" } else { "" };
        if self.is_zero() {
            let exponent = -(-self.exponent).div_euclid(3) * 3;
            let places = exponent - self.exponent;
            let fraction = if places == 0 {
                String::new()
            } else {
                format!(".{}", "0".repeat(places as usize))
            };
            return format!("{sign}0{fraction}E{exponent:+}");
        }
        let exponent = self.adjusted().div_euclid(3) * 3;
        let point = (self.adjusted() - exponent + 1) as usize;
        let mut coefficient = self.coefficient.abs().to_str_radix(10);
        if coefficient.len() < point {
            coefficient.push_str(&"0".repeat(point - coefficient.len()));
        } else if coefficient.len() > point {
            coefficient.insert(point, '.');
        }
        if exponent == 0 {
            format!("{sign}{coefficient}")
        } else {
            format!("{sign}{coefficient}E{exponent:+}")
        }
    }

    pub(crate) fn format_work_cost(spec: &str) -> Result<u64> {
        formatting::work_cost(spec)
    }
    pub(crate) fn sort_key(&self) -> BigInt {
        self.rescale(ETINY)
    }
    pub(crate) fn integer(&self) -> BigInt {
        self.rescale(0)
    }
    pub(crate) fn float(&self) -> Result<f64> {
        self.to_string().parse().map_err(|_| error())
    }

    fn rescale(&self, exponent: i32) -> BigInt {
        let shift = self.exponent - exponent;
        if shift >= 0 {
            &self.coefficient * ten(shift as u32)
        } else if -shift >= digits(&self.coefficient) {
            BigInt::zero()
        } else {
            &self.coefficient / ten((-shift) as u32)
        }
    }

    pub(crate) fn quantize(&self, places: i32) -> Result<Self> {
        let exponent = places.checked_neg().ok_or_else(error)?;
        if !(ETINY..=EMAX).contains(&exponent) {
            return Err(error());
        }
        let value = Self::new(self.rescale(exponent), exponent, self.negative());
        value.validate()?;
        Ok(value)
    }

    fn context(mut self) -> Result<Self> {
        let exponent = self
            .exponent
            .max(self.exponent + digits(&self.coefficient) - PRECISION)
            .max(ETINY);
        let negative = self.negative();
        self.coefficient = self.rescale(exponent);
        self.exponent = exponent.min(EMAX);
        self.negative_zero = self.coefficient.is_zero() && negative;
        if !self.is_zero() && exponent > EMAX {
            return Err(error());
        }
        self.validate()?;
        Ok(self)
    }

    pub(crate) fn unary(&self, op: &str) -> Result<Self> {
        let coefficient = match op {
            "neg" => -&self.coefficient,
            "abs" => self.coefficient.abs(),
            _ => self.coefficient.clone(),
        };
        // Decimal context unary operations canonicalize the sign of zero.
        Self::new(coefficient, self.exponent, false).context()
    }

    pub(crate) fn arithmetic(&self, op: &str, other: &Self) -> Result<Self> {
        match op {
            "add" | "sub" => {
                let exp = self.exponent.min(other.exponent);
                let right = if op == "sub" {
                    -other.rescale(exp)
                } else {
                    other.rescale(exp)
                };
                let coefficient = self.rescale(exp) + right;
                let negative = self.negative() && (other.negative() ^ (op == "sub"));
                Self::new(coefficient, exp, negative).context()
            }
            "mul" => Self::new(
                &self.coefficient * &other.coefficient,
                self.exponent + other.exponent,
                self.negative() ^ other.negative(),
            )
            .context(),
            "div" => self.divide(other),
            "floordiv" | "mod" => self.remainder(op, other),
            "pow" => self.power(other),
            _ => Err(error()),
        }
    }

    fn divide(&self, other: &Self) -> Result<Self> {
        if other.is_zero() {
            return Err(VmExecutionError::new("division by zero"));
        }
        let ideal = self.exponent - other.exponent;
        let negative = self.negative() ^ other.negative();
        if self.is_zero() {
            return Self::new(BigInt::zero(), ideal, negative).context();
        }
        let shift = (PRECISION + digits(&other.coefficient) - digits(&self.coefficient)).max(0);
        let numerator = &self.coefficient * ten(shift as u32);
        let mut result = Self::new(&numerator / &other.coefficient, ideal - shift, negative);
        let exact = (&numerator % &other.coefficient).is_zero();
        result = result.context()?;
        if exact && !result.is_zero() {
            while result.exponent < ideal && (&result.coefficient % 10u8).is_zero() {
                result.coefficient /= 10u8;
                result.exponent += 1;
            }
        }
        Ok(result)
    }

    fn remainder(&self, op: &str, other: &Self) -> Result<Self> {
        if other.is_zero() {
            return Err(VmExecutionError::new("division by zero"));
        }
        let exp = self.exponent.min(other.exponent);
        let left = self.rescale(exp);
        let right = other.rescale(exp);
        let quotient = &left / &right;
        if digits(&quotient) > PRECISION {
            return Err(error());
        }
        if op == "floordiv" {
            Ok(Self::new(quotient, 0, self.negative() ^ other.negative()))
        } else {
            Self::new(left % right, exp, self.negative()).context()
        }
    }

    fn power(&self, other: &Self) -> Result<Self> {
        if other.compare(&Self::new(BigInt::from(5), -1, false)) == Ordering::Equal {
            return self.sqrt();
        }
        let integer = other.integer();
        if other.compare(&Self::new(integer.clone(), 0, false)) != Ordering::Equal {
            return Err(VmExecutionError::new(
                "unsupported fractional decimal exponent",
            ));
        }
        if self.coefficient.abs() == ten((-self.exponent).max(0) as u32) && self.exponent <= 0 {
            let places = if integer.is_negative() {
                0
            } else {
                ((-&integer) * self.exponent).to_u32().unwrap_or(90).min(90)
            };
            let negative = self.negative() && !(&integer % 2u8).is_zero();
            let coefficient = ten(places) * if negative { -1 } else { 1 };
            return Ok(Self::new(coefficient, -(places as i32), false));
        }
        let exponent = integer
            .abs()
            .to_u32()
            .filter(|n| *n <= 4096)
            .ok_or_else(error)?;
        if self.coefficient.bits().saturating_mul(exponent as u64)
            > crate::interpreter::MAX_INTEGER_BITS
        {
            return Err(VmExecutionError::new(
                "decimal power allocation limit exceeded",
            ));
        }
        if self.is_zero() && exponent == 0 {
            return Err(error());
        }
        if self.is_zero() && !integer.is_negative() {
            return Ok(Self::new(
                BigInt::zero(),
                0,
                self.negative() && exponent % 2 == 1,
            ));
        }
        let value = Self::new(
            self.coefficient.pow(exponent),
            self.exponent * exponent as i32,
            self.negative() && exponent % 2 == 1,
        );
        if integer.is_negative() {
            Self::new(BigInt::from(1), 0, false).divide(&value)
        } else {
            value.context()
        }
    }

    fn sqrt(&self) -> Result<Self> {
        if self.negative() && !self.is_zero() {
            return Err(error());
        }
        if self.is_zero() {
            return Ok(Self::new(BigInt::zero(), 0, false));
        }
        let exp = (self.adjusted().div_euclid(2) - (PRECISION - 1)).max(ETINY);
        let scaled = self.rescale(exp * 2);
        let root = crate::values::bigint_integer_sqrt(&scaled);
        // Decimal power with a non-integral exponent rounds to the full
        // context precision even when the mathematical root is exact.
        Self::new(root, exp, false).context()
    }

    pub(crate) fn compare(&self, other: &Self) -> Ordering {
        let exp = self.exponent.min(other.exponent);
        self.rescale(exp).cmp(&other.rescale(exp))
    }

    pub(crate) fn compare_value(&self, other: &VmValue) -> Result<Ordering> {
        if let VmValue::Float(value) = other.snapshot() {
            if value.is_nan() {
                return Err(error());
            }
            if value.is_infinite() {
                return Ok(if value.is_sign_negative() {
                    Ordering::Greater
                } else {
                    Ordering::Less
                });
            }
            let bits = value.to_bits();
            let exponent = ((bits >> 52) & 0x7ff) as i32;
            let fraction = bits & ((1u64 << 52) - 1);
            let (mantissa, shift) = if exponent == 0 {
                (fraction, -1074)
            } else {
                (fraction | (1u64 << 52), exponent - 1023 - 52)
            };
            let mut coefficient = BigInt::from(mantissa);
            let exponent = if shift >= 0 {
                coefficient <<= shift as usize;
                0
            } else {
                coefficient *= BigInt::from(5u8).pow((-shift) as u32);
                shift
            };
            if value.is_sign_negative() {
                coefficient = -coefficient;
            }
            return Ok(self.compare(&Self::new(coefficient, exponent, false)));
        }
        Ok(self.compare(&Self::from_value(other)?))
    }
}

impl fmt::Display for VmRawDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = self.coefficient.abs().to_str_radix(10);
        if self.negative() {
            f.write_str("-")?;
        }
        if self.exponent > 0 || self.adjusted() < -6 {
            f.write_str(&digits[..1])?;
            if digits.len() > 1 {
                write!(f, ".{}", &digits[1..])?;
            }
            write!(f, "E{:+}", self.adjusted())
        } else {
            let point = digits.len() as i32 + self.exponent;
            if point <= 0 {
                write!(f, "0.{}{}", "0".repeat((-point) as usize), digits)
            } else if point < digits.len() as i32 {
                write!(
                    f,
                    "{}.{}",
                    &digits[..point as usize],
                    &digits[point as usize..]
                )
            } else {
                f.write_str(&digits)
            }
        }
    }
}

pub(crate) fn work_cost(op: &str, left: &VmValue, right: &VmValue) -> u64 {
    let left = left.snapshot();
    let right = right.snapshot();
    if !matches!(left, VmValue::RawDecimal(_)) && !matches!(right, VmValue::RawDecimal(_)) {
        return 0;
    }
    let bits = |value: &VmValue| match value {
        VmValue::RawDecimal(v) => v.coefficient.bits(),
        VmValue::Decimal(v) => v.scaled.bits(),
        VmValue::Int(v) => v.bits(),
        _ => 64,
    };
    let work = bits(&left).saturating_add(bits(&right)).saturating_mul(4);
    if op == "pow" {
        let exponent = VmRawDecimal::from_value(&right)
            .ok()
            .map(|v| v.integer().abs().to_u64().unwrap_or(4096).min(4096))
            .unwrap_or(1);
        work.saturating_mul(exponent.max(1))
    } else {
        work
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantum_and_signed_zero_survive_rounding() {
        let value = VmRawDecimal::from_fixed(&VmDecimal::from_str_literal("2").unwrap());
        assert_eq!(value.quantize(2).unwrap().to_string(), "2.00");
        let value = VmRawDecimal::parse("-0.001").unwrap().quantize(2).unwrap();
        assert_eq!(value.to_string(), "-0.00");
        assert_eq!(value.unary("pos").unwrap().to_string(), "0.00");
        assert!(value.float().unwrap().is_sign_negative());
        assert_eq!(value.to_fixed().unwrap(), VmDecimal::zero());
        assert_eq!(
            VmRawDecimal::parse("2.00").unwrap().integer(),
            BigInt::from(2)
        );
    }

    #[test]
    fn context_limits_and_exact_underflow_quantum() {
        let one = VmRawDecimal::parse("-1.00").unwrap();
        let divisor = VmRawDecimal::from_value(&VmValue::Int(ten(200))).unwrap();
        assert_eq!(one.divide(&divisor).unwrap().to_string(), "-0E-190");
        assert!(one.quantize(191).is_err());
        assert!(one.quantize(-101).is_err());
        assert!(one.quantize(91).is_err());
        let zero = VmRawDecimal::parse("0").unwrap();
        assert_eq!(zero.quantize(190).unwrap().to_string(), "0E-190");
        assert!(one.divide(&zero).is_err());
        assert!(VmRawDecimal::parse("1E+101").is_err());
    }

    #[test]
    fn exact_binary_float_comparison_and_hash_order() {
        let value = VmRawDecimal::parse("0.10").unwrap();
        assert_eq!(
            value.compare_value(&VmValue::Float(0.1)).unwrap(),
            Ordering::Less
        );
        assert_eq!(
            value.compare(&VmRawDecimal::parse("0.1").unwrap()),
            Ordering::Equal
        );
        assert_eq!(
            value.sort_key(),
            VmRawDecimal::parse("0.1").unwrap().sort_key()
        );
        assert_eq!(
            value.compare_value(&VmValue::Float(f64::INFINITY)).unwrap(),
            Ordering::Less
        );
        assert_eq!(
            value
                .compare_value(&VmValue::Float(-f64::INFINITY))
                .unwrap(),
            Ordering::Greater
        );
    }

    #[test]
    fn formatting_bounds_and_grouping() {
        let value = VmRawDecimal::parse("-0.001").unwrap();
        assert_eq!(value.format("z.2f").unwrap(), "0.00");
        assert_eq!(value.format("010,.2f").unwrap(), "-00,000.00");
        assert_eq!(value.format("^15.2f").unwrap(), "     -0.00     ");
        assert!(value.format("131073f").is_err());
        assert!(value.format(".131072f").is_err());
        assert!(value.format("#.0f").is_err());
        assert!(value.format(".f").is_err());
        assert!(value.format(",n").is_err());
    }
}
