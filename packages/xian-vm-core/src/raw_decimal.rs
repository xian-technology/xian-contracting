//! Exact Decimal values and bounded arithmetic through the historical context.
//! Exact constructors preserve quantum; arithmetic uses 91 digits and ROUND_DOWN.
use crate::{VmDecimal, VmExecutionError, VmValue};
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, ToPrimitive, Zero};
use std::str::FromStr;
use std::{cmp::Ordering, fmt};

#[path = "raw_decimal_format.rs"]
mod formatting;

type Result<T> = std::result::Result<T, VmExecutionError>;
const ETINY: i32 = -190;
const EMAX: i32 = 100;
const EXACT_LIMIT: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Finite,
    Infinity,
    QuietNaN,
    SignalingNaN,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmRawDecimal {
    pub(crate) coefficient: BigInt,
    pub(crate) exponent: i32,
    // For finite nonzero values the coefficient holds the sign. This flag also
    // carries the sign of zeros and special values, whose coefficient is payload.
    negative_zero: bool,
    class: Class,
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
        Self {
            negative_zero: coefficient.is_zero() && negative,
            coefficient,
            exponent,
            class: Class::Finite,
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self> {
        if text.is_empty() || text.len() > EXACT_LIMIT || !text.is_ascii() {
            return Err(error());
        }
        let negative = text.starts_with('-');
        let unsigned = text.strip_prefix(['-', '+']).unwrap_or(text);
        if unsigned.eq_ignore_ascii_case("inf") || unsigned.eq_ignore_ascii_case("infinity") {
            return Ok(Self {
                coefficient: BigInt::zero(),
                exponent: 0,
                negative_zero: negative,
                class: Class::Infinity,
            });
        }
        if let Some(special) = Self::parse_nan(unsigned, negative)? {
            return Ok(special);
        }
        Self::parse_finite(text, negative)
    }

    fn parse_nan(unsigned: &str, negative: bool) -> Result<Option<Self>> {
        for (prefix, class) in [("sNaN", Class::SignalingNaN), ("NaN", Class::QuietNaN)] {
            if unsigned
                .get(..prefix.len())
                .is_some_and(|s| s.eq_ignore_ascii_case(prefix))
            {
                let payload = &unsigned[prefix.len()..];
                if !payload.bytes().all(|c| c.is_ascii_digit()) {
                    return Err(error());
                }
                let coefficient = if payload.is_empty() {
                    BigInt::zero()
                } else {
                    BigInt::from_str(payload).map_err(|_| error())?
                };
                return Ok(Some(Self {
                    coefficient,
                    exponent: 0,
                    negative_zero: negative,
                    class,
                }));
            }
        }
        Ok(None)
    }

    fn parse_finite(text: &str, negative: bool) -> Result<Self> {
        let (mantissa, exp) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
        let exp: i32 = exp.parse().map_err(|_| error())?;
        let unsigned_mantissa = mantissa.strip_prefix(['-', '+']).unwrap_or(mantissa);
        if unsigned_mantissa.matches('.').count() > 1
            || !unsigned_mantissa
                .bytes()
                .all(|c| c.is_ascii_digit() || c == b'.')
        {
            return Err(error());
        }
        let places = mantissa
            .split_once('.')
            .map_or(0, |(_, part)| part.len() as i32);
        let coefficient = BigInt::from_str(&mantissa.replace('.', "")).map_err(|_| error())?;
        let exponent = exp.checked_sub(places).ok_or_else(error)?;
        if exponent.unsigned_abs() > EXACT_LIMIT as u32
            || coefficient.bits() > crate::interpreter::MAX_INTEGER_BITS
        {
            return Err(error());
        }
        Ok(Self::new(coefficient, exponent, negative))
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

    pub(crate) fn from_integer(value: BigInt) -> Result<Self> {
        if value.bits() > crate::interpreter::MAX_INTEGER_BITS
            || digits(&value) as usize > EXACT_LIMIT - 1
        {
            return Err(error());
        }
        Ok(Self::new(value, 0, false))
    }

    pub(crate) fn from_float(value: f64) -> Result<Self> {
        if value.is_nan() {
            return Self::parse("NaN");
        }
        if value.is_infinite() {
            return Self::parse(if value.is_sign_negative() {
                "-Infinity"
            } else {
                "Infinity"
            });
        }
        Ok(Self::from_finite_float(value))
    }

    fn from_finite_float(value: f64) -> Self {
        let bits = value.to_bits();
        let exponent = ((bits >> 52) & 0x7ff) as i32;
        let fraction = bits & ((1u64 << 52) - 1);
        let (mut mantissa, mut shift) = if exponent == 0 {
            (fraction, -1074)
        } else {
            (fraction | (1u64 << 52), exponent - 1023 - 52)
        };
        if mantissa == 0 {
            return Self::new(BigInt::zero(), 0, value.is_sign_negative());
        }
        // Remove powers of two before converting to base ten. Decimal.from_float
        // emits the shortest exact coefficient, not artificial trailing zeros.
        while shift < 0 && mantissa % 2 == 0 {
            mantissa /= 2;
            shift += 1;
        }
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
        Self::new(coefficient, exponent, false)
    }

    pub(crate) fn from_value(value: &VmValue) -> Result<Self> {
        match value.snapshot() {
            VmValue::RawDecimal(value) => Ok(value),
            VmValue::Decimal(value) => Ok(Self::from_fixed(&value)),
            VmValue::Int(value) => Self::from_integer(value),
            VmValue::Bool(value) => Self::from_integer(BigInt::from(u8::from(value))),
            _ => Err(VmExecutionError::new(
                "raw Decimal arithmetic requires decimal or integer operands",
            )),
        }
    }

    pub(crate) fn is_finite(&self) -> bool {
        self.class == Class::Finite
    }
    pub(crate) fn is_infinite(&self) -> bool {
        self.class == Class::Infinity
    }
    pub(crate) fn is_nan(&self) -> bool {
        matches!(self.class, Class::QuietNaN | Class::SignalingNaN)
    }
    pub(crate) fn is_snan(&self) -> bool {
        self.class == Class::SignalingNaN
    }
    pub(crate) fn is_zero(&self) -> bool {
        self.is_finite() && self.coefficient.is_zero()
    }
    pub(crate) fn is_normal(&self) -> bool {
        self.is_finite() && !self.is_zero() && self.adjusted() >= -100
    }
    pub(crate) fn is_subnormal(&self) -> bool {
        self.is_finite() && !self.is_zero() && self.adjusted() < -100
    }
    pub(crate) fn is_negative(&self) -> bool {
        self.negative()
    }
    fn negative(&self) -> bool {
        self.coefficient.sign() == Sign::Minus || self.negative_zero
    }
    pub(crate) fn adjusted(&self) -> i32 {
        if self.is_finite() {
            self.exponent + digits(&self.coefficient) - 1
        } else {
            0
        }
    }
    pub(crate) fn to_fixed(&self) -> Result<VmDecimal> {
        if !self.is_finite() {
            return Err(VmExecutionError::new("cannot store non-finite Decimal"));
        }
        VmDecimal::from_str_literal(&self.to_string())
    }
    pub(crate) fn tuple_parts(&self) -> (bool, Vec<u8>, Option<i32>, Option<char>) {
        let digits = if self.is_nan() && self.coefficient.is_zero() {
            Vec::new()
        } else {
            self.coefficient
                .abs()
                .to_str_radix(10)
                .bytes()
                .map(|v| v - b'0')
                .collect()
        };
        let special = match self.class {
            Class::Finite => None,
            Class::Infinity => Some('F'),
            Class::QuietNaN => Some('n'),
            Class::SignalingNaN => Some('N'),
        };
        (
            self.negative(),
            digits,
            self.is_finite().then_some(self.exponent),
            special,
        )
    }
    pub(crate) fn engineering(&self) -> String {
        if !self.is_finite() {
            return self.to_string();
        }
        if self.exponent <= 0 && self.adjusted() >= -6 {
            return self.to_string();
        }
        let sign = if self.negative() { "-" } else { "" };
        if self.is_zero() {
            return self.engineering_zero(sign);
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

    fn engineering_zero(&self, sign: &str) -> String {
        let exponent = -(-self.exponent).div_euclid(3) * 3;
        let places = exponent - self.exponent;
        let fraction = if places == 0 {
            String::new()
        } else {
            format!(".{}", "0".repeat(places as usize))
        };
        format!("{sign}0{fraction}E{exponent:+}")
    }

    pub(crate) fn format_work_cost(spec: &str) -> Result<u64> {
        formatting::work_cost(spec)
    }
    pub(crate) fn integer(&self) -> Result<BigInt> {
        if !self.is_finite() {
            return Err(error());
        }
        let size = self
            .coefficient
            .bits()
            .saturating_add(self.exponent.max(0) as u64 * 4);
        if size > crate::interpreter::MAX_INTEGER_BITS {
            return Err(error());
        }
        Ok(self.rescale(0))
    }
    pub(crate) fn integer_ratio(&self) -> Result<(BigInt, BigInt)> {
        if !self.is_finite() {
            return Err(error());
        }
        let (mut numerator, mut denominator) = if self.exponent >= 0 {
            (self.integer()?, BigInt::from(1u8))
        } else {
            (self.coefficient.clone(), ten(self.exponent.unsigned_abs()))
        };
        // Euclid avoids a separate dependency and works for every exact input.
        let (mut a, mut b) = (numerator.abs(), denominator.clone());
        while !b.is_zero() {
            let remainder = &a % &b;
            a = b;
            b = remainder;
        }
        numerator /= &a;
        denominator /= a;
        Ok((numerator, denominator))
    }
    pub(crate) fn float(&self) -> Result<f64> {
        if self.is_snan() {
            return Err(error());
        }
        if self.is_nan() {
            return Ok(f64::NAN.copysign(if self.negative() { -1.0 } else { 1.0 }));
        }
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
        // Quiet NaNs propagate before context exponent checks in Decimal.
        if self.is_nan() && places != i32::MIN && places != i32::MAX {
            return self.calculate("quantize", &[Self::new(BigInt::from(1u8), 0, false)], None);
        }
        let exponent = places.checked_neg().ok_or_else(error)?;
        if !(ETINY..=EMAX).contains(&exponent) {
            return Err(error());
        }
        self.calculate(
            "quantize",
            &[Self::new(BigInt::from(1u8), exponent, false)],
            None,
        )
    }
    pub(crate) fn calculate(
        &self,
        operation: &str,
        others: &[Self],
        rounding: Option<&str>,
    ) -> Result<Self> {
        let mut texts = vec![self.to_string()];
        texts.extend(others.iter().map(ToString::to_string));
        let args: Vec<_> = texts.iter().map(String::as_str).collect();
        Self::parse(&crate::decimal_backend::calculate(
            operation, &args, rounding,
        )?)
    }
    pub(crate) fn unary(&self, op: &str) -> Result<Self> {
        self.calculate(
            match op {
                "neg" => "minus",
                "abs" => "abs",
                _ => "plus",
            },
            &[],
            None,
        )
    }
    pub(crate) fn arithmetic(&self, op: &str, other: &Self) -> Result<Self> {
        self.calculate(
            match op {
                "floordiv" => "divint",
                "mod" => "rem",
                other => other,
            },
            std::slice::from_ref(other),
            None,
        )
    }
    pub(crate) fn compare(&self, other: &Self) -> Result<Ordering> {
        if self.is_nan() || other.is_nan() {
            return Err(error());
        }
        Ok(self.total_compare(other))
    }
    /// Canonical ordering for deterministic containers. Numeric equality ignores
    /// quantum; NaN payload/sign ordering never invokes Decimal's trapping compare.
    pub(crate) fn total_compare(&self, other: &Self) -> Ordering {
        let rank = |v: &Self| {
            if v.is_nan() {
                3
            } else if v.is_infinite() {
                if v.negative() {
                    0
                } else {
                    2
                }
            } else {
                1
            }
        };
        let ranks = rank(self).cmp(&rank(other));
        if ranks != Ordering::Equal {
            return ranks;
        }
        if self.is_nan() {
            return (self.is_snan(), self.negative(), &self.coefficient).cmp(&(
                other.is_snan(),
                other.negative(),
                &other.coefficient,
            ));
        }
        if self.is_infinite() {
            return Ordering::Equal;
        }
        self.compare_finite(other)
    }
    fn compare_finite(&self, other: &Self) -> Ordering {
        let sign = self.coefficient.sign().cmp(&other.coefficient.sign());
        if sign != Ordering::Equal || self.is_zero() {
            return sign;
        }
        let adjusted = self.adjusted().cmp(&other.adjusted());
        let magnitude = if adjusted != Ordering::Equal {
            adjusted
        } else {
            let left = self.coefficient.abs().to_str_radix(10);
            let right = other.coefficient.abs().to_str_radix(10);
            let count = left.len().max(right.len());
            left.bytes()
                .chain(std::iter::repeat(b'0'))
                .take(count)
                .cmp(right.bytes().chain(std::iter::repeat(b'0')).take(count))
        };
        if self.negative() {
            magnitude.reverse()
        } else {
            magnitude
        }
    }
    pub(crate) fn compare_value(&self, other: &VmValue) -> Result<Ordering> {
        let other = match other.snapshot() {
            VmValue::Float(value) => Self::from_float(value)?,
            value => Self::from_value(&value)?,
        };
        self.compare(&other)
    }
}

impl VmRawDecimal {
    fn fmt_special(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.class {
            Class::Infinity => "Infinity",
            Class::QuietNaN => "NaN",
            Class::SignalingNaN => "sNaN",
            Class::Finite => unreachable!(),
        })?;
        if self.is_nan() && !self.coefficient.is_zero() {
            write!(f, "{}", self.coefficient)?;
        }
        Ok(())
    }
    fn fmt_scientific(&self, f: &mut fmt::Formatter<'_>, digits: &str) -> fmt::Result {
        f.write_str(&digits[..1])?;
        if digits.len() > 1 {
            write!(f, ".{}", &digits[1..])?;
        }
        write!(f, "E{:+}", self.adjusted())
    }
    fn fmt_fixed(&self, f: &mut fmt::Formatter<'_>, digits: &str) -> fmt::Result {
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
            f.write_str(digits)
        }
    }
}
impl fmt::Display for VmRawDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative() {
            f.write_str("-")?;
        }
        if !self.is_finite() {
            return self.fmt_special(f);
        }
        let digits = self.coefficient.abs().to_str_radix(10);
        if self.exponent > 0 || self.adjusted() < -6 {
            self.fmt_scientific(f, &digits)
        } else {
            self.fmt_fixed(f, &digits)
        }
    }
}

pub(crate) fn modular_work_cost(values: &[VmValue]) -> u64 {
    let size = values.iter().fold(0u64, |total, value| {
        let size = match value.snapshot() {
            VmValue::RawDecimal(value) => value
                .coefficient
                .bits()
                .saturating_add(value.exponent.unsigned_abs() as u64),
            VmValue::Int(value) => value.bits(),
            _ => 64,
        };
        total.saturating_add(size)
    });
    size.saturating_mul(size).saturating_mul(4).max(64)
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
        if is_general_fractional_power(&right) {
            let digits = bits(&left).saturating_add(bits(&right)) / 3 + 91;
            return work.max(digits.saturating_mul(digits).saturating_mul(16));
        }
        let exponent = VmRawDecimal::from_value(&right)
            .ok()
            .and_then(|v| v.integer().ok())
            .map(|v| v.abs().to_u64().unwrap_or(4096).min(4096))
            .unwrap_or(1);
        work.saturating_mul(exponent.max(1))
    } else {
        work
    }
}

fn is_general_fractional_power(exponent: &VmValue) -> bool {
    let Ok(exponent) = VmRawDecimal::from_value(exponent) else {
        return false;
    };
    if !exponent.is_finite() {
        return false;
    }
    let half = VmRawDecimal::new(BigInt::from(5u8), -1, false);
    if exponent.total_compare(&half) == Ordering::Equal {
        return false;
    }
    let Ok(integer) = exponent.integer() else {
        return false;
    };
    exponent.total_compare(&VmRawDecimal::new(integer, 0, false)) != Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_constructor_and_general_power_regressions() {
        assert_eq!(
            VmRawDecimal::parse("Infinity").unwrap().to_string(),
            "Infinity"
        );
        assert_eq!(VmRawDecimal::parse("NaN123").unwrap().to_string(), "NaN123");
        assert!(VmRawDecimal::parse("1E-1074").is_ok());
        let base = VmRawDecimal::parse("2").unwrap();
        let exponent = VmRawDecimal::parse("1.2").unwrap();
        assert_eq!(base.arithmetic("pow", &exponent).unwrap().to_string(),
            "2.297396709994070013597253893555855178887701778195595011027422236987206412507026113622946226");
    }

    #[test]
    fn exact_float_construction_bypasses_arithmetic_precision() {
        assert_eq!(
            VmRawDecimal::from_float(0.1).unwrap().to_string(),
            "0.1000000000000000055511151231257827021181583404541015625"
        );
        let tiny = VmRawDecimal::from_float(f64::from_bits(1)).unwrap();
        assert_eq!(tiny.exponent, -1074);
        assert_eq!(digits(&tiny.coefficient), 751);
        assert_eq!(
            tiny.integer_ratio().unwrap(),
            (BigInt::from(1), BigInt::from(1) << 1074usize)
        );
        assert_eq!(tiny.unary("pos").unwrap().to_string(), "0E-190");
        assert_eq!(VmRawDecimal::from_float(-0.0).unwrap().to_string(), "-0");
        assert_eq!(VmRawDecimal::from_float(4.0).unwrap().to_string(), "4");
        assert_eq!(
            VmRawDecimal::from_float(f64::INFINITY).unwrap().to_string(),
            "Infinity"
        );
    }

    #[test]
    fn special_values_propagate_but_cannot_become_persisted_numbers() {
        let nan = VmRawDecimal::parse("-NaN12").unwrap();
        assert_eq!(nan.tuple_parts(), (true, vec![1, 2], None, Some('n')));
        assert!(nan.compare(&nan).is_err());
        assert!(nan.integer().is_err());
        assert!(nan.to_fixed().is_err());
        assert!(nan.integer_ratio().is_err());
        assert_eq!(
            nan.arithmetic("add", &VmRawDecimal::parse("1").unwrap())
                .unwrap(),
            nan
        );
        assert!(VmRawDecimal::parse("sNaN").unwrap().unary("pos").is_err());
        let infinity = VmRawDecimal::parse("Infinity").unwrap();
        assert_eq!(infinity.tuple_parts(), (false, vec![0], None, Some('F')));
        assert!(infinity.quantize(2).is_err());
        assert_eq!(infinity.engineering(), "Infinity");
        assert_eq!(infinity.format("+010,.2f").unwrap(), " +Infinity");
        assert_eq!(nan.format(".2%").unwrap(), "-NaN12%");
        let plain_nan = VmRawDecimal::parse("-NaN").unwrap();
        assert_eq!(plain_nan.format("010").unwrap(), "      -NaN");
        assert_eq!(plain_nan.format("0=10").unwrap(), "-000000NaN");
    }

    #[test]
    fn canonical_container_order_retains_exact_tiny_values() {
        let tiny = VmRawDecimal::from_float(f64::from_bits(1)).unwrap();
        let zero = VmRawDecimal::parse("0").unwrap();
        assert_eq!(tiny.total_compare(&zero), Ordering::Greater);
        assert_eq!(
            VmRawDecimal::parse("-Infinity")
                .unwrap()
                .total_compare(&zero),
            Ordering::Less
        );
        assert_eq!(
            VmRawDecimal::parse("Infinity")
                .unwrap()
                .total_compare(&tiny),
            Ordering::Greater
        );
        assert_eq!(
            VmRawDecimal::parse("NaN").unwrap().total_compare(&tiny),
            Ordering::Greater
        );
        assert_eq!(
            VmRawDecimal::parse("-0.00").unwrap().total_compare(&zero),
            Ordering::Equal
        );
    }

    #[test]
    fn exact_value_and_formatting_resources_are_bounded() {
        for text in [
            "1E999999999999",
            "1E-131073",
            "1.2.3",
            "--Infinity",
            "NaNfoo",
        ] {
            assert!(VmRawDecimal::parse(text).is_err(), "{text}");
        }
        let value = VmRawDecimal::parse("1E131072").unwrap();
        assert!(value.format("f").is_err());
        assert!(VmRawDecimal::parse("NaN")
            .unwrap()
            .format("131073f")
            .is_err());
        assert!(VmRawDecimal::from_integer(
            BigInt::from(1) << crate::interpreter::MAX_INTEGER_BITS as usize
        )
        .is_err());
    }

    #[test]
    fn only_new_general_fractional_powers_get_transcendental_work_charge() {
        let base = VmValue::RawDecimal(VmRawDecimal::parse("2").unwrap());
        let half = VmValue::RawDecimal(VmRawDecimal::parse("0.5").unwrap());
        let general = VmValue::RawDecimal(VmRawDecimal::parse("0.2").unwrap());
        let integer = VmValue::RawDecimal(VmRawDecimal::parse("2").unwrap());
        assert_eq!(work_cost("pow", &base, &half), 20);
        assert_eq!(work_cost("pow", &base, &integer), 32);
        assert!(work_cost("pow", &base, &general) >= 91 * 91 * 16);
    }

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
            VmRawDecimal::parse("2.00").unwrap().integer().unwrap(),
            BigInt::from(2)
        );
    }

    #[test]
    fn context_limits_and_exact_underflow_quantum() {
        let one = VmRawDecimal::parse("-1.00").unwrap();
        let divisor = VmRawDecimal::from_value(&VmValue::Int(ten(200))).unwrap();
        assert_eq!(
            one.arithmetic("div", &divisor).unwrap().to_string(),
            "-0E-190"
        );
        assert!(one.quantize(191).is_err());
        assert!(one.quantize(-101).is_err());
        assert!(one.quantize(91).is_err());
        let zero = VmRawDecimal::parse("0").unwrap();
        assert_eq!(zero.quantize(190).unwrap().to_string(), "0E-190");
        assert!(one.arithmetic("div", &zero).is_err());
        assert!(VmRawDecimal::parse("1E+101").unwrap().unary("pos").is_err());
    }

    #[test]
    fn exact_binary_float_comparison_and_hash_order() {
        let value = VmRawDecimal::parse("0.10").unwrap();
        assert_eq!(
            value.compare_value(&VmValue::Float(0.1)).unwrap(),
            Ordering::Less
        );
        assert_eq!(
            value.compare(&VmRawDecimal::parse("0.1").unwrap()).unwrap(),
            Ordering::Equal
        );
        assert_eq!(
            value.total_compare(&VmRawDecimal::parse("0.1").unwrap()),
            Ordering::Equal
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
