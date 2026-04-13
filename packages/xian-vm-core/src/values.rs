use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, Timelike};
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, ToPrimitive, Zero};
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

const DECIMAL_SCALE: u32 = 30;
const DECIMAL_MAX_SCALED_DIGITS: u32 = 91;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmDecimal {
    pub(crate) scaled: BigInt,
}

impl VmDecimal {
    pub fn from_str_literal(value: &str) -> Result<Self, VmExecutionError> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(VmExecutionError::new("decimal() requires a value"));
        }

        let (negative, unsigned) = if let Some(rest) = trimmed.strip_prefix('-') {
            (true, rest)
        } else if let Some(rest) = trimmed.strip_prefix('+') {
            (false, rest)
        } else {
            (false, trimmed)
        };

        let (mantissa, exponent) =
            if let Some((mantissa, exponent)) = unsigned.split_once(['e', 'E']) {
                let exponent = exponent.parse::<i64>().map_err(|_| {
                    VmExecutionError::new(format!("invalid decimal exponent '{trimmed}'"))
                })?;
                (mantissa, exponent)
            } else {
                (unsigned, 0)
            };

        let (whole, fraction) = if let Some((whole, fraction)) = mantissa.split_once('.') {
            (whole, fraction)
        } else {
            (mantissa, "")
        };

        if whole.is_empty() && fraction.is_empty() {
            return Err(VmExecutionError::new(format!(
                "invalid decimal literal '{trimmed}'"
            )));
        }
        if !whole.chars().all(|ch| ch.is_ascii_digit())
            || !fraction.chars().all(|ch| ch.is_ascii_digit())
        {
            return Err(VmExecutionError::new(format!(
                "invalid decimal literal '{trimmed}'"
            )));
        }

        let mut digits = format!("{whole}{fraction}");
        let mut scale = fraction.len() as i64 - exponent;

        if scale < 0 {
            digits.push_str(&"0".repeat(scale.unsigned_abs() as usize));
            scale = 0;
        }

        if scale > DECIMAL_SCALE as i64 {
            let trim = (scale - DECIMAL_SCALE as i64) as usize;
            if trim >= digits.len() {
                return Ok(Self::zero());
            }
            digits.truncate(digits.len() - trim);
            scale = DECIMAL_SCALE as i64;
        }

        if scale < DECIMAL_SCALE as i64 {
            digits.push_str(&"0".repeat((DECIMAL_SCALE as i64 - scale) as usize));
        }

        let digits = digits.trim_start_matches('0');
        if digits.is_empty() {
            return Ok(Self::zero());
        }

        let mut scaled = BigInt::from_str(digits)
            .map_err(|_| VmExecutionError::new(format!("invalid decimal literal '{trimmed}'")))?;
        if negative {
            scaled = -scaled;
        }

        Self::from_scaled(scaled)
    }

    pub(crate) fn from_vm_value(value: &VmValue) -> Result<Self, VmExecutionError> {
        match value {
            VmValue::Decimal(value) => Ok(value.clone()),
            VmValue::Int(value) => Self::from_str_literal(&value.to_string()),
            VmValue::Float(value) => Self::from_str_literal(&value.to_string()),
            VmValue::Bool(value) => Self::from_str_literal(if *value { "1" } else { "0" }),
            VmValue::String(value) => Self::from_str_literal(value),
            other => Err(VmExecutionError::new(format!(
                "expected decimal-compatible value, got {}",
                other.type_name()
            ))),
        }
    }

    pub(crate) fn from_scaled(scaled: BigInt) -> Result<Self, VmExecutionError> {
        let scaled = normalize_zero_bigint(scaled);
        if scaled.abs() > *decimal_max_scaled() {
            return Err(VmExecutionError::new(format!(
                "decimal value {} exceeds the supported decimal range",
                Self {
                    scaled: scaled.clone()
                }
            )));
        }
        Ok(Self { scaled })
    }

    pub(crate) fn zero() -> Self {
        Self {
            scaled: BigInt::zero(),
        }
    }

    pub(crate) fn one() -> Self {
        Self {
            scaled: decimal_scale_factor().clone(),
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.scaled.is_zero()
    }

    pub(crate) fn to_i64(&self) -> Result<i64, VmExecutionError> {
        bigint_to_i64(&self.to_bigint(), &format!("decimal value {}", self))
    }

    pub(crate) fn to_bigint(&self) -> BigInt {
        &self.scaled / decimal_scale_factor()
    }

    pub(crate) fn to_f64(&self) -> Result<f64, VmExecutionError> {
        self.to_string().parse::<f64>().map_err(|_| {
            VmExecutionError::new(format!(
                "decimal value {} cannot be converted to float",
                self
            ))
        })
    }

    pub(crate) fn python_repr(&self) -> String {
        if self.scaled.is_zero() {
            return "0".to_owned();
        }

        let (digits, exponent) = normalized_decimal_parts(&self.scaled.abs());
        let adjusted_exponent = exponent + digits.len() as i64 - 1;
        let rendered = if exponent <= 0 && adjusted_exponent >= -6 {
            render_plain_decimal(&digits, exponent)
        } else {
            render_engineering_decimal(&digits, adjusted_exponent)
        };

        if self.scaled.sign() == Sign::Minus {
            format!("-{rendered}")
        } else {
            rendered
        }
    }

    pub(crate) fn add(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_scaled(&self.scaled + &other.scaled)
    }

    pub(crate) fn sub(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_scaled(&self.scaled - &other.scaled)
    }

    pub(crate) fn mul(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_scaled((&self.scaled * &other.scaled) / decimal_scale_factor())
    }

    pub(crate) fn div(&self, other: &Self) -> Result<Self, VmExecutionError> {
        if other.is_zero() {
            return Err(VmExecutionError::new("division by zero"));
        }
        Self::from_scaled((&self.scaled * decimal_scale_factor()) / &other.scaled)
    }

    pub(crate) fn modulo(&self, other: &Self) -> Result<Self, VmExecutionError> {
        if other.is_zero() {
            return Err(VmExecutionError::new("modulo by zero"));
        }
        Self::from_scaled(&self.scaled % &other.scaled)
    }

    pub(crate) fn floor_div(&self, other: &Self) -> Result<Self, VmExecutionError> {
        if other.is_zero() {
            return Err(VmExecutionError::new("division by zero"));
        }
        let quotient = &self.scaled / &other.scaled;
        Self::from_scaled(quotient * decimal_scale_factor())
    }

    pub(crate) fn pow(&self, exponent: &Self) -> Result<Self, VmExecutionError> {
        if exponent.is_zero() {
            return Ok(Self::one());
        }
        if exponent.scaled == *decimal_half_scale_factor() {
            return self.sqrt();
        }
        if (&exponent.scaled % decimal_scale_factor()).is_zero() {
            return self.pow_integer(&(&exponent.scaled / decimal_scale_factor()));
        }
        Err(VmExecutionError::new(format!(
            "unsupported decimal exponent {}",
            exponent
        )))
    }

    fn pow_integer(&self, exponent: &BigInt) -> Result<Self, VmExecutionError> {
        if exponent.is_zero() {
            return Ok(Self::one());
        }
        if exponent.sign() == Sign::Minus {
            if self.is_zero() {
                return Err(VmExecutionError::new(
                    "0 cannot be raised to a negative power",
                ));
            }
            let positive = self.pow_integer(&(-exponent))?;
            return Self::one().div(&positive);
        }

        let mut remaining = exponent.clone();
        let mut base = self.clone();
        let mut result = Self::one();
        let two = BigInt::from(2u8);
        let zero = BigInt::zero();
        let one = BigInt::from(1u8);

        while remaining > zero {
            if (&remaining % &two) == one {
                result = result.mul(&base)?;
            }
            remaining /= &two;
            if remaining > zero {
                base = base.mul(&base)?;
            }
        }

        Ok(result)
    }

    fn sqrt(&self) -> Result<Self, VmExecutionError> {
        if self.scaled.sign() == Sign::Minus {
            return Err(VmExecutionError::new(
                "cannot take square root of a negative decimal",
            ));
        }
        let radicand = &self.scaled * decimal_scale_factor();
        Self::from_scaled(bigint_integer_sqrt(&radicand))
    }
}

impl fmt::Display for VmDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.scaled.is_zero() {
            return f.write_str("0");
        }

        let negative = self.scaled.sign() == Sign::Minus;
        let digits = self.scaled.abs().to_str_radix(10);
        let rendered = if digits.len() <= DECIMAL_SCALE as usize {
            let fraction = format!(
                "{}{}",
                "0".repeat(DECIMAL_SCALE as usize - digits.len()),
                digits
            );
            format!("0.{}", trim_decimal_fraction(&fraction))
        } else {
            let split = digits.len() - DECIMAL_SCALE as usize;
            let whole = &digits[..split];
            let fraction = trim_decimal_fraction(&digits[split..]);
            if fraction.is_empty() {
                whole.to_owned()
            } else {
                format!("{whole}.{fraction}")
            }
        };

        if negative {
            write!(f, "-{rendered}")
        } else {
            f.write_str(&rendered)
        }
    }
}

fn decimal_scale_factor() -> &'static BigInt {
    static SCALE_FACTOR: OnceLock<BigInt> = OnceLock::new();
    SCALE_FACTOR.get_or_init(|| BigInt::from(10u8).pow(DECIMAL_SCALE))
}

fn decimal_half_scale_factor() -> &'static BigInt {
    static HALF_SCALE_FACTOR: OnceLock<BigInt> = OnceLock::new();
    HALF_SCALE_FACTOR.get_or_init(|| decimal_scale_factor() / BigInt::from(2u8))
}

fn decimal_max_scaled() -> &'static BigInt {
    static MAX_SCALED: OnceLock<BigInt> = OnceLock::new();
    MAX_SCALED.get_or_init(|| BigInt::from(10u8).pow(DECIMAL_MAX_SCALED_DIGITS) - BigInt::from(1u8))
}

fn bigint_integer_sqrt(value: &BigInt) -> BigInt {
    if value.sign() != Sign::Plus {
        return BigInt::zero();
    }
    let one = BigInt::from(1u8);
    let two = BigInt::from(2u8);
    let mut x0 = value.clone();
    let mut x1 = (&x0 + &one) / &two;
    while x1 < x0 {
        x0 = x1.clone();
        x1 = (&x1 + value / &x1) / &two;
    }
    x0
}

fn normalize_zero_bigint(value: BigInt) -> BigInt {
    if value.is_zero() {
        BigInt::zero()
    } else {
        value
    }
}

fn trim_decimal_fraction(fraction: &str) -> String {
    fraction.trim_end_matches('0').to_owned()
}

fn normalized_decimal_parts(value: &BigInt) -> (String, i64) {
    let mut coefficient = value.clone();
    let mut exponent = -(DECIMAL_SCALE as i64);
    let ten = BigInt::from(10u8);
    while (&coefficient % &ten).is_zero() {
        coefficient /= &ten;
        exponent += 1;
    }
    (coefficient.to_str_radix(10), exponent)
}

fn render_plain_decimal(digits: &str, exponent: i64) -> String {
    if exponent >= 0 {
        let mut rendered = digits.to_owned();
        rendered.push_str(&"0".repeat(exponent as usize));
        return rendered;
    }

    let split = digits.len() as i64 + exponent;
    if split > 0 {
        let split = split as usize;
        let fraction = trim_decimal_fraction(&digits[split..]);
        if fraction.is_empty() {
            digits[..split].to_owned()
        } else {
            format!("{}.{fraction}", &digits[..split])
        }
    } else {
        let mut fraction = String::with_capacity((-split) as usize + digits.len());
        fraction.push_str(&"0".repeat((-split) as usize));
        fraction.push_str(digits);
        format!("0.{}", trim_decimal_fraction(&fraction))
    }
}

fn render_engineering_decimal(digits: &str, adjusted_exponent: i64) -> String {
    let engineering_exponent = adjusted_exponent - adjusted_exponent.rem_euclid(3);
    let integer_digits = (adjusted_exponent - engineering_exponent + 1) as usize;
    let mut coefficient = digits.to_owned();
    if coefficient.len() < integer_digits {
        coefficient.push_str(&"0".repeat(integer_digits - coefficient.len()));
    }

    let mantissa = if coefficient.len() == integer_digits {
        coefficient
    } else {
        let fraction = trim_decimal_fraction(&coefficient[integer_digits..]);
        if fraction.is_empty() {
            coefficient[..integer_digits].to_owned()
        } else {
            format!("{}.{fraction}", &coefficient[..integer_digits])
        }
    };

    if engineering_exponent == 0 {
        mantissa
    } else if engineering_exponent > 0 {
        format!("{mantissa}E+{engineering_exponent}")
    } else {
        format!("{mantissa}E{engineering_exponent}")
    }
}

pub(crate) fn vm_int<T>(value: T) -> VmValue
where
    T: Into<BigInt>,
{
    VmValue::Int(value.into())
}

pub(crate) fn bigint_to_i64(value: &BigInt, context: &str) -> Result<i64, VmExecutionError> {
    value
        .to_i64()
        .ok_or_else(|| VmExecutionError::new(format!("{context} exceeds the supported i64 range")))
}

pub(crate) fn bigint_to_u32(value: &BigInt, context: &str) -> Result<u32, VmExecutionError> {
    if value.sign() == Sign::Minus {
        return Err(VmExecutionError::new(format!(
            "{context} must be non-negative"
        )));
    }
    value
        .to_u32()
        .ok_or_else(|| VmExecutionError::new(format!("{context} exceeds the supported u32 range")))
}

pub(crate) fn bigint_to_usize(value: &BigInt, context: &str) -> Result<usize, VmExecutionError> {
    if value.sign() == Sign::Minus {
        return Err(VmExecutionError::new(format!(
            "{context} must be non-negative"
        )));
    }
    value.to_usize().ok_or_else(|| {
        VmExecutionError::new(format!("{context} exceeds the supported usize range"))
    })
}

pub(crate) fn bigint_to_f64(value: &BigInt, context: &str) -> Result<f64, VmExecutionError> {
    value.to_f64().ok_or_else(|| {
        VmExecutionError::new(format!("{context} exceeds the supported float range"))
    })
}

pub(crate) fn f64_to_bigint_trunc(value: f64, context: &str) -> Result<BigInt, VmExecutionError> {
    if !value.is_finite() {
        return Err(VmExecutionError::new(format!(
            "{context} must be finite for integer conversion"
        )));
    }
    BigInt::from_str(&format!("{:.0}", value.trunc())).map_err(|_| {
        VmExecutionError::new(format!(
            "{context} cannot be converted to an integer without overflow"
        ))
    })
}

pub(crate) fn bigint_floor_div(left: &BigInt, right: &BigInt) -> Result<BigInt, VmExecutionError> {
    if right.is_zero() {
        return Err(VmExecutionError::new("division by zero"));
    }
    let quotient = left / right;
    let remainder = left % right;
    if !remainder.is_zero() && remainder.sign() != right.sign() {
        Ok(quotient - BigInt::from(1))
    } else {
        Ok(quotient)
    }
}

pub(crate) fn bigint_modulo(left: &BigInt, right: &BigInt) -> Result<BigInt, VmExecutionError> {
    let quotient = bigint_floor_div(left, right)?;
    Ok(left - (quotient * right))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmDateTime {
    pub(crate) value: NaiveDateTime,
}

impl VmDateTime {
    pub fn new(
        year: i64,
        month: i64,
        day: i64,
        hour: i64,
        minute: i64,
        second: i64,
        microsecond: i64,
    ) -> Result<Self, VmExecutionError> {
        let date = NaiveDate::from_ymd_opt(year as i32, month as u32, day as u32)
            .ok_or_else(|| VmExecutionError::new("invalid datetime date"))?;
        let value = date
            .and_hms_micro_opt(
                hour as u32,
                minute as u32,
                second as u32,
                microsecond as u32,
            )
            .ok_or_else(|| VmExecutionError::new("invalid datetime time"))?;
        Ok(Self { value })
    }

    pub fn parse(date_string: &str, format: &str) -> Result<Self, VmExecutionError> {
        NaiveDateTime::parse_from_str(date_string, format)
            .map(|value| Self { value })
            .map_err(|_| VmExecutionError::new("datetime.strptime() failed"))
    }

    pub fn add_timedelta(&self, delta: &VmTimeDelta) -> Result<Self, VmExecutionError> {
        self.value
            .checked_add_signed(delta.duration())
            .map(|value| Self { value })
            .ok_or_else(|| VmExecutionError::new("datetime overflow"))
    }

    pub fn sub_datetime(&self, other: &Self) -> Result<VmTimeDelta, VmExecutionError> {
        VmTimeDelta::from_raw_seconds(self.value.signed_duration_since(other.value).num_seconds())
    }

    pub fn year(&self) -> i64 {
        self.value.year() as i64
    }

    pub fn month(&self) -> i64 {
        self.value.month() as i64
    }

    pub fn day(&self) -> i64 {
        self.value.day() as i64
    }

    pub fn hour(&self) -> i64 {
        self.value.hour() as i64
    }

    pub fn minute(&self) -> i64 {
        self.value.minute() as i64
    }

    pub fn second(&self) -> i64 {
        self.value.second() as i64
    }

    pub fn microsecond(&self) -> i64 {
        self.value.and_utc().timestamp_subsec_micros() as i64
    }
}

impl fmt::Display for VmDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.microsecond() == 0 {
            write!(f, "{}", self.value.format("%Y-%m-%d %H:%M:%S"))
        } else {
            write!(f, "{}", self.value.format("%Y-%m-%d %H:%M:%S%.6f"))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmTimeDelta {
    pub(crate) raw_seconds: i64,
}

impl VmTimeDelta {
    pub fn new(
        weeks: i64,
        days: i64,
        hours: i64,
        minutes: i64,
        seconds: i64,
    ) -> Result<Self, VmExecutionError> {
        let raw_seconds = weeks
            .checked_mul(604_800)
            .and_then(|value| value.checked_add(days.checked_mul(86_400)?))
            .and_then(|value| value.checked_add(hours.checked_mul(3_600)?))
            .and_then(|value| value.checked_add(minutes.checked_mul(60)?))
            .and_then(|value| value.checked_add(seconds))
            .ok_or_else(|| VmExecutionError::new("timedelta overflow"))?;
        Self::from_raw_seconds(raw_seconds)
    }

    pub fn from_raw_seconds(raw_seconds: i64) -> Result<Self, VmExecutionError> {
        Ok(Self { raw_seconds })
    }

    pub fn duration(&self) -> Duration {
        Duration::seconds(self.raw_seconds)
    }

    pub fn add(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_raw_seconds(
            self.raw_seconds
                .checked_add(other.raw_seconds)
                .ok_or_else(|| VmExecutionError::new("timedelta overflow"))?,
        )
    }

    pub fn sub(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_raw_seconds(
            self.raw_seconds
                .checked_sub(other.raw_seconds)
                .ok_or_else(|| VmExecutionError::new("timedelta overflow"))?,
        )
    }

    pub fn mul_int(&self, other: i64) -> Result<Self, VmExecutionError> {
        Self::from_raw_seconds(
            self.raw_seconds
                .checked_mul(other)
                .ok_or_else(|| VmExecutionError::new("timedelta overflow"))?,
        )
    }

    pub fn mul_timedelta(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_raw_seconds(
            self.raw_seconds
                .checked_mul(other.raw_seconds)
                .ok_or_else(|| VmExecutionError::new("timedelta overflow"))?,
        )
    }

    pub fn seconds(&self) -> i64 {
        self.raw_seconds
    }

    pub fn minutes(&self) -> i64 {
        self.raw_seconds / 60
    }

    pub fn hours(&self) -> i64 {
        self.raw_seconds / 3_600
    }

    pub fn days(&self) -> i64 {
        self.raw_seconds / 86_400
    }

    pub fn weeks(&self) -> i64 {
        self.raw_seconds / 604_800
    }
}

impl fmt::Display for VmTimeDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let negative = self.raw_seconds < 0;
        let mut remaining = self.raw_seconds.abs();
        let days = remaining / 86_400;
        remaining %= 86_400;
        let hours = remaining / 3_600;
        remaining %= 3_600;
        let minutes = remaining / 60;
        let seconds = remaining % 60;
        let prefix = if negative { "-" } else { "" };
        if days == 0 {
            write!(f, "{prefix}{hours}:{minutes:02}:{seconds:02}")
        } else if days == 1 {
            write!(f, "{prefix}1 day, {hours}:{minutes:02}:{seconds:02}")
        } else {
            write!(f, "{prefix}{days} days, {hours}:{minutes:02}:{seconds:02}")
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum VmValue {
    None,
    Bool(bool),
    Int(BigInt),
    Float(f64),
    Decimal(VmDecimal),
    DateTime(VmDateTime),
    TimeDelta(VmTimeDelta),
    String(String),
    List(Vec<VmValue>),
    Tuple(Vec<VmValue>),
    Dict(Vec<(VmValue, VmValue)>),
    ContractHandle(VmContractHandle),
    StorageRef(VmStorageRef),
    EventRef(Box<VmEventDefinition>),
    Builtin(String),
    FunctionRef(String),
    TypeMarker(String),
    Exception(VmException),
}

impl VmValue {
    pub(crate) fn truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Bool(value) => *value,
            Self::Int(value) => !value.is_zero(),
            Self::Float(value) => *value != 0.0,
            Self::Decimal(value) => !value.is_zero(),
            Self::DateTime(_) => true,
            Self::TimeDelta(value) => value.seconds() != 0,
            Self::String(value) => !value.is_empty(),
            Self::List(values) | Self::Tuple(values) => !values.is_empty(),
            Self::Dict(entries) => !entries.is_empty(),
            Self::ContractHandle(_)
            | Self::StorageRef(_)
            | Self::EventRef(_)
            | Self::Builtin(_)
            | Self::FunctionRef(_)
            | Self::TypeMarker(_)
            | Self::Exception(_) => true,
        }
    }

    pub(crate) fn python_repr(&self) -> String {
        match self {
            Self::None => "None".to_owned(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Int(value) => value.to_string(),
            Self::Float(value) => format!("{value:?}"),
            Self::Decimal(value) => value.python_repr(),
            Self::DateTime(value) => value.to_string(),
            Self::TimeDelta(value) => value.to_string(),
            Self::String(value) => value.clone(),
            Self::List(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(VmValue::python_repr)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::Tuple(values) => {
                let mut rendered = values
                    .iter()
                    .map(VmValue::python_repr)
                    .collect::<Vec<_>>()
                    .join(", ");
                if values.len() == 1 {
                    rendered.push(',');
                }
                format!("({rendered})")
            }
            Self::Dict(entries) => format!(
                "{{{}}}",
                entries
                    .iter()
                    .map(|(key, value)| {
                        format!("{}: {}", key.python_repr(), value.python_repr())
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::ContractHandle(handle) => format!("<contract:{}>", handle.module),
            Self::StorageRef(storage) => format!("<storage:{}>", storage.binding),
            Self::EventRef(event) => format!("<event:{}>", event.event_name),
            Self::Builtin(name) => format!("<builtin:{name}>"),
            Self::FunctionRef(name) => format!("<function:{name}>"),
            Self::TypeMarker(name) => name.clone(),
            Self::Exception(value) => value.python_repr(),
        }
    }

    pub(crate) fn as_i64(&self) -> Result<i64, VmExecutionError> {
        match self {
            Self::Int(value) => bigint_to_i64(value, "integer value"),
            Self::Bool(value) => Ok(if *value { 1 } else { 0 }),
            Self::Decimal(value) => value.to_i64(),
            _ => Err(VmExecutionError::new(format!(
                "expected int-compatible value, got {}",
                self.type_name()
            ))),
        }
    }

    pub(crate) fn as_bigint(&self) -> Result<BigInt, VmExecutionError> {
        match self {
            Self::Int(value) => Ok(value.clone()),
            Self::Bool(value) => Ok(if *value {
                BigInt::from(1)
            } else {
                BigInt::zero()
            }),
            Self::Decimal(value) => Ok(value.to_bigint()),
            _ => Err(VmExecutionError::new(format!(
                "expected int-compatible value, got {}",
                self.type_name()
            ))),
        }
    }

    pub(crate) fn as_string(&self) -> Result<String, VmExecutionError> {
        match self {
            Self::String(value) => Ok(value.clone()),
            _ => Err(VmExecutionError::new(format!(
                "expected string value, got {}",
                self.type_name()
            ))),
        }
    }

    pub(crate) fn as_contract_handle(&self) -> Result<VmContractHandle, VmExecutionError> {
        match self {
            Self::ContractHandle(handle) => Ok(handle.clone()),
            _ => Err(VmExecutionError::new(format!(
                "expected contract handle, got {}",
                self.type_name()
            ))),
        }
    }

    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Decimal(_) => "decimal",
            Self::DateTime(_) => "datetime",
            Self::TimeDelta(_) => "timedelta",
            Self::String(_) => "str",
            Self::List(_) => "list",
            Self::Tuple(_) => "tuple",
            Self::Dict(_) => "dict",
            Self::ContractHandle(_) => "contract_handle",
            Self::StorageRef(_) => "storage_ref",
            Self::EventRef(_) => "event_ref",
            Self::Builtin(_) => "builtin",
            Self::FunctionRef(_) => "function_ref",
            Self::TypeMarker(_) => "type_marker",
            Self::Exception(_) => "exception",
        }
    }
}

impl fmt::Display for VmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.python_repr())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmStorageRef {
    pub binding: String,
    pub storage_type: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmException {
    pub name: String,
    pub args: Vec<VmValue>,
}

impl VmException {
    pub fn python_repr(&self) -> String {
        if self.args.is_empty() {
            return format!("{}()", self.name);
        }
        let rendered = self
            .args
            .iter()
            .map(python_exception_arg_repr)
            .collect::<Vec<_>>()
            .join(", ");
        format!("{}({rendered})", self.name)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmEventDefinition {
    pub binding: String,
    pub event_name: String,
    pub params: VmValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmContractHandle {
    pub module: String,
    pub origin: String,
}

fn python_exception_arg_repr(value: &VmValue) -> String {
    match value {
        VmValue::String(inner) => {
            let escaped = inner.replace('\\', "\\\\").replace('\'', "\\'");
            format!("'{escaped}'")
        }
        other => other.python_repr(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmContractTarget {
    StaticImport { binding: String, module: String },
    DynamicImport { module: String },
    LocalHandle { binding: String, module: String },
    FactoryCall { factory: String, module: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmContractCall {
    pub target: VmContractTarget,
    pub function: String,
    pub args: Vec<VmValue>,
    pub kwargs: Vec<(String, VmValue)>,
    pub caller_contract: Option<String>,
    pub signer: Option<String>,
    pub entry: Option<(String, String)>,
    pub submission_name: Option<String>,
    pub now: VmValue,
    pub block_num: VmValue,
    pub block_hash: VmValue,
    pub chain_id: VmValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmEvent {
    pub contract: String,
    pub event: String,
    pub signer: VmValue,
    pub caller: VmValue,
    pub data_indexed: Vec<(String, VmValue)>,
    pub data: Vec<(String, VmValue)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmExecutionContext {
    pub this: Option<String>,
    pub caller: Option<String>,
    pub signer: Option<String>,
    pub owner: Option<String>,
    pub entry: Option<(String, String)>,
    pub submission_name: Option<String>,
    pub now: VmValue,
    pub block_num: VmValue,
    pub block_hash: VmValue,
    pub chain_id: VmValue,
}

impl Default for VmExecutionContext {
    fn default() -> Self {
        Self {
            this: None,
            caller: None,
            signer: None,
            owner: None,
            entry: None,
            submission_name: None,
            now: VmValue::None,
            block_num: vm_int(-1),
            block_hash: VmValue::None,
            chain_id: VmValue::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmExecutionError {
    message: String,
}

impl VmExecutionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self::new(message)
    }
}

impl fmt::Display for VmExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::{VmDecimal, VmValue};

    #[test]
    fn formats_decimal_python_repr_like_contracting_decimal_strings() {
        let cases = [
            ("1000", "1E+3"),
            ("50000000", "50E+6"),
            ("1234000", "1.234E+6"),
            ("1234500", "1.2345E+6"),
            ("0.0001", "0.0001"),
            ("0.0000001", "100E-9"),
            ("1234.5", "1234.5"),
            ("12345", "12345"),
        ];
        for (literal, expected) in cases {
            let value = VmDecimal::from_str_literal(literal).expect("decimal literal should parse");
            assert_eq!(VmValue::Decimal(value.clone()).python_repr(), expected);
        }
    }

    #[test]
    fn preserves_plain_decimal_strings_for_state_values() {
        let cases = [
            ("1000", "1000"),
            ("50000000", "50000000"),
            ("1234500", "1234500"),
            ("0.0000001", "0.0000001"),
        ];
        for (literal, expected) in cases {
            let value = VmDecimal::from_str_literal(literal).expect("decimal literal should parse");
            assert_eq!(value.to_string(), expected);
        }
    }
}

impl std::error::Error for VmExecutionError {}
