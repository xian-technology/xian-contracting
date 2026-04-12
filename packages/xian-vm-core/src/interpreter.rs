use crate::{validate_module_ir, FunctionIr, ModuleIr};
use chrono::{Datelike, Duration, NaiveDate, NaiveDateTime, Timelike};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use num_bigint::{BigInt, Sign};
use num_traits::{Num, Signed, ToPrimitive, Zero};
use serde_json::{Map, Value};
use sha2::Digest as Sha2Digest;
use sha2::Sha256;
use sha3::Sha3_256;
use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt;
use std::str::FromStr;
use std::sync::OnceLock;

const STORAGE_DELIMITER: &str = ":";
const STORAGE_INDEX_SEPARATOR: &str = ".";
const MAX_HASH_DIMENSIONS: usize = 16;
const MAX_STORAGE_KEY_SIZE: usize = 1024;
const DECIMAL_SCALE: u32 = 30;
const DECIMAL_MAX_SCALED_DIGITS: u32 = 91;
pub(crate) const VM_GAS_CALL_DISPATCH: u64 = 5_000;
const VM_GAS_EVENT_EMIT: u64 = 8_000;
const VM_GAS_VARIABLE_GET: u64 = 1_280;
const VM_GAS_VARIABLE_SET: u64 = 5_120;
const VM_GAS_FUNCTION_ENTRY_COMPLEXITY_FLOOR: u64 = 40;
const VM_GAS_FUNCTION_ENTRY_EXCESS_NODE: u64 = 150;
const VM_GAS_LOOP_ITERATION: u64 = 96;
const VM_GAS_STMT_ASSIGN: u64 = 64;
const VM_GAS_STMT_STORAGE_SET: u64 = 5_120;
const VM_GAS_STMT_STORAGE_MUTATE: u64 = 5_120;
const VM_GAS_STMT_AUG_ASSIGN: u64 = 96;
const VM_GAS_STMT_RETURN: u64 = 32;
const VM_GAS_STMT_EXPR: u64 = 32;
const VM_GAS_STMT_IF: u64 = 96;
const VM_GAS_STMT_FOR: u64 = 96;
const VM_GAS_STMT_ASSERT: u64 = 96;
const VM_GAS_STMT_BREAK: u64 = 32;
const VM_GAS_STMT_CONTINUE: u64 = 32;
const VM_GAS_STMT_PASS: u64 = 32;
const VM_GAS_EXPR_NAME: u64 = 64;
const VM_GAS_EXPR_CONSTANT: u64 = 32;
const VM_GAS_EXPR_LIST: u64 = 128;
const VM_GAS_EXPR_TUPLE: u64 = 128;
const VM_GAS_EXPR_DICT: u64 = 608;
const VM_GAS_EXPR_ATTRIBUTE: u64 = 96;
const VM_GAS_EXPR_SUBSCRIPT: u64 = 96;
const VM_GAS_EXPR_STORAGE_GET: u64 = 1_280;
const VM_GAS_EXPR_COMPARE: u64 = 96;
const VM_GAS_EXPR_BOOL_OP: u64 = 96;
const VM_GAS_EXPR_BINARY_OP: u64 = 96;
const VM_GAS_EXPR_UNARY_OP: u64 = 64;
const VM_GAS_EXPR_IF_EXPR: u64 = 96;
const VM_GAS_EXPR_F_STRING: u64 = 96;
const VM_GAS_EXPR_FORMATTED_VALUE: u64 = 96;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmDecimal {
    scaled: BigInt,
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

    fn from_vm_value(value: &VmValue) -> Result<Self, VmExecutionError> {
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

    fn from_scaled(scaled: BigInt) -> Result<Self, VmExecutionError> {
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

    fn zero() -> Self {
        Self {
            scaled: BigInt::zero(),
        }
    }

    fn is_zero(&self) -> bool {
        self.scaled.is_zero()
    }

    fn to_i64(&self) -> Result<i64, VmExecutionError> {
        bigint_to_i64(&self.to_bigint(), &format!("decimal value {}", self))
    }

    fn to_bigint(&self) -> BigInt {
        &self.scaled / decimal_scale_factor()
    }

    fn to_f64(&self) -> Result<f64, VmExecutionError> {
        self.to_string().parse::<f64>().map_err(|_| {
            VmExecutionError::new(format!(
                "decimal value {} cannot be converted to float",
                self
            ))
        })
    }

    fn add(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_scaled(&self.scaled + &other.scaled)
    }

    fn sub(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_scaled(&self.scaled - &other.scaled)
    }

    fn mul(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_scaled((&self.scaled * &other.scaled) / decimal_scale_factor())
    }

    fn div(&self, other: &Self) -> Result<Self, VmExecutionError> {
        if other.is_zero() {
            return Err(VmExecutionError::new("division by zero"));
        }
        Self::from_scaled((&self.scaled * decimal_scale_factor()) / &other.scaled)
    }

    fn modulo(&self, other: &Self) -> Result<Self, VmExecutionError> {
        if other.is_zero() {
            return Err(VmExecutionError::new("modulo by zero"));
        }
        Self::from_scaled(&self.scaled % &other.scaled)
    }

    fn floor_div(&self, other: &Self) -> Result<Self, VmExecutionError> {
        if other.is_zero() {
            return Err(VmExecutionError::new("division by zero"));
        }
        let quotient = &self.scaled / &other.scaled;
        Self::from_scaled(quotient * decimal_scale_factor())
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

fn decimal_max_scaled() -> &'static BigInt {
    static MAX_SCALED: OnceLock<BigInt> = OnceLock::new();
    MAX_SCALED.get_or_init(|| BigInt::from(10u8).pow(DECIMAL_MAX_SCALED_DIGITS) - BigInt::from(1u8))
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

fn vm_int<T>(value: T) -> VmValue
where
    T: Into<BigInt>,
{
    VmValue::Int(value.into())
}

fn bigint_to_i64(value: &BigInt, context: &str) -> Result<i64, VmExecutionError> {
    value
        .to_i64()
        .ok_or_else(|| VmExecutionError::new(format!("{context} exceeds the supported i64 range")))
}

fn bigint_to_u32(value: &BigInt, context: &str) -> Result<u32, VmExecutionError> {
    if value.sign() == Sign::Minus {
        return Err(VmExecutionError::new(format!(
            "{context} must be non-negative"
        )));
    }
    value
        .to_u32()
        .ok_or_else(|| VmExecutionError::new(format!("{context} exceeds the supported u32 range")))
}

fn bigint_to_usize(value: &BigInt, context: &str) -> Result<usize, VmExecutionError> {
    if value.sign() == Sign::Minus {
        return Err(VmExecutionError::new(format!(
            "{context} must be non-negative"
        )));
    }
    value.to_usize().ok_or_else(|| {
        VmExecutionError::new(format!("{context} exceeds the supported usize range"))
    })
}

fn bigint_to_f64(value: &BigInt, context: &str) -> Result<f64, VmExecutionError> {
    value.to_f64().ok_or_else(|| {
        VmExecutionError::new(format!("{context} exceeds the supported float range"))
    })
}

fn f64_to_bigint_trunc(value: f64, context: &str) -> Result<BigInt, VmExecutionError> {
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

fn bigint_floor_div(left: &BigInt, right: &BigInt) -> Result<BigInt, VmExecutionError> {
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

fn bigint_modulo(left: &BigInt, right: &BigInt) -> Result<BigInt, VmExecutionError> {
    let quotient = bigint_floor_div(left, right)?;
    Ok(left - (quotient * right))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmDateTime {
    value: NaiveDateTime,
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
    raw_seconds: i64,
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
}

impl VmValue {
    fn truthy(&self) -> bool {
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
            | Self::TypeMarker(_) => true,
        }
    }

    pub(crate) fn python_repr(&self) -> String {
        match self {
            Self::None => "None".to_owned(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Int(value) => value.to_string(),
            Self::Float(value) => format!("{value:?}"),
            Self::Decimal(value) => value.to_string(),
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
        }
    }

    fn as_i64(&self) -> Result<i64, VmExecutionError> {
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

    fn as_bigint(&self) -> Result<BigInt, VmExecutionError> {
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

    fn as_string(&self) -> Result<String, VmExecutionError> {
        match self {
            Self::String(value) => Ok(value.clone()),
            _ => Err(VmExecutionError::new(format!(
                "expected string value, got {}",
                self.type_name()
            ))),
        }
    }

    fn as_contract_handle(&self) -> Result<VmContractHandle, VmExecutionError> {
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
        }
    }
}

fn vm_trace_enabled(flag: &str) -> bool {
    env::var_os(flag).is_some()
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

    fn unsupported(message: impl Into<String>) -> Self {
        Self::new(message)
    }
}

impl fmt::Display for VmExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VmExecutionError {}

fn vm_statement_gas_cost(
    node: &str,
    _object: &Map<String, Value>,
) -> Result<u64, VmExecutionError> {
    Ok(match node {
        "assign" => VM_GAS_STMT_ASSIGN,
        "storage_set" => VM_GAS_STMT_STORAGE_SET,
        "storage_mutate" => VM_GAS_STMT_STORAGE_MUTATE,
        "aug_assign" => VM_GAS_STMT_AUG_ASSIGN,
        "return" => VM_GAS_STMT_RETURN,
        "expr" => VM_GAS_STMT_EXPR,
        "if" => VM_GAS_STMT_IF,
        "for" => VM_GAS_STMT_FOR,
        "assert" => VM_GAS_STMT_ASSERT,
        "break" => VM_GAS_STMT_BREAK,
        "continue" => VM_GAS_STMT_CONTINUE,
        "pass" => VM_GAS_STMT_PASS,
        other => {
            return Err(VmExecutionError::new(format!(
                "unsupported statement node '{other}'"
            )))
        }
    })
}

fn vm_expression_gas_cost(
    node: &str,
    object: &Map<String, Value>,
) -> Result<u64, VmExecutionError> {
    Ok(match node {
        "name" => VM_GAS_EXPR_NAME,
        "constant" => VM_GAS_EXPR_CONSTANT,
        "list" => VM_GAS_EXPR_LIST,
        "tuple" => VM_GAS_EXPR_TUPLE,
        "dict" => VM_GAS_EXPR_DICT,
        "attribute" => VM_GAS_EXPR_ATTRIBUTE,
        "subscript" => VM_GAS_EXPR_SUBSCRIPT,
        "storage_get" => VM_GAS_EXPR_STORAGE_GET,
        "slice" => VM_GAS_EXPR_SUBSCRIPT,
        "call" => VM_GAS_CALL_DISPATCH,
        "compare" => {
            let comparisons = required_array(object, "operators")?.len().max(1) as u64;
            VM_GAS_EXPR_COMPARE * comparisons
        }
        "bool_op" => {
            let branches = required_array(object, "values")?.len().saturating_sub(1).max(1) as u64;
            VM_GAS_EXPR_BOOL_OP * branches
        }
        "bin_op" => VM_GAS_EXPR_BINARY_OP,
        "unary_op" => VM_GAS_EXPR_UNARY_OP,
        "if_expr" => VM_GAS_EXPR_IF_EXPR,
        "f_string" => {
            let segments = required_array(object, "values")?.len().max(1) as u64;
            VM_GAS_EXPR_F_STRING * segments
        }
        "formatted_value" => VM_GAS_EXPR_FORMATTED_VALUE,
        other => {
            return Err(VmExecutionError::new(format!(
                "unsupported expression node '{other}'"
            )))
        }
    })
}

fn charge_storage_read(
    host: &mut dyn VmHost,
    key: &str,
    value: &VmValue,
) -> Result<(), VmExecutionError> {
    host.charge_storage_read(key, value)
}

fn ir_node_complexity(value: &Value) -> u64 {
    match value {
        Value::Object(object) => {
            let self_cost = if object.contains_key("node") { 1 } else { 0 };
            self_cost
                + object
                    .values()
                    .map(ir_node_complexity)
                    .sum::<u64>()
        }
        Value::Array(items) => items.iter().map(ir_node_complexity).sum(),
        _ => 0,
    }
}

fn function_entry_gas_cost(function: &FunctionIr) -> u64 {
    let mut complexity = 0;
    for parameter in &function.parameters {
        if let Some(default) = &parameter.default {
            complexity += ir_node_complexity(default);
        }
    }
    complexity += function.body.iter().map(ir_node_complexity).sum::<u64>();
    complexity
        .saturating_sub(VM_GAS_FUNCTION_ENTRY_COMPLEXITY_FLOOR)
        .saturating_mul(VM_GAS_FUNCTION_ENTRY_EXCESS_NODE)
}

pub trait VmHost {
    fn charge_execution_cost(&mut self, _cost: u64) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn charge_storage_read(
        &mut self,
        _key: &str,
        _value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn charge_storage_write(
        &mut self,
        _key: &str,
        _value: &VmValue,
    ) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn emit_event(&mut self, _event: VmEvent) -> Result<(), VmExecutionError> {
        Ok(())
    }

    fn read_variable(
        &mut self,
        _contract: &str,
        _binding: &str,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        Ok(None)
    }

    fn read_hash(
        &mut self,
        _contract: &str,
        _binding: &str,
        _key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        Ok(None)
    }

    fn load_owner(
        &mut self,
        _contract: &str,
    ) -> Result<Option<String>, VmExecutionError> {
        Ok(None)
    }

    fn call_contract(&mut self, call: VmContractCall) -> Result<VmValue, VmExecutionError> {
        Err(VmExecutionError::unsupported(format!(
            "host does not support contract call {}.{}",
            contract_target_label(&call.target),
            call.function
        )))
    }

    fn handle_syscall(
        &mut self,
        syscall_id: &str,
        _args: Vec<VmValue>,
        _kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        Err(VmExecutionError::unsupported(format!(
            "unsupported host syscall '{syscall_id}'"
        )))
    }
}

#[derive(Debug, Clone, PartialEq)]
struct VariableState {
    default_value: VmValue,
    value: Option<VmValue>,
    foreign_key: Option<String>,
    snapshot_local: bool,
    dirty: bool,
}

#[derive(Debug, Clone, PartialEq)]
struct HashState {
    default_value: VmValue,
    entries: HashMap<String, VmValue>,
    foreign_key: Option<String>,
    snapshot_local: bool,
    dirty_entries: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmVariableSnapshot {
    pub binding: String,
    pub default_value: VmValue,
    pub value: Option<VmValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmHashSnapshot {
    pub binding: String,
    pub default_value: VmValue,
    pub entries: HashMap<String, VmValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmModuleStorageSnapshot {
    pub contract_name: String,
    pub variables: Vec<VmVariableSnapshot>,
    pub hashes: Vec<VmHashSnapshot>,
}

#[derive(Debug, Clone, PartialEq)]
enum ControlFlow {
    Next,
    Return(VmValue),
    Break,
    Continue,
}

enum NativeMethodResult {
    Value(VmValue),
    Mutated { receiver: VmValue, value: VmValue },
}

pub struct VmInstance {
    module: ModuleIr,
    functions: HashMap<String, FunctionIr>,
    imports: HashMap<String, String>,
    globals: HashMap<String, VmValue>,
    variables: HashMap<String, VariableState>,
    hashes: HashMap<String, HashState>,
    context: VmExecutionContext,
}

impl VmInstance {
    pub fn new(module: ModuleIr, context: VmExecutionContext) -> Result<Self, VmExecutionError> {
        Self::new_with_host(module, context, &mut NoopHost {})
    }

    pub fn new_with_host(
        module: ModuleIr,
        context: VmExecutionContext,
        host: &mut dyn VmHost,
    ) -> Result<Self, VmExecutionError> {
        validate_module_ir(&module).map_err(|err| VmExecutionError::new(err.to_string()))?;

        let functions = module
            .functions
            .iter()
            .cloned()
            .map(|function| (function.name.clone(), function))
            .collect::<HashMap<_, _>>();
        let imports = module
            .imports
            .iter()
            .map(|import| {
                (
                    import
                        .alias
                        .clone()
                        .unwrap_or_else(|| import.module.clone()),
                    import.module.clone(),
                )
            })
            .collect::<HashMap<_, _>>();

        let mut instance = Self {
            module,
            functions,
            imports,
            globals: HashMap::new(),
            variables: HashMap::new(),
            hashes: HashMap::new(),
            context,
        };

        if instance.context.this.is_none() {
            instance.context.this = Some(instance.module.module_name.clone());
        }

        for (binding, module) in instance.imports.clone() {
            instance.globals.insert(
                binding,
                VmValue::ContractHandle(VmContractHandle {
                    module,
                    origin: "static_import".to_owned(),
                }),
            );
        }

        let declarations = instance.module.global_declarations.clone();
        for declaration in &declarations {
            instance.apply_global_declaration(declaration, host)?;
        }

        let module_body = instance.module.module_body.clone();
        if !module_body.is_empty() {
            let mut scope = instance.globals.clone();
            let flow = instance.execute_block(&module_body, &mut scope, host)?;
            if flow != ControlFlow::Next {
                return Err(VmExecutionError::new(
                    "module body cannot return or break execution",
                ));
            }
            instance.globals = scope;
        }

        Ok(instance)
    }

    pub fn context(&self) -> &VmExecutionContext {
        &self.context
    }

    pub fn context_mut(&mut self) -> &mut VmExecutionContext {
        &mut self.context
    }

    pub fn has_export(&self, name: &str) -> bool {
        self.functions
            .get(name)
            .map(|function| function.visibility == "export")
            .unwrap_or(false)
    }

    pub fn storage_snapshot(&self) -> VmModuleStorageSnapshot {
        VmModuleStorageSnapshot {
            contract_name: self.module.module_name.clone(),
            variables: self
                .variables
                .iter()
                .filter(|(_, state)| state.snapshot_local && state.dirty)
                .map(|(binding, state)| VmVariableSnapshot {
                    binding: binding.clone(),
                    default_value: state.default_value.clone(),
                    value: state.value.clone(),
                })
                .collect(),
            hashes: self
                .hashes
                .iter()
                .filter(|(_, state)| state.snapshot_local)
                .map(|(binding, state)| VmHashSnapshot {
                    binding: binding.clone(),
                    default_value: state.default_value.clone(),
                    entries: state
                        .entries
                        .iter()
                        .filter(|(key, _)| state.dirty_entries.contains(*key))
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                })
                .filter(|snapshot| !snapshot.entries.is_empty())
                .collect(),
        }
    }

    pub fn apply_foreign_snapshot(&mut self, snapshot: &VmModuleStorageSnapshot) {
        for variable in &snapshot.variables {
            self.variables.insert(
                foreign_storage_key(&snapshot.contract_name, &variable.binding),
                VariableState {
                    default_value: variable.default_value.clone(),
                    value: variable.value.clone(),
                    foreign_key: None,
                    snapshot_local: false,
                    dirty: false,
                },
            );
        }
        for hash in &snapshot.hashes {
            self.hashes.insert(
                foreign_storage_key(&snapshot.contract_name, &hash.binding),
                HashState {
                    default_value: hash.default_value.clone(),
                    entries: hash.entries.clone(),
                    foreign_key: None,
                    snapshot_local: false,
                    dirty_entries: HashSet::new(),
                },
            );
        }
    }

    pub fn set_foreign_variable(
        &mut self,
        foreign_contract: &str,
        foreign_name: &str,
        value: VmValue,
    ) {
        let key = foreign_storage_key(foreign_contract, foreign_name);
        self.variables
            .entry(key)
            .and_modify(|state| state.value = Some(value.clone()))
            .or_insert(VariableState {
                default_value: VmValue::None,
                value: Some(value),
                foreign_key: None,
                snapshot_local: false,
                dirty: false,
            });
    }

    pub fn set_foreign_hash_value(
        &mut self,
        foreign_contract: &str,
        foreign_name: &str,
        key: &VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        let storage_key = foreign_storage_key(foreign_contract, foreign_name);
        let normalized = normalize_hash_key(key)?;
        self.hashes
            .entry(storage_key)
            .and_modify(|state| {
                state.entries.insert(normalized.clone(), value.clone());
            })
            .or_insert_with(|| {
                let mut entries = HashMap::new();
                entries.insert(normalized, value);
                HashState {
                    default_value: VmValue::None,
                    entries,
                    foreign_key: None,
                    snapshot_local: false,
                    dirty_entries: HashSet::new(),
                }
            });
        Ok(())
    }

    pub fn get_variable(&self, binding: &str) -> Option<VmValue> {
        self.variables.get(binding).map(|state| {
            state
                .value
                .clone()
                .unwrap_or_else(|| state.default_value.clone())
        })
    }

    pub fn get_hash_value(
        &self,
        binding: &str,
        key: &VmValue,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let normalized = normalize_hash_key(key)?;
        Ok(self.hashes.get(binding).map(|state| {
            state
                .entries
                .get(&normalized)
                .cloned()
                .unwrap_or_else(|| state.default_value.clone())
        }))
    }

    pub fn set_variable_state(
        &mut self,
        binding: &str,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        self.variable_set(binding, value)
    }

    pub fn set_hash_value(
        &mut self,
        binding: &str,
        key: &VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        self.hash_set(binding, key, value)
    }

    pub fn call_function(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        let trace_calls = vm_trace_enabled("XIAN_VM_TRACE_CALLS");
        if trace_calls {
            eprintln!(
                "[vm-call] enter {}.{} caller={} signer={}",
                self.module.module_name,
                name,
                option_string_value(&self.context.caller).python_repr(),
                option_string_value(&self.context.signer).python_repr(),
            );
        }
        let previous_entry = self.context.entry.clone();
        let injected_entry = if self.context.entry.is_none() {
            self.context.entry = Some((self.module.module_name.clone(), name.to_owned()));
            true
        } else {
            false
        };
        let result = self.call_named_function(host, name, args, kwargs);
        if injected_entry {
            self.context.entry = previous_entry;
        }
        if trace_calls {
            match &result {
                Ok(value) => eprintln!(
                    "[vm-call] exit {}.{} -> {} ({})",
                    self.module.module_name,
                    name,
                    value.python_repr(),
                    value.type_name(),
                ),
                Err(err) => eprintln!(
                    "[vm-call] error {}.{} -> {}",
                    self.module.module_name,
                    name,
                    err
                ),
            }
        }
        result
    }

    fn eval_slice_subscript(
        &mut self,
        value: VmValue,
        slice: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let lower = match slice.get("lower") {
            Some(Value::Null) | None => None,
            Some(lower) => Some(self.eval_expression(lower, scope, host)?.as_bigint()?),
        };
        let upper = match slice.get("upper") {
            Some(Value::Null) | None => None,
            Some(upper) => Some(self.eval_expression(upper, scope, host)?.as_bigint()?),
        };
        let step = match slice.get("step") {
            Some(Value::Null) | None => None,
            Some(step) => Some(self.eval_expression(step, scope, host)?.as_bigint()?),
        };
        subscript_slice_value(value, lower, upper, step)
    }

    fn apply_global_declaration(
        &mut self,
        declaration: &Value,
        host: &mut dyn VmHost,
    ) -> Result<(), VmExecutionError> {
        let object = as_object(declaration, "global declaration")?;
        let node = required_string(object, "node")?;
        match node {
            "storage_decl" => {
                let binding = required_string(object, "name")?.to_owned();
                let storage_type = required_string(object, "storage_type")?.to_owned();
                let args = required_array(object, "args")?;
                let keywords = required_array(object, "keywords")?;

                match storage_type.as_str() {
                    "Variable" | "ForeignVariable" => {
                        let state = self.build_variable_state(
                            &binding,
                            &storage_type,
                            args,
                            keywords,
                            host,
                        )?;
                        self.variables.insert(binding.clone(), state);
                    }
                    "Hash" | "ForeignHash" => {
                        let state = self.build_hash_state(
                            &binding,
                            &storage_type,
                            args,
                            keywords,
                            host,
                        )?;
                        self.hashes.insert(binding.clone(), state);
                    }
                    other => {
                        return Err(VmExecutionError::new(format!(
                            "unsupported storage declaration type '{other}'"
                        )))
                    }
                }

                self.globals.insert(
                    binding.clone(),
                    VmValue::StorageRef(VmStorageRef {
                        binding,
                        storage_type,
                    }),
                );
                Ok(())
            }
            "event_decl" => {
                let binding = required_string(object, "name")?.to_owned();
                let event_name = required_string(object, "event_name")?.to_owned();
                let params = self.eval_expression(
                    required_value(object, "params")?,
                    &mut self.globals.clone(),
                    host,
                )?;
                self.globals.insert(
                    binding.clone(),
                    VmValue::EventRef(Box::new(VmEventDefinition {
                        binding,
                        event_name,
                        params,
                    })),
                );
                Ok(())
            }
            "binding_decl" => {
                let binding = required_string(object, "name")?.to_owned();
                let value = self.eval_expression(
                    required_value(object, "value")?,
                    &mut self.globals.clone(),
                    host,
                )?;
                self.globals.insert(binding, value);
                Ok(())
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported global declaration node '{other}'"
            ))),
        }
    }

    fn build_variable_state(
        &mut self,
        binding: &str,
        storage_type: &str,
        args: &[Value],
        keywords: &[Value],
        host: &mut dyn VmHost,
    ) -> Result<VariableState, VmExecutionError> {
        let default_value = if storage_type == "Variable" {
            keyword_value(self, keywords, "default_value", host)?.unwrap_or(VmValue::None)
        } else {
            VmValue::None
        };

        let foreign_key = if storage_type == "ForeignVariable" {
            let foreign_contract = keyword_value(self, keywords, "foreign_contract", host)?
                .or_else(|| positional_value(self, args, 2, host).ok().flatten())
                .ok_or_else(|| {
                    VmExecutionError::new(format!(
                        "ForeignVariable '{binding}' requires foreign_contract"
                    ))
                })?
                .as_string()?;
            let foreign_name = keyword_value(self, keywords, "foreign_name", host)?
                .or_else(|| positional_value(self, args, 3, host).ok().flatten())
                .ok_or_else(|| {
                    VmExecutionError::new(format!(
                        "ForeignVariable '{binding}' requires foreign_name"
                    ))
                })?
                .as_string()?;
            Some(foreign_storage_key(&foreign_contract, &foreign_name))
        } else {
            None
        };

        Ok(VariableState {
            default_value,
            value: None,
            foreign_key,
            snapshot_local: storage_type == "Variable",
            dirty: false,
        })
    }

    fn build_hash_state(
        &mut self,
        binding: &str,
        storage_type: &str,
        args: &[Value],
        keywords: &[Value],
        host: &mut dyn VmHost,
    ) -> Result<HashState, VmExecutionError> {
        let default_value =
            keyword_value(self, keywords, "default_value", host)?.unwrap_or(VmValue::None);
        let foreign_key = if storage_type == "ForeignHash" {
            let foreign_contract = keyword_value(self, keywords, "foreign_contract", host)?
                .or_else(|| positional_value(self, args, 2, host).ok().flatten())
                .ok_or_else(|| {
                    VmExecutionError::new(format!(
                        "ForeignHash '{binding}' requires foreign_contract"
                    ))
                })?
                .as_string()?;
            let foreign_name = keyword_value(self, keywords, "foreign_name", host)?
                .or_else(|| positional_value(self, args, 3, host).ok().flatten())
                .ok_or_else(|| {
                    VmExecutionError::new(format!("ForeignHash '{binding}' requires foreign_name"))
                })?
                .as_string()?;
            Some(foreign_storage_key(&foreign_contract, &foreign_name))
        } else {
            None
        };

        Ok(HashState {
            default_value,
            entries: HashMap::new(),
            foreign_key,
            snapshot_local: storage_type == "Hash",
            dirty_entries: HashSet::new(),
        })
    }

    fn call_named_function(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        let function = self
            .functions
            .get(name)
            .cloned()
            .ok_or_else(|| VmExecutionError::new(format!("unknown function '{name}'")))?;
        host.charge_execution_cost(function_entry_gas_cost(&function))?;
        let mut scope = self.bind_function_arguments(&function, args, kwargs, host)?;
        match self.execute_block(&function.body, &mut scope, host)? {
            ControlFlow::Next => Ok(VmValue::None),
            ControlFlow::Return(value) => Ok(value),
            ControlFlow::Break | ControlFlow::Continue => Err(VmExecutionError::new(format!(
                "function '{name}' leaked loop control"
            ))),
        }
    }

    fn bind_function_arguments(
        &mut self,
        function: &FunctionIr,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<HashMap<String, VmValue>, VmExecutionError> {
        let mut remaining_args = args;
        let mut remaining_kwargs = kwargs.into_iter().collect::<HashMap<_, _>>();
        let mut bound = HashMap::new();
        let mut vararg_name = None;
        let mut kwarg_name = None;

        for parameter in &function.parameters {
            match parameter.kind.as_str() {
                "positional_or_keyword" => {
                    if !remaining_args.is_empty() {
                        bound.insert(parameter.name.clone(), remaining_args.remove(0));
                        continue;
                    }
                    if let Some(value) = remaining_kwargs.remove(&parameter.name) {
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    if let Some(default) = &parameter.default {
                        let value = self.eval_expression(default, &mut bound.clone(), host)?;
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    return Err(VmExecutionError::new(format!(
                        "missing required argument '{}'",
                        parameter.name
                    )));
                }
                "keyword_only" => {
                    if let Some(value) = remaining_kwargs.remove(&parameter.name) {
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    if let Some(default) = &parameter.default {
                        let value = self.eval_expression(default, &mut bound.clone(), host)?;
                        bound.insert(parameter.name.clone(), value);
                        continue;
                    }
                    return Err(VmExecutionError::new(format!(
                        "missing required keyword-only argument '{}'",
                        parameter.name
                    )));
                }
                "vararg" => {
                    vararg_name = Some(parameter.name.clone());
                }
                "kwarg" => {
                    kwarg_name = Some(parameter.name.clone());
                }
                other => {
                    return Err(VmExecutionError::new(format!(
                        "unsupported parameter kind '{other}'"
                    )))
                }
            }
        }

        if let Some(name) = vararg_name {
            bound.insert(name, VmValue::Tuple(remaining_args));
            remaining_args = Vec::new();
        }

        if !remaining_args.is_empty() {
            return Err(VmExecutionError::new(format!(
                "too many positional arguments for '{}'",
                function.name
            )));
        }

        if let Some(name) = kwarg_name {
            let mut entries = Vec::new();
            for (key, value) in remaining_kwargs.drain() {
                entries.push((VmValue::String(key), value));
            }
            bound.insert(name, VmValue::Dict(entries));
        } else if let Some(unexpected) = remaining_kwargs.keys().next() {
            return Err(VmExecutionError::new(format!(
                "unexpected keyword argument '{unexpected}'"
            )));
        }

        Ok(bound)
    }

    fn execute_block(
        &mut self,
        statements: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        for statement in statements {
            let flow = self.execute_statement(statement, scope, host)?;
            if flow != ControlFlow::Next {
                return Ok(flow);
            }
        }
        Ok(ControlFlow::Next)
    }

    fn execute_statement(
        &mut self,
        statement: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let object = as_object(statement, "statement")?;
        let node = required_string(object, "node")?;
        host.charge_execution_cost(vm_statement_gas_cost(node, object)?)?;
        let trace_statements = vm_trace_enabled("XIAN_VM_TRACE_STATEMENTS");
        if trace_statements {
            eprintln!("[vm-stmt] {} {}", self.module.module_name, node);
        }
        match node {
            "assign" => {
                let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
                for target in required_array(object, "targets")? {
                    self.assign_target(target, value.clone(), scope, false)?;
                }
                Ok(ControlFlow::Next)
            }
            "storage_set" => {
                let binding = required_string(object, "binding")?;
                let key = self.eval_expression(required_value(object, "key")?, scope, host)?;
                let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
                self.hash_set(binding, &key, value.clone())?;
                host.charge_storage_write(
                    &hash_storage_key(&self.module.module_name, binding, &key)?,
                    &value,
                )?;
                Ok(ControlFlow::Next)
            }
            "storage_mutate" => {
                let binding = required_string(object, "binding")?;
                let key = self.eval_expression(required_value(object, "key")?, scope, host)?;
                let current = self.hash_get(binding, &key, host)?;
                let operand =
                    self.eval_expression(required_value(object, "value")?, scope, host)?;
                let operator = required_string(object, "operator")?;
                let result = apply_binary_operator(operator, current, operand)?;
                self.hash_set(binding, &key, result.clone())?;
                host.charge_storage_write(
                    &hash_storage_key(&self.module.module_name, binding, &key)?,
                    &result,
                )?;
                Ok(ControlFlow::Next)
            }
            "aug_assign" => {
                let target = required_value(object, "target")?;
                let current = self.eval_target_value(target, scope, host)?;
                let operand =
                    self.eval_expression(required_value(object, "value")?, scope, host)?;
                let result =
                    apply_binary_operator(required_string(object, "operator")?, current, operand)?;
                self.assign_target(target, result, scope, false)?;
                Ok(ControlFlow::Next)
            }
            "return" => {
                let value = match object.get("value") {
                    Some(Value::Null) | None => VmValue::None,
                    Some(value) => self.eval_expression(value, scope, host)?,
                };
                Ok(ControlFlow::Return(value))
            }
            "expr" => {
                self.eval_expression(required_value(object, "value")?, scope, host)?;
                Ok(ControlFlow::Next)
            }
            "if" => {
                let test = self.eval_expression(required_value(object, "test")?, scope, host)?;
                if test.truthy() {
                    self.execute_block(required_array(object, "body")?, scope, host)
                } else {
                    self.execute_block(required_array(object, "orelse")?, scope, host)
                }
            }
            "for" => self.execute_for_loop(object, scope, host),
            "assert" => {
                let test = self.eval_expression(required_value(object, "test")?, scope, host)?;
                if !test.truthy() {
                    let error_repr = object
                        .get("message")
                        .map(|value| self.eval_expression(value, scope, host))
                        .transpose()?
                        .map(|message| format!("AssertionError({})", message.python_repr()))
                        .unwrap_or_else(|| "AssertionError()".to_owned());
                    return Err(VmExecutionError::new(error_repr));
                }
                Ok(ControlFlow::Next)
            }
            "break" => Ok(ControlFlow::Break),
            "continue" => Ok(ControlFlow::Continue),
            "pass" => Ok(ControlFlow::Next),
            other => Err(VmExecutionError::new(format!(
                "unsupported statement node '{other}'"
            ))),
        }
    }

    fn execute_for_loop(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<ControlFlow, VmExecutionError> {
        let iter_value = self.eval_expression(required_value(object, "iter")?, scope, host)?;
        let values = iterate_value(&iter_value)?;
        let body = required_array(object, "body")?;
        let orelse = required_array(object, "orelse")?;

        let mut broke = false;
        for item in values {
            host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
            self.assign_target(required_value(object, "target")?, item, scope, false)?;
            match self.execute_block(body, scope, host)? {
                ControlFlow::Next => {}
                ControlFlow::Continue => continue,
                ControlFlow::Break => {
                    broke = true;
                    break;
                }
                ControlFlow::Return(value) => return Ok(ControlFlow::Return(value)),
            }
        }

        if !broke {
            self.execute_block(orelse, scope, host)
        } else {
            Ok(ControlFlow::Next)
        }
    }

    fn assign_target(
        &mut self,
        target: &Value,
        value: VmValue,
        scope: &mut HashMap<String, VmValue>,
        module_scope: bool,
    ) -> Result<(), VmExecutionError> {
        let object = as_object(target, "target")?;
        match required_string(object, "node")? {
            "name" => {
                let id = required_string(object, "id")?.to_owned();
                if module_scope {
                    self.globals.insert(id.clone(), value.clone());
                }
                scope.insert(id, value);
                Ok(())
            }
            "tuple_target" | "list_target" => {
                let items = match value {
                    VmValue::List(items) | VmValue::Tuple(items) => items,
                    other => {
                        return Err(VmExecutionError::new(format!(
                            "cannot destructure {}",
                            other.type_name()
                        )))
                    }
                };
                let elements = required_array(object, "elements")?;
                if elements.len() != items.len() {
                    return Err(VmExecutionError::new(
                        "destructuring target count does not match value length",
                    ));
                }
                for (target, item) in elements.iter().zip(items.into_iter()) {
                    self.assign_target(target, item, scope, module_scope)?;
                }
                Ok(())
            }
            "subscript" => {
                let container = self.eval_expression(
                    required_value(object, "value")?,
                    scope,
                    &mut NoopHost {},
                )?;
                let index = self.eval_expression(
                    required_value(object, "slice")?,
                    scope,
                    &mut NoopHost {},
                )?;
                let updated = assign_subscript(container, &index, value)?;
                self.assign_target(
                    required_value(object, "value")?,
                    updated,
                    scope,
                    module_scope,
                )
            }
            "attribute" => Err(VmExecutionError::new(
                "attribute assignment is not yet supported in xian-vm-core",
            )),
            other => Err(VmExecutionError::new(format!(
                "unsupported assignment target '{other}'"
            ))),
        }
    }

    fn eval_target_value(
        &mut self,
        target: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let object = as_object(target, "target")?;
        match required_string(object, "node")? {
            "name" | "attribute" | "subscript" => self.eval_expression(target, scope, host),
            other => Err(VmExecutionError::new(format!(
                "unsupported aug-assign target '{other}'"
            ))),
        }
    }

    fn eval_expression(
        &mut self,
        expression: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let object = as_object(expression, "expression")?;
        let node = required_string(object, "node")?;
        host.charge_execution_cost(vm_expression_gas_cost(node, object)?)?;
        match node {
            "name" => self.eval_name(object, scope),
            "constant" => self.eval_constant(object),
            "list" => {
                let mut values = Vec::new();
                for element in required_array(object, "elements")? {
                    values.push(self.eval_expression(element, scope, host)?);
                }
                Ok(VmValue::List(values))
            }
            "tuple" => {
                let mut values = Vec::new();
                for element in required_array(object, "elements")? {
                    values.push(self.eval_expression(element, scope, host)?);
                }
                Ok(VmValue::Tuple(values))
            }
            "dict" => {
                let mut entries = Vec::new();
                for entry in required_array(object, "entries")? {
                    let entry_object = as_object(entry, "dict entry")?;
                    let key =
                        self.eval_expression(required_value(entry_object, "key")?, scope, host)?;
                    let value =
                        self.eval_expression(required_value(entry_object, "value")?, scope, host)?;
                    entries.push((key, value));
                }
                Ok(VmValue::Dict(entries))
            }
            "attribute" => self.eval_attribute(object, scope, host),
            "subscript" => {
                let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
                let slice = required_value(object, "slice")?;
                if let Some(slice_object) = slice.as_object() {
                    if required_string(slice_object, "node")? == "slice" {
                        return self.eval_slice_subscript(value, slice_object, scope, host);
                    }
                }
                let index = self.eval_expression(slice, scope, host)?;
                subscript_value(value, &index)
            }
            "storage_get" => {
                let binding = required_string(object, "binding")?;
                let key = self.eval_expression(required_value(object, "key")?, scope, host)?;
                self.hash_get(binding, &key, host)
            }
            "slice" => Err(VmExecutionError::new(
                "slice expressions are only supported as subscripts",
            )),
            "call" => self.eval_call(object, scope, host),
            "compare" => self.eval_compare(object, scope, host),
            "bool_op" => self.eval_bool_op(object, scope, host),
            "bin_op" => {
                let left = self.eval_expression(required_value(object, "left")?, scope, host)?;
                let right = self.eval_expression(required_value(object, "right")?, scope, host)?;
                apply_binary_operator(required_string(object, "operator")?, left, right)
            }
            "unary_op" => {
                let operand =
                    self.eval_expression(required_value(object, "operand")?, scope, host)?;
                apply_unary_operator(required_string(object, "operator")?, operand)
            }
            "if_expr" => {
                let test = self.eval_expression(required_value(object, "test")?, scope, host)?;
                if test.truthy() {
                    self.eval_expression(required_value(object, "body")?, scope, host)
                } else {
                    self.eval_expression(required_value(object, "orelse")?, scope, host)
                }
            }
            "f_string" => {
                let mut buffer = String::new();
                for value in required_array(object, "values")? {
                    buffer.push_str(&self.eval_expression(value, scope, host)?.python_repr());
                }
                Ok(VmValue::String(buffer))
            }
            "formatted_value" => {
                let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
                Ok(VmValue::String(value.python_repr()))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported expression node '{other}'"
            ))),
        }
    }

    fn eval_name(
        &self,
        object: &Map<String, Value>,
        scope: &HashMap<String, VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        if let Some(host_binding_id) = optional_string(object, "host_binding_id") {
            return self.resolve_host_binding(host_binding_id);
        }

        let id = required_string(object, "id")?;
        if let Some(value) = scope.get(id) {
            return Ok(value.clone());
        }
        if let Some(value) = self.globals.get(id) {
            return Ok(value.clone());
        }
        if self.functions.contains_key(id) {
            return Ok(VmValue::FunctionRef(id.to_owned()));
        }
        if let Some(builtin) = builtin_name_value(id) {
            return Ok(builtin);
        }
        Err(VmExecutionError::new(format!("unknown name '{id}'")))
    }

    fn eval_constant(&self, object: &Map<String, Value>) -> Result<VmValue, VmExecutionError> {
        match required_string(object, "value_type")? {
            "none" => Ok(VmValue::None),
            "bool" => Ok(VmValue::Bool(required_bool(object, "value")?)),
            "int" => Ok(VmValue::Int(required_bigint(object, "value")?)),
            "float" => Ok(VmValue::Float(required_f64(object, "value")?)),
            "str" => Ok(VmValue::String(
                required_string(object, "value")?.to_owned(),
            )),
            other => Err(VmExecutionError::new(format!(
                "unsupported constant value_type '{other}'"
            ))),
        }
    }

    fn eval_attribute(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        if let Some(host_binding_id) = optional_string(object, "host_binding_id") {
            return self.resolve_host_binding(host_binding_id);
        }
        let value = self.eval_expression(required_value(object, "value")?, scope, host)?;
        let attr = required_string(object, "attr")?;
        native_attribute_value(&value, attr)
    }

    fn resolve_host_binding(&self, host_binding_id: &str) -> Result<VmValue, VmExecutionError> {
        match host_binding_id {
            "numeric.decimal.new" => Ok(VmValue::TypeMarker("decimal".to_owned())),
            "time.datetime.new" | "time.datetime.strptime" => {
                Ok(VmValue::TypeMarker("datetime.datetime".to_owned()))
            }
            "time.timedelta.new" => Ok(VmValue::TypeMarker("datetime.timedelta".to_owned())),
            "time.seconds" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 0, 0, 0, 1)?)),
            "time.minutes" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 0, 0, 1, 0)?)),
            "time.hours" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 0, 1, 0, 0)?)),
            "time.days" => Ok(VmValue::TimeDelta(VmTimeDelta::new(0, 1, 0, 0, 0)?)),
            "time.weeks" => Ok(VmValue::TimeDelta(VmTimeDelta::new(1, 0, 0, 0, 0)?)),
            "context.caller" => Ok(option_string_value(&self.context.caller)),
            "context.signer" => Ok(option_string_value(&self.context.signer)),
            "context.this" => Ok(option_string_value(&self.context.this)),
            "context.owner" => Ok(option_string_value(&self.context.owner)),
            "context.entry" => Ok(option_entry_value(&self.context.entry)),
            "context.submission_name" => Ok(option_string_value(&self.context.submission_name)),
            "env.now" => Ok(self.context.now.clone()),
            "env.block_num" => Ok(self.context.block_num.clone()),
            "env.block_hash" => Ok(self.context.block_hash.clone()),
            "env.chain_id" => Ok(self.context.chain_id.clone()),
            other => Err(VmExecutionError::new(format!(
                "unsupported host binding '{other}'"
            ))),
        }
    }

    fn eval_call(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let args = self.eval_call_arguments(required_array(object, "args")?, scope, host)?;
        let kwargs = self.eval_call_keywords(required_array(object, "keywords")?, scope, host)?;
        let func = required_value(object, "func")?;

        if let Some(syscall_id) = optional_string(object, "syscall_id") {
            return self.eval_syscall(object, syscall_id, args, kwargs, scope, host);
        }

        if let Some(value) =
            self.eval_native_attribute_call(func, args.clone(), kwargs.clone(), scope, host)?
        {
            return Ok(value);
        }

        let callee = self.eval_expression(func, scope, host)?;
        match callee {
            VmValue::Builtin(name) => self.call_builtin(&name, args, kwargs),
            VmValue::FunctionRef(name) => self.call_named_function(host, &name, args, kwargs),
            other => Err(VmExecutionError::new(format!(
                "value of type {} is not callable",
                other.type_name()
            ))),
        }
    }

    fn eval_native_attribute_call(
        &mut self,
        func: &Value,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<Option<VmValue>, VmExecutionError> {
        let func_object = as_object(func, "callable")?;
        if required_string(func_object, "node")? != "attribute"
            || optional_string(func_object, "host_binding_id").is_some()
        {
            return Ok(None);
        }

        let receiver_expr = required_value(func_object, "value")?;
        let receiver = self.eval_expression(receiver_expr, scope, host)?;
        let attr = required_string(func_object, "attr")?;
        let result = call_native_method(receiver, attr, args, kwargs)?;
        match result {
            NativeMethodResult::Value(value) => Ok(Some(value)),
            NativeMethodResult::Mutated { receiver, value } => {
                let module_scope = target_writes_module_scope(receiver_expr, scope, &self.globals)?;
                self.assign_target(receiver_expr, receiver, scope, module_scope)?;
                Ok(Some(value))
            }
        }
    }

    fn eval_call_arguments(
        &mut self,
        args: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<Vec<VmValue>, VmExecutionError> {
        let mut values = Vec::new();
        for argument in args {
            values.push(self.eval_expression(argument, scope, host)?);
        }
        Ok(values)
    }

    fn eval_call_keywords(
        &mut self,
        keywords: &[Value],
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<Vec<(String, VmValue)>, VmExecutionError> {
        let mut values = Vec::new();
        for keyword in keywords {
            let keyword_object = as_object(keyword, "keyword")?;
            values.push((
                required_string(keyword_object, "arg")?.to_owned(),
                self.eval_expression(required_value(keyword_object, "value")?, scope, host)?,
            ));
        }
        Ok(values)
    }

    fn eval_syscall(
        &mut self,
        object: &Map<String, Value>,
        syscall_id: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        match syscall_id {
            "numeric.decimal.new" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("decimal() expects one argument"));
                }
                Ok(VmValue::Decimal(VmDecimal::from_vm_value(
                    args.first().expect("decimal() argument should exist"),
                )?))
            }
            "time.datetime.new" => time_datetime_new(args, kwargs),
            "time.datetime.strptime" => time_datetime_strptime(args, kwargs),
            "time.timedelta.new" => time_timedelta_new(args, kwargs),
            "hash.sha3_256" => hash_sha3_256(args, kwargs),
            "hash.sha256" => hash_sha256(args, kwargs),
            "crypto.ed25519_verify" => crypto_ed25519_verify(args, kwargs),
            "crypto.key_is_valid" => crypto_key_is_valid(args, kwargs),
            "storage.variable.get" => {
                host.charge_execution_cost(VM_GAS_VARIABLE_GET)?;
                let binding = required_string(object, "receiver_binding")?;
                self.variable_get(binding, host)
            }
            "storage.variable.set" => {
                host.charge_execution_cost(VM_GAS_VARIABLE_SET)?;
                let binding = required_string(object, "receiver_binding")?;
                let value = args
                    .first()
                    .cloned()
                    .ok_or_else(|| VmExecutionError::new("Variable.set expects one argument"))?;
                self.variable_set(binding, value.clone())?;
                host.charge_storage_write(
                    &variable_storage_key(&self.module.module_name, binding),
                    &value,
                )?;
                Ok(VmValue::None)
            }
            "storage.foreign_variable.get" => {
                host.charge_execution_cost(VM_GAS_VARIABLE_GET)?;
                let binding = required_string(object, "receiver_binding")?;
                self.variable_get(binding, host)
            }
            "contract.import" => {
                let module = resolve_contract_import_arg(&args, &kwargs)?;
                Ok(VmValue::ContractHandle(VmContractHandle {
                    module,
                    origin: "dynamic_import".to_owned(),
                }))
            }
            "event.log.emit" => {
                host.charge_execution_cost(VM_GAS_EVENT_EMIT)?;
                let event_binding = required_string(object, "event_binding")?;
                let event = self.globals.get(event_binding).cloned().ok_or_else(|| {
                    VmExecutionError::new(format!("unknown event binding '{event_binding}'"))
                })?;
                let event = match event {
                    VmValue::EventRef(event) => *event,
                    other => {
                        return Err(VmExecutionError::new(format!(
                            "binding '{event_binding}' is not an event reference but {}",
                            other.type_name()
                        )))
                    }
                };
                let payload = if let Some(first) = args.first() {
                    first.clone()
                } else if kwargs.is_empty() {
                    VmValue::None
                } else {
                    VmValue::Dict(
                        kwargs
                            .iter()
                            .map(|(key, value)| (VmValue::String(key.clone()), value.clone()))
                            .collect(),
                    )
                };
                let (data_indexed, data) = normalize_event_payload(&event.params, payload)?;
                for (key, value) in &data_indexed {
                    host.charge_storage_write(key, value)?;
                }
                for (key, value) in &data {
                    host.charge_storage_write(key, value)?;
                }
                host.emit_event(VmEvent {
                    contract: self
                        .context
                        .this
                        .clone()
                        .unwrap_or_else(|| self.module.module_name.clone()),
                    event: event.event_name,
                    signer: option_string_value(&self.context.signer),
                    caller: option_string_value(&self.context.caller),
                    data_indexed,
                    data,
                })?;
                Ok(VmValue::None)
            }
            "contract.export_call" => {
                let function_name = required_string(object, "function_name")?;
                let contract_target = required_value(object, "contract_target")?;
                let target = self.resolve_contract_target(contract_target, scope, host)?;
                host.call_contract(VmContractCall {
                    target,
                    function: function_name.to_owned(),
                    args,
                    kwargs,
                    caller_contract: self.context.this.clone(),
                    signer: self.context.signer.clone(),
                    entry: self.context.entry.clone(),
                    submission_name: self.context.submission_name.clone(),
                    now: self.context.now.clone(),
                    block_num: self.context.block_num.clone(),
                    block_hash: self.context.block_hash.clone(),
                    chain_id: self.context.chain_id.clone(),
                })
            }
            "event.indexed" => {
                let type_value = if args.len() == 1 {
                    coerce_type_marker(args[0].clone())
                } else {
                    VmValue::Tuple(args.into_iter().map(coerce_type_marker).collect())
                };
                Ok(VmValue::Dict(vec![
                    (VmValue::String("type".to_owned()), type_value),
                    (VmValue::String("idx".to_owned()), VmValue::Bool(true)),
                ]))
            }
            other => {
                if let Some(cost) = explicit_syscall_metering_cost(other, &args, &kwargs)? {
                    host.charge_execution_cost(cost)?;
                }
                host.handle_syscall(other, args, kwargs)
            }
        }
    }

    fn resolve_contract_target(
        &mut self,
        value: &Value,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmContractTarget, VmExecutionError> {
        let object = as_object(value, "contract_target")?;
        match required_string(object, "kind")? {
            "static_import" => {
                let binding = required_string(object, "binding")?.to_owned();
                let module = self.imports.get(&binding).cloned().ok_or_else(|| {
                    VmExecutionError::new(format!("unknown static import binding '{binding}'"))
                })?;
                Ok(VmContractTarget::StaticImport { binding, module })
            }
            "dynamic_import" => {
                let source = required_value(object, "source")?;
                let handle = self
                    .eval_expression(source, scope, host)?
                    .as_contract_handle()?;
                Ok(VmContractTarget::DynamicImport {
                    module: handle.module,
                })
            }
            "local_handle" => {
                let binding = required_string(object, "binding")?.to_owned();
                let source = required_value(object, "source")?;
                let handle = self
                    .eval_expression(source, scope, host)?
                    .as_contract_handle()?;
                Ok(VmContractTarget::LocalHandle {
                    binding,
                    module: handle.module,
                })
            }
            "factory_call" => {
                let factory = required_string(object, "factory")?.to_owned();
                let source = required_value(object, "source")?;
                let handle = self
                    .eval_expression(source, scope, host)?
                    .as_contract_handle()?;
                Ok(VmContractTarget::FactoryCall {
                    factory,
                    module: handle.module,
                })
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported contract target kind '{other}'"
            ))),
        }
    }

    fn eval_compare(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let mut left = self.eval_expression(required_value(object, "left")?, scope, host)?;
        let operators = required_array(object, "operators")?;
        let comparators = required_array(object, "comparators")?;
        if operators.len() != comparators.len() {
            return Err(VmExecutionError::new(
                "compare operator/comparator count mismatch",
            ));
        }

        for (operator, comparator) in operators.iter().zip(comparators.iter()) {
            let right = self.eval_expression(comparator, scope, host)?;
            let passed = apply_compare_operator(required_string_value(operator)?, &left, &right)?;
            if !passed {
                return Ok(VmValue::Bool(false));
            }
            left = right;
        }

        Ok(VmValue::Bool(true))
    }

    fn eval_bool_op(
        &mut self,
        object: &Map<String, Value>,
        scope: &mut HashMap<String, VmValue>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let operator = required_string(object, "operator")?;
        let values = required_array(object, "values")?;
        match operator {
            "and" => {
                let mut last = VmValue::Bool(true);
                for value in values {
                    last = self.eval_expression(value, scope, host)?;
                    if !last.truthy() {
                        return Ok(last);
                    }
                }
                Ok(last)
            }
            "or" => {
                let mut last = VmValue::Bool(false);
                for value in values {
                    last = self.eval_expression(value, scope, host)?;
                    if last.truthy() {
                        return Ok(last);
                    }
                }
                Ok(last)
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported bool operator '{other}'"
            ))),
        }
    }

    fn call_builtin(
        &self,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        match name {
            "len" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("len() expects one argument"));
                }
                match &args[0] {
                    VmValue::String(value) => Ok(vm_int(value.chars().count())),
                    VmValue::List(values) | VmValue::Tuple(values) => Ok(vm_int(values.len())),
                    VmValue::Dict(entries) => Ok(vm_int(entries.len())),
                    other => Err(VmExecutionError::new(format!(
                        "len() does not support {}",
                        other.type_name()
                    ))),
                }
            }
            "range" => {
                if !kwargs.is_empty() || args.is_empty() || args.len() > 3 {
                    return Err(VmExecutionError::new(
                        "range() expects between one and three positional arguments",
                    ));
                }
                let (start, stop, step) = match args.len() {
                    1 => (BigInt::zero(), args[0].as_bigint()?, BigInt::from(1)),
                    2 => (args[0].as_bigint()?, args[1].as_bigint()?, BigInt::from(1)),
                    3 => (
                        args[0].as_bigint()?,
                        args[1].as_bigint()?,
                        args[2].as_bigint()?,
                    ),
                    _ => unreachable!(),
                };
                if step.is_zero() {
                    return Err(VmExecutionError::new("range() step cannot be zero"));
                }
                let mut values = Vec::new();
                let mut current = start;
                if step.sign() != Sign::Minus {
                    while current < stop {
                        values.push(VmValue::Int(current.clone()));
                        current += &step;
                    }
                } else {
                    while current > stop {
                        values.push(VmValue::Int(current.clone()));
                        current += &step;
                    }
                }
                Ok(VmValue::List(values))
            }
            "str" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("str() expects one argument"));
                }
                Ok(VmValue::String(args[0].python_repr()))
            }
            "bool" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("bool() expects one argument"));
                }
                Ok(VmValue::Bool(args[0].truthy()))
            }
            "int" => {
                if !kwargs.is_empty() || args.is_empty() || args.len() > 2 {
                    return Err(VmExecutionError::new(
                        "int() expects one or two positional arguments",
                    ));
                }
                match (&args[0], args.get(1)) {
                    (VmValue::String(value), Some(base)) => {
                        let base = bigint_to_u32(&base.as_bigint()?, "int() base")?;
                        if !(2..=36).contains(&base) {
                            return Err(VmExecutionError::new(
                                "int() base must be between 2 and 36",
                            ));
                        }
                        BigInt::from_str_radix(value, base)
                            .map(VmValue::Int)
                            .map_err(|_| {
                                VmExecutionError::new(format!(
                                    "cannot convert '{value}' to int with base {base}"
                                ))
                            })
                    }
                    (_, Some(_)) => Err(VmExecutionError::new(
                        "int() base argument requires a string input",
                    )),
                    (VmValue::Int(value), None) => Ok(VmValue::Int(value.clone())),
                    (VmValue::Bool(value), None) => Ok(vm_int(if *value { 1 } else { 0 })),
                    (VmValue::Float(value), None) => {
                        Ok(VmValue::Int(f64_to_bigint_trunc(*value, "float() input")?))
                    }
                    (VmValue::Decimal(value), None) => Ok(VmValue::Int(value.to_bigint())),
                    (VmValue::String(value), None) => {
                        BigInt::from_str(value).map(VmValue::Int).map_err(|_| {
                            VmExecutionError::new(format!("cannot convert '{value}' to int"))
                        })
                    }
                    (other, None) => Err(VmExecutionError::new(format!(
                        "int() does not support {}",
                        other.type_name()
                    ))),
                }
            }
            "pow" => {
                if !kwargs.is_empty() || args.len() < 2 || args.len() > 3 {
                    return Err(VmExecutionError::new(
                        "pow() expects two or three positional arguments",
                    ));
                }
                if let Some(modulus) = args.get(2) {
                    let base = args[0].as_bigint()?;
                    let exponent = args[1].as_bigint()?;
                    let modulus = modulus.as_bigint()?;
                    if exponent.sign() == Sign::Minus {
                        return Err(VmExecutionError::new(
                            "pow() 3rd argument not allowed unless all arguments are integers",
                        ));
                    }
                    if modulus.is_zero() {
                        return Err(VmExecutionError::new("pow() 3rd argument cannot be 0"));
                    }
                    return Ok(VmValue::Int(base.modpow(&exponent, &modulus)));
                }
                match (&args[0], &args[1]) {
                    (VmValue::Int(base), VmValue::Int(exponent)) => Ok(VmValue::Int(
                        base.pow(bigint_to_u32(exponent, "pow() exponent")?),
                    )),
                    (VmValue::Float(base), VmValue::Float(exponent)) => {
                        Ok(VmValue::Float(base.powf(*exponent)))
                    }
                    (VmValue::Float(base), VmValue::Int(exponent)) => Ok(VmValue::Float(
                        base.powf(bigint_to_f64(exponent, "pow() exponent")?),
                    )),
                    (VmValue::Int(base), VmValue::Float(exponent)) => Ok(VmValue::Float(
                        bigint_to_f64(base, "pow() base")?.powf(*exponent),
                    )),
                    (left, right) => Err(VmExecutionError::new(format!(
                        "pow() does not support {} and {}",
                        left.type_name(),
                        right.type_name()
                    ))),
                }
            }
            "format" => {
                if args.is_empty() || args.len() > 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "format() expects one or two positional arguments",
                    ));
                }
                let spec = if let Some(value) = args.get(1) {
                    value.as_string()?
                } else {
                    String::new()
                };
                Ok(VmValue::String(format_builtin_value(&args[0], &spec)?))
            }
            "float" => {
                if !kwargs.is_empty() || args.len() != 1 {
                    return Err(VmExecutionError::new("float() expects one argument"));
                }
                match &args[0] {
                    VmValue::Int(value) => {
                        Ok(VmValue::Float(bigint_to_f64(value, "float() input")?))
                    }
                    VmValue::Bool(value) => Ok(VmValue::Float(if *value { 1.0 } else { 0.0 })),
                    VmValue::Float(value) => Ok(VmValue::Float(*value)),
                    VmValue::Decimal(value) => Ok(VmValue::Float(value.to_f64()?)),
                    VmValue::String(value) => {
                        value.parse::<f64>().map(VmValue::Float).map_err(|_| {
                            VmExecutionError::new(format!("cannot convert '{value}' to float"))
                        })
                    }
                    other => Err(VmExecutionError::new(format!(
                        "float() does not support {}",
                        other.type_name()
                    ))),
                }
            }
            "dict" => {
                if args.len() > 1 {
                    return Err(VmExecutionError::new(
                        "dict() accepts at most one positional argument",
                    ));
                }
                let mut entries = Vec::new();
                if let Some(initial) = args.first() {
                    match initial {
                        VmValue::Dict(existing) => entries.extend(existing.clone()),
                        VmValue::List(items) | VmValue::Tuple(items) => {
                            for item in items {
                                match item {
                                    VmValue::List(values) | VmValue::Tuple(values)
                                        if values.len() == 2 =>
                                    {
                                        entries.push((values[0].clone(), values[1].clone()));
                                    }
                                    other => {
                                        return Err(VmExecutionError::new(format!(
                                            "dict() expected key/value pairs, got {}",
                                            other.type_name()
                                        )))
                                    }
                                }
                            }
                        }
                        other => {
                            return Err(VmExecutionError::new(format!(
                                "dict() does not support {}",
                                other.type_name()
                            )))
                        }
                    }
                }
                for (key, value) in kwargs {
                    dict_set(&mut entries, VmValue::String(key), value);
                }
                Ok(VmValue::Dict(entries))
            }
            "list" => {
                if args.len() > 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "list() accepts at most one positional argument",
                    ));
                }
                if let Some(value) = args.first() {
                    let items = iterate_value(value)?;
                    Ok(VmValue::List(items))
                } else {
                    Ok(VmValue::List(Vec::new()))
                }
            }
            "tuple" => {
                if args.len() > 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "tuple() accepts at most one positional argument",
                    ));
                }
                if let Some(value) = args.first() {
                    let items = iterate_value(value)?;
                    Ok(VmValue::Tuple(items))
                } else {
                    Ok(VmValue::Tuple(Vec::new()))
                }
            }
            "sorted" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "sorted() expects one positional argument",
                    ));
                }
                let values = iterate_value(&args[0])?;
                Ok(VmValue::List(sorted_values(values)?))
            }
            "sum" => {
                if kwargs.len() > 0 || args.is_empty() || args.len() > 2 {
                    return Err(VmExecutionError::new(
                        "sum() expects one or two positional arguments",
                    ));
                }
                let mut total = if let Some(start) = args.get(1) {
                    start.clone()
                } else {
                    vm_int(0)
                };
                for value in iterate_value(&args[0])? {
                    total = apply_binary_operator("add", total, value)?;
                }
                Ok(total)
            }
            "min" => {
                if kwargs.len() > 0 || args.is_empty() {
                    return Err(VmExecutionError::new(
                        "min() expects at least one positional argument",
                    ));
                }
                let values = builtin_ordered_values(args)?;
                let mut best = values
                    .first()
                    .cloned()
                    .ok_or_else(|| VmExecutionError::new("min() received no values"))?;
                for candidate in values.into_iter().skip(1) {
                    if compare_vm_values(&candidate, &best)? == std::cmp::Ordering::Less {
                        best = candidate;
                    }
                }
                Ok(best)
            }
            "max" => {
                if kwargs.len() > 0 || args.is_empty() {
                    return Err(VmExecutionError::new(
                        "max() expects at least one positional argument",
                    ));
                }
                let values = builtin_ordered_values(args)?;
                let mut best = values
                    .first()
                    .cloned()
                    .ok_or_else(|| VmExecutionError::new("max() received no values"))?;
                for candidate in values.into_iter().skip(1) {
                    if compare_vm_values(&candidate, &best)? == std::cmp::Ordering::Greater {
                        best = candidate;
                    }
                }
                Ok(best)
            }
            "all" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "all() expects one positional argument",
                    ));
                }
                Ok(VmValue::Bool(
                    iterate_value(&args[0])?.iter().all(VmValue::truthy),
                ))
            }
            "any" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "any() expects one positional argument",
                    ));
                }
                Ok(VmValue::Bool(
                    iterate_value(&args[0])?.iter().any(VmValue::truthy),
                ))
            }
            "reversed" => {
                if args.len() != 1 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "reversed() expects one positional argument",
                    ));
                }
                let mut values = iterate_value(&args[0])?;
                values.reverse();
                Ok(VmValue::List(values))
            }
            "zip" => {
                if args.is_empty() || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "zip() expects one or more positional arguments",
                    ));
                }
                let iterables = args
                    .iter()
                    .map(iterate_value)
                    .collect::<Result<Vec<_>, _>>()?;
                let length = iterables.iter().map(Vec::len).min().unwrap_or(0);
                let mut zipped = Vec::with_capacity(length);
                for index in 0..length {
                    zipped.push(VmValue::Tuple(
                        iterables
                            .iter()
                            .map(|values| values[index].clone())
                            .collect(),
                    ));
                }
                Ok(VmValue::List(zipped))
            }
            "isinstance" => {
                if args.len() != 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "isinstance() expects two positional arguments",
                    ));
                }
                Ok(VmValue::Bool(type_matches(&args[0], &args[1])))
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported builtin '{other}'"
            ))),
        }
    }

    fn variable_get(
        &mut self,
        binding: &str,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let module_name = self.module.module_name.clone();
        let (foreign_key, default_value, current_value) = {
            let state = self.variables.get(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown variable binding '{binding}'"))
            })?;
            (
                state.foreign_key.clone(),
                state.default_value.clone(),
                state.value.clone(),
            )
        };
        if let Some(foreign_key) = foreign_key {
            let (foreign_contract, foreign_binding) =
                split_foreign_storage_key(&foreign_key)?;
            if self
                .variables
                .get(&foreign_key)
                .and_then(|state| state.value.clone())
                .is_none()
            {
                let loaded = host.read_variable(&foreign_contract, &foreign_binding)?;
                let foreign = self
                    .variables
                    .entry(foreign_key)
                    .or_insert_with(|| VariableState {
                        default_value: VmValue::None,
                        value: None,
                        foreign_key: None,
                        snapshot_local: false,
                        dirty: false,
                    });
                if foreign.value.is_none() {
                    foreign.value = loaded;
                }
                let value = foreign
                    .value
                    .clone()
                    .unwrap_or_else(|| foreign.default_value.clone());
                charge_storage_read(
                    host,
                    &variable_storage_key(&foreign_contract, &foreign_binding),
                    &value,
                )?;
                return Ok(value);
            }
            let foreign = self.variables.get(&foreign_storage_key(&foreign_contract, &foreign_binding)).ok_or_else(|| {
                VmExecutionError::new(format!(
                    "missing foreign variable backing state '{}:{}'",
                    foreign_contract, foreign_binding
                ))
            })?;
            let value = foreign
                .value
                .clone()
                .unwrap_or_else(|| foreign.default_value.clone());
            charge_storage_read(
                host,
                &variable_storage_key(&foreign_contract, &foreign_binding),
                &value,
            )?;
            return Ok(value);
        }
        if current_value.is_none() {
            let loaded = host.read_variable(&module_name, binding)?;
            let state = self.variables.get_mut(binding).ok_or_else(|| {
                VmExecutionError::new(format!("unknown variable binding '{binding}'"))
            })?;
            if state.value.is_none() {
                state.value = loaded;
            }
            let value = state
                .value
                .clone()
                .unwrap_or_else(|| state.default_value.clone());
            charge_storage_read(
                host,
                &variable_storage_key(&module_name, binding),
                &value,
            )?;
            return Ok(value);
        }
        let value = current_value.unwrap_or(default_value);
        charge_storage_read(host, &variable_storage_key(&module_name, binding), &value)?;
        Ok(value)
    }

    fn variable_set(&mut self, binding: &str, value: VmValue) -> Result<(), VmExecutionError> {
        let state = self.variables.get_mut(binding).ok_or_else(|| {
            VmExecutionError::new(format!("unknown variable binding '{binding}'"))
        })?;
        if state.foreign_key.is_some() {
            return Err(VmExecutionError::new(format!(
                "cannot set foreign variable '{binding}'"
            )));
        }
        state.value = Some(value);
        state.dirty = true;
        Ok(())
    }

    fn hash_get(
        &mut self,
        binding: &str,
        key: &VmValue,
        host: &mut dyn VmHost,
    ) -> Result<VmValue, VmExecutionError> {
        let storage_key = normalize_hash_key(key)?;
        let module_name = self.module.module_name.clone();
        let (foreign_key, default_value, current_entry) = {
            let state = self
                .hashes
                .get(binding)
                .ok_or_else(|| VmExecutionError::new(format!("unknown hash binding '{binding}'")))?;
            (
                state.foreign_key.clone(),
                state.default_value.clone(),
                state.entries.get(&storage_key).cloned(),
            )
        };
        if let Some(foreign_key) = foreign_key {
            let (foreign_contract, foreign_binding) =
                split_foreign_storage_key(&foreign_key)?;
            let has_value = self
                .hashes
                .get(&foreign_key)
                .map(|state| state.entries.contains_key(&storage_key))
                .unwrap_or(false);
            if !has_value {
                let loaded = host.read_hash(&foreign_contract, &foreign_binding, key)?;
                let foreign = self.hashes.entry(foreign_key).or_insert_with(|| HashState {
                    default_value: VmValue::None,
                    entries: HashMap::new(),
                    foreign_key: None,
                    snapshot_local: false,
                    dirty_entries: HashSet::new(),
                });
                if let Some(value) = loaded {
                    foreign.entries.insert(storage_key.clone(), value);
                }
                let value = foreign
                    .entries
                    .get(&storage_key)
                    .cloned()
                    .unwrap_or_else(|| foreign.default_value.clone());
                charge_storage_read(
                    host,
                    &hash_storage_key(&foreign_contract, &foreign_binding, key)?,
                    &value,
                )?;
                return Ok(value);
            }
            let foreign = self
                .hashes
                .get(&foreign_storage_key(&foreign_contract, &foreign_binding))
                .ok_or_else(|| {
                    VmExecutionError::new(format!(
                        "missing foreign hash backing state '{}:{}'",
                        foreign_contract, foreign_binding
                    ))
                })?;
            let value = foreign
                .entries
                .get(&storage_key)
                .cloned()
                .unwrap_or_else(|| foreign.default_value.clone());
            charge_storage_read(
                host,
                &hash_storage_key(&foreign_contract, &foreign_binding, key)?,
                &value,
            )?;
            return Ok(value);
        }
        if current_entry.is_none() {
            let loaded = host.read_hash(&module_name, binding, key)?;
            let state = self
                .hashes
                .get_mut(binding)
                .ok_or_else(|| VmExecutionError::new(format!("unknown hash binding '{binding}'")))?;
            if let Some(value) = loaded {
                state.entries.insert(storage_key.clone(), value);
            }
            let value = state
                .entries
                .get(&storage_key)
                .cloned()
                .unwrap_or_else(|| state.default_value.clone());
            charge_storage_read(host, &hash_storage_key(&module_name, binding, key)?, &value)?;
            return Ok(value);
        }
        let value = current_entry.unwrap_or(default_value);
        charge_storage_read(host, &hash_storage_key(&module_name, binding, key)?, &value)?;
        Ok(value)
    }

    fn hash_set(
        &mut self,
        binding: &str,
        key: &VmValue,
        value: VmValue,
    ) -> Result<(), VmExecutionError> {
        let storage_key = normalize_hash_key(key)?;
        let state = self
            .hashes
            .get_mut(binding)
            .ok_or_else(|| VmExecutionError::new(format!("unknown hash binding '{binding}'")))?;
        if state.foreign_key.is_some() {
            return Err(VmExecutionError::new(format!(
                "cannot set foreign hash '{binding}'"
            )));
        }
        state.entries.insert(storage_key.clone(), value);
        state.dirty_entries.insert(storage_key);
        Ok(())
    }
}

fn builtin_name_value(name: &str) -> Option<VmValue> {
    match name {
        "len" | "range" | "str" | "bool" | "int" | "float" | "dict" | "list" | "tuple"
        | "isinstance" | "sorted" | "sum" | "min" | "max" | "all" | "any" | "reversed" | "zip"
        | "pow" | "format" => Some(VmValue::Builtin(name.to_owned())),
        "Any" | "decimal" => Some(VmValue::TypeMarker(name.to_owned())),
        _ => None,
    }
}

fn coerce_type_marker(value: VmValue) -> VmValue {
    match value {
        VmValue::Builtin(name)
            if matches!(
                name.as_str(),
                "str" | "int" | "float" | "bool" | "list" | "dict" | "tuple"
            ) =>
        {
            VmValue::TypeMarker(name)
        }
        other => other,
    }
}

fn apply_binary_operator(
    operator: &str,
    left: VmValue,
    right: VmValue,
) -> Result<VmValue, VmExecutionError> {
    let coerce_decimal = |value: &VmValue, side: &str| -> Result<VmDecimal, VmExecutionError> {
        VmDecimal::from_vm_value(value).map_err(|err| {
            VmExecutionError::new(format!(
                "binary operator '{operator}' could not coerce {side} operand {} ({}) to decimal: {err}",
                value.python_repr(),
                value.type_name()
            ))
        })
    };
    match operator {
        "add" => match (left, right) {
            (VmValue::DateTime(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::DateTime(left.add_timedelta(&right)?))
            }
            (VmValue::TimeDelta(left), VmValue::DateTime(right)) => {
                Ok(VmValue::DateTime(right.add_timedelta(&left)?))
            }
            (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::TimeDelta(left.add(&right)?))
            }
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.add(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.add(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.add(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => Ok(VmValue::Int(left + right)),
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left + right)),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "left int operand")? + right,
            )),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left + bigint_to_f64(&right, "right int operand")?,
            )),
            (VmValue::String(left), VmValue::String(right)) => Ok(VmValue::String(left + &right)),
            (VmValue::List(mut left), VmValue::List(right)) => {
                left.extend(right);
                Ok(VmValue::List(left))
            }
            (VmValue::Tuple(mut left), VmValue::Tuple(right)) => {
                left.extend(right);
                Ok(VmValue::Tuple(left))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported add operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "sub" => match (left, right) {
            (VmValue::DateTime(left), VmValue::DateTime(right)) => {
                Ok(VmValue::TimeDelta(left.sub_datetime(&right)?))
            }
            (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::TimeDelta(left.sub(&right)?))
            }
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.sub(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.sub(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.sub(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => Ok(VmValue::Int(left - right)),
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left - right)),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "left int operand")? - right,
            )),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left - bigint_to_f64(&right, "right int operand")?,
            )),
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported sub operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "mul" => match (left, right) {
            (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
                Ok(VmValue::TimeDelta(left.mul_timedelta(&right)?))
            }
            (VmValue::TimeDelta(left), VmValue::Int(right)) => Ok(VmValue::TimeDelta(
                left.mul_int(bigint_to_i64(&right, "timedelta multiplier")?)?,
            )),
            (VmValue::Int(left), VmValue::TimeDelta(right)) => Ok(VmValue::TimeDelta(
                right.mul_int(bigint_to_i64(&left, "timedelta multiplier")?)?,
            )),
            (VmValue::List(values), VmValue::Int(count)) => {
                Ok(VmValue::List(repeat_values(&values, &count)?))
            }
            (VmValue::Int(count), VmValue::List(values)) => {
                Ok(VmValue::List(repeat_values(&values, &count)?))
            }
            (VmValue::Tuple(values), VmValue::Int(count)) => {
                Ok(VmValue::Tuple(repeat_values(&values, &count)?))
            }
            (VmValue::Int(count), VmValue::Tuple(values)) => {
                Ok(VmValue::Tuple(repeat_values(&values, &count)?))
            }
            (VmValue::String(value), VmValue::Int(count)) => {
                Ok(VmValue::String(repeat_string(&value, &count)?))
            }
            (VmValue::Int(count), VmValue::String(value)) => {
                Ok(VmValue::String(repeat_string(&value, &count)?))
            }
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.mul(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.mul(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.mul(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => Ok(VmValue::Int(left * right)),
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left * right)),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "left int operand")? * right,
            )),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left * bigint_to_f64(&right, "right int operand")?,
            )),
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported mul operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "div" => match (left, right) {
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.div(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.div(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.div(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => {
                if right.is_zero() {
                    return Err(VmExecutionError::new("division by zero"));
                }
                Ok(VmValue::Float(
                    bigint_to_f64(&left, "left int operand")?
                        / bigint_to_f64(&right, "right int operand")?,
                ))
            }
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left / right)),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "left int operand")? / right,
            )),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left / bigint_to_f64(&right, "right int operand")?,
            )),
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported div operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "floordiv" => match (left, right) {
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.floor_div(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.floor_div(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.floor_div(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => {
                Ok(VmValue::Int(bigint_floor_div(&left, &right)?))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported floordiv operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "mod" => match (left, right) {
            (VmValue::Decimal(left), VmValue::Decimal(right)) => {
                Ok(VmValue::Decimal(left.modulo(&right)?))
            }
            (VmValue::Decimal(left), right) => Ok(VmValue::Decimal(
                left.modulo(&coerce_decimal(&right, "right")?)?,
            )),
            (left, VmValue::Decimal(right)) => Ok(VmValue::Decimal(
                coerce_decimal(&left, "left")?.modulo(&right)?,
            )),
            (VmValue::Int(left), VmValue::Int(right)) => {
                Ok(VmValue::Int(bigint_modulo(&left, &right)?))
            }
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported mod operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        "pow" => match (left, right) {
            (VmValue::Int(left), VmValue::Int(right)) => Ok(VmValue::Int(
                left.pow(bigint_to_u32(&right, "pow exponent")?),
            )),
            (VmValue::Float(left), VmValue::Float(right)) => Ok(VmValue::Float(left.powf(right))),
            (VmValue::Float(left), VmValue::Int(right)) => Ok(VmValue::Float(
                left.powf(bigint_to_f64(&right, "pow exponent")?),
            )),
            (VmValue::Int(left), VmValue::Float(right)) => Ok(VmValue::Float(
                bigint_to_f64(&left, "pow base")?.powf(right),
            )),
            (left, right) => Err(VmExecutionError::new(format!(
                "unsupported pow operands {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        },
        other => Err(VmExecutionError::new(format!(
            "unsupported binary operator '{other}'"
        ))),
    }
}

fn apply_unary_operator(operator: &str, operand: VmValue) -> Result<VmValue, VmExecutionError> {
    match operator {
        "not" => Ok(VmValue::Bool(!operand.truthy())),
        "neg" => match operand {
            VmValue::Int(value) => Ok(VmValue::Int(-value)),
            VmValue::Float(value) => Ok(VmValue::Float(-value)),
            VmValue::Decimal(value) => Ok(VmValue::Decimal(VmDecimal::from_scaled(-value.scaled)?)),
            other => Err(VmExecutionError::new(format!(
                "unsupported neg operand {}",
                other.type_name()
            ))),
        },
        "pos" => match operand {
            VmValue::Int(value) => Ok(VmValue::Int(value)),
            VmValue::Float(value) => Ok(VmValue::Float(value)),
            VmValue::Decimal(value) => Ok(VmValue::Decimal(value)),
            VmValue::TimeDelta(value) => Ok(VmValue::TimeDelta(value)),
            other => Err(VmExecutionError::new(format!(
                "unsupported pos operand {}",
                other.type_name()
            ))),
        },
        other => Err(VmExecutionError::new(format!(
            "unsupported unary operator '{other}'"
        ))),
    }
}

fn apply_compare_operator(
    operator: &str,
    left: &VmValue,
    right: &VmValue,
) -> Result<bool, VmExecutionError> {
    match operator {
        "eq" => vm_values_equal(left, right),
        "not_eq" => Ok(!vm_values_equal(left, right)?),
        "gt" => compare_ord(left, right, |left, right| left > right),
        "gt_e" => compare_ord(left, right, |left, right| left >= right),
        "lt" => compare_ord(left, right, |left, right| left < right),
        "lt_e" => compare_ord(left, right, |left, right| left <= right),
        "in" => contains_value(right, left),
        "not_in" => contains_value(right, left).map(|value| !value),
        "is" => Ok(left == right),
        "is_not" => Ok(left != right),
        other => Err(VmExecutionError::new(format!(
            "unsupported compare operator '{other}'"
        ))),
    }
}

fn compare_ord<F>(left: &VmValue, right: &VmValue, op: F) -> Result<bool, VmExecutionError>
where
    F: Fn(f64, f64) -> bool,
{
    let coerce_decimal = |value: &VmValue, side: &str| -> Result<VmDecimal, VmExecutionError> {
        VmDecimal::from_vm_value(value).map_err(|err| {
            VmExecutionError::new(format!(
                "comparison could not coerce {side} operand {} ({}) to decimal: {err}",
                value.python_repr(),
                value.type_name()
            ))
        })
    };
    match (left, right) {
        (VmValue::DateTime(left), VmValue::DateTime(right)) => Ok(op_datetime(left, right, &op)),
        (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => Ok(op_timedelta(left, right, &op)),
        (VmValue::Decimal(left), VmValue::Decimal(right)) => Ok(op_decimal(left, right, &op)),
        (VmValue::Decimal(left), right) => Ok(op_decimal(left, &coerce_decimal(right, "right")?, &op)),
        (left, VmValue::Decimal(right)) => Ok(op_decimal(&coerce_decimal(left, "left")?, right, &op)),
        (VmValue::Int(left), VmValue::Int(right)) => Ok(op_bigint(left, right, &op)),
        (VmValue::Float(left), VmValue::Float(right)) => Ok(op(*left, *right)),
        (VmValue::Int(left), VmValue::Float(right)) => {
            Ok(op(bigint_to_f64(left, "left int operand")?, *right))
        }
        (VmValue::Float(left), VmValue::Int(right)) => {
            Ok(op(*left, bigint_to_f64(right, "right int operand")?))
        }
        (VmValue::String(left), VmValue::String(right)) => Ok(op_string(left, right, &op)),
        (left, right) => Err(VmExecutionError::new(format!(
            "values {} and {} are not order-comparable",
            left.type_name(),
            right.type_name()
        ))),
    }
}

fn op_string<F>(left: &str, right: &str, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let left_score = if left > right {
        1.0
    } else if left == right {
        0.0
    } else {
        -1.0
    };
    op(left_score, 0.0)
}

fn op_decimal<F>(left: &VmDecimal, right: &VmDecimal, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let left_score = match left.scaled.cmp(&right.scaled) {
        std::cmp::Ordering::Greater => 1.0,
        std::cmp::Ordering::Equal => 0.0,
        std::cmp::Ordering::Less => -1.0,
    };
    op(left_score, 0.0)
}

fn op_bigint<F>(left: &BigInt, right: &BigInt, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let score = match left.cmp(right) {
        std::cmp::Ordering::Greater => 1.0,
        std::cmp::Ordering::Equal => 0.0,
        std::cmp::Ordering::Less => -1.0,
    };
    op(score, 0.0)
}

fn op_datetime<F>(left: &VmDateTime, right: &VmDateTime, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let score = match left.value.cmp(&right.value) {
        std::cmp::Ordering::Greater => 1.0,
        std::cmp::Ordering::Equal => 0.0,
        std::cmp::Ordering::Less => -1.0,
    };
    op(score, 0.0)
}

fn op_timedelta<F>(left: &VmTimeDelta, right: &VmTimeDelta, op: &F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    let score = match left.raw_seconds.cmp(&right.raw_seconds) {
        std::cmp::Ordering::Greater => 1.0,
        std::cmp::Ordering::Equal => 0.0,
        std::cmp::Ordering::Less => -1.0,
    };
    op(score, 0.0)
}

fn native_attribute_value(value: &VmValue, attr: &str) -> Result<VmValue, VmExecutionError> {
    match value {
        VmValue::DateTime(value) => match attr {
            "year" => Ok(vm_int(value.year())),
            "month" => Ok(vm_int(value.month())),
            "day" => Ok(vm_int(value.day())),
            "hour" => Ok(vm_int(value.hour())),
            "minute" => Ok(vm_int(value.minute())),
            "second" => Ok(vm_int(value.second())),
            "microsecond" => Ok(vm_int(value.microsecond())),
            other => Err(VmExecutionError::new(format!(
                "datetime has no attribute '{other}'"
            ))),
        },
        VmValue::TimeDelta(value) => match attr {
            "seconds" => Ok(vm_int(value.seconds())),
            "minutes" => Ok(vm_int(value.minutes())),
            "hours" => Ok(vm_int(value.hours())),
            "days" => Ok(vm_int(value.days())),
            "weeks" => Ok(vm_int(value.weeks())),
            other => Err(VmExecutionError::new(format!(
                "timedelta has no attribute '{other}'"
            ))),
        },
        other => Err(VmExecutionError::new(format!(
            "value of type {} has no native attribute '{}'",
            other.type_name(),
            attr
        ))),
    }
}

fn time_datetime_new(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    let year = positional_or_keyword_i64(&args, &kwargs, 0, "year")?;
    let month = positional_or_keyword_i64(&args, &kwargs, 1, "month")?;
    let day = positional_or_keyword_i64(&args, &kwargs, 2, "day")?;
    let hour = optional_positional_or_keyword_i64(&args, &kwargs, 3, "hour")?.unwrap_or(0);
    let minute = optional_positional_or_keyword_i64(&args, &kwargs, 4, "minute")?.unwrap_or(0);
    let second = optional_positional_or_keyword_i64(&args, &kwargs, 5, "second")?.unwrap_or(0);
    let microsecond =
        optional_positional_or_keyword_i64(&args, &kwargs, 6, "microsecond")?.unwrap_or(0);
    Ok(VmValue::DateTime(VmDateTime::new(
        year,
        month,
        day,
        hour,
        minute,
        second,
        microsecond,
    )?))
}

fn time_datetime_strptime(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 2 {
        return Err(VmExecutionError::new(
            "datetime.datetime.strptime() expects two positional arguments",
        ));
    }
    let date_string = args[0].as_string()?;
    let format = args[1].as_string()?;
    Ok(VmValue::DateTime(VmDateTime::parse(&date_string, &format)?))
}

fn time_timedelta_new(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    let weeks = optional_positional_or_keyword_i64(&args, &kwargs, 0, "weeks")?.unwrap_or(0);
    let days = optional_positional_or_keyword_i64(&args, &kwargs, 1, "days")?.unwrap_or(0);
    let hours = optional_positional_or_keyword_i64(&args, &kwargs, 2, "hours")?.unwrap_or(0);
    let minutes = optional_positional_or_keyword_i64(&args, &kwargs, 3, "minutes")?.unwrap_or(0);
    let seconds = optional_positional_or_keyword_i64(&args, &kwargs, 4, "seconds")?.unwrap_or(0);
    Ok(VmValue::TimeDelta(VmTimeDelta::new(
        weeks, days, hours, minutes, seconds,
    )?))
}

fn hash_sha3_256(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 1 {
        return Err(VmExecutionError::new("hashlib.sha3() expects one argument"));
    }
    let mut hasher = Sha3_256::new();
    hasher.update(hash_bytes_from_value(&args[0])?);
    Ok(VmValue::String(hex::encode(hasher.finalize())))
}

fn hash_sha256(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 1 {
        return Err(VmExecutionError::new(
            "hashlib.sha256() expects one argument",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(hash_bytes_from_value(&args[0])?);
    Ok(VmValue::String(hex::encode(hasher.finalize())))
}

fn crypto_ed25519_verify(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 3 {
        return Err(VmExecutionError::new(
            "crypto.verify() expects three positional arguments",
        ));
    }
    let key_hex = args[0].as_string()?;
    let message = args[1].as_string()?;
    let signature_hex = args[2].as_string()?;

    let key_bytes = match hex::decode(key_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(VmValue::Bool(false)),
    };
    let signature_bytes = match hex::decode(signature_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(VmValue::Bool(false)),
    };
    let verifying_key = match VerifyingKey::from_bytes(
        &key_bytes
            .try_into()
            .map_err(|_| VmExecutionError::new("invalid verify key length"))?,
    ) {
        Ok(key) => key,
        Err(_) => return Ok(VmValue::Bool(false)),
    };
    let signature = match Signature::try_from(signature_bytes.as_slice()) {
        Ok(signature) => signature,
        Err(_) => return Ok(VmValue::Bool(false)),
    };
    Ok(VmValue::Bool(
        verifying_key.verify(message.as_bytes(), &signature).is_ok(),
    ))
}

fn crypto_key_is_valid(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if !kwargs.is_empty() || args.len() != 1 {
        return Err(VmExecutionError::new(
            "crypto.key_is_valid() expects one argument",
        ));
    }
    let key = args[0].as_string()?;
    Ok(VmValue::Bool(
        key.len() == 64 && key.chars().all(|ch| ch.is_ascii_hexdigit()),
    ))
}

fn hash_bytes_from_value(value: &VmValue) -> Result<Vec<u8>, VmExecutionError> {
    let input = value.as_string()?;
    match hex::decode(&input) {
        Ok(bytes) => Ok(bytes),
        Err(_) => Ok(input.into_bytes()),
    }
}

fn positional_or_keyword_i64(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    index: usize,
    name: &str,
) -> Result<i64, VmExecutionError> {
    optional_positional_or_keyword_i64(args, kwargs, index, name)?
        .ok_or_else(|| VmExecutionError::new(format!("missing required argument '{name}'")))
}

fn optional_positional_or_keyword_i64(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    index: usize,
    name: &str,
) -> Result<Option<i64>, VmExecutionError> {
    if let Some(value) = args.get(index) {
        return Ok(Some(value.as_i64()?));
    }
    if let Some((_, value)) = kwargs.iter().find(|(key, _)| key == name) {
        return Ok(Some(value.as_i64()?));
    }
    Ok(None)
}

fn format_builtin_value(value: &VmValue, spec: &str) -> Result<String, VmExecutionError> {
    match value {
        VmValue::Int(value) => format_bigint(value, spec),
        VmValue::String(value) if spec.is_empty() => Ok(value.clone()),
        VmValue::Bool(_) | VmValue::Float(_) | VmValue::Decimal(_) if spec.is_empty() => {
            Ok(value.python_repr())
        }
        other => Err(VmExecutionError::new(format!(
            "format() does not support {} with spec '{}'",
            other.type_name(),
            spec
        ))),
    }
}

fn format_bigint(value: &BigInt, spec: &str) -> Result<String, VmExecutionError> {
    if spec.is_empty() || spec == "d" {
        return Ok(value.to_string());
    }

    let (width_spec, format_type) = spec
        .chars()
        .last()
        .map(|format_type| (&spec[..spec.len() - format_type.len_utf8()], format_type))
        .ok_or_else(|| VmExecutionError::new("invalid format spec"))?;

    let zero_pad = width_spec.starts_with('0');
    let width = if width_spec.is_empty() {
        0
    } else {
        width_spec.parse::<usize>().map_err(|_| {
            VmExecutionError::new(format!("unsupported integer format spec '{spec}'"))
        })?
    };

    let rendered = match format_type {
        'x' => value.to_str_radix(16),
        'X' => value.to_str_radix(16).to_uppercase(),
        'd' => value.to_string(),
        _ => {
            return Err(VmExecutionError::new(format!(
                "unsupported integer format spec '{spec}'"
            )))
        }
    };

    if width == 0 || rendered.len() >= width {
        return Ok(rendered);
    }

    let pad_char = if zero_pad { '0' } else { ' ' };
    let padding = pad_char.to_string().repeat(width - rendered.len());
    Ok(format!("{padding}{rendered}"))
}

fn repeat_values(values: &[VmValue], count: &BigInt) -> Result<Vec<VmValue>, VmExecutionError> {
    if count.sign() == Sign::Minus {
        return Ok(Vec::new());
    }
    let count = bigint_to_usize(count, "sequence repeat count")?;
    let mut repeated = Vec::with_capacity(values.len().saturating_mul(count));
    for _ in 0..count {
        repeated.extend(values.iter().cloned());
    }
    Ok(repeated)
}

fn repeat_string(value: &str, count: &BigInt) -> Result<String, VmExecutionError> {
    if count.sign() == Sign::Minus {
        return Ok(String::new());
    }
    Ok(value.repeat(bigint_to_usize(count, "string repeat count")?))
}

fn render_simple_format(template: &str, args: &[VmValue]) -> Result<String, VmExecutionError> {
    let mut rendered = String::new();
    let mut chars = template.chars().peekable();
    let mut next_arg = 0usize;

    while let Some(ch) = chars.next() {
        match ch {
            '{' => {
                if chars.peek() == Some(&'{') {
                    chars.next();
                    rendered.push('{');
                    continue;
                }

                let mut token = String::new();
                loop {
                    let Some(inner) = chars.next() else {
                        return Err(VmExecutionError::new("str.format() missing closing '}'"));
                    };
                    if inner == '}' {
                        break;
                    }
                    token.push(inner);
                }

                let index = if token.is_empty() {
                    let index = next_arg;
                    next_arg += 1;
                    index
                } else {
                    token.parse::<usize>().map_err(|_| {
                        VmExecutionError::new(format!("unsupported str.format() field '{token}'"))
                    })?
                };
                let value = args.get(index).ok_or_else(|| {
                    VmExecutionError::new("str.format() placeholder index out of range")
                })?;
                rendered.push_str(&value.python_repr());
            }
            '}' => {
                if chars.peek() == Some(&'}') {
                    chars.next();
                    rendered.push('}');
                } else {
                    return Err(VmExecutionError::new("str.format() unmatched '}'"));
                }
            }
            other => rendered.push(other),
        }
    }

    Ok(rendered)
}

fn call_native_method(
    receiver: VmValue,
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<NativeMethodResult, VmExecutionError> {
    if !kwargs.is_empty() {
        return Err(VmExecutionError::new(format!(
            "native method '{}()' does not accept keyword arguments",
            method
        )));
    }

    match receiver {
        VmValue::List(mut values) => match method {
            "append" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("list.append() expects one argument"));
                }
                values.push(args[0].clone());
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value: VmValue::None,
                })
            }
            "remove" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("list.remove() expects one argument"));
                }
                let index = values
                    .iter()
                    .position(|value| value == &args[0])
                    .ok_or_else(|| VmExecutionError::new("list.remove(x): x not in list"))?;
                values.remove(index);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value: VmValue::None,
                })
            }
            "extend" => {
                if args.len() != 1 {
                    return Err(VmExecutionError::new("list.extend() expects one argument"));
                }
                values.extend(iterate_value(&args[0])?);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value: VmValue::None,
                })
            }
            "insert" => {
                if args.len() != 2 {
                    return Err(VmExecutionError::new("list.insert() expects two arguments"));
                }
                let index = normalize_sequence_insert_index(&args[0], values.len())?;
                values.insert(index, args[1].clone());
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value: VmValue::None,
                })
            }
            "pop" => {
                let index = match args.as_slice() {
                    [] => values
                        .len()
                        .checked_sub(1)
                        .ok_or_else(|| VmExecutionError::new("pop from empty list"))?,
                    [index] => normalize_sequence_index(index, values.len())?,
                    _ => {
                        return Err(VmExecutionError::new(
                            "list.pop() accepts at most one argument",
                        ))
                    }
                };
                let value = values.remove(index);
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::List(values),
                    value,
                })
            }
            other => Err(VmExecutionError::new(format!(
                "unsupported list method '{}()'",
                other
            ))),
        },
        VmValue::String(value) => match method {
            "lower" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::String(
                    value.to_lowercase(),
                ))),
                _ => Err(VmExecutionError::new("str.lower() expects no arguments")),
            },
            "isascii" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                    value.is_ascii(),
                ))),
                _ => Err(VmExecutionError::new("str.isascii() expects no arguments")),
            },
            "isalpha" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                    !value.is_empty() && value.chars().all(char::is_alphabetic),
                ))),
                _ => Err(VmExecutionError::new("str.isalpha() expects no arguments")),
            },
            "isdigit" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                    !value.is_empty() && value.chars().all(char::is_numeric),
                ))),
                _ => Err(VmExecutionError::new("str.isdigit() expects no arguments")),
            },
            "islower" => match args.as_slice() {
                [] => {
                    let has_cased = value.chars().any(char::is_alphabetic);
                    Ok(NativeMethodResult::Value(VmValue::Bool(
                        has_cased
                            && value
                                .chars()
                                .all(|ch| !ch.is_alphabetic() || ch.is_lowercase()),
                    )))
                }
                _ => Err(VmExecutionError::new("str.islower() expects no arguments")),
            },
            "isalnum" => match args.as_slice() {
                [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                    !value.is_empty() && value.chars().all(char::is_alphanumeric),
                ))),
                _ => Err(VmExecutionError::new("str.isalnum() expects no arguments")),
            },
            "startswith" => match args.as_slice() {
                [prefix] => Ok(NativeMethodResult::Value(VmValue::Bool(
                    value.starts_with(&prefix.as_string()?),
                ))),
                _ => Err(VmExecutionError::new(
                    "str.startswith() expects one argument",
                )),
            },
            "replace" => match args.as_slice() {
                [old, new] => Ok(NativeMethodResult::Value(VmValue::String(
                    value.replace(&old.as_string()?, &new.as_string()?),
                ))),
                [old, new, count] => {
                    let count = count.as_bigint()?;
                    let replaced = if count < BigInt::zero() {
                        value.replace(&old.as_string()?, &new.as_string()?)
                    } else {
                        value.replacen(
                            &old.as_string()?,
                            &new.as_string()?,
                            bigint_to_usize(&count, "str.replace count")?,
                        )
                    };
                    Ok(NativeMethodResult::Value(VmValue::String(replaced)))
                }
                _ => Err(VmExecutionError::new(
                    "str.replace() expects two or three arguments",
                )),
            },
            "join" => match args.as_slice() {
                [items] => {
                    let rendered = iterate_value(items)?
                        .into_iter()
                        .map(|item| item.as_string())
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(NativeMethodResult::Value(VmValue::String(
                        rendered.join(&value),
                    )))
                }
                _ => Err(VmExecutionError::new("str.join() expects one argument")),
            },
            "format" => Ok(NativeMethodResult::Value(VmValue::String(
                render_simple_format(&value, &args)?,
            ))),
            other => Err(VmExecutionError::new(format!(
                "unsupported str method '{}()'",
                other
            ))),
        },
        VmValue::Dict(entries) => match method {
            "keys" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("dict.keys() expects no arguments"));
                }
                Ok(NativeMethodResult::Value(VmValue::List(
                    entries.iter().map(|(key, _)| key.clone()).collect(),
                )))
            }
            "values" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("dict.values() expects no arguments"));
                }
                Ok(NativeMethodResult::Value(VmValue::List(
                    entries.iter().map(|(_, value)| value.clone()).collect(),
                )))
            }
            "items" => {
                if !args.is_empty() {
                    return Err(VmExecutionError::new("dict.items() expects no arguments"));
                }
                Ok(NativeMethodResult::Value(VmValue::List(
                    entries
                        .iter()
                        .map(|(key, value)| VmValue::Tuple(vec![key.clone(), value.clone()]))
                        .collect(),
                )))
            }
            "get" => match args.as_slice() {
                [key] => Ok(NativeMethodResult::Value(
                    dict_get(&entries, key).unwrap_or(VmValue::None),
                )),
                [key, default] => Ok(NativeMethodResult::Value(
                    dict_get(&entries, key).unwrap_or_else(|| default.clone()),
                )),
                _ => Err(VmExecutionError::new(
                    "dict.get() expects one or two arguments",
                )),
            },
            other => Err(VmExecutionError::new(format!(
                "unsupported dict method '{}()'",
                other
            ))),
        },
        other => Err(VmExecutionError::new(format!(
            "value of type {} has no native method '{}()'",
            other.type_name(),
            method
        ))),
    }
}

fn target_writes_module_scope(
    target: &Value,
    scope: &HashMap<String, VmValue>,
    globals: &HashMap<String, VmValue>,
) -> Result<bool, VmExecutionError> {
    let object = as_object(target, "target")?;
    match required_string(object, "node")? {
        "name" => {
            let id = required_string(object, "id")?;
            Ok(!scope.contains_key(id) && globals.contains_key(id))
        }
        "subscript" => target_writes_module_scope(required_value(object, "value")?, scope, globals),
        _ => Ok(false),
    }
}

fn builtin_ordered_values(args: Vec<VmValue>) -> Result<Vec<VmValue>, VmExecutionError> {
    if args.len() == 1 {
        iterate_value(&args[0])
    } else {
        Ok(args)
    }
}

fn sorted_values(values: Vec<VmValue>) -> Result<Vec<VmValue>, VmExecutionError> {
    let mut ordered = Vec::with_capacity(values.len());
    for value in values {
        let mut insert_at = ordered.len();
        for (index, existing) in ordered.iter().enumerate() {
            if compare_vm_values(&value, existing)? == std::cmp::Ordering::Less {
                insert_at = index;
                break;
            }
        }
        ordered.insert(insert_at, value);
    }
    Ok(ordered)
}

fn compare_vm_values(
    left: &VmValue,
    right: &VmValue,
) -> Result<std::cmp::Ordering, VmExecutionError> {
    match (left, right) {
        (VmValue::DateTime(left), VmValue::DateTime(right)) => Ok(left.value.cmp(&right.value)),
        (VmValue::TimeDelta(left), VmValue::TimeDelta(right)) => {
            Ok(left.raw_seconds.cmp(&right.raw_seconds))
        }
        (VmValue::Bool(left), VmValue::Bool(right)) => Ok(left.cmp(right)),
        (VmValue::Decimal(left), VmValue::Decimal(right)) => Ok(left.scaled.cmp(&right.scaled)),
        (VmValue::Decimal(left), right) => {
            Ok(left.scaled.cmp(&VmDecimal::from_vm_value(right)?.scaled))
        }
        (left, VmValue::Decimal(right)) => {
            Ok(VmDecimal::from_vm_value(left)?.scaled.cmp(&right.scaled))
        }
        (VmValue::Bool(left), VmValue::Int(right)) => Ok(BigInt::from(if *left { 1 } else { 0 }).cmp(right)),
        (VmValue::Int(left), VmValue::Bool(right)) => Ok(left.cmp(&BigInt::from(if *right { 1 } else { 0 }))),
        (VmValue::Bool(left), VmValue::Float(right)) => (if *left { 1.0 } else { 0.0 })
            .partial_cmp(right)
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::Float(left), VmValue::Bool(right)) => left
            .partial_cmp(&(if *right { 1.0 } else { 0.0 }))
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::Int(left), VmValue::Int(right)) => Ok(left.cmp(right)),
        (VmValue::Float(left), VmValue::Float(right)) => left
            .partial_cmp(right)
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::Int(left), VmValue::Float(right)) => bigint_to_f64(left, "left int operand")?
            .partial_cmp(right)
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::Float(left), VmValue::Int(right)) => left
            .partial_cmp(&bigint_to_f64(right, "right int operand")?)
            .ok_or_else(|| VmExecutionError::new("cannot compare NaN values")),
        (VmValue::String(left), VmValue::String(right)) => Ok(left.cmp(right)),
        (left, right) => Err(VmExecutionError::new(format!(
            "values {} and {} are not order-comparable",
            left.type_name(),
            right.type_name()
        ))),
    }
}

fn compare_numeric_values(
    left: &VmValue,
    right: &VmValue,
) -> Result<Option<std::cmp::Ordering>, VmExecutionError> {
    let left_numeric = matches!(
        left,
        VmValue::Bool(_) | VmValue::Int(_) | VmValue::Float(_) | VmValue::Decimal(_)
    );
    let right_numeric = matches!(
        right,
        VmValue::Bool(_) | VmValue::Int(_) | VmValue::Float(_) | VmValue::Decimal(_)
    );
    if !left_numeric || !right_numeric {
        return Ok(None);
    }

    match (left, right) {
        (VmValue::Bool(left), VmValue::Bool(right)) => Ok(Some(left.cmp(right))),
        (VmValue::Bool(_), _)
        | (_, VmValue::Bool(_))
        | (VmValue::Decimal(_), _)
        | (_, VmValue::Decimal(_))
        | (VmValue::Int(_), VmValue::Int(_))
        | (VmValue::Float(_), VmValue::Float(_))
        | (VmValue::Int(_), VmValue::Float(_))
        | (VmValue::Float(_), VmValue::Int(_)) => Ok(Some(compare_vm_values(left, right)?)),
        _ => Ok(None),
    }
}

fn vm_values_equal(left: &VmValue, right: &VmValue) -> Result<bool, VmExecutionError> {
    if let Some(ordering) = compare_numeric_values(left, right)? {
        return Ok(ordering == std::cmp::Ordering::Equal);
    }

    match (left, right) {
        (VmValue::List(left), VmValue::List(right))
        | (VmValue::Tuple(left), VmValue::Tuple(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (left_item, right_item) in left.iter().zip(right.iter()) {
                if !vm_values_equal(left_item, right_item)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        (VmValue::Dict(left), VmValue::Dict(right)) => {
            if left.len() != right.len() {
                return Ok(false);
            }
            for (left_key, left_value) in left {
                let Some((_, right_value)) = right
                    .iter()
                    .find(|(right_key, _)| vm_values_equal(left_key, right_key).unwrap_or(false))
                else {
                    return Ok(false);
                };
                if !vm_values_equal(left_value, right_value)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        _ => Ok(left == right),
    }
}

fn contains_value(container: &VmValue, needle: &VmValue) -> Result<bool, VmExecutionError> {
    match container {
        VmValue::String(value) => match needle {
            VmValue::String(needle) => Ok(value.contains(needle)),
            _ => Err(VmExecutionError::new(
                "string membership requires a string needle",
            )),
        },
        VmValue::List(values) | VmValue::Tuple(values) => {
            for item in values {
                if vm_values_equal(item, needle)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        VmValue::Dict(entries) => {
            for (key, _) in entries {
                if vm_values_equal(key, needle)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        other => Err(VmExecutionError::new(format!(
            "membership is not supported for {}",
            other.type_name()
        ))),
    }
}

fn iterate_value(value: &VmValue) -> Result<Vec<VmValue>, VmExecutionError> {
    match value {
        VmValue::List(values) | VmValue::Tuple(values) => Ok(values.clone()),
        VmValue::Dict(entries) => Ok(entries.iter().map(|(key, _)| key.clone()).collect()),
        VmValue::String(value) => Ok(value
            .chars()
            .map(|ch| VmValue::String(ch.to_string()))
            .collect()),
        other => Err(VmExecutionError::new(format!(
            "value of type {} is not iterable",
            other.type_name()
        ))),
    }
}

fn assign_subscript(
    container: VmValue,
    index: &VmValue,
    value: VmValue,
) -> Result<VmValue, VmExecutionError> {
    match container {
        VmValue::List(mut values) => {
            let idx = normalize_sequence_index(index, values.len())?;
            values[idx] = value;
            Ok(VmValue::List(values))
        }
        VmValue::Dict(mut entries) => {
            dict_set(&mut entries, index.clone(), value);
            Ok(VmValue::Dict(entries))
        }
        other => Err(VmExecutionError::new(format!(
            "subscript assignment is not supported for {}",
            other.type_name()
        ))),
    }
}

fn subscript_value(container: VmValue, index: &VmValue) -> Result<VmValue, VmExecutionError> {
    match container {
        VmValue::List(values) => {
            let idx = normalize_sequence_index(index, values.len())?;
            Ok(values[idx].clone())
        }
        VmValue::Tuple(values) => {
            let idx = normalize_sequence_index(index, values.len())?;
            Ok(values[idx].clone())
        }
        VmValue::Dict(entries) => dict_get(&entries, index).ok_or_else(|| {
            VmExecutionError::new(format!("missing dict key {}", index.python_repr()))
        }),
        VmValue::String(value) => {
            let chars = value.chars().map(|ch| ch.to_string()).collect::<Vec<_>>();
            let idx = normalize_sequence_index(index, chars.len())?;
            Ok(VmValue::String(chars[idx].clone()))
        }
        other => Err(VmExecutionError::new(format!(
            "subscript access is not supported for {}",
            other.type_name()
        ))),
    }
}

fn subscript_slice_value(
    container: VmValue,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
) -> Result<VmValue, VmExecutionError> {
    match container {
        VmValue::List(values) => Ok(VmValue::List(
            slice_positions(values.len(), lower, upper, step)?
                .into_iter()
                .map(|index| values[index].clone())
                .collect(),
        )),
        VmValue::Tuple(values) => Ok(VmValue::Tuple(
            slice_positions(values.len(), lower, upper, step)?
                .into_iter()
                .map(|index| values[index].clone())
                .collect(),
        )),
        VmValue::String(value) => {
            let chars = value.chars().map(|ch| ch.to_string()).collect::<Vec<_>>();
            Ok(VmValue::String(
                slice_positions(chars.len(), lower, upper, step)?
                    .into_iter()
                    .map(|index| chars[index].clone())
                    .collect::<String>(),
            ))
        }
        other => Err(VmExecutionError::new(format!(
            "slice access is not supported for {}",
            other.type_name()
        ))),
    }
}

fn normalize_sequence_index(index: &VmValue, length: usize) -> Result<usize, VmExecutionError> {
    let raw = index.as_bigint()?;
    let length_value = BigInt::from(length);
    let adjusted = if raw.sign() == Sign::Minus {
        &length_value + &raw
    } else {
        raw
    };
    if adjusted.sign() == Sign::Minus || adjusted >= length_value {
        return Err(VmExecutionError::new("sequence index out of bounds"));
    }
    bigint_to_usize(&adjusted, "sequence index")
}

fn normalize_sequence_insert_index(
    index: &VmValue,
    length: usize,
) -> Result<usize, VmExecutionError> {
    let raw = index.as_bigint()?;
    let length_value = BigInt::from(length);
    let adjusted = if raw.sign() == Sign::Minus {
        &length_value + &raw
    } else {
        raw
    };
    let clamped = if adjusted.sign() == Sign::Minus {
        BigInt::from(0usize)
    } else if adjusted > length_value {
        length_value
    } else {
        adjusted
    };
    bigint_to_usize(&clamped, "sequence insert index")
}

fn slice_positions(
    length: usize,
    lower: Option<BigInt>,
    upper: Option<BigInt>,
    step: Option<BigInt>,
) -> Result<Vec<usize>, VmExecutionError> {
    let length_value = i64::try_from(length)
        .map_err(|_| VmExecutionError::new("sequence length exceeds supported range"))?;
    let step_value = match step {
        Some(value) => bigint_to_i64(&value, "slice step")?,
        None => 1,
    };
    if step_value == 0 {
        return Err(VmExecutionError::new("slice step cannot be zero"));
    }

    let normalize = |value: Option<BigInt>,
                     default: i64,
                     allow_negative_endpoint: bool|
     -> Result<i64, VmExecutionError> {
        let mut raw = match value {
            Some(value) => bigint_to_i64(&value, "slice bound")?,
            None => return Ok(default),
        };
        if raw < 0 {
            raw += length_value;
        }
        if allow_negative_endpoint {
            if raw < -1 {
                raw = -1;
            }
        } else if raw < 0 {
            raw = 0;
        }
        if raw > length_value {
            raw = length_value;
        }
        Ok(raw)
    };

    let mut positions = Vec::new();
    if step_value > 0 {
        let start = normalize(lower, 0, false)?;
        let stop = normalize(upper, length_value, false)?;
        let mut index = start;
        while index < stop {
            positions.push(
                usize::try_from(index)
                    .map_err(|_| VmExecutionError::new("slice position out of bounds"))?,
            );
            index += step_value;
        }
        return Ok(positions);
    }

    let start = normalize(lower, length_value - 1, true)?;
    let stop = normalize(upper, -1, true)?;
    let mut index = start;
    while index > stop {
        positions.push(
            usize::try_from(index)
                .map_err(|_| VmExecutionError::new("slice position out of bounds"))?,
        );
        index += step_value;
    }
    Ok(positions)
}

fn dict_set(entries: &mut Vec<(VmValue, VmValue)>, key: VmValue, value: VmValue) {
    if let Some(existing) = entries.iter_mut().find(|(entry_key, _)| *entry_key == key) {
        existing.1 = value;
        return;
    }
    entries.push((key, value));
}

fn dict_get(entries: &[(VmValue, VmValue)], key: &VmValue) -> Option<VmValue> {
    entries
        .iter()
        .find(|(entry_key, _)| entry_key == key)
        .map(|(_, value)| value.clone())
}

fn type_matches(value: &VmValue, marker: &VmValue) -> bool {
    match marker {
        VmValue::TypeMarker(name) => type_matches_name(value, name),
        VmValue::Builtin(name) => type_matches_name(value, name),
        VmValue::Tuple(markers) => markers.iter().any(|marker| type_matches(value, marker)),
        _ => false,
    }
}

fn type_matches_name(value: &VmValue, name: &str) -> bool {
    match name {
        "Any" => true,
        "bool" => matches!(value, VmValue::Bool(_)),
        "int" => matches!(value, VmValue::Int(_)),
        "float" => matches!(value, VmValue::Float(_)),
        "decimal" => matches!(value, VmValue::Decimal(_)),
        "datetime.datetime" => matches!(value, VmValue::DateTime(_)),
        "datetime.timedelta" => matches!(value, VmValue::TimeDelta(_)),
        "str" => matches!(value, VmValue::String(_)),
        "list" => matches!(value, VmValue::List(_)),
        "dict" => matches!(value, VmValue::Dict(_)),
        "tuple" => matches!(value, VmValue::Tuple(_)),
        _ => false,
    }
}

fn option_string_value(value: &Option<String>) -> VmValue {
    value
        .as_ref()
        .map(|value| VmValue::String(value.clone()))
        .unwrap_or(VmValue::None)
}

fn option_entry_value(value: &Option<(String, String)>) -> VmValue {
    value
        .as_ref()
        .map(|(contract, function)| {
            VmValue::Tuple(vec![
                VmValue::String(contract.clone()),
                VmValue::String(function.clone()),
            ])
        })
        .unwrap_or(VmValue::None)
}

fn normalize_event_payload(
    schema: &VmValue,
    payload: VmValue,
) -> Result<(Vec<(String, VmValue)>, Vec<(String, VmValue)>), VmExecutionError> {
    let schema_entries = match schema {
        VmValue::Dict(entries) => entries,
        other => {
            return Err(VmExecutionError::new(format!(
                "event schema must be a dict, got {}",
                other.type_name()
            )))
        }
    };
    let payload_entries = match payload {
        VmValue::Dict(entries) => entries,
        other => {
            return Err(VmExecutionError::new(format!(
                "event payload must be a dict, got {}",
                other.type_name()
            )))
        }
    };

    let mut data_indexed = Vec::new();
    let mut data = Vec::new();

    for (schema_key, schema_value) in schema_entries {
        let key = match schema_key {
            VmValue::String(value) => value.clone(),
            other => {
                return Err(VmExecutionError::new(format!(
                    "event schema keys must be strings, got {}",
                    other.type_name()
                )))
            }
        };
        let value = dict_get(&payload_entries, &VmValue::String(key.clone())).ok_or_else(|| {
            VmExecutionError::new(format!("event payload is missing key '{}'", key))
        })?;
        if event_param_is_indexed(schema_value) {
            data_indexed.push((key, value));
        } else {
            data.push((key, value));
        }
    }

    if payload_entries.len() != data_indexed.len() + data.len() {
        return Err(VmExecutionError::new("event payload has unexpected keys"));
    }

    Ok((data_indexed, data))
}

fn event_param_is_indexed(schema_value: &VmValue) -> bool {
    match schema_value {
        VmValue::Dict(entries) => {
            dict_get(entries, &VmValue::String("idx".to_owned())) == Some(VmValue::Bool(true))
        }
        _ => false,
    }
}

fn contract_target_label(target: &VmContractTarget) -> &str {
    match target {
        VmContractTarget::StaticImport { module, .. }
        | VmContractTarget::DynamicImport { module }
        | VmContractTarget::LocalHandle { module, .. }
        | VmContractTarget::FactoryCall { module, .. } => module,
    }
}

fn normalize_hash_key(value: &VmValue) -> Result<String, VmExecutionError> {
    let normalized = match value {
        VmValue::Tuple(values) => {
            if values.len() > MAX_HASH_DIMENSIONS {
                return Err(VmExecutionError::new(format!(
                    "Too many dimensions ({}) for hash. Max is {MAX_HASH_DIMENSIONS}",
                    values.len()
                )));
            }
            let mut rendered = Vec::new();
            for item in values {
                let part = storage_key_part(item)?;
                rendered.push(part);
            }
            rendered.join(STORAGE_DELIMITER)
        }
        other => storage_key_part(other)?,
    };

    if normalized.len() > MAX_STORAGE_KEY_SIZE {
        return Err(VmExecutionError::new(format!(
            "Key is too long ({}). Max is {MAX_STORAGE_KEY_SIZE}.",
            normalized.len()
        )));
    }

    Ok(normalized)
}

fn storage_key_part(value: &VmValue) -> Result<String, VmExecutionError> {
    let rendered = match value {
        VmValue::String(value) => value.clone(),
        VmValue::Int(value) => value.to_string(),
        VmValue::Bool(true) => "True".to_owned(),
        VmValue::Bool(false) => "False".to_owned(),
        VmValue::Float(value) => format!("{value:?}"),
        VmValue::None => "None".to_owned(),
        VmValue::TypeMarker(name) => name.clone(),
        other => other.python_repr(),
    };

    if rendered.contains(STORAGE_DELIMITER) {
        return Err(VmExecutionError::new("Illegal delimiter in key."));
    }
    if rendered.contains(STORAGE_INDEX_SEPARATOR) {
        return Err(VmExecutionError::new("Illegal separator in key."));
    }
    Ok(rendered)
}

fn foreign_storage_key(contract: &str, name: &str) -> String {
    format!("{contract}{STORAGE_DELIMITER}{name}")
}

fn variable_storage_key(contract: &str, binding: &str) -> String {
    format!("{contract}{STORAGE_INDEX_SEPARATOR}{binding}")
}

fn hash_storage_key(
    contract: &str,
    binding: &str,
    key: &VmValue,
) -> Result<String, VmExecutionError> {
    Ok(format!(
        "{}{}{}",
        variable_storage_key(contract, binding),
        STORAGE_DELIMITER,
        normalize_hash_key(key)?
    ))
}

fn split_foreign_storage_key(key: &str) -> Result<(String, String), VmExecutionError> {
    let Some((contract, binding)) = key.split_once(STORAGE_DELIMITER) else {
        return Err(VmExecutionError::new(format!(
            "invalid foreign storage key '{key}'"
        )));
    };
    Ok((contract.to_owned(), binding.to_owned()))
}

fn explicit_syscall_metering_cost(
    syscall_id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<Option<u64>, VmExecutionError> {
    match syscall_id {
        "zk.verify_groth16_bn254" => {
            if !kwargs.is_empty() || args.len() != 3 {
                return Err(VmExecutionError::new(
                    "zk.verify_groth16_bn254() expects three positional arguments",
                ));
            }
            let vk_hex = args[0].as_string()?;
            let proof_hex = args[1].as_string()?;
            let public_inputs = as_string_list(&args[2], "public_inputs")?;
            Ok(Some(
                zk_payload_metering_cost(&vk_hex, &proof_hex, &public_inputs)?,
            ))
        }
        "zk.verify_groth16" => {
            if !kwargs.is_empty() || args.len() != 3 {
                return Err(VmExecutionError::new(
                    "zk.verify_groth16() expects three positional arguments",
                ));
            }
            let vk_id = args[0].as_string()?;
            let proof_hex = args[1].as_string()?;
            let public_inputs = as_string_list(&args[2], "public_inputs")?;
            Ok(Some(
                zk_registry_metering_cost(&vk_id, &proof_hex, &public_inputs)?,
            ))
        }
        "zk.shielded_note_append_commitments" => {
            if args.len() != 3 || !kwargs.is_empty() {
                return Err(VmExecutionError::new(
                    "zk.shielded_note_append_commitments() expects three positional arguments",
                ));
            }
            let commitments = as_string_list(&args[2], "commitments")?;
            Ok(Some(
                250_000 + (commitments.len() as u64 * 500_000),
            ))
        }
        "zk.shielded_command_nullifier_digest" => {
            if args.len() != 1 || !kwargs.is_empty() {
                return Err(VmExecutionError::new(
                    "zk.shielded_command_nullifier_digest() expects one positional argument",
                ));
            }
            let input_nullifiers = as_string_list(&args[0], "input_nullifiers")?;
            Ok(Some(
                100_000 + (input_nullifiers.len() as u64 * 50_000),
            ))
        }
        "zk.shielded_command_binding" => Ok(Some(100_000)),
        "zk.shielded_command_execution_tag" => Ok(Some(50_000)),
        "zk.shielded_output_payload_hash" => {
            if args.len() != 1 || !kwargs.is_empty() {
                return Err(VmExecutionError::new(
                    "zk.shielded_output_payload_hash() expects one positional argument",
                ));
            }
            let payload_hex = args[0].as_string()?;
            if payload_hex.is_empty() {
                return Ok(Some(0));
            }
            Ok(Some(hex_payload_bytes(&payload_hex)?))
        }
        _ => Ok(None),
    }
}

fn as_string_list(value: &VmValue, label: &str) -> Result<Vec<String>, VmExecutionError> {
    match value {
        VmValue::List(values) | VmValue::Tuple(values) => values
            .iter()
            .map(VmValue::as_string)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| VmExecutionError::new(format!("{label} must be a list of strings"))),
        _ => Err(VmExecutionError::new(format!(
            "{label} must be a list of strings"
        ))),
    }
}

fn hex_payload_bytes(value: &str) -> Result<u64, VmExecutionError> {
    let Some(payload) = value.strip_prefix("0x") else {
        return Ok(0);
    };
    if payload.len() % 2 != 0 {
        return Ok(0);
    }
    Ok((payload.len() / 2) as u64)
}

fn zk_payload_metering_cost(
    vk_hex: &str,
    proof_hex: &str,
    public_inputs: &[String],
) -> Result<u64, VmExecutionError> {
    let payload_bytes = hex_payload_bytes(vk_hex)?
        + hex_payload_bytes(proof_hex)?
        + public_inputs
            .iter()
            .map(|value| hex_payload_bytes(value))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<u64>();
    Ok(750_000 + (public_inputs.len() as u64 * 50_000) + (payload_bytes * 50))
}

fn zk_registry_metering_cost(
    vk_id: &str,
    proof_hex: &str,
    public_inputs: &[String],
) -> Result<u64, VmExecutionError> {
    let payload_bytes = vk_id.len() as u64
        + hex_payload_bytes(proof_hex)?
        + public_inputs
            .iter()
            .map(|value| hex_payload_bytes(value))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .sum::<u64>();
    Ok(500_000 + 250_000 + (public_inputs.len() as u64 * 50_000) + (payload_bytes * 25))
}

fn resolve_contract_import_arg(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<String, VmExecutionError> {
    if let Some((_, value)) = kwargs.iter().find(|(key, _)| key == "module") {
        return value.as_string();
    }
    if let Some((_, value)) = kwargs.iter().find(|(key, _)| key == "name") {
        return value.as_string();
    }
    let first = args
        .first()
        .ok_or_else(|| VmExecutionError::new("contract.import expects a module name"))?;
    first.as_string()
}

fn positional_value(
    instance: &mut VmInstance,
    args: &[Value],
    index: usize,
    host: &mut dyn VmHost,
) -> Result<Option<VmValue>, VmExecutionError> {
    args.get(index)
        .map(|value| instance.eval_expression(value, &mut instance.globals.clone(), host))
        .transpose()
}

fn keyword_value(
    instance: &mut VmInstance,
    keywords: &[Value],
    name: &str,
    host: &mut dyn VmHost,
) -> Result<Option<VmValue>, VmExecutionError> {
    let Some(keyword) = keywords.iter().find(|keyword| {
        as_object(keyword, "keyword")
            .ok()
            .and_then(|object| optional_string(object, "arg"))
            == Some(name)
    }) else {
        return Ok(None);
    };
    let keyword_object = as_object(keyword, "keyword")?;
    instance
        .eval_expression(required_value(keyword_object, "value")?, &mut instance.globals.clone(), host)
        .map(Some)
}

fn required_value<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Value, VmExecutionError> {
    object
        .get(field)
        .ok_or_else(|| VmExecutionError::new(format!("missing field '{field}'")))
}

fn required_array<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a [Value], VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be an array")))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be a string")))
}

fn optional_string<'a>(object: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    object.get(field).and_then(Value::as_str)
}

fn required_string_value(value: &Value) -> Result<&str, VmExecutionError> {
    value
        .as_str()
        .ok_or_else(|| VmExecutionError::new("value must be a string"))
}

fn required_bool(object: &Map<String, Value>, field: &str) -> Result<bool, VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be a bool")))
}

fn required_bigint(object: &Map<String, Value>, field: &str) -> Result<BigInt, VmExecutionError> {
    let value = object
        .get(field)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be an int")))?;
    match value {
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                return Ok(BigInt::from(value));
            }
            if let Some(value) = number.as_u64() {
                return Ok(BigInt::from(value));
            }
            BigInt::from_str(&number.to_string())
                .map_err(|_| VmExecutionError::new(format!("field '{field}' must be an int")))
        }
        Value::String(value) => BigInt::from_str(value)
            .map_err(|_| VmExecutionError::new(format!("field '{field}' must be an int"))),
        _ => Err(VmExecutionError::new(format!(
            "field '{field}' must be an int"
        ))),
    }
}

fn required_f64(object: &Map<String, Value>, field: &str) -> Result<f64, VmExecutionError> {
    object
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| VmExecutionError::new(format!("field '{field}' must be a float")))
}

fn as_object<'a>(
    value: &'a Value,
    label: &str,
) -> Result<&'a Map<String, Value>, VmExecutionError> {
    value.as_object().ok_or_else(|| {
        VmExecutionError::new(format!(
            "{label} must be an object, got {}",
            serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_owned())
        ))
    })
}

struct NoopHost;

impl VmHost for NoopHost {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_module_ir, XIAN_IR_V1, XIAN_VM_HOST_CATALOG_V1, XIAN_VM_V1_PROFILE};
    use serde_json::json;

    #[derive(Default)]
    struct RecordingHost {
        events: Vec<VmEvent>,
        calls: Vec<VmContractCall>,
    }

    #[derive(Default)]
    struct SyscallRecordingHost {
        syscalls: Vec<(String, Vec<VmValue>, Vec<(String, VmValue)>)>,
    }

    impl VmHost for RecordingHost {
        fn emit_event(&mut self, event: VmEvent) -> Result<(), VmExecutionError> {
            self.events.push(event);
            Ok(())
        }

        fn call_contract(&mut self, call: VmContractCall) -> Result<VmValue, VmExecutionError> {
            self.calls.push(call.clone());
            match call.function.as_str() {
                "transfer" => Ok(VmValue::Bool(true)),
                "balance_of" => Ok(vm_int(77)),
                _ => Ok(VmValue::None),
            }
        }
    }

    impl VmHost for SyscallRecordingHost {
        fn handle_syscall(
            &mut self,
            syscall_id: &str,
            args: Vec<VmValue>,
            kwargs: Vec<(String, VmValue)>,
        ) -> Result<VmValue, VmExecutionError> {
            self.syscalls
                .push((syscall_id.to_owned(), args.clone(), kwargs.clone()));
            match syscall_id {
                "zk.verify_groth16" => Ok(VmValue::Bool(true)),
                "zk.shielded_output_payload_hash" => {
                    Ok(VmValue::String("0x".to_owned() + &"ab".repeat(32)))
                }
                other => Err(VmExecutionError::new(format!(
                    "unexpected syscall '{other}'"
                ))),
            }
        }
    }

    #[test]
    fn executes_storage_event_and_contract_calls() {
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "sample_token",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [
                    {
                        "node": "import",
                        "span": {"line": 1, "col": 0, "end_line": 1, "end_col": 15},
                        "module": "currency",
                        "alias": null
                    }
                ],
                "global_declarations": [
                    {
                        "node": "storage_decl",
                        "span": {"line": 2, "col": 0, "end_line": 2, "end_col": 24},
                        "name": "balances",
                        "storage_type": "Hash",
                        "syscall_id": "storage.hash.new",
                        "args": [],
                        "keywords": [
                            {
                                "arg": "default_value",
                                "span": {"line": 2, "col": 16, "end_line": 2, "end_col": 23},
                                "value": {
                                    "node": "constant",
                                    "span": {"line": 2, "col": 23, "end_line": 2, "end_col": 24},
                                    "value_type": "int",
                                    "value": 0
                                }
                            }
                        ]
                    },
                    {
                        "node": "storage_decl",
                        "span": {"line": 3, "col": 0, "end_line": 3, "end_col": 18},
                        "name": "metadata",
                        "storage_type": "Variable",
                        "syscall_id": "storage.variable.new",
                        "args": [],
                        "keywords": []
                    },
                    {
                        "node": "event_decl",
                        "span": {"line": 4, "col": 0, "end_line": 4, "end_col": 10},
                        "name": "TransferEvent",
                        "syscall_id": "event.log.new",
                        "event_name": "Transfer",
                        "params": {
                            "node": "dict",
                            "span": {"line": 4, "col": 0, "end_line": 4, "end_col": 10},
                            "entries": [
                                {
                                    "key": {
                                        "node": "constant",
                                        "span": {"line": 4, "col": 1, "end_line": 4, "end_col": 7},
                                        "value_type": "str",
                                        "value": "from"
                                    },
                                    "value": {
                                        "node": "call",
                                        "span": {"line": 4, "col": 8, "end_line": 4, "end_col": 20},
                                        "func": {
                                            "node": "name",
                                            "span": {"line": 4, "col": 8, "end_line": 4, "end_col": 15},
                                            "id": "indexed",
                                            "host_binding_id": "event.indexed"
                                        },
                                        "args": [
                                            {
                                                "node": "name",
                                                "span": {"line": 4, "col": 16, "end_line": 4, "end_col": 19},
                                                "id": "str",
                                                "host_binding_id": null
                                            }
                                        ],
                                        "keywords": [],
                                        "syscall_id": "event.indexed"
                                    }
                                }
                            ]
                        }
                    }
                ],
                "functions": [
                    {
                        "node": "function",
                        "span": {"line": 6, "col": 0, "end_line": 14, "end_col": 20},
                        "name": "transfer",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "amount",
                                "kind": "positional_or_keyword",
                                "annotation": "int",
                                "default": null,
                                "span": {"line": 6, "col": 13, "end_line": 6, "end_col": 23}
                            },
                            {
                                "name": "to",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 6, "col": 25, "end_line": 6, "end_col": 32}
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "assign",
                                "span": {"line": 7, "col": 4, "end_line": 7, "end_col": 21},
                                "targets": [
                                    {
                                        "node": "name",
                                        "span": {"line": 7, "col": 4, "end_line": 7, "end_col": 10},
                                        "id": "sender",
                                        "host_binding_id": null
                                    }
                                ],
                                "value": {
                                    "node": "attribute",
                                    "span": {"line": 7, "col": 13, "end_line": 7, "end_col": 23},
                                    "value": {
                                        "node": "name",
                                        "span": {"line": 7, "col": 13, "end_line": 7, "end_col": 16},
                                        "id": "ctx",
                                        "host_binding_id": null
                                    },
                                    "attr": "caller",
                                    "path": "ctx.caller",
                                    "host_binding_id": "context.caller"
                                }
                            },
                            {
                                "node": "expr",
                                "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 21},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 21},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 16},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 8, "col": 4, "end_line": 8, "end_col": 12},
                                            "id": "metadata",
                                            "host_binding_id": null
                                        },
                                        "attr": "set",
                                        "path": "metadata.set",
                                        "host_binding_id": null
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": {"line": 8, "col": 17, "end_line": 8, "end_col": 20},
                                            "id": "now",
                                            "host_binding_id": "env.now"
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "storage.variable.set",
                                    "receiver_binding": "metadata",
                                    "receiver_type": "Variable",
                                    "method": "set"
                                }
                            },
                            {
                                "node": "storage_mutate",
                                "span": {"line": 9, "col": 4, "end_line": 9, "end_col": 30},
                                "binding": "balances",
                                "storage_type": "Hash",
                                "read_syscall_id": "storage.hash.get",
                                "write_syscall_id": "storage.hash.set",
                                "key": {
                                    "node": "name",
                                    "span": {"line": 9, "col": 13, "end_line": 9, "end_col": 19},
                                    "id": "sender",
                                    "host_binding_id": null
                                },
                                "operator": "sub",
                                "value": {
                                    "node": "name",
                                    "span": {"line": 9, "col": 24, "end_line": 9, "end_col": 30},
                                    "id": "amount",
                                    "host_binding_id": null
                                }
                            },
                            {
                                "node": "storage_mutate",
                                "span": {"line": 10, "col": 4, "end_line": 10, "end_col": 25},
                                "binding": "balances",
                                "storage_type": "Hash",
                                "read_syscall_id": "storage.hash.get",
                                "write_syscall_id": "storage.hash.set",
                                "key": {
                                    "node": "name",
                                    "span": {"line": 10, "col": 13, "end_line": 10, "end_col": 15},
                                    "id": "to",
                                    "host_binding_id": null
                                },
                                "operator": "add",
                                "value": {
                                    "node": "name",
                                    "span": {"line": 10, "col": 20, "end_line": 10, "end_col": 26},
                                    "id": "amount",
                                    "host_binding_id": null
                                }
                            },
                            {
                                "node": "expr",
                                "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 43},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 43},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 21},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 12},
                                            "id": "currency",
                                            "host_binding_id": null
                                        },
                                        "attr": "transfer",
                                        "path": "currency.transfer",
                                        "host_binding_id": null
                                    },
                                    "args": [],
                                    "keywords": [
                                        {
                                            "arg": "amount",
                                            "span": {"line": 11, "col": 22, "end_line": 11, "end_col": 35},
                                            "value": {
                                                "node": "name",
                                                "span": {"line": 11, "col": 29, "end_line": 11, "end_col": 35},
                                                "id": "amount",
                                                "host_binding_id": null
                                            }
                                        },
                                        {
                                            "arg": "to",
                                            "span": {"line": 11, "col": 37, "end_line": 11, "end_col": 42},
                                            "value": {
                                                "node": "name",
                                                "span": {"line": 11, "col": 40, "end_line": 11, "end_col": 42},
                                                "id": "to",
                                                "host_binding_id": null
                                            }
                                        }
                                    ],
                                    "syscall_id": "contract.export_call",
                                    "contract_target": {
                                        "kind": "static_import",
                                        "binding": "currency",
                                        "span": {"line": 11, "col": 4, "end_line": 11, "end_col": 12}
                                    },
                                    "function_name": "transfer"
                                }
                            },
                            {
                                "node": "expr",
                                "span": {"line": 12, "col": 4, "end_line": 12, "end_col": 40},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 12, "col": 4, "end_line": 12, "end_col": 40},
                                    "func": {
                                        "node": "name",
                                        "span": {"line": 12, "col": 4, "end_line": 12, "end_col": 17},
                                        "id": "TransferEvent",
                                        "host_binding_id": null
                                    },
                                    "args": [
                                        {
                                            "node": "dict",
                                            "span": {"line": 12, "col": 18, "end_line": 12, "end_col": 39},
                                            "entries": [
                                                {
                                                    "key": {
                                                        "node": "constant",
                                                        "span": {"line": 12, "col": 19, "end_line": 12, "end_col": 25},
                                                        "value_type": "str",
                                                        "value": "from"
                                                    },
                                                    "value": {
                                                        "node": "name",
                                                        "span": {"line": 12, "col": 27, "end_line": 12, "end_col": 33},
                                                        "id": "sender",
                                                        "host_binding_id": null
                                                    }
                                                }
                                            ]
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "event.log.emit",
                                    "event_binding": "TransferEvent"
                                }
                            },
                            {
                                "node": "return",
                                "span": {"line": 13, "col": 4, "end_line": 13, "end_col": 23},
                                "value": {
                                    "node": "storage_get",
                                    "span": {"line": 13, "col": 11, "end_line": 13, "end_col": 23},
                                    "binding": "balances",
                                    "storage_type": "Hash",
                                    "syscall_id": "storage.hash.get",
                                    "key": {
                                        "node": "name",
                                        "span": {"line": 13, "col": 20, "end_line": 13, "end_col": 22},
                                        "id": "to",
                                        "host_binding_id": null
                                    }
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "Variable", "id": "storage.variable.new", "kind": "syscall", "category": "storage"},
                    {"binding": "Variable.set", "id": "storage.variable.set", "kind": "syscall", "category": "storage"},
                    {"binding": "Hash", "id": "storage.hash.new", "kind": "syscall", "category": "storage"},
                    {"binding": "Hash.__getitem__", "id": "storage.hash.get", "kind": "syscall", "category": "storage"},
                    {"binding": "Hash.__setitem__", "id": "storage.hash.set", "kind": "syscall", "category": "storage"},
                    {"binding": "LogEvent", "id": "event.log.new", "kind": "syscall", "category": "event"},
                    {"binding": "LogEvent.__call__", "id": "event.log.emit", "kind": "syscall", "category": "event"},
                    {"binding": "indexed", "id": "event.indexed", "kind": "syscall", "category": "event"},
                    {"binding": "__contract_export__", "id": "contract.export_call", "kind": "syscall", "category": "contract"},
                    {"binding": "ctx.caller", "id": "context.caller", "kind": "context_field", "category": "context"},
                    {"binding": "now", "id": "env.now", "kind": "env_value", "category": "environment"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(
            module,
            VmExecutionContext {
                caller: Some("alice".to_owned()),
                signer: Some("alice".to_owned()),
                now: vm_int(1234),
                ..VmExecutionContext::default()
            },
        )
        .expect("instance should initialize");

        instance
            .hash_set("balances", &VmValue::String("alice".to_owned()), vm_int(20))
            .expect("seed sender balance");

        let mut host = RecordingHost::default();
        let result = instance
            .call_function(
                &mut host,
                "transfer",
                vec![vm_int(5), VmValue::String("bob".to_owned())],
                vec![],
            )
            .expect("transfer should execute");

        assert_eq!(result, vm_int(5));
        assert_eq!(instance.get_variable("metadata"), Some(vm_int(1234)));
        assert_eq!(
            instance
                .get_hash_value("balances", &VmValue::String("alice".to_owned()))
                .expect("alice balance should exist"),
            Some(vm_int(15))
        );
        assert_eq!(
            instance
                .get_hash_value("balances", &VmValue::String("bob".to_owned()))
                .expect("bob balance should exist"),
            Some(vm_int(5))
        );
        assert_eq!(host.events.len(), 1);
        assert_eq!(host.events[0].contract, "sample_token");
        assert_eq!(host.events[0].event, "Transfer");
        assert_eq!(host.events[0].signer, VmValue::String("alice".to_owned()));
        assert_eq!(host.events[0].caller, VmValue::String("alice".to_owned()));
        assert_eq!(
            host.events[0].data_indexed,
            vec![("from".to_owned(), VmValue::String("alice".to_owned()))]
        );
        assert_eq!(host.events[0].data, Vec::<(String, VmValue)>::new());
        assert_eq!(host.calls.len(), 1);
        assert_eq!(contract_target_label(&host.calls[0].target), "currency");
        assert_eq!(host.calls[0].function, "transfer");
    }

    #[test]
    fn resolves_dynamic_imports_and_factory_calls() {
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "adapter",
                "source_hash": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": {"line": 1, "col": 0, "end_line": 2, "end_col": 24},
                        "name": "load_token",
                        "visibility": "private",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "token",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 1, "col": 14, "end_line": 1, "end_col": 24}
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": {"line": 2, "col": 4, "end_line": 2, "end_col": 24},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 2, "col": 11, "end_line": 2, "end_col": 24},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 2, "col": 11, "end_line": 2, "end_col": 23},
                                        "value": {
                                            "node": "name",
                                            "span": {"line": 2, "col": 11, "end_line": 2, "end_col": 20},
                                            "id": "importlib",
                                            "host_binding_id": null
                                        },
                                        "attr": "import_module",
                                        "path": "importlib.import_module",
                                        "host_binding_id": "contract.import"
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": {"line": 2, "col": 21, "end_line": 2, "end_col": 24},
                                            "id": "token",
                                            "host_binding_id": null
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "contract.import"
                                }
                            }
                        ]
                    },
                    {
                        "node": "function",
                        "span": {"line": 4, "col": 0, "end_line": 5, "end_col": 40},
                        "name": "balance_of_token",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "token",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 4, "col": 20, "end_line": 4, "end_col": 30}
                            },
                            {
                                "name": "account",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": {"line": 4, "col": 32, "end_line": 4, "end_col": 44}
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "return",
                                "span": {"line": 5, "col": 4, "end_line": 5, "end_col": 40},
                                "value": {
                                    "node": "call",
                                    "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 40},
                                    "func": {
                                        "node": "attribute",
                                        "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 29},
                                        "value": {
                                            "node": "call",
                                            "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 28},
                                            "func": {
                                                "node": "name",
                                                "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 21},
                                                "id": "load_token",
                                                "host_binding_id": null
                                            },
                                            "args": [
                                                {
                                                    "node": "name",
                                                    "span": {"line": 5, "col": 22, "end_line": 5, "end_col": 27},
                                                    "id": "token",
                                                    "host_binding_id": null
                                                }
                                            ],
                                            "keywords": []
                                        },
                                        "attr": "balance_of",
                                        "path": "load_token.balance_of",
                                        "host_binding_id": null
                                    },
                                    "args": [],
                                    "keywords": [
                                        {
                                            "arg": "account",
                                            "span": {"line": 5, "col": 30, "end_line": 5, "end_col": 39},
                                            "value": {
                                                "node": "name",
                                                "span": {"line": 5, "col": 38, "end_line": 5, "end_col": 45},
                                                "id": "account",
                                                "host_binding_id": null
                                            }
                                        }
                                    ],
                                    "syscall_id": "contract.export_call",
                                    "contract_target": {
                                        "kind": "factory_call",
                                        "factory": "load_token",
                                        "source": {
                                            "node": "call",
                                            "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 28},
                                            "func": {
                                                "node": "name",
                                                "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 21},
                                                "id": "load_token",
                                                "host_binding_id": null
                                            },
                                            "args": [
                                                {
                                                    "node": "name",
                                                    "span": {"line": 5, "col": 22, "end_line": 5, "end_col": 27},
                                                    "id": "token",
                                                    "host_binding_id": null
                                                }
                                            ],
                                            "keywords": []
                                        },
                                        "span": {"line": 5, "col": 11, "end_line": 5, "end_col": 28}
                                    },
                                    "function_name": "balance_of"
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "importlib.import_module", "id": "contract.import", "kind": "syscall", "category": "import"},
                    {"binding": "__contract_export__", "id": "contract.export_call", "kind": "syscall", "category": "contract"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "balance_of_token",
                vec![
                    VmValue::String("shielded_note".to_owned()),
                    VmValue::String("alice".to_owned()),
                ],
                vec![],
            )
            .expect("call should execute");

        assert_eq!(result, vm_int(77));
        assert_eq!(host.calls.len(), 1);
        match &host.calls[0].target {
            VmContractTarget::FactoryCall { factory, module } => {
                assert_eq!(factory, "load_token");
                assert_eq!(module, "shielded_note");
            }
            other => panic!("unexpected contract target: {other:?}"),
        }
        assert_eq!(host.calls[0].function, "balance_of");
    }

    #[test]
    fn supports_string_replace_with_optional_count() {
        let replaced = call_native_method(
            VmValue::String("foo-foo-foo".to_owned()),
            "replace",
            vec![
                VmValue::String("foo".to_owned()),
                VmValue::String("bar".to_owned()),
            ],
            vec![],
        )
        .expect("replace should succeed");
        match replaced {
            NativeMethodResult::Value(VmValue::String(value)) => {
                assert_eq!(value, "bar-bar-bar".to_owned());
            }
            _ => panic!("unexpected replace result"),
        }

        let limited = call_native_method(
            VmValue::String("foo-foo-foo".to_owned()),
            "replace",
            vec![
                VmValue::String("foo".to_owned()),
                VmValue::String("bar".to_owned()),
                vm_int(2),
            ],
            vec![],
        )
        .expect("replace with count should succeed");
        match limited {
            NativeMethodResult::Value(VmValue::String(value)) => {
                assert_eq!(value, "bar-bar-foo".to_owned());
            }
            _ => panic!("unexpected replace result with count"),
        }

        let negative = call_native_method(
            VmValue::String("foo-foo".to_owned()),
            "replace",
            vec![
                VmValue::String("foo".to_owned()),
                VmValue::String("bar".to_owned()),
                vm_int(-1),
            ],
            vec![],
        )
        .expect("replace with negative count should replace all");
        match negative {
            NativeMethodResult::Value(VmValue::String(value)) => {
                assert_eq!(value, "bar-bar".to_owned());
            }
            _ => panic!("unexpected replace result with negative count"),
        }
    }

    #[test]
    fn delegates_zk_syscalls_to_host() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "zk_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "probe",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "payload",
                                "kind": "positional_or_keyword",
                                "annotation": "str",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "assign",
                                "span": span.clone(),
                                "targets": [
                                    {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "verified",
                                        "host_binding_id": null
                                    }
                                ],
                                "value": {
                                    "node": "call",
                                    "span": span.clone(),
                                    "func": {
                                        "node": "attribute",
                                        "span": span.clone(),
                                        "value": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "zk",
                                            "host_binding_id": null
                                        },
                                        "attr": "verify_groth16",
                                        "path": "zk.verify_groth16",
                                        "host_binding_id": "zk.verify_groth16"
                                    },
                                    "args": [
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "str",
                                            "value": "vk-main"
                                        },
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "str",
                                            "value": "proof-main"
                                        },
                                        {
                                            "node": "list",
                                            "span": span.clone(),
                                            "elements": [
                                                {
                                                    "node": "name",
                                                    "span": span.clone(),
                                                    "id": "payload",
                                                    "host_binding_id": null
                                                },
                                                {
                                                    "node": "constant",
                                                    "span": span.clone(),
                                                    "value_type": "str",
                                                    "value": "42"
                                                }
                                            ]
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "zk.verify_groth16"
                                }
                            },
                            {
                                "node": "assign",
                                "span": span.clone(),
                                "targets": [
                                    {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "digest",
                                        "host_binding_id": null
                                    }
                                ],
                                "value": {
                                    "node": "call",
                                    "span": span.clone(),
                                    "func": {
                                        "node": "attribute",
                                        "span": span.clone(),
                                        "value": {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "zk",
                                            "host_binding_id": null
                                        },
                                        "attr": "shielded_output_payload_hash",
                                        "path": "zk.shielded_output_payload_hash",
                                        "host_binding_id": "zk.shielded_output_payload_hash"
                                    },
                                    "args": [
                                        {
                                            "node": "name",
                                            "span": span.clone(),
                                            "id": "payload",
                                            "host_binding_id": null
                                        }
                                    ],
                                    "keywords": [],
                                    "syscall_id": "zk.shielded_output_payload_hash"
                                }
                            },
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "dict",
                                    "span": span.clone(),
                                    "entries": [
                                        {
                                            "key": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "verified"
                                            },
                                            "value": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "verified",
                                                "host_binding_id": null
                                            }
                                        },
                                        {
                                            "key": {
                                                "node": "constant",
                                                "span": span.clone(),
                                                "value_type": "str",
                                                "value": "digest"
                                            },
                                            "value": {
                                                "node": "name",
                                                "span": span.clone(),
                                                "id": "digest",
                                                "host_binding_id": null
                                            }
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": [
                    {"binding": "zk.verify_groth16", "id": "zk.verify_groth16", "kind": "syscall", "category": "zk"},
                    {"binding": "zk.shielded_output_payload_hash", "id": "zk.shielded_output_payload_hash", "kind": "syscall", "category": "zk"}
                ]
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = SyscallRecordingHost::default();

        let result = instance
            .call_function(
                &mut host,
                "probe",
                vec![VmValue::String("0x1234".to_owned())],
                vec![],
            )
            .expect("call should execute");

        let VmValue::Dict(entries) = result else {
            panic!("expected dict result");
        };
        assert_eq!(
            dict_get(&entries, &VmValue::String("verified".to_owned())),
            Some(VmValue::Bool(true))
        );
        assert_eq!(
            dict_get(&entries, &VmValue::String("digest".to_owned())),
            Some(VmValue::String("0x".to_owned() + &"ab".repeat(32)))
        );
        assert_eq!(host.syscalls.len(), 2);
        assert_eq!(host.syscalls[0].0, "zk.verify_groth16");
        assert_eq!(
            host.syscalls[0].1,
            vec![
                VmValue::String("vk-main".to_owned()),
                VmValue::String("proof-main".to_owned()),
                VmValue::List(vec![
                    VmValue::String("0x1234".to_owned()),
                    VmValue::String("42".to_owned()),
                ]),
            ]
        );
        assert_eq!(host.syscalls[1].0, "zk.shielded_output_payload_hash");
        assert_eq!(
            host.syscalls[1].1,
            vec![VmValue::String("0x1234".to_owned())]
        );
    }

    #[test]
    fn formats_assert_failures_like_python_repr() {
        let span = json!({"line": 1, "col": 0, "end_line": 1, "end_col": 1});
        let module = parse_module_ir(
            &json!({
                "ir_version": XIAN_IR_V1,
                "vm_profile": XIAN_VM_V1_PROFILE,
                "host_catalog_version": XIAN_VM_HOST_CATALOG_V1,
                "module_name": "assert_probe",
                "source_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "docstring": null,
                "imports": [],
                "global_declarations": [],
                "functions": [
                    {
                        "node": "function",
                        "span": span.clone(),
                        "name": "must_be_positive",
                        "visibility": "export",
                        "decorator": null,
                        "docstring": null,
                        "parameters": [
                            {
                                "name": "value",
                                "kind": "positional_or_keyword",
                                "annotation": "int",
                                "default": null,
                                "span": span.clone()
                            }
                        ],
                        "returns": null,
                        "body": [
                            {
                                "node": "assert",
                                "span": span.clone(),
                                "test": {
                                    "node": "compare",
                                    "span": span.clone(),
                                    "left": {
                                        "node": "name",
                                        "span": span.clone(),
                                        "id": "value",
                                        "host_binding_id": null
                                    },
                                    "ops": ["gt"],
                                    "comparators": [
                                        {
                                            "node": "constant",
                                            "span": span.clone(),
                                            "value_type": "int",
                                            "value": 0
                                        }
                                    ]
                                },
                                "message": {
                                    "node": "constant",
                                    "span": span.clone(),
                                    "value_type": "str",
                                    "value": "value must be positive"
                                }
                            },
                            {
                                "node": "return",
                                "span": span.clone(),
                                "value": {
                                    "node": "name",
                                    "span": span.clone(),
                                    "id": "value",
                                    "host_binding_id": null
                                }
                            }
                        ]
                    }
                ],
                "module_body": [],
                "host_dependencies": []
            })
            .to_string(),
        )
        .expect("module should parse");

        let mut instance = VmInstance::new(module, VmExecutionContext::default())
            .expect("instance should initialize");
        let mut host = RecordingHost::default();

        let error = instance
            .call_function(&mut host, "must_be_positive", vec![vm_int(-1)], vec![])
            .expect_err("call should fail");

        assert_eq!(error.to_string(), "AssertionError('value must be positive')");
    }
}
