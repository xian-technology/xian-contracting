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
        let mut scale = fraction.len() as i128 - exponent as i128;

        if scale > DECIMAL_SCALE as i128 {
            let trim = scale - DECIMAL_SCALE as i128;
            if trim >= digits.len() as i128 {
                return Ok(Self::zero());
            }
            digits.truncate(digits.len() - trim as usize);
            scale = DECIMAL_SCALE as i128;
        }

        if scale < DECIMAL_SCALE as i128 {
            let zeros_to_append = DECIMAL_SCALE as i128 - scale;
            let scaled_digits = digits.trim_start_matches('0').len() as i128 + zeros_to_append;
            if scaled_digits > DECIMAL_MAX_SCALED_DIGITS as i128 {
                return Err(VmExecutionError::new(format!(
                    "decimal value {trimmed} exceeds the supported decimal range"
                )));
            }
            digits.push_str(&"0".repeat(zeros_to_append as usize));
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
        let value = &value.snapshot();
        match value {
            VmValue::Decimal(value) => Ok(value.clone()),
            VmValue::Int(value) => Self::from_str_literal(&value.to_string()),
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

    pub(crate) fn is_zero(&self) -> bool {
        self.scaled.is_zero()
    }

    pub(crate) fn to_bigint(&self) -> BigInt {
        &self.scaled / decimal_scale_factor()
    }

    pub(crate) fn python_repr(&self) -> String {
        self.to_string()
    }

    /// Fee settlement and reward arithmetic (the interpreter uses `numeric_v2`).
    #[cfg(any(feature = "engine", test))]
    pub(crate) fn add(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_scaled(&self.scaled + &other.scaled)
    }

    #[cfg(any(feature = "engine", test))]
    pub(crate) fn sub(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_scaled(&self.scaled - &other.scaled)
    }

    #[cfg(any(feature = "engine", test))]
    pub(crate) fn mul(&self, other: &Self) -> Result<Self, VmExecutionError> {
        Self::from_scaled((&self.scaled * &other.scaled) / decimal_scale_factor())
    }

    #[cfg(any(feature = "engine", test))]
    pub(crate) fn div(&self, other: &Self) -> Result<Self, VmExecutionError> {
        if other.is_zero() {
            return Err(VmExecutionError::new("division by zero"));
        }
        Self::from_scaled((&self.scaled * decimal_scale_factor()) / &other.scaled)
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

pub(crate) fn decimal_scale_factor() -> &'static BigInt {
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

#[path = "time_parsing.rs"]
mod time_parsing;

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
        if !(1..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || !(0..=23).contains(&hour)
            || !(0..=59).contains(&minute)
            || !(0..=59).contains(&second)
            || !(0..=999_999).contains(&microsecond)
        {
            return Err(VmExecutionError::new("invalid datetime components"));
        }
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

    pub fn parse_work_cost(date_string: &str, format: &str) -> Result<u64, VmExecutionError> {
        time_parsing::work_cost(date_string, format)
    }

    pub fn parse(date_string: &str, format: &str) -> Result<Self, VmExecutionError> {
        time_parsing::parse(date_string, format).map(|value| Self { value })
    }

    pub fn add_timedelta(&self, delta: &VmTimeDelta) -> Result<Self, VmExecutionError> {
        self.value
            .checked_add_signed(delta.duration())
            .filter(|value| (1..=9999).contains(&value.year()))
            .map(|value| Self { value })
            .ok_or_else(|| VmExecutionError::new("datetime overflow"))
    }

    pub fn sub_datetime(&self, other: &Self) -> Result<VmTimeDelta, VmExecutionError> {
        let microseconds = self
            .value
            .signed_duration_since(other.value)
            .num_microseconds()
            .ok_or_else(|| VmExecutionError::new("timedelta overflow"))?;
        VmTimeDelta::from_raw_seconds(microseconds.div_euclid(1_000_000))
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
        // Python timedelta bounds normalized days, including the final day's seconds.
        if !(-86_399_999_913_600..=86_399_999_999_999).contains(&raw_seconds) {
            return Err(VmExecutionError::new("timedelta overflow"));
        }
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
        // Historical Timedelta multiplies normalized components, not total seconds.
        let days = i128::from(self.raw_seconds.div_euclid(86_400))
            * i128::from(other.raw_seconds.div_euclid(86_400));
        let seconds = i128::from(self.raw_seconds.rem_euclid(86_400))
            * i128::from(other.raw_seconds.rem_euclid(86_400));
        let total = i64::try_from(days * 86_400 + seconds)
            .map_err(|_| VmExecutionError::new("timedelta overflow"))?;
        Self::from_raw_seconds(total)
    }

    pub fn seconds(&self) -> i64 {
        self.raw_seconds
    }

    pub fn minutes(&self) -> i64 {
        self.raw_seconds.div_euclid(60)
    }

    pub fn hours(&self) -> i64 {
        self.raw_seconds.div_euclid(3_600)
    }

    pub fn days(&self) -> i64 {
        self.raw_seconds.div_euclid(86_400)
    }

    pub fn weeks(&self) -> i64 {
        self.raw_seconds.div_euclid(604_800)
    }
}

impl fmt::Display for VmTimeDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let days = self.raw_seconds.div_euclid(86_400);
        let remaining = self.raw_seconds.rem_euclid(86_400);
        let hours = remaining / 3_600;
        let minutes = (remaining % 3_600) / 60;
        let seconds = remaining % 60;
        if days == 0 {
            write!(f, "{hours}:{minutes:02}:{seconds:02}")
        } else {
            let unit = if days.abs() == 1 { "day" } else { "days" };
            write!(f, "{days} {unit}, {hours}:{minutes:02}:{seconds:02}")
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum VmValue {
    Reference(crate::VmReference),
    Iterator(Box<crate::VmIterator>),
    Range(crate::VmRange),
    View(Box<crate::VmDictView>),
    None,
    Bool(bool),
    Int(BigInt),
    Decimal(VmDecimal),
    DateTime(VmDateTime),
    TimeDelta(VmTimeDelta),
    String(String),
    Bytes(Vec<u8>),
    ByteArray(Vec<u8>),
    Set(Vec<VmValue>),
    /// Builtin set produced by dictionary-view algebra; normalize explicitly at external boundaries.
    BuiltinSet(Vec<VmValue>),
    FrozenSet(Vec<VmValue>),
    List(Vec<VmValue>),
    Tuple(Vec<VmValue>),
    Dict(Vec<(VmValue, VmValue)>),
    ContractHandle(VmContractHandle),
    DeploymentHandle,
    StorageRef(VmStorageRef),
    ForeignStorageRef(VmForeignStorageRef),
    EventRef(Box<VmEventDefinition>),
    BoundMethod(Box<crate::VmBoundMethod>),
    MappingProxy(Box<VmValue>),
    HostCallable(crate::VmHostCallable),
    InterfaceDescriptor(Box<crate::VmInterfaceDescriptor>),
    InterfaceSubject(Box<crate::VmInterfaceSubject>),
    Builtin(String),
    FunctionRef(String),
    TypeMarker(String),
    Exception(VmException),
}

impl VmValue {
    pub(crate) fn external_value(&self) -> Result<Self, VmExecutionError> {
        crate::heap::validate_external_values(std::iter::once(self))?;
        self.detached()
    }
    pub(crate) fn storage_value(&self) -> Result<Self, VmExecutionError> {
        let detached = self.external_value()?;
        // Persistence eligibility cannot depend on whether chi metering is on.
        crate::set_member_codec::validate_set_normalization_work(&detached)?;
        detached.validate_storage_payload()?;
        Ok(detached)
    }

    fn validate_storage_payload(&self) -> Result<(), VmExecutionError> {
        match self {
            Self::Set(_) | Self::FrozenSet(_) => {
                crate::set_member_codec::encode_set_value(self)?;
            }
            Self::List(values) | Self::Tuple(values) | Self::BuiltinSet(values) => {
                for value in values {
                    value.validate_storage_payload()?;
                }
            }
            // Keys were checked at the VM boundary (`external_value`): only
            // strings that are not codec tags reach here.
            Self::Dict(entries) => {
                for (_, value) in entries {
                    value.validate_storage_payload()?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn truthy(&self) -> bool {
        match self {
            Self::Reference(value) => value.with_value(|value| value.truthy()),
            Self::Iterator(_) => true,
            Self::View(view) => view.len() != 0,
            Self::Range(range) => !range.len().is_zero(),
            Self::MappingProxy(value) => value.truthy(),
            Self::BoundMethod(_) => true,
            Self::None => false,
            Self::Bool(value) => *value,
            Self::Int(value) => !value.is_zero(),
            Self::Decimal(value) => !value.is_zero(),
            Self::DateTime(_) => true,
            Self::TimeDelta(value) => value.seconds() != 0,
            Self::String(value) => !value.is_empty(),
            Self::Bytes(value) | Self::ByteArray(value) => !value.is_empty(),
            Self::Set(values) | Self::BuiltinSet(values) | Self::FrozenSet(values) => {
                !values.is_empty()
            }
            Self::List(values) | Self::Tuple(values) => !values.is_empty(),
            Self::Dict(entries) => !entries.is_empty(),
            Self::DeploymentHandle
            | Self::ContractHandle(_)
            | Self::StorageRef(_)
            | Self::ForeignStorageRef(_)
            | Self::EventRef(_)
            | Self::HostCallable(_)
            | Self::InterfaceSubject(_)
            | Self::InterfaceDescriptor(_)
            | Self::Builtin(_)
            | Self::FunctionRef(_)
            | Self::TypeMarker(_)
            | Self::Exception(_) => true,
        }
    }

    pub(crate) fn python_repr(&self) -> String {
        self.try_python_repr()
            .unwrap_or_else(|_| "<value exceeds rendering limit>".to_owned())
    }

    pub(crate) fn try_python_repr(&self) -> Result<String, VmExecutionError> {
        crate::rendering::render(self)
    }

    pub(crate) fn python_repr_atom(&self) -> String {
        match self {
            Self::Reference(value) => value.with_value(|value| value.python_repr()),
            Self::None => "None".to_owned(),
            Self::Bool(true) => "True".to_owned(),
            Self::Bool(false) => "False".to_owned(),
            Self::Int(value) => value.to_string(),
            Self::Decimal(value) => value.python_repr(),
            Self::DateTime(value) => value.to_string(),
            Self::TimeDelta(value) => value.to_string(),
            Self::String(value) => value.clone(),
            Self::Bytes(value) => python_bytes_repr(value),
            Self::ByteArray(value) => python_bytearray_repr(value),
            Self::Set(values) | Self::BuiltinSet(values) => python_set_repr(values),
            Self::FrozenSet(values) => python_frozenset_repr(values),
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
            Self::DeploymentHandle => "<Contract deployment helper>".into(),
            Self::ContractHandle(handle) => format!("<contract:{}>", handle.module),
            Self::StorageRef(storage) => format!("<storage:{}>", storage.binding),
            Self::ForeignStorageRef(storage) => {
                format!("<foreign-storage:{}.{}>", storage.contract, storage.binding)
            }
            Self::EventRef(event) => format!("<event:{}>", event.event_name),
            Self::BoundMethod(bound) => format!(
                "<bound method {}.{}>",
                bound.receiver.type_name(),
                bound.method
            ),
            Self::MappingProxy(value) => format!("mappingproxy({})", value.python_repr()),
            Self::HostCallable(callable) => format!("<host callable {}>", callable.binding()),
            Self::InterfaceSubject(_) => "<InterfaceSubject>".into(),
            Self::InterfaceDescriptor(descriptor) => {
                format!("<{} descriptor>", descriptor.class_name())
            }
            Self::Builtin(name) => format!("<builtin:{name}>"),
            Self::FunctionRef(name) => format!("<function:{name}>"),
            Self::TypeMarker(name) => name.clone(),
            Self::Exception(value) => value.python_repr(),
            Self::Iterator(_) => "<iterator>".to_owned(),
            Self::View(_) => "<dict_view>".to_owned(),
            Self::Range(range) => {
                if range.step == BigInt::from(1) {
                    format!("range({}, {})", range.start, range.stop)
                } else {
                    format!("range({}, {}, {})", range.start, range.stop, range.step)
                }
            }
        }
    }

    pub(crate) fn as_i64(&self) -> Result<i64, VmExecutionError> {
        match self {
            Self::Reference(value) => value.with_value(|value| value.as_i64()),
            Self::Bool(_) | Self::Decimal(_) => Err(VmExecutionError::new("expected an integer")),
            Self::Int(value) => bigint_to_i64(value, "integer value"),
            _ => Err(VmExecutionError::new(format!(
                "expected int-compatible value, got {}",
                self.type_name()
            ))),
        }
    }

    /// The integer this value holds (through a reference), or `message`.
    pub(crate) fn integer_or(&self, message: &str) -> Result<BigInt, VmExecutionError> {
        match self.snapshot() {
            Self::Int(value) => Ok(value),
            _ => Err(VmExecutionError::new(message)),
        }
    }

    pub(crate) fn as_bigint(&self) -> Result<BigInt, VmExecutionError> {
        match self {
            Self::Reference(value) => value.with_value(|value| value.as_bigint()),
            Self::Bool(_) | Self::Decimal(_) => Err(VmExecutionError::new("expected an integer")),
            Self::Int(value) => Ok(value.clone()),
            _ => Err(VmExecutionError::new(format!(
                "expected int-compatible value, got {}",
                self.type_name()
            ))),
        }
    }

    pub(crate) fn as_string(&self) -> Result<String, VmExecutionError> {
        match self {
            Self::Reference(value) => value.with_value(|value| value.as_string()),
            Self::String(value) => Ok(value.clone()),
            _ => Err(VmExecutionError::new(format!(
                "expected string value, got {}",
                self.type_name()
            ))),
        }
    }

    pub(crate) fn as_contract_handle(&self) -> Result<VmContractHandle, VmExecutionError> {
        match self {
            Self::Reference(value) => value.with_value(|value| value.as_contract_handle()),
            Self::ContractHandle(handle) => Ok(handle.clone()),
            _ => Err(VmExecutionError::new(format!(
                "expected contract handle, got {}",
                self.type_name()
            ))),
        }
    }

    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Self::Reference(value) => value.with_value(Self::type_name),
            Self::None => "none",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Decimal(_) => "decimal",
            Self::DateTime(_) => "datetime",
            Self::TimeDelta(_) => "timedelta",
            Self::String(_) => "str",
            Self::Bytes(_) => "bytes",
            Self::ByteArray(_) => "bytearray",
            Self::Set(_) | Self::BuiltinSet(_) => "set",
            Self::FrozenSet(_) => "frozenset",
            Self::List(_) => "list",
            Self::Tuple(_) => "tuple",
            Self::Dict(_) => "dict",
            Self::DeploymentHandle => "Contract",
            Self::ContractHandle(_) => "contract_handle",
            Self::StorageRef(_) => "storage_ref",
            Self::ForeignStorageRef(_) => "foreign_storage_ref",
            Self::EventRef(_) => "event_ref",
            Self::BoundMethod(_) => "bound_method",
            Self::MappingProxy(_) => "mappingproxy",
            Self::HostCallable(_) => "host_callable",
            Self::InterfaceSubject(_) => "InterfaceSubject",
            Self::InterfaceDescriptor(descriptor) => descriptor.class_name(),
            Self::Builtin(_) => "builtin",
            Self::FunctionRef(_) => "function_ref",
            Self::TypeMarker(_) => "type_marker",
            Self::Exception(_) => "exception",
            Self::Iterator(_) => "iterator",
            Self::View(_) => "dict_view",
            Self::Range(_) => "range",
        }
    }
}

impl fmt::Display for VmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.python_repr())
    }
}

/// Function-local foreign storage is a read-only capability, never persisted state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmForeignStorageRef {
    pub contract: String,
    pub binding: String,
    pub is_hash: bool,
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

/// An exception argument as a plain value: the exception outlives the
/// execution's heap, so a list or dict it holds by reference is copied out
/// now. A value that cannot be detached (a cycle) keeps its reference.
fn detached_argument(value: VmValue) -> VmValue {
    value.detached().unwrap_or(value)
}

fn python_exception_arg_repr(value: &VmValue) -> String {
    match &value.snapshot() {
        VmValue::String(inner) => {
            let escaped = inner.replace('\\', "\\\\").replace('\'', "\\'");
            format!("'{escaped}'")
        }
        other => other.python_repr(),
    }
}

fn python_bytes_repr(value: &[u8]) -> String {
    format!("b'{}'", escape_python_bytes_body(value))
}

fn python_bytearray_repr(value: &[u8]) -> String {
    format!("bytearray({})", python_bytes_repr(value))
}

fn python_set_repr(values: &[VmValue]) -> String {
    if values.is_empty() {
        return "set()".to_owned();
    }
    format!(
        "{{{}}}",
        values
            .iter()
            .map(VmValue::python_repr)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn python_frozenset_repr(values: &[VmValue]) -> String {
    if values.is_empty() {
        return "frozenset()".to_owned();
    }
    format!("frozenset({})", python_set_repr(values))
}

fn escape_python_bytes_body(value: &[u8]) -> String {
    let mut rendered = String::new();
    for byte in value {
        match byte {
            b'\\' => rendered.push_str("\\\\"),
            b'\'' => rendered.push_str("\\'"),
            b'\n' => rendered.push_str("\\n"),
            b'\r' => rendered.push_str("\\r"),
            b'\t' => rendered.push_str("\\t"),
            0x20..=0x7e => rendered.push(char::from(*byte)),
            other => rendered.push_str(&format!("\\x{other:02x}")),
        }
    }
    rendered
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
    /// The transaction's `__input_hash` (its random seed input).
    pub input_hash: VmValue,
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
    /// The transaction's `__input_hash` (its random seed input).
    pub input_hash: VmValue,
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
            input_hash: VmValue::None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmExecutionError {
    message: String,
    exception: Option<Box<VmException>>,
}

impl VmExecutionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exception: None,
        }
    }

    /// A Python-style exception. The message is its representation; hosts
    /// read the type and arguments from `exception()` instead of the text.
    pub fn raised(name: impl Into<String>, args: Vec<VmValue>) -> Self {
        let exception = VmException {
            name: name.into(),
            args: args.into_iter().map(detached_argument).collect(),
        };
        Self {
            message: exception.python_repr(),
            exception: Some(Box::new(exception)),
        }
    }

    /// An exception with one message argument whose text keeps an established
    /// spelling. Hosts read the structured form instead.
    pub(crate) fn described(
        name: &str,
        text: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            message: text.into(),
            exception: Some(Box::new(VmException {
                name: name.to_owned(),
                args: vec![VmValue::String(message.into())],
            })),
        }
    }

    pub(crate) fn with_exception(mut self, exception: VmException) -> Self {
        self.exception = Some(Box::new(exception));
        self
    }

    pub fn exception(&self) -> Option<&VmException> {
        self.exception.as_deref()
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
    fn stored_dictionaries_take_only_plain_string_keys() {
        let wire = "V2 wire dictionaries require string keys and cannot use reserved codec tags";
        for key in [
            VmValue::Int(1.into()),
            VmValue::None,
            VmValue::Bool(true),
            VmValue::Tuple(vec![VmValue::Int(1.into())]),
            VmValue::String("__fixed__".into()),
        ] {
            let stored = VmValue::List(vec![VmValue::Dict(vec![(key, VmValue::None)])]);
            assert_eq!(stored.storage_value().unwrap_err().to_string(), wire);
        }
        let plain = VmValue::Dict(vec![(VmValue::String("a".into()), VmValue::None)]);
        assert_eq!(plain.storage_value().unwrap(), plain);
    }

    #[test]
    fn decimal_python_repr_is_the_plain_decimal_text() {
        let cases = [
            ("1000", "1000"),
            ("50000000", "50000000"),
            ("1234000", "1234000"),
            ("0.0001", "0.0001"),
            ("0.0000001", "0.0000001"),
            ("1234.5", "1234.5"),
            ("-12345", "-12345"),
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

    #[test]
    fn truncates_tiny_decimal_exponents_without_allocating_large_buffers() {
        let value =
            VmDecimal::from_str_literal("1e-1000000").expect("tiny decimal should truncate");
        assert_eq!(value.to_string(), "0");
    }

    #[test]
    fn rejects_huge_decimal_exponents_without_allocating_large_buffers() {
        let error =
            VmDecimal::from_str_literal("1e1000000").expect_err("huge decimal should overflow");
        assert_eq!(
            error.to_string(),
            "decimal value 1e1000000 exceeds the supported decimal range"
        );
    }

    #[test]
    fn handles_extreme_i64_decimal_exponents_without_panicking() {
        let tiny =
            VmDecimal::from_str_literal("1e-9223372036854775808").expect("tiny value should parse");
        assert_eq!(tiny.to_string(), "0");

        let huge = VmDecimal::from_str_literal("1e9223372036854775807")
            .expect_err("huge value should overflow");
        assert_eq!(
            huge.to_string(),
            "decimal value 1e9223372036854775807 exceeds the supported decimal range"
        );
    }
}

impl std::error::Error for VmExecutionError {}
