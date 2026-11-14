//! `format(number, spec)` with a Decimal presentation, as Python's
//! `format(Decimal(text), spec)` renders it: a decimal (from its text, so the
//! quantum is the text's) or an int with a float presentation type. The value
//! is finite and exact (`coefficient * 10**exponent`); rescaling truncates;
//! output allocation is bounded.
use crate::{VmDecimal, VmExecutionError};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use std::fmt;
use std::str::FromStr;

type Result<T> = std::result::Result<T, VmExecutionError>;
const LIMIT: usize = 128 * 1024;
const EXACT_LIMIT: usize = 128 * 1024;

/// A finite decimal `coefficient * 10**exponent`; the coefficient holds the sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FormatDecimal {
    coefficient: BigInt,
    exponent: i32,
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

impl FormatDecimal {
    /// A decimal as `Decimal(str(value))` holds it.
    pub(crate) fn of_decimal(value: &VmDecimal) -> Result<Self> {
        Self::parse(&value.to_string())
    }

    pub(crate) fn of_integer(value: BigInt) -> Result<Self> {
        if value.bits() > crate::interpreter::MAX_INTEGER_BITS
            || digits(&value) as usize > EXACT_LIMIT - 1
        {
            return Err(error());
        }
        Ok(Self {
            coefficient: value,
            exponent: 0,
        })
    }

    fn parse(text: &str) -> Result<Self> {
        if text.is_empty() || text.len() > EXACT_LIMIT || !text.is_ascii() {
            return Err(error());
        }
        Self::parse_finite(text)
    }

    fn parse_finite(text: &str) -> Result<Self> {
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
        Ok(Self {
            coefficient,
            exponent,
        })
    }

    fn is_zero(&self) -> bool {
        self.coefficient.is_zero()
    }
    fn negative(&self) -> bool {
        self.coefficient.is_negative()
    }
    fn adjusted(&self) -> i32 {
        self.exponent + digits(&self.coefficient) - 1
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
}

/// `str(Decimal)`: scientific notation for positive exponents and small
/// adjusted exponents, fixed point otherwise.
impl fmt::Display for FormatDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative() {
            f.write_str("-")?;
        }
        let digits = self.coefficient.abs().to_str_radix(10);
        if self.exponent > 0 || self.adjusted() < -6 {
            self.fmt_scientific(f, &digits)
        } else {
            self.fmt_fixed(f, &digits)
        }
    }
}

impl FormatDecimal {
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

struct Spec {
    fill: char,
    align: char,
    sign: char,
    width: usize,
    precision: Option<usize>,
    kind: char,
    grouping: bool,
    positive_zero: bool,
}

fn number(chars: &[char], position: &mut usize) -> Result<Option<usize>> {
    let start = *position;
    let mut value = 0usize;
    while let Some(digit) = chars.get(*position).and_then(|ch| ch.to_digit(10)) {
        if !chars[*position].is_ascii() {
            return Err(error());
        }
        value = value
            .checked_mul(10)
            .and_then(|n| n.checked_add(digit as usize))
            .filter(|n| *n <= LIMIT)
            .ok_or_else(error)?;
        *position += 1;
    }
    Ok((*position != start).then_some(value))
}

fn parse(text: &str) -> Result<Spec> {
    let chars: Vec<_> = text.chars().collect();
    let mut spec = Spec {
        fill: ' ',
        align: '>',
        sign: '-',
        width: 0,
        precision: None,
        kind: 'G',
        grouping: false,
        positive_zero: false,
    };
    let mut i = 0;
    parse_prefix(&chars, &mut i, &mut spec);
    spec.width = number(&chars, &mut i)?.unwrap_or(0);
    if chars.get(i) == Some(&',') {
        spec.grouping = true;
        i += 1;
    }
    if chars.get(i) == Some(&'.') {
        i += 1;
        spec.precision = Some(number(&chars, &mut i)?.ok_or_else(error)?);
    }
    parse_kind(&chars, &mut i, &mut spec)?;
    Ok(spec)
}

fn parse_kind(chars: &[char], i: &mut usize, spec: &mut Spec) -> Result<()> {
    if let Some(kind) = chars.get(*i) {
        if !"eEfFgGn%".contains(*kind) {
            return Err(error());
        }
        spec.kind = *kind;
        *i += 1;
    }
    if *i != chars.len() || (spec.kind == 'n' && spec.grouping) {
        return Err(error());
    }
    Ok(())
}

fn parse_prefix(chars: &[char], i: &mut usize, spec: &mut Spec) {
    if chars.get(1).is_some_and(|ch| "<>=^".contains(*ch)) {
        spec.fill = chars[0];
        spec.align = chars[1];
        *i = 2;
    } else if chars.first().is_some_and(|ch| "<>=^".contains(*ch)) {
        spec.align = chars[0];
        *i = 1;
    }
    if chars.get(*i).is_some_and(|ch| "+- ".contains(*ch)) {
        spec.sign = chars[*i];
        *i += 1;
    }
    if chars.get(*i) == Some(&'z') {
        spec.positive_zero = true;
        *i += 1;
    }
    if chars.get(*i) == Some(&'0') {
        spec.fill = '0';
        spec.align = '=';
        *i += 1;
    }
}

fn fixed(coefficient: &BigInt, exponent: i32) -> String {
    let digits = coefficient.abs().to_str_radix(10);
    if exponent >= 0 {
        return format!("{digits}{}", "0".repeat(exponent as usize));
    }
    let point = digits.len() as i32 + exponent;
    if point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else {
        format!(
            "{}.{}",
            &digits[..point as usize],
            &digits[point as usize..]
        )
    }
}

fn scientific(value: &FormatDecimal, precision: Option<usize>, uppercase: bool) -> String {
    let places = precision.unwrap_or((digits(&value.coefficient) - 1) as usize);
    let exponent = if value.is_zero() {
        value.exponent + places as i32
    } else {
        value.adjusted()
    };
    let coefficient = value.rescale(exponent - places as i32);
    let mut digits = coefficient.abs().to_str_radix(10);
    if value.is_zero() {
        digits = "0".repeat(places + 1);
    }
    let fraction = if places == 0 {
        String::new()
    } else {
        format!(".{}", &digits[1..])
    };
    format!(
        "{}{fraction}{}{exponent:+}",
        &digits[..1],
        if uppercase { 'E' } else { 'e' }
    )
}

fn magnitude(value: &FormatDecimal, spec: &Spec) -> Result<String> {
    bound_output(value, spec)?;
    let mut value = value.clone();
    value.coefficient = value.coefficient.abs();
    if spec.kind == '%' {
        value.exponent += 2;
    }
    let rendered = match spec.kind {
        'f' | 'F' | '%' => {
            let exponent = spec
                .precision
                .map_or(value.exponent.min(0), |p| -(p as i32));
            fixed(&value.rescale(exponent), exponent)
        }
        'e' | 'E' => scientific(&value, spec.precision, spec.kind == 'E'),
        _ => general(&mut value, spec),
    };
    Ok(if spec.kind == '%' {
        rendered + "%"
    } else {
        rendered
    })
}

fn general(value: &mut FormatDecimal, spec: &Spec) -> String {
    if let Some(precision) = spec.precision {
        let discarded = digits(&value.coefficient) - (precision.max(1) as i32);
        if discarded > 0 {
            let exponent = value.exponent + discarded;
            value.coefficient = value.rescale(exponent);
            value.exponent = exponent;
        }
    }
    let text = value.to_string();
    if spec.kind == 'G' {
        text
    } else {
        text.replace('E', "e")
    }
}

fn bound_output(value: &FormatDecimal, spec: &Spec) -> Result<()> {
    // Bound output expansion before rescaling or allocating a padded coefficient.
    let places = spec
        .precision
        .unwrap_or(value.exponent.unsigned_abs() as usize);
    let whole = value.adjusted().max(0) as usize + 3;
    if matches!(spec.kind, 'f' | 'F' | '%') && whole.saturating_add(places) > LIMIT {
        return Err(error());
    }
    if spec.precision.is_some_and(|p| p >= LIMIT - 16) {
        return Err(error());
    }
    Ok(())
}

fn group(text: &str) -> String {
    let end = text.find(['.', 'e', 'E', '%']).unwrap_or(text.len());
    let mut output = String::new();
    for (i, ch) in text[..end].chars().enumerate() {
        if i > 0 && (end - i) % 3 == 0 {
            output.push(',');
        }
        output.push(ch);
    }
    output.push_str(&text[end..]);
    output
}

fn sign(value: &FormatDecimal, spec: &Spec, body: &str) -> &'static str {
    let zero = body
        .split(['e', 'E', '%'])
        .next()
        .unwrap_or("")
        .chars()
        .all(|ch| ch == '0' || ch == '.');
    if value.negative() && !(spec.positive_zero && zero) {
        "-"
    } else {
        match spec.sign {
            '+' => "+",
            ' ' => " ",
            _ => "",
        }
    }
}

fn group_padding(mut body: String, sign: &str, spec: &Spec) -> String {
    if spec.align == '=' && spec.fill == '0' {
        let whole = body.find(['.', 'e', 'E', '%']).unwrap_or(body.len());
        let (mut low, mut high) = (0, spec.width);
        while low < high {
            let middle = (low + high) / 2;
            let width = sign.len() + body.len() + middle + (whole + middle - 1) / 3;
            if width < spec.width {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        body = format!("{}{body}", "0".repeat(low));
    }
    body
}

fn pad(body: &str, sign: &str, spec: &Spec) -> Result<String> {
    let padding = spec.width.saturating_sub(body.len() + sign.len());
    if padding * spec.fill.len_utf8() + body.len() + sign.len() > LIMIT {
        return Err(error());
    }
    let pad = |count| std::iter::repeat_n(spec.fill, count).collect::<String>();
    Ok(match spec.align {
        '<' => format!("{sign}{body}{}", pad(padding)),
        '=' => format!("{sign}{}{body}", pad(padding)),
        '^' => format!(
            "{}{sign}{body}{}",
            pad(padding / 2),
            pad(padding - padding / 2)
        ),
        _ => format!("{}{sign}{body}", pad(padding)),
    })
}

impl FormatDecimal {
    pub(crate) fn format(&self, spec: &str) -> Result<String> {
        let spec = parse(spec)?;
        let mut body = magnitude(self, &spec)?;
        let sign = sign(self, &spec, &body);
        if spec.grouping {
            body = group_padding(body, sign, &spec);
            body = group(&body);
        }
        pad(&body, sign, &spec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decimal(text: &str) -> FormatDecimal {
        FormatDecimal::parse(text).unwrap()
    }

    #[test]
    fn values_and_formatting_resources_are_bounded() {
        for text in ["1E999999999999", "1E-131073", "1.2.3", "Infinity", "NaN"] {
            assert!(FormatDecimal::parse(text).is_err(), "{text}");
        }
        assert!(decimal("1E131072").format("f").is_err());
        assert!(FormatDecimal::of_integer(
            BigInt::from(1) << crate::interpreter::MAX_INTEGER_BITS as usize
        )
        .is_err());
    }

    #[test]
    fn decimals_keep_the_quantum_of_their_text() {
        let hundred = FormatDecimal::of_decimal(&VmDecimal::from_str_literal("100").unwrap());
        assert_eq!(hundred.unwrap().format("").unwrap(), "100");
        assert_eq!(decimal("1E+2").format("").unwrap(), "1E+2");
        assert_eq!(decimal("0.0000001").to_string(), "1E-7");
        assert_eq!(
            FormatDecimal::of_integer(BigInt::from(-25))
                .unwrap()
                .format(".1e")
                .unwrap(),
            "-2.5e+1"
        );
    }

    #[test]
    fn formatting_bounds_and_grouping() {
        let value = decimal("-0.001");
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
