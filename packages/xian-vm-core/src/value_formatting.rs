//! Bounded, locale-independent Python formatting shared by calls and f-strings.
use super::*;
use num_traits::{Signed, ToPrimitive};

type Result<T> = std::result::Result<T, VmExecutionError>;
const LIMIT: usize = 128 * 1024;

#[derive(Clone, Debug)]
struct Spec {
    fill: char,
    explicit_fill: bool,
    align: Option<char>,
    sign: Option<char>,
    positive_zero: bool,
    alternate: bool,
    zero: bool,
    width: usize,
    grouping: Option<char>,
    precision: Option<usize>,
    kind: Option<char>,
}

fn error() -> VmExecutionError {
    VmExecutionError::new("invalid or unsupported format specification")
}
fn limit() -> VmExecutionError {
    VmExecutionError::new("formatted output exceeds allocation limit")
}
fn bounded(value: String) -> Result<String> {
    if value.len() > LIMIT {
        Err(limit())
    } else {
        Ok(value)
    }
}
fn number(chars: &[char], pos: &mut usize) -> Result<Option<usize>> {
    let start = *pos;
    let mut number = 0usize;
    while let Some(ch) = chars.get(*pos).filter(|ch| ch.is_ascii_digit()) {
        number = number
            .checked_mul(10)
            .and_then(|n| n.checked_add(*ch as usize - '0' as usize))
            .filter(|n| *n <= LIMIT)
            .ok_or_else(limit)?;
        *pos += 1;
    }
    Ok((*pos != start).then_some(number))
}
fn take(chars: &[char], pos: &mut usize, accepted: &str) -> Option<char> {
    let ch = *chars.get(*pos)?;
    if !accepted.contains(ch) {
        return None;
    }
    *pos += 1;
    Some(ch)
}
fn parse(text: &str) -> Result<Spec> {
    if text.len() > LIMIT {
        return Err(limit());
    }
    let chars: Vec<_> = text.chars().collect();
    let mut pos = 0;
    let mut spec = Spec {
        fill: ' ',
        explicit_fill: false,
        align: None,
        sign: None,
        positive_zero: false,
        alternate: false,
        zero: false,
        width: 0,
        grouping: None,
        precision: None,
        kind: None,
    };
    if chars.get(1).is_some_and(|ch| "<>=^".contains(*ch)) {
        spec.fill = chars[0];
        spec.explicit_fill = true;
        spec.align = Some(chars[1]);
        pos = 2;
    } else {
        spec.align = take(&chars, &mut pos, "<>=^");
    }
    spec.sign = take(&chars, &mut pos, "+- ");
    spec.positive_zero = take(&chars, &mut pos, "z").is_some();
    spec.alternate = take(&chars, &mut pos, "#").is_some();
    spec.zero = take(&chars, &mut pos, "0").is_some();
    spec.width = number(&chars, &mut pos)?.unwrap_or(0);
    spec.grouping = take(&chars, &mut pos, ",_");
    if take(&chars, &mut pos, ".").is_some() {
        spec.precision = Some(number(&chars, &mut pos)?.ok_or_else(error)?);
    }
    spec.kind = chars.get(pos).copied();
    pos += usize::from(spec.kind.is_some());
    if pos != chars.len() {
        return Err(error());
    }
    Ok(spec)
}

pub(super) fn format_work_cost(value: &VmValue, text: &str) -> Result<u64> {
    let size = RenderCost::default().value(value, 0)? as u64;
    let extra = if let VmValue::RawDecimal(_) = value.snapshot() {
        crate::VmRawDecimal::format_work_cost(text)?
    } else {
        let spec = parse(text)?;
        (spec.width.saturating_add(spec.precision.unwrap_or(0)) as u64).saturating_mul(4)
    };
    Ok(size.saturating_mul(4).saturating_add(extra))
}

#[derive(Default)]
struct RenderCost {
    active: std::collections::HashSet<usize>,
    nodes: usize,
}
impl RenderCost {
    fn value(&mut self, value: &VmValue, depth: usize) -> Result<usize> {
        self.nodes += 1;
        if depth > 128 || self.nodes > LIMIT {
            return Err(limit());
        }
        if let VmValue::Reference(reference) = value {
            if !self.active.insert(reference.id()) {
                return Ok(8);
            }
            let result = reference.with_value(|value| self.contents(value, depth));
            self.active.remove(&reference.id());
            return result;
        }
        self.contents(value, depth)
    }
    fn contents(&mut self, value: &VmValue, depth: usize) -> Result<usize> {
        match value {
            VmValue::List(values)
            | VmValue::Tuple(values)
            | VmValue::Set(values)
            | VmValue::BuiltinSet(values)
            | VmValue::FrozenSet(values) => self.sequence(values.iter(), depth),
            VmValue::Dict(values) => self.sequence(values.iter().flat_map(|(k, v)| [k, v]), depth),
            VmValue::Exception(value) => self.sequence(value.args.iter(), depth),
            VmValue::MappingProxy(mapping) => self.value(mapping, depth + 1),
            VmValue::DecimalTuple(tuple) => self.sequence(tuple.as_values().iter(), depth),
            _ => Ok(scalar_render_cost(value)),
        }
    }
    fn sequence<'a>(
        &mut self,
        values: impl Iterator<Item = &'a VmValue>,
        depth: usize,
    ) -> Result<usize> {
        let mut total = 8usize;
        for value in values {
            total = total
                .saturating_add(self.value(value, depth + 1)?)
                .saturating_add(4);
            if total > LIMIT * 16 {
                return Err(limit());
            }
        }
        Ok(total)
    }
}
fn scalar_render_cost(value: &VmValue) -> usize {
    match value {
        VmValue::String(text) => text.len().saturating_mul(10) + 2,
        VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => bytes.len().saturating_mul(4) + 16,
        VmValue::Int(number) => (number.bits() as usize).div_ceil(3) + 1,
        VmValue::RawDecimal(number) => {
            (number.coefficient.bits() as usize).div_ceil(3)
                + number.exponent.unsigned_abs() as usize
                + 16
        }
        _ => 64,
    }
}

pub(super) fn format_value(value: &VmValue, text: &str) -> Result<String> {
    if text.is_empty() {
        return string(value);
    }
    let value = value.snapshot();
    if let VmValue::RawDecimal(value) = &value {
        return value.format(text);
    }
    bounded(format_scalar(&value, &parse(text)?)?)
}
fn format_scalar(value: &VmValue, spec: &Spec) -> Result<String> {
    match value {
        VmValue::String(value) => string_format(value, spec),
        VmValue::Int(value) => integer_format(value, spec),
        VmValue::Bool(value) => integer_format(&BigInt::from(u8::from(*value)), spec),
        VmValue::Float(value) => float_format(*value, spec),
        _ => Err(error()),
    }
}

pub(super) fn convert(value: &VmValue, conversion: Option<char>) -> Result<VmValue> {
    let Some(conversion) = conversion else {
        return Ok(value.clone());
    };
    Ok(VmValue::String(conversion_string(value, conversion)?))
}
fn conversion_string(value: &VmValue, conversion: char) -> Result<String> {
    match conversion {
        's' => string(value),
        'r' => representation(value),
        'a' => ascii_repr(&representation(value)?),
        _ => Err(error()),
    }
}

fn string(value: &VmValue) -> Result<String> {
    if let VmValue::Float(number) = value.snapshot() {
        return float_shortest(number);
    }
    super::builtin_dispatch::public_string(value, 0)
}
fn representation(value: &VmValue) -> Result<String> {
    if let VmValue::Float(number) = value.snapshot() {
        return float_shortest(number);
    }
    crate::rendering::render_repr(value)
}
fn ascii_repr(text: &str) -> Result<String> {
    let mut result = String::new();
    for ch in text.chars() {
        let code = ch as u32;
        match code {
            0..=127 => result.push(ch),
            128..=255 => result.push_str(&format!("\\x{code:02x}")),
            256..=65535 => result.push_str(&format!("\\u{code:04x}")),
            _ => result.push_str(&format!("\\U{code:08x}")),
        }
        if result.len() > LIMIT {
            return Err(limit());
        }
    }
    Ok(result)
}
fn string_format(text: &str, spec: &Spec) -> Result<String> {
    if spec.sign.is_some()
        || spec.positive_zero
        || spec.alternate
        || spec.grouping.is_some()
        || spec.align == Some('=')
        || !matches!(spec.kind, None | Some('s'))
    {
        return Err(error());
    }
    let truncated: String = text
        .chars()
        .take(spec.precision.unwrap_or(usize::MAX))
        .collect();
    pad(&truncated, "", spec, '<')
}
fn pad(body: &str, prefix: &str, spec: &Spec, default: char) -> Result<String> {
    let length = body.chars().count() + prefix.chars().count();
    let padding = spec.width.saturating_sub(length);
    let fill = if spec.zero && !spec.explicit_fill {
        '0'
    } else {
        spec.fill
    };
    let bytes = padding
        .checked_mul(fill.len_utf8())
        .and_then(|n| n.checked_add(body.len() + prefix.len()))
        .ok_or_else(limit)?;
    if bytes > LIMIT {
        return Err(limit());
    }
    let default = if spec.zero && default == '>' {
        '='
    } else {
        default
    };
    Ok(layout(
        body,
        prefix,
        padding,
        fill,
        spec.align.unwrap_or(default),
    ))
}
fn layout(body: &str, prefix: &str, padding: usize, fill: char, align: char) -> String {
    let spaces = |n| std::iter::repeat_n(fill, n).collect::<String>();
    match align {
        '<' => format!("{prefix}{body}{}", spaces(padding)),
        '=' => format!("{prefix}{}{body}", spaces(padding)),
        '^' => format!(
            "{}{prefix}{body}{}",
            spaces(padding / 2),
            spaces(padding - padding / 2)
        ),
        _ => format!("{}{prefix}{body}", spaces(padding)),
    }
}

fn sign(negative: bool, spec: &Spec) -> &'static str {
    if negative {
        "-"
    } else {
        match spec.sign {
            Some('+') => "+",
            Some(' ') => " ",
            _ => "",
        }
    }
}
fn integer_format(value: &BigInt, spec: &Spec) -> Result<String> {
    if spec.kind.is_some_and(|ch| "eEfFgG%".contains(ch)) {
        let float = value.to_f64().filter(|n| n.is_finite()).ok_or_else(error)?;
        return float_format(float, spec);
    }
    if spec.precision.is_some() || spec.positive_zero {
        return Err(error());
    }
    if spec.kind == Some('c') {
        return character_format(value, spec);
    }
    integer_digits(value, spec)
}
fn radix(spec: &Spec) -> Result<(u32, &'static str)> {
    match spec.kind {
        None | Some('d' | 'n') => Ok((10, "")),
        Some('b') => Ok((2, "0b")),
        Some('o') => Ok((8, "0o")),
        Some('x') => Ok((16, "0x")),
        Some('X') => Ok((16, "0X")),
        _ => Err(error()),
    }
}
fn integer_digits(value: &BigInt, spec: &Spec) -> Result<String> {
    let (radix, alternate) = radix(spec)?;
    validate_integer_grouping(spec, radix)?;
    let digits = if radix == 10 {
        (value.bits() * 30103).div_ceil(100000)
    } else {
        value.bits().div_ceil(u64::from(radix.ilog2()))
    };
    if digits > LIMIT as u64 {
        return Err(limit());
    }
    let mut body = value.abs().to_str_radix(radix);
    if spec.kind == Some('X') {
        body.make_ascii_uppercase();
    }
    let prefix = format!(
        "{}{}",
        sign(value.is_negative(), spec),
        if spec.alternate { alternate } else { "" }
    );
    numeric_pad(body, prefix, spec, if radix == 10 { 3 } else { 4 })
}

fn validate_integer_grouping(spec: &Spec, radix: u32) -> Result<()> {
    if spec.grouping.is_some()
        && (spec.kind == Some('n') || (radix != 10 && spec.grouping == Some(',')))
    {
        return Err(error());
    }
    Ok(())
}
fn character_format(value: &BigInt, spec: &Spec) -> Result<String> {
    if spec.sign.is_some() || spec.alternate || spec.grouping.is_some() {
        return Err(error());
    }
    let ch = value.to_u32().and_then(char::from_u32).ok_or_else(error)?;
    pad(&ch.to_string(), "", spec, '>')
}
fn group(body: &str, delimiter: char, size: usize) -> String {
    let end = group_end(body, size);
    let mut result = String::with_capacity(body.len() + end / size);
    for (index, ch) in body[..end].chars().enumerate() {
        if index > 0 && (end - index) % size == 0 {
            result.push(delimiter);
        }
        result.push(ch);
    }
    result.push_str(&body[end..]);
    result
}
fn numeric_pad(mut body: String, prefix: String, spec: &Spec, group_size: usize) -> Result<String> {
    if let Some(delimiter) = spec.grouping {
        if grouped_zero_padding(&body, spec, group_size) {
            body = pad_grouped_zeros(&body, prefix.len(), spec.width, group_size)?;
        }
        body = group(&body, delimiter, group_size);
    }
    pad(&body, &prefix, spec, '>')
}
fn grouped_zero_padding(body: &str, spec: &Spec, size: usize) -> bool {
    (spec.fill == '0' || (spec.zero && !spec.explicit_fill))
        && spec.align.is_none_or(|ch| ch == '=')
        && (size == 4 || body.starts_with(|ch: char| ch.is_ascii_digit()))
}
fn pad_grouped_zeros(body: &str, prefix: usize, width: usize, size: usize) -> Result<String> {
    let end = group_end(body, size);
    let length = |zeros: usize| body.len() + zeros + (end + zeros).saturating_sub(1) / size;
    let mut zeros = width.saturating_sub(prefix + length(0));
    while zeros > 0 && prefix + length(zeros - 1) >= width {
        zeros -= 1;
    }
    if body.len().saturating_add(zeros) > LIMIT {
        return Err(limit());
    }
    Ok(format!("{}{body}", "0".repeat(zeros)))
}
fn group_end(body: &str, size: usize) -> usize {
    if size == 4 {
        body.len()
    } else {
        body.find(['.', 'e', 'E', '%']).unwrap_or(body.len())
    }
}

fn float_shortest(value: f64) -> Result<String> {
    Ok(crate::values::python_float_repr(value))
}
fn normalize_exponent(text: String, uppercase: bool) -> Result<String> {
    let Some((body, exponent)) = text.split_once(['e', 'E']) else {
        return Ok(if uppercase {
            text.to_ascii_uppercase()
        } else {
            text
        });
    };
    let exponent: i32 = exponent.parse().map_err(|_| error())?;
    Ok(format!(
        "{body}{}{exponent:+03}",
        if uppercase { 'E' } else { 'e' }
    ))
}
fn float_format(value: f64, spec: &Spec) -> Result<String> {
    if !matches!(
        spec.kind,
        None | Some('e' | 'E' | 'f' | 'F' | 'g' | 'G' | 'n' | '%')
    ) || (spec.kind == Some('n') && spec.grouping.is_some())
    {
        return Err(error());
    }
    let mut body = float_magnitude(value.abs(), spec)?;
    let negative =
        value.is_sign_negative() && !value.is_nan() && !(spec.positive_zero && rounded_zero(&body));
    if spec.kind.is_some_and(char::is_uppercase) {
        body.make_ascii_uppercase();
    }
    numeric_pad(body, sign(negative, spec).to_owned(), spec, 3)
}
fn rounded_zero(body: &str) -> bool {
    let mantissa = body.split(['e', 'E', '%']).next().unwrap_or(body);
    mantissa.chars().any(|ch| ch == '0') && mantissa.chars().all(|ch| ch == '0' || ch == '.')
}
fn float_magnitude(mut value: f64, spec: &Spec) -> Result<String> {
    let kind = spec.kind.unwrap_or('\0');
    if kind == '%' {
        value *= 100.0;
    }
    if !value.is_finite() {
        return Ok(format!(
            "{}{}",
            if value.is_nan() { "nan" } else { "inf" },
            if kind == '%' { "%" } else { "" }
        ));
    }
    let precision = spec.precision.unwrap_or(6);
    if precision.saturating_add(320) > LIMIT {
        return Err(limit());
    }
    let body = finite_float(value, precision, spec)?;
    let mut body = alternate_point(body, spec.alternate);
    if kind == '%' {
        body.push('%');
    }
    Ok(body)
}
fn finite_float(value: f64, precision: usize, spec: &Spec) -> Result<String> {
    match spec.kind {
        Some('f' | 'F' | '%') => Ok(format!("{value:.precision$}")),
        Some('e' | 'E') => {
            normalize_exponent(format!("{value:.precision$e}"), spec.kind == Some('E'))
        }
        None if spec.precision.is_none() => float_shortest(value),
        _ => general_float(value, precision, spec),
    }
}

fn general_float(value: f64, precision: usize, spec: &Spec) -> Result<String> {
    let precision = precision.max(1);
    let scientific = format!("{value:.places$e}", places = precision - 1);
    let (_, exponent) = scientific.split_once('e').ok_or_else(error)?;
    let exponent: i32 = exponent.parse().map_err(|_| error())?;
    let threshold = precision as i32 - i32::from(spec.kind.is_none());
    let mut body = if exponent < -4 || exponent >= threshold {
        normalize_exponent(scientific, false)?
    } else {
        format!(
            "{value:.places$}",
            places = (precision as i32 - exponent - 1).max(0) as usize
        )
    };
    if !spec.alternate {
        body = strip_fraction_zeros(body);
    }
    if spec.kind.is_none() && !body.contains(['e', 'E', '.']) {
        body.push_str(".0");
    }
    Ok(body)
}
fn strip_fraction_zeros(mut text: String) -> String {
    let end = text.find(['e', 'E']).unwrap_or(text.len());
    if text[..end].contains('.') {
        let trimmed = text[..end]
            .trim_end_matches('0')
            .trim_end_matches('.')
            .len();
        text.replace_range(trimmed..end, "");
    }
    text
}
fn alternate_point(mut text: String, alternate: bool) -> String {
    let end = text.find(['e', 'E']).unwrap_or(text.len());
    if alternate && !text[..end].contains('.') {
        text.insert(end, '.');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_independent_historical_format_vectors() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/value_formatting.json")).unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let text = vector["value"].as_str().unwrap();
            let value = match vector["kind"].as_str().unwrap() {
                "float" => VmValue::Float(f64::from_bits(u64::from_str_radix(text, 16).unwrap())),
                "int" => VmValue::Int(text.parse().unwrap()),
                _ => VmValue::String(text.into()),
            };
            let spec = vector["spec"].as_str().unwrap();
            let expected = vector["result"].as_str().unwrap();
            assert_eq!(format_value(&value, spec).unwrap(), expected, "{vector}");
        }
    }

    #[test]
    fn format_limits_and_invalid_combinations_precede_allocations() {
        let integer = VmValue::Int(42.into());
        for spec in ["99999999999999999999999d", ".2d", "z", ",x", "+c", "q"] {
            assert!(format_value(&integer, spec).is_err(), "{spec}");
        }
        let string = VmValue::String("x".into());
        for spec in ["+s", "=10", ",s", "#s", "猫>131072"] {
            assert!(format_value(&string, spec).is_err(), "{spec}");
        }
        assert!(format_value(&VmValue::Float(1.), ".131072f").is_err());
        assert_eq!(format_value(&integer, "131072d").unwrap().len(), LIMIT);
        assert!(format_work_cost(&integer, "131073d").is_err());
    }

    #[test]
    fn large_decimal_integer_within_output_limit_is_accepted() {
        let value = VmValue::Int(BigInt::from(10u8).pow(125_000));
        let expected = format!("1{}", "0".repeat(125_000));
        assert_eq!(format_value(&value, "d").unwrap(), expected);
    }

    #[test]
    fn rendering_cost_tracks_proxy_and_decimal_tuple_contents() {
        let proxy = |size| {
            VmValue::MappingProxy(Box::new(VmValue::Dict(
                (0..size)
                    .map(|n| {
                        (
                            VmValue::Int(n.into()),
                            VmValue::String("payload".repeat(10)),
                        )
                    })
                    .collect(),
            )))
        };
        assert!(
            format_work_cost(&proxy(100), "").unwrap()
                > format_work_cost(&proxy(1), "").unwrap() * 50
        );
        let tuple = |size| {
            VmValue::DecimalTuple(
                crate::VmDecimalTuple::new(
                    false,
                    vec![1; size],
                    crate::VmDecimalExponent::Finite(0),
                )
                .unwrap(),
            )
        };
        assert!(
            format_work_cost(&tuple(1000), "").unwrap()
                > format_work_cost(&tuple(10), "").unwrap() * 20
        );
        let heap = crate::heap::VmHeap::default();
        let value = heap.capture(VmValue::Dict(vec![])).unwrap();
        let VmValue::Reference(reference) = &value else {
            panic!("expected reference");
        };
        let proxy = VmValue::MappingProxy(Box::new(value.clone()));
        reference
            .replace(VmValue::Dict(vec![(
                VmValue::String("self".into()),
                proxy.clone(),
            )]))
            .unwrap();
        assert!(format_work_cost(&proxy, "").unwrap() < 1000);
    }

    #[test]
    fn conversions_preserve_quotes_and_escape_nonprintable_characters() {
        let text = VmValue::String("é\u{200b}\u{10ffff}".into());
        assert_eq!(
            convert(&text, Some('r')).unwrap().as_string().unwrap(),
            "'é\\u200b\\U0010ffff'"
        );
        assert_eq!(
            convert(&text, Some('a')).unwrap().as_string().unwrap(),
            "'\\xe9\\u200b\\U0010ffff'"
        );
        assert_eq!(
            convert(&VmValue::Float(1e-7), Some('r'))
                .unwrap()
                .as_string()
                .unwrap(),
            "1e-07"
        );
        assert!(convert(&text, Some('x')).is_err());
        let expanded = VmValue::String("\0".repeat(LIMIT / 4));
        assert!(convert(&expanded, Some('r')).is_err());
        let boundary = VmValue::String("a".repeat(LIMIT - 2));
        assert_eq!(
            convert(&boundary, Some('r'))
                .unwrap()
                .as_string()
                .unwrap()
                .len(),
            LIMIT
        );
    }
}
