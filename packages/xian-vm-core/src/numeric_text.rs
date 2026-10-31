//! Numeric text syntax shared by explicit-base and default-base conversions.
use super::*;

fn invalid() -> VmExecutionError {
    VmExecutionError::new("invalid numeric string")
}

pub(super) fn int_value(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue, VmExecutionError> {
    if args.is_empty() && kwargs.is_empty() {
        return Ok(vm_int(0));
    }
    let (value, base) = integer_arguments(&args, kwargs)?;
    let radix = base
        .as_ref()
        .map(VmValue::as_bigint)
        .transpose()?
        .map(|value| bigint_to_u32(&value, "int() base"))
        .transpose()?
        .unwrap_or(10);
    match value {
        VmValue::String(text) => parse_int(text, radix),
        VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => parse_int_bytes(bytes, radix),
        _ => numeric_int(value, base.is_some()),
    }
}

fn integer_arguments<'a>(
    args: &'a [VmValue],
    kwargs: Vec<(String, VmValue)>,
) -> Result<(&'a VmValue, Option<VmValue>), VmExecutionError> {
    if args.len() > 2 || kwargs.len() > 1 {
        return Err(invalid());
    }
    let mut base = args.get(1).cloned();
    if let Some((key, value)) = kwargs.into_iter().next() {
        if key != "base" || base.is_some() {
            return Err(invalid());
        }
        base = Some(value);
    }
    let value = args.first().ok_or_else(invalid)?;
    Ok((value, base))
}

fn parse_int_bytes(bytes: &[u8], radix: u32) -> Result<VmValue, VmExecutionError> {
    ensure_int_bytes_input_size(bytes)?;
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    if !text.is_ascii() {
        return Err(invalid());
    }
    parse_int(text, radix)
}

fn numeric_int(value: &VmValue, explicit_base: bool) -> Result<VmValue, VmExecutionError> {
    if explicit_base {
        return Err(VmExecutionError::new("int() base requires text or bytes"));
    }
    match value {
        VmValue::Int(value) => checked_int_value(value.clone(), "int()"),
        VmValue::Bool(value) => Ok(vm_int(*value as u8)),
        VmValue::Float(value) => checked_int_value(f64_to_bigint_trunc(*value, "int()")?, "int()"),
        VmValue::Decimal(value) => checked_int_value(value.to_bigint(), "int()"),
        _ => Err(invalid()),
    }
}

fn validate_base(base: u32) -> Result<(), VmExecutionError> {
    if base == 0 || (2..=36).contains(&base) {
        return Ok(());
    }
    Err(invalid())
}

fn parse_int(text: &str, base: u32) -> Result<VmValue, VmExecutionError> {
    ensure_int_input_size(text)?;
    validate_base(base)?;
    let text = text.trim();
    let negative = text.starts_with('-');
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    let (digits, radix, prefixed) = integer_prefix(digits, base);
    let digits = if prefixed {
        digits.strip_prefix('_').unwrap_or(digits)
    } else {
        digits
    };
    let clean = remove_underscores(digits, |ch| ch.is_ascii() && ch.is_digit(radix))?;
    validate_digits(&clean, radix, base == 0 && !prefixed)?;
    let value = BigInt::from_str_radix(&clean, radix).map_err(|_| invalid())?;
    checked_int_value(if negative { -value } else { value }, "int()")
}

fn validate_digits(clean: &str, radix: u32, autodetect: bool) -> Result<(), VmExecutionError> {
    if autodetect && clean.starts_with('0') && clean.chars().any(|ch| ch != '0') {
        return Err(invalid());
    }
    if clean.is_empty() || !clean.chars().all(|ch| ch.is_ascii() && ch.is_digit(radix)) {
        return Err(invalid());
    }
    Ok(())
}

fn integer_prefix(digits: &str, base: u32) -> (&str, u32, bool) {
    for (prefix, radix) in [("0x", 16), ("0b", 2), ("0o", 8)] {
        if (base == 0 || base == radix)
            && digits
                .get(..2)
                .is_some_and(|text| text.eq_ignore_ascii_case(prefix))
        {
            return (&digits[2..], radix, true);
        }
    }
    (digits, if base == 0 { 10 } else { base }, false)
}

pub(super) fn parse_float(text: &str) -> Result<f64, VmExecutionError> {
    let clean = remove_underscores(text.trim(), |ch| ch.is_ascii_digit())?;
    clean.parse().map_err(|_| invalid())
}

fn remove_underscores(
    text: &str,
    digit: impl Fn(char) -> bool,
) -> Result<String, VmExecutionError> {
    let mut chars = text.chars().peekable();
    let mut previous_digit = false;
    let mut clean = String::new();
    while let Some(ch) = chars.next() {
        if ch == '_' {
            if !previous_digit || !chars.peek().is_some_and(|ch| digit(*ch)) {
                return Err(invalid());
            }
            previous_digit = false;
        } else {
            previous_digit = digit(ch);
            clean.push(ch);
        }
    }
    Ok(clean)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integer_prefixes_signs_and_separators() {
        for (text, base, expected) in [
            (" -0x_ff ", 0, -255),
            ("001", 10, 1),
            ("00", 0, 0),
            ("1_000", 10, 1000),
            ("ff", 16, 255),
        ] {
            assert_eq!(parse_int(text, base).unwrap(), vm_int(expected));
        }
        for (text, base) in [
            ("012", 0),
            ("1__0", 10),
            ("1_", 10),
            ("_1", 10),
            ("0x__ff", 16),
            ("", 10),
            ("2", 2),
            ("1", 1),
        ] {
            assert!(parse_int(text, base).is_err(), "{text}, base {base}");
        }
    }

    #[test]
    fn floating_separators_require_decimal_digits_on_both_sides() {
        assert_eq!(parse_float("1_000.5").unwrap(), 1000.5);
        assert_eq!(parse_float("1_2.5e1_0").unwrap(), 125000000000.0);
        for text in ["1_.0", "1._0", "_1", "1_", "1__0", "1e_2"] {
            assert!(parse_float(text).is_err(), "{text}");
        }
    }
}
