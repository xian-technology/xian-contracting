//! Exact binary64 introspection and bounded, correctly rounded hexadecimal input.
use super::*;
use crate::interpreter::MAX_INT_STRING_CHARS;

pub(super) fn call(number: f64, method: &str, args: &[VmValue]) -> Result<VmValue> {
    if !args.is_empty() {
        return Err(VmExecutionError::new("float method expects no arguments"));
    }
    Ok(match method {
        "is_integer" => VmValue::Bool(number.is_finite() && number.fract() == 0.0),
        "conjugate" => VmValue::Float(number),
        "hex" => VmValue::String(hex(number)),
        "as_integer_ratio" => ratio(number)?,
        _ => return Err(VmExecutionError::new("unsupported float method")),
    })
}

fn hex(number: f64) -> String {
    if number.is_nan() {
        return "nan".into();
    }
    let sign = if number.is_sign_negative() { "-" } else { "" };
    if number.is_infinite() {
        return format!("{sign}inf");
    }
    if number == 0.0 {
        return format!("{sign}0x0.0p+0");
    }
    let bits = number.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1_u64 << 52) - 1);
    if exponent == 0 {
        format!("{sign}0x0.{fraction:013x}p-1022")
    } else {
        format!("{sign}0x1.{fraction:013x}p{:+}", exponent - 1023)
    }
}

fn ratio(number: f64) -> Result<VmValue> {
    if !number.is_finite() {
        return Err(VmExecutionError::new(
            "cannot convert NaN or infinity to integer ratio",
        ));
    }
    let bits = number.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let mut mantissa = bits & ((1_u64 << 52) - 1);
    let mut shift = if exponent == 0 {
        -1074
    } else {
        exponent - 1075
    };
    if exponent != 0 {
        mantissa |= 1_u64 << 52;
    }
    if mantissa == 0 {
        return Ok(VmValue::Tuple(vec![
            VmValue::Int(0.into()),
            VmValue::Int(1.into()),
        ]));
    }
    let trailing = mantissa.trailing_zeros();
    mantissa >>= trailing;
    shift += trailing as i32;
    let mut numerator = BigInt::from(mantissa);
    let mut denominator = BigInt::from(1);
    if shift < 0 {
        denominator <<= (-shift) as usize;
    } else {
        numerator <<= shift as usize;
    }
    if number.is_sign_negative() {
        numerator = -numerator;
    }
    Ok(VmValue::Tuple(vec![
        VmValue::Int(numerator),
        VmValue::Int(denominator),
    ]))
}

pub(super) fn from_hex(args: &[VmValue]) -> Result<VmValue> {
    if args.len() != 1 {
        return Err(invalid());
    }
    let VmValue::String(text) = args[0].snapshot() else {
        return Err(invalid());
    };
    if text.len() > MAX_INT_STRING_CHARS {
        return Err(VmExecutionError::new(
            "float hexadecimal input exceeds length limit",
        ));
    }
    let text = text
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .to_ascii_lowercase();
    let (negative, text) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text.as_str()),
    };
    if matches!(text, "inf" | "infinity" | "nan") {
        let value = if text == "nan" {
            f64::NAN
        } else {
            f64::INFINITY
        };
        return Ok(VmValue::Float(if negative { -value } else { value }));
    }
    let (mantissa, exponent) = parse_hex(text)?;
    let value = rounded_binary64(&mantissa, exponent)?;
    Ok(VmValue::Float(if negative { -value } else { value }))
}

fn invalid() -> VmExecutionError {
    VmExecutionError::new("invalid hexadecimal floating-point string")
}

fn parse_exponent(text: &str) -> Result<i64> {
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let magnitude = digits.bytes().fold(0_i64, |value, byte| {
        (value * 10 + i64::from(byte - b'0')).min(1_000_000_000)
    });
    Ok(if negative { -magnitude } else { magnitude })
}

fn parse_hex(text: &str) -> Result<(BigInt, i64)> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    let (coefficient, mut exponent) = match text.split_once('p') {
        Some((coefficient, exponent)) => (coefficient, parse_exponent(exponent)?),
        None => (text, 0),
    };
    let (whole, fraction) = coefficient.split_once('.').unwrap_or((coefficient, ""));
    let digits = format!("{whole}{fraction}");
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    exponent -= 4 * fraction.len() as i64;
    let number = BigInt::parse_bytes(digits.as_bytes(), 16).ok_or_else(invalid)?;
    Ok((number, exponent))
}

fn rounded_shift(number: &BigInt, shift: i64) -> BigInt {
    if shift <= 0 {
        return number << (-shift) as usize;
    }
    if shift > number.bits() as i64 {
        return BigInt::zero();
    }
    let shift = shift as usize;
    let mut rounded = number >> shift;
    let remainder = number - (&rounded << shift);
    let halfway = BigInt::from(1) << (shift - 1);
    if remainder > halfway || (remainder == halfway && rounded.bit(0)) {
        rounded += 1;
    }
    rounded
}

fn rounded_binary64(number: &BigInt, exponent: i64) -> Result<f64> {
    if number.is_zero() {
        return Ok(0.0);
    }
    let adjusted = number.bits() as i64 - 1 + exponent;
    if adjusted > 1023 {
        return Err(VmExecutionError::new(
            "hexadecimal value too large to represent as a float",
        ));
    }
    if adjusted < -1075 {
        return Ok(0.0);
    }
    let subnormal = adjusted < -1022;
    let shift = if subnormal {
        -1074 - exponent
    } else {
        number.bits() as i64 - 53
    };
    let mut rounded = rounded_shift(number, shift);
    if subnormal {
        return Ok(f64::from_bits(rounded.to_u64().ok_or_else(invalid)?));
    }
    let mut quantum = exponent + shift;
    if rounded.bits() > 53 {
        rounded >>= 1;
        quantum += 1;
    }
    let exponent_bits = quantum + 52 + 1023;
    if exponent_bits >= 2047 {
        return Err(VmExecutionError::new(
            "hexadecimal value too large to represent as a float",
        ));
    }
    let fraction = rounded.to_u64().ok_or_else(invalid)? & ((1_u64 << 52) - 1);
    Ok(f64::from_bits((exponent_bits as u64) << 52 | fraction))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hexadecimal_round_trip_preserves_every_binary64_shape() {
        for bits in [
            0,
            1,
            2,
            (1_u64 << 52) - 1,
            1_u64 << 52,
            0x3ff8_0000_0000_0000,
            0x7fef_ffff_ffff_ffff,
            1_u64 << 63,
            0xbff0_0000_0000_0001,
        ] {
            let number = f64::from_bits(bits);
            let VmValue::Float(actual) = from_hex(&[VmValue::String(hex(number))]).unwrap() else {
                panic!()
            };
            assert_eq!(actual.to_bits(), bits);
        }
    }

    #[test]
    fn hexadecimal_rounding_handles_halfway_and_overflow() {
        let VmValue::Float(smallest) = from_hex(&[VmValue::String("0x3p-1076".into())]).unwrap()
        else {
            panic!()
        };
        assert_eq!(smallest.to_bits(), 1);
        for (text, bits) in [
            ("0x1p-1075", 0),
            ("0x3p-1075", 2),
            ("0x1.00000000000008p0", 0x3ff0_0000_0000_0000),
            ("0x1.00000000000018p0", 0x3ff0_0000_0000_0002),
        ] {
            let VmValue::Float(actual) = from_hex(&[VmValue::String(text.into())]).unwrap() else {
                panic!()
            };
            assert_eq!(actual.to_bits(), bits, "{text}");
        }
        assert!(from_hex(&[VmValue::String("0x1.fffffffffffff8p1023".into())]).is_err());
        assert!(from_hex(&[VmValue::String("1.2.3".into())]).is_err());
    }
}
