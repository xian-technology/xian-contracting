use super::*;

pub(super) fn call(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<VmValue, VmExecutionError> {
    if args.len() > 2 {
        return Err(VmExecutionError::new(
            "round() expects at most two arguments",
        ));
    }
    let mut number = args.first();
    let mut digits = args.get(1);
    for (key, value) in kwargs {
        let slot = match key.as_str() {
            "number" => &mut number,
            "ndigits" => &mut digits,
            _ => return Err(VmExecutionError::new("unexpected round() keyword")),
        };
        if slot.replace(value).is_some() {
            return Err(VmExecutionError::new("duplicate round() argument"));
        }
    }
    let number = number.ok_or_else(|| VmExecutionError::new("round() requires a number"))?;
    round_value(number, parse_digits(digits)?)
}

fn parse_digits(digits: Option<&VmValue>) -> Result<Option<i32>, VmExecutionError> {
    match digits.map(VmValue::snapshot) {
        None | Some(VmValue::None) => Ok(None),
        Some(value) => {
            let integer = value.as_bigint()?;
            Ok(Some(integer.to_i32().unwrap_or(
                if integer.sign() == Sign::Minus {
                    i32::MIN
                } else {
                    i32::MAX
                },
            )))
        }
    }
}

fn round_value(value: &VmValue, digits: Option<i32>) -> Result<VmValue, VmExecutionError> {
    match value.snapshot() {
        VmValue::Bool(value) => round_value(&vm_int(u8::from(value)), digits),
        VmValue::Int(number) => {
            checked_int_value(round_integer(&number, digits.unwrap_or(0)), "round()")
        }
        VmValue::Float(number) => round_float(number, digits),
        VmValue::Decimal(number) => round_decimal(number, digits),
        other => Err(VmExecutionError::new(format!(
            "round() does not support {}",
            other.type_name()
        ))),
    }
}

fn round_integer(number: &BigInt, places: i32) -> BigInt {
    if places >= 0 {
        return number.clone();
    }
    let exponent = places.unsigned_abs();
    // 10^n exceeds any n-bit integer. Avoid allocating powers for huge ndigits.
    if u64::from(exponent) > number.bits() {
        return BigInt::zero();
    }
    let factor = BigInt::from(10u8).pow(exponent);
    round_ratio(number, &factor) * factor
}

fn round_ratio(number: &BigInt, denominator: &BigInt) -> BigInt {
    let quotient = number / denominator;
    let remainder = (number % denominator).abs() * BigInt::from(2u8);
    let odd = (&quotient % BigInt::from(2u8)) != BigInt::zero();
    if remainder > *denominator || (remainder == *denominator && odd) {
        quotient + if number.sign() == Sign::Minus { -1 } else { 1 }
    } else {
        quotient
    }
}

fn round_decimal(number: VmDecimal, digits: Option<i32>) -> Result<VmValue, VmExecutionError> {
    let Some(places) = digits else {
        return Ok(VmValue::Int(round_ratio(
            &number.scaled,
            &BigInt::from(10u8).pow(30),
        )));
    };
    if places >= 30 {
        return Ok(VmValue::Decimal(number));
    }
    if places < -61 {
        return Ok(VmValue::Decimal(VmDecimal::from_scaled(BigInt::zero())?));
    }
    let factor = BigInt::from(10u8).pow((30 - places) as u32);
    // Contracting's Decimal context uses ROUND_DOWN when ndigits is supplied.
    let rounded = (&number.scaled / &factor) * factor;
    Ok(VmValue::Decimal(VmDecimal::from_scaled(rounded)?))
}

fn round_float(number: f64, digits: Option<i32>) -> Result<VmValue, VmExecutionError> {
    let Some(places) = digits else {
        if !number.is_finite() {
            return Err(VmExecutionError::new(
                "cannot round non-finite float to integer",
            ));
        }
        let (numerator, denominator) = float_ratio(number);
        return Ok(VmValue::Int(round_ratio(&numerator, &denominator)));
    };
    if !number.is_finite() || places > 323 {
        return Ok(VmValue::Float(number));
    }
    if places < -308 {
        return Ok(VmValue::Float(0.0f64.copysign(number)));
    }
    rounded_float_places(number, places)
}

fn rounded_float_places(number: f64, places: i32) -> Result<VmValue, VmExecutionError> {
    let (mut numerator, mut denominator) = float_ratio(number);
    let factor = BigInt::from(10u8).pow(places.unsigned_abs());
    if places >= 0 {
        numerator *= factor;
    } else {
        denominator *= factor;
    }
    let rounded = round_ratio(&numerator, &denominator);
    let result: f64 = format!("{rounded}e{}", -places)
        .parse()
        .map_err(|_| VmExecutionError::new("round() float conversion failed"))?;
    if !result.is_finite() {
        return Err(VmExecutionError::new("round() float overflow"));
    }
    Ok(VmValue::Float(result.copysign(number)))
}

fn float_ratio(number: f64) -> (BigInt, BigInt) {
    let bits = number.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1u64 << 52) - 1);
    let mantissa = if exponent == 0 {
        fraction
    } else {
        fraction | (1u64 << 52)
    };
    let shift = if exponent == 0 {
        -1074
    } else {
        exponent - 1023 - 52
    };
    let mut numerator = BigInt::from(mantissa);
    let denominator = if shift < 0 {
        BigInt::from(1u8) << shift.unsigned_abs()
    } else {
        numerator <<= shift as usize;
        BigInt::from(1u8)
    };
    if number.is_sign_negative() {
        numerator = -numerator;
    }
    (numerator, denominator)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ties_are_even_and_signed() {
        for (value, expected) in [(25, 20), (35, 40), (-25, -20), (-35, -40)] {
            assert_eq!(
                round_integer(&BigInt::from(value), -1),
                BigInt::from(expected)
            );
        }
        assert_eq!(round_integer(&BigInt::from(123), i32::MIN), BigInt::zero());
    }
    #[test]
    fn float_rounding_uses_the_exact_binary_input() {
        assert_eq!(round_float(2.675, Some(2)).unwrap(), VmValue::Float(2.67));
        assert_eq!(round_float(0.125, Some(2)).unwrap(), VmValue::Float(0.12));
        assert_eq!(round_float(1e308, Some(2)).unwrap(), VmValue::Float(1e308));
        assert!(round_float(1.79e308, Some(-308)).is_err());
    }
}
