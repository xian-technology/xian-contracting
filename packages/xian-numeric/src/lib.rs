//! Exact numeric input rules for Xian VM v2.

pub const INTEGER_BITS: u64 = 512;
pub const DECIMAL_SCALE: usize = 30;
pub const DECIMAL_INTEGER_DIGITS: usize = 61;

/// Parse an exact decimal and render the canonical wire spelling. The accepted
/// grammar is `[+-]?(digits(.digits?)?|.digits)([eE][+-]?digits)?` using ASCII
/// digits. Callers handling Python source remove lexical underscores first.
pub fn canonical_decimal(text: &str) -> Result<String, &'static str> {
    let (negative, unsigned) = split_sign(text);
    let (mantissa, exponent) = match unsigned.split_once(['e', 'E']) {
        Some((mantissa, exponent)) => (mantissa, parse_exponent(exponent, text.len())?),
        None => (unsigned, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if (whole.is_empty() && fraction.is_empty())
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return Err("invalid decimal digits");
    }

    let digits = format!("{whole}{fraction}");
    let significant = digits.trim_matches('0');
    if significant.is_empty() {
        return Ok("0".into());
    }
    let leading_zeroes = digits.len() - digits.trim_start_matches('0').len();
    let point = whole.len() as i128 + exponent - leading_zeroes as i128;
    if point > DECIMAL_INTEGER_DIGITS as i128 {
        return Err("decimal magnitude must be below 10^61");
    }
    if significant.len() as i128 - point > DECIMAL_SCALE as i128 {
        return Err("decimal requires more than 30 fractional digits");
    }

    Ok(render_decimal(negative, significant, point))
}

fn render_decimal(negative: bool, significant: &str, point: i128) -> String {
    let mut result = String::new();
    if negative {
        result.push('-');
    }
    if point <= 0 {
        result.push_str("0.");
        result.push_str(&"0".repeat((-point) as usize));
        result.push_str(significant);
    } else if point as usize >= significant.len() {
        result.push_str(significant);
        result.push_str(&"0".repeat(point as usize - significant.len()));
    } else {
        let (whole, fraction) = significant.split_at(point as usize);
        result.push_str(whole);
        result.push('.');
        result.push_str(fraction);
    }
    result
}

fn split_sign(text: &str) -> (bool, &str) {
    if let Some(rest) = text.strip_prefix('-') {
        (true, rest)
    } else {
        (false, text.strip_prefix('+').unwrap_or(text))
    }
}

fn parse_exponent(text: &str, input_len: usize) -> Result<i128, &'static str> {
    let (negative, digits) = split_sign(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid decimal exponent");
    }
    // Larger shifts cannot affect the outcome for this many source digits.
    let limit = input_len as i128 + (DECIMAL_INTEGER_DIGITS + DECIMAL_SCALE) as i128;
    let value = digits.bytes().fold(0, |value, digit| {
        (value * 10 + i128::from(digit - b'0')).min(limit)
    });
    Ok(if negative { -value } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_values_at_both_limits() {
        let maximum = format!("{}.{}", "9".repeat(61), "9".repeat(30));
        assert_eq!(canonical_decimal(&maximum).unwrap(), maximum);
        for (source, expected) in [
            ("-.5", "-0.5"),
            ("1.25", "1.25"),
            ("+0012300e-2", "123"),
            ("100000e-35", "0.000000000000000000000000000001"),
            ("-0e9999999999999999999999", "0"),
        ] {
            assert_eq!(canonical_decimal(source).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_invalid_and_unrepresentable_values() {
        for source in [
            "",
            ".",
            "+",
            "１",
            " 1",
            "1 ",
            "1e",
            "1e+",
            "1_0",
            "1e1e1",
            "1.2.3",
            "1e-31",
            "1e61",
            "-1e99999999999999999999999",
            "1e-999999999999999999999",
        ] {
            assert!(canonical_decimal(source).is_err(), "{source}");
        }
    }
}
