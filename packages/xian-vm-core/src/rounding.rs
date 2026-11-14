//! Half-to-even rounding: `quantize(..., "half_even")` and Python's `round()`.
use super::*;

/// Every V2 int (512 bits) and decimal (scaled by 10**30, below 10**91) is
/// below 10**155, so rounding to a power of ten at or above 10**156 gives 0.
const ROUNDED_AWAY: u32 = 156;

/// The `round` builtin: bound like the other builtins (positionally), then
/// charged one numeric operation, like `quantize`.
pub(super) fn builtin_round(
    host: &mut dyn VmHost,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<VmValue, VmExecutionError> {
    let (number, ndigits) = round_arguments(args, kwargs)?;
    host.charge_execution_cost(numeric_v2::OP_GAS)?;
    round(number, ndigits)
}

/// `round()`'s `number` and `ndigits` (`None` when omitted).
fn round_arguments<'a>(
    args: &'a [VmValue],
    kwargs: &[(String, VmValue)],
) -> Result<(&'a VmValue, &'a VmValue), VmExecutionError> {
    match (args, kwargs.is_empty()) {
        ([number], true) => Ok((number, &VmValue::None)),
        ([number, ndigits], true) => Ok((number, ndigits)),
        _ => Err(VmExecutionError::new(
            "round() expects one or two positional arguments",
        )),
    }
}

/// `round(number, ndigits)` as Python rounds an int or a `Decimal`: half to
/// even; an int, except a decimal with `ndigits`, which stays a decimal
/// (`ndigits` past 30 changes nothing). A bool is neither number in V2.
fn round(number: &VmValue, ndigits: &VmValue) -> Result<VmValue, VmExecutionError> {
    let (scaled, places) = match number {
        VmValue::Int(value) => (value, 0),
        VmValue::Decimal(value) => (&value.scaled, xian_numeric::DECIMAL_SCALE as u32),
        _ => return Err(VmExecutionError::new("round() requires an int or decimal")),
    };
    match ndigits {
        VmValue::None => numeric_v2::checked(round_ratio(scaled, &ten_to(places))),
        VmValue::Int(ndigits) => {
            let rounded = round_to_power(scaled, &(BigInt::from(places) - ndigits));
            match number {
                VmValue::Decimal(_) => VmDecimal::from_scaled(rounded).map(VmValue::Decimal),
                _ => numeric_v2::checked(rounded),
            }
        }
        _ => Err(VmExecutionError::new(
            "round() ndigits must be an int or None",
        )),
    }
}

/// `value` rounded half to even to a multiple of `10**exponent` (itself when
/// the exponent is not positive).
fn round_to_power(value: &BigInt, exponent: &BigInt) -> BigInt {
    if exponent.sign() != Sign::Plus {
        return value.clone();
    }
    let unit = ten_to(
        exponent
            .to_u32()
            .map_or(ROUNDED_AWAY, |e| e.min(ROUNDED_AWAY)),
    );
    round_ratio(value, &unit) * unit
}

fn ten_to(exponent: u32) -> BigInt {
    BigInt::from(10u8).pow(exponent)
}

/// `number / denominator` rounded half to even (`quantize(..., "half_even")`).
pub(super) fn round_ratio(number: &BigInt, denominator: &BigInt) -> BigInt {
    let quotient = number / denominator;
    let remainder = (number % denominator).abs() * BigInt::from(2u8);
    let odd = (&quotient % BigInt::from(2u8)) != BigInt::zero();
    if remainder > *denominator || (remainder == *denominator && odd) {
        quotient + if number.sign() == Sign::Minus { -1 } else { 1 }
    } else {
        quotient
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(text: &str) -> VmValue {
        VmValue::Decimal(VmDecimal::from_str_literal(text).unwrap())
    }

    fn int(value: i64) -> VmValue {
        VmValue::Int(value.into())
    }

    fn big(value: BigInt) -> VmValue {
        VmValue::Int(value)
    }

    fn message(result: Result<VmValue, VmExecutionError>) -> String {
        result.unwrap_err().to_string()
    }

    /// CPython: `round(Decimal(text))`, `round(Decimal(text), n)`, `round(int, n)`.
    #[test]
    fn rounds_like_cpython() {
        for (value, ndigits, expected) in [
            (dec("2.5"), VmValue::None, int(2)),
            (dec("-2.5"), VmValue::None, int(-2)),
            (dec("3.5"), VmValue::None, int(4)),
            (dec("-0.5"), VmValue::None, int(0)),
            (dec("1.005"), int(2), dec("1")),
            (dec("-1.015"), int(2), dec("-1.02")),
            (dec("1234.5678"), int(-2), dec("1200")),
            (dec("1250"), int(-2), dec("1200")),
            (dec("-1350"), int(-2), dec("-1400")),
            (
                dec("0.000000000000000000000000000015"),
                int(29),
                dec("0.00000000000000000000000000002"),
            ),
            (dec("1.5"), int(30), dec("1.5")),
            (dec("1.5"), int(31), dec("1.5")),
            (dec("8.5"), int(0), dec("8")),
            (dec("-8.5"), int(0), dec("-8")),
            (dec("7.5"), int(0), dec("8")),
            (int(7), VmValue::None, int(7)),
            (int(7), int(3), int(7)),
            (int(7), int(0), int(7)),
            (int(25), int(-1), int(20)),
            (int(35), int(-1), int(40)),
            (int(-25), int(-1), int(-20)),
            (int(-15), int(-1), int(-20)),
            (int(149), int(-2), int(100)),
            (int(150), int(-2), int(200)),
            (int(250), int(-2), int(200)),
        ] {
            assert_eq!(
                round(&value, &ndigits).unwrap(),
                expected,
                "{value:?} {ndigits:?}"
            );
        }
    }

    #[test]
    fn huge_ndigits_round_to_zero_or_change_nothing_without_huge_work() {
        let huge = big(BigInt::from(1) << 511usize);
        let largest = big((BigInt::from(1) << 512usize) - 1);
        let max_decimal = dec(&format!("{}.{}", "9".repeat(61), "9".repeat(30)));
        for value in [int(5), largest.clone(), max_decimal.clone()] {
            assert_eq!(
                round(&value, &big(-(BigInt::from(1) << 511usize)))
                    .unwrap()
                    .truthy(),
                false
            );
            assert_eq!(round(&value, &huge).unwrap(), value);
        }
        // 2**512 - 1 < 10**155 / 2, and its tens round past 512 bits.
        assert_eq!(round(&largest, &int(-155)).unwrap(), int(0));
        assert_eq!(
            round(&largest, &int(-154)).unwrap(),
            big(BigInt::from(10u8).pow(154))
        );
        assert_eq!(
            round_to_power(&BigInt::from(-7), &BigInt::from(1u8)),
            BigInt::from(-10)
        );
        assert!(message(round(&largest, &int(-1))).contains("512-bit"));
        assert!(message(round(&max_decimal, &int(0))).contains("decimal range"));
        assert_eq!(
            round(&max_decimal, &VmValue::None).unwrap(),
            big(BigInt::from(10u8).pow(61))
        );
    }

    #[test]
    fn refuses_bools_and_other_types_in_the_vm_error_style() {
        let number = "round() requires an int or decimal";
        let places = "round() ndigits must be an int or None";
        let shape = "round() expects one or two positional arguments";
        assert_eq!(message(round(&VmValue::Bool(true), &VmValue::None)), number);
        assert_eq!(
            message(round(&VmValue::String("2".into()), &int(1))),
            number
        );
        assert_eq!(message(round(&int(1), &VmValue::Bool(true))), places);
        assert_eq!(message(round(&dec("1.5"), &dec("1"))), places);
        assert_eq!(
            message(round_arguments(&[], &[]).map(|_| VmValue::None)),
            shape
        );
        assert_eq!(
            message(round_arguments(&[int(1), int(2), int(3)], &[]).map(|_| VmValue::None)),
            shape
        );
        assert_eq!(
            message(
                round_arguments(&[int(1)], &[("ndigits".into(), int(2))]).map(|_| VmValue::None)
            ),
            shape
        );
        let one = [int(1)];
        let (number, ndigits) = round_arguments(&one, &[]).unwrap();
        assert_eq!((number, ndigits), (&int(1), &VmValue::None));
        let two = [int(1), int(2)];
        let (number, ndigits) = round_arguments(&two, &[]).unwrap();
        assert_eq!((number, ndigits), (&int(1), &int(2)));
    }
    #[test]
    fn ties_are_even_and_signed() {
        let ten = BigInt::from(10);
        for (value, expected) in [(25, 2), (35, 4), (-25, -2), (-35, -4), (26, 3), (-24, -2)] {
            assert_eq!(
                round_ratio(&BigInt::from(value), &ten),
                BigInt::from(expected)
            );
        }
    }
}
