use super::*;

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
