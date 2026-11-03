//! Binary64 power policy: one pinned portable kernel, with canonical NaN output.
//!
//! `f64::powf` delegates to platform-dependent math and produced adjacent results
//! for sqrt(f64::MAX) on macOS/Linux. libm is exact-version pinned with arch and
//! intrinsic dispatch disabled. Its fixed-size arithmetic needs no input-sized
//! allocations; existing VM power charges and integer-conversion checks apply.

pub(in crate::interpreter) fn pow(base: f64, exponent: f64) -> f64 {
    let result = libm::pow(base, exponent);
    if result.is_nan() {
        // IEEE operations may propagate different NaN signs/payloads by target.
        f64::from_bits(0x7ff8_0000_0000_0000)
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::pow;

    #[test]
    fn max_finite_square_root_rounds_below_power_of_two() {
        assert_eq!(pow(f64::MAX, 0.5).to_bits(), 0x5fef_ffff_ffff_ffff);
    }

    #[test]
    fn exact_powers_preserve_subnormal_ties_and_signed_zero() {
        for (base, exponent, expected) in [
            (2.0, -1074.0, 1),
            (2.0, -1075.0, 0),
            (-0.0, 3.0, 0x8000_0000_0000_0000),
            (-0.0, 2.0, 0),
            (-0.0, -3.0, 0xfff0_0000_0000_0000),
            (-2.0, 3.0, (-8.0f64).to_bits()),
            (f64::from_bits(1), 0.5, 0x1e60_0000_0000_0000),
        ] {
            assert_eq!(pow(base, exponent).to_bits(), expected, "{base}^{exponent}");
        }
    }

    #[test]
    fn nan_results_are_canonical_but_special_identities_remain_one() {
        for nan in [
            f64::from_bits(0x7ff8_0000_0000_0001),
            f64::from_bits(0xfff8_0000_0000_0002),
            f64::from_bits(0x7ff0_0000_0000_0001),
        ] {
            assert_eq!(pow(nan, 1.0).to_bits(), 0x7ff8_0000_0000_0000);
            assert_eq!(pow(2.0, nan).to_bits(), 0x7ff8_0000_0000_0000);
            assert_eq!(pow(nan, 0.0), 1.0);
            assert_eq!(pow(1.0, nan), 1.0);
        }
        assert_eq!(pow(-1.0, 0.5).to_bits(), 0x7ff8_0000_0000_0000);
        assert_eq!(pow(f64::INFINITY, 2.0), f64::INFINITY);
    }
}
