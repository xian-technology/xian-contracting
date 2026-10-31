//! Bounded, deterministic access to the pinned historical Decimal backend.
use std::ffi::{c_char, c_int, CStr, CString};

use crate::VmExecutionError;

const MAX_INPUT_BYTES: usize = 128 * 1024;
const MAX_OUTPUT_BYTES: usize = MAX_INPUT_BYTES + 64;

extern "C" {
    fn xian_decimal_calculate(
        operation: *const c_char,
        arguments: *const *const c_char,
        count: usize,
        rounding: c_int,
        output: *mut *mut c_char,
    ) -> c_int;
    fn xian_decimal_free(text: *mut c_char);
}

struct BackendOutput(*mut c_char);

impl Drop for BackendOutput {
    fn drop(&mut self) {
        // SAFETY: The shim allocated this nullable pointer and owns its free routine.
        unsafe { xian_decimal_free(self.0) };
    }
}

pub(crate) fn calculate(
    operation: &str,
    args: &[&str],
    rounding: Option<&str>,
) -> Result<String, VmExecutionError> {
    if args.is_empty() || args.len() > 3 || operation.len() > 64 {
        return Err(VmExecutionError::new(
            "decimal operand count or operation name exceeds limit",
        ));
    }
    let rounding = rounding_code(rounding)?;
    let operation = CString::new(operation)
        .map_err(|_| VmExecutionError::new("invalid decimal operation name"))?;
    let args: Vec<CString> = args
        .iter()
        .map(|value| validated_input(value))
        .collect::<Result<_, _>>()?;
    let pointers: Vec<_> = args.iter().map(|value| value.as_ptr()).collect();
    let mut output = BackendOutput(std::ptr::null_mut());
    // SAFETY: All strings are NUL terminated and live across the call. The pointer
    // array has count entries; the shim validates arity and owns all C allocations.
    let status = unsafe {
        xian_decimal_calculate(
            operation.as_ptr(),
            pointers.as_ptr(),
            pointers.len(),
            rounding,
            &mut output.0,
        )
    };
    check_status(status)?;
    output.to_string()
}

impl BackendOutput {
    fn to_string(&self) -> Result<String, VmExecutionError> {
        if self.0.is_null() {
            return Err(VmExecutionError::new("decimal backend allocation failed"));
        }
        // SAFETY: A successful shim call returns one owned NUL-terminated string.
        let bytes = unsafe { CStr::from_ptr(self.0) }.to_bytes();
        if bytes.len() > MAX_OUTPUT_BYTES {
            return Err(VmExecutionError::new(
                "decimal output resource limit exceeded",
            ));
        }
        String::from_utf8(bytes.to_vec())
            .map_err(|_| VmExecutionError::new("invalid decimal backend output"))
    }
}

fn validated_input(value: &str) -> Result<CString, VmExecutionError> {
    if value.is_empty() || value.len() > MAX_INPUT_BYTES || !value.is_ascii() {
        return Err(VmExecutionError::new(
            "decimal input resource limit exceeded",
        ));
    }
    // Reject compact enormous exponents before entering C. The parsed decimal's
    // effective exponent and coefficient length are checked again by the shim.
    if let Some((_, exponent)) = value.rsplit_once(['e', 'E']) {
        let exponent = exponent
            .parse::<i64>()
            .map_err(|_| VmExecutionError::new("invalid decimal exponent"))?;
        if exponent.unsigned_abs() > MAX_INPUT_BYTES as u64 {
            return Err(VmExecutionError::new(
                "decimal exponent resource limit exceeded",
            ));
        }
    }
    CString::new(value).map_err(|_| VmExecutionError::new("invalid decimal input"))
}

fn rounding_code(rounding: Option<&str>) -> Result<c_int, VmExecutionError> {
    // Position matches the stable mpd rounding enum in the vendored 4.0.0 header.
    const MODES: [&str; 8] = [
        "ROUND_UP",
        "ROUND_DOWN",
        "ROUND_CEILING",
        "ROUND_FLOOR",
        "ROUND_HALF_UP",
        "ROUND_HALF_DOWN",
        "ROUND_HALF_EVEN",
        "ROUND_05UP",
    ];
    MODES
        .iter()
        .position(|mode| *mode == rounding.unwrap_or("ROUND_DOWN"))
        .map(|index| index as c_int)
        .ok_or_else(|| VmExecutionError::new("invalid decimal rounding mode"))
}

fn check_status(status: c_int) -> Result<(), VmExecutionError> {
    let message = match status {
        0 => return Ok(()),
        1 => "invalid decimal operation",
        2 => "division by zero",
        3 => "decimal overflow",
        4 => "decimal resource limit exceeded or allocation failed",
        5 => "invalid decimal backend arguments",
        _ => "unsupported decimal operation",
    };
    Err(VmExecutionError::new(message))
}

#[cfg(test)]
mod tests {
    use super::calculate;

    #[test]
    fn matches_pinned_historical_decimal_vectors() {
        type Vector = (String, Vec<String>, (u8, String));
        let vectors: Vec<Vector> =
            serde_json::from_str(include_str!("../tests/decimal_vectors.json")).unwrap();
        assert_eq!(vectors.len(), 2266);
        for (index, (operation, inputs, (status, expected))) in vectors.iter().enumerate() {
            let arguments: Vec<&str> = inputs.iter().map(String::as_str).collect();
            let actual = calculate(operation, &arguments, None);
            match status {
                0 => assert_eq!(
                    actual.unwrap(),
                    *expected,
                    "case {index}: {operation} {inputs:?}"
                ),
                1..=3 => {
                    let category = match status {
                        1 => "invalid decimal operation",
                        2 => "division by zero",
                        3 => "decimal overflow",
                        _ => unreachable!(),
                    };
                    assert_eq!(
                        actual.unwrap_err().to_string(),
                        category,
                        "case {index}: {operation} {inputs:?}"
                    );
                    assert!(expected.is_empty());
                }
                _ => panic!("unknown oracle status {status} in case {index}"),
            }
        }
    }

    #[test]
    fn preserves_exact_inputs_and_special_payloads() {
        for value in ["1.2300", "-0.000", "-sNaN123", "Infinity", "1E-1074"] {
            assert_eq!(calculate("parse", &[value], None).unwrap(), value);
        }
        let large = "7".repeat(150);
        assert_eq!(calculate("parse", &[&large], None).unwrap(), large);
    }

    #[test]
    fn fractional_power_and_sqrt_follow_different_rounding_rules() {
        // Recorded with the pinned Python 3.12.10/libmpdec 4.0.0 oracle.
        assert_eq!(calculate("pow", &["2", "0.3"], None).unwrap(),
            "1.231144413344916284499393069167743109876137761100817794337065538246100719719358458404022749");
        assert_eq!(calculate("sqrt", &["3"], None).unwrap(),
            "1.732050807568877293527446341505872366942805253810380628055806979451933016908800037081146187");
        assert_eq!(calculate("pow", &["3", "0.5"], None).unwrap(),
            "1.732050807568877293527446341505872366942805253810380628055806979451933016908800037081146186");
        assert_eq!(
            calculate("pow", &["4", "0.5"], None).unwrap(),
            format!("2.{}", "0".repeat(90))
        );
        assert_eq!(calculate("sqrt", &["4"], None).unwrap(), "2");
        assert_eq!(
            calculate("pow", &["32", "0.2"], None).unwrap(),
            format!("2.{}", "0".repeat(90))
        );
    }

    #[test]
    fn operations_use_the_historical_context_and_traps() {
        assert_eq!(
            calculate("div", &["1", "3"], None).unwrap(),
            format!("0.{}", "3".repeat(91))
        );
        assert_eq!(
            calculate("mul", &["1E-190", "0.1"], None).unwrap(),
            "0E-190"
        );
        assert!(calculate("div", &["1", "0"], None)
            .unwrap_err()
            .to_string()
            .contains("division by zero"));
        assert!(calculate("add", &["sNaN", "1"], None).is_err());
        assert!(calculate("mul", &["1E100", "10"], None).is_err());
        assert_eq!(calculate("pow", &["0", "-1"], None).unwrap(), "Infinity");
        assert_eq!(calculate("add", &["NaN123", "1"], None).unwrap(), "NaN123");
    }

    #[test]
    fn decimal_methods_preserve_context_and_exact_copy_semantics() {
        for (op, args, expected) in [
            ("copy_sign", vec!["1.2300", "-0"], "-1.2300"),
            ("compare_total", vec!["-0", "0"], "-1"),
            ("compare", vec!["NaN", "0"], "NaN"),
            ("fma", vec!["1.2", "3", "0.4"], "4.0"),
            ("logical_xor", vec!["1010", "1100"], "110"),
            ("shift", vec!["123", "2"], "12300"),
            ("remainder_near", vec!["10", "6"], "-2"),
            ("powmod", vec!["3", "7", "11"], "9"),
        ] {
            assert_eq!(calculate(op, &args, None).unwrap(), expected, "{op}");
        }
        assert_eq!(
            calculate("quantize", &["1.25", "0.1"], Some("ROUND_HALF_UP")).unwrap(),
            "1.3"
        );
    }

    #[test]
    fn rejects_unbounded_work_and_invalid_dispatch_before_execution() {
        for (op, args) in [
            ("parse", vec!["1E999999999999999999"]),
            ("add", vec!["1"]),
            ("unknown", vec!["1"]),
            ("parse", vec!["1\0"]),
        ] {
            assert!(calculate(op, &args, None).is_err(), "{op}");
        }
        let maximum_power = format!("1.{}1", "0".repeat(1022));
        assert!(calculate("pow", &[&maximum_power, "0.5"], None).is_ok());
        let excessive_power = format!("1.{}1", "0".repeat(1023));
        assert!(calculate("pow", &[&excessive_power, "0.5"], None).is_err());
        let near_one = format!("1.{}1", "0".repeat(4093));
        assert!(calculate("pow", &[&near_one, "1E4094"], None).is_err());
        assert!(calculate("pow", &["1.0001", "1E512"], None).is_err());
        assert!(calculate("powmod", &["2", "1E512", "3"], None).is_err());
        assert_eq!(
            calculate("pow", &["1.0001", "1E511"], None)
                .unwrap_err()
                .to_string(),
            "decimal overflow"
        );
        let huge = "1".repeat(4097);
        assert!(calculate("pow", &[&huge, "0.1"], None).is_err());
        assert!(calculate("powmod", &["2", "1E4097", "3"], None).is_err());
        assert!(calculate("plus", &["1"], Some("ROUND_UNKNOWN")).is_err());
    }

    #[test]
    fn every_rounding_mode_matches_decimal_quantization() {
        for (rounding, expected) in [
            ("ROUND_UP", ["1.3", "-1.3", "1.6"]),
            ("ROUND_DOWN", ["1.2", "-1.2", "1.5"]),
            ("ROUND_CEILING", ["1.3", "-1.2", "1.6"]),
            ("ROUND_FLOOR", ["1.2", "-1.3", "1.5"]),
            ("ROUND_HALF_UP", ["1.3", "-1.3", "1.6"]),
            ("ROUND_HALF_DOWN", ["1.2", "-1.2", "1.5"]),
            ("ROUND_HALF_EVEN", ["1.2", "-1.2", "1.6"]),
            ("ROUND_05UP", ["1.2", "-1.2", "1.6"]),
        ] {
            for (value, expected) in ["1.25", "-1.25", "1.55"].into_iter().zip(expected) {
                assert_eq!(
                    calculate("quantize", &[value, "0.1"], Some(rounding)).unwrap(),
                    expected,
                    "{rounding}({value})"
                );
            }
        }
    }

    #[test]
    fn rejects_hostile_input_and_accepts_exact_boundaries() {
        let maximum = "1".repeat(super::MAX_INPUT_BYTES);
        assert_eq!(calculate("parse", &[&maximum], None).unwrap(), maximum);
        assert!(calculate("parse", &[&(maximum + "1")], None).is_err());
        for value in [
            "",
            "1E+",
            "1E-99999999999999999999",
            "1E131073",
            "1E-131073",
            "١",
            "1.2.3",
        ] {
            assert!(calculate("parse", &[value], None).is_err(), "{value}");
        }
        for value in ["1E+131072", "1E-131072"] {
            assert_eq!(calculate("parse", &[value], None).unwrap(), value);
        }
        assert_eq!(
            calculate("add", &[], None).unwrap_err().to_string(),
            "decimal operand count or operation name exceeds limit"
        );
        assert_eq!(
            calculate("add", &["1", "2", "3", "4"], None)
                .unwrap_err()
                .to_string(),
            "decimal operand count or operation name exceeds limit"
        );
        assert_eq!(
            calculate(&"a".repeat(65), &["1"], None)
                .unwrap_err()
                .to_string(),
            "decimal operand count or operation name exceeds limit"
        );
        assert_eq!(
            calculate(&"a".repeat(64), &["1"], None)
                .unwrap_err()
                .to_string(),
            "unsupported decimal operation"
        );
        assert_eq!(
            calculate("parse", &[""], None).unwrap_err().to_string(),
            "decimal input resource limit exceeded"
        );
        assert_eq!(
            calculate("parse", &["١"], None).unwrap_err().to_string(),
            "decimal input resource limit exceeded"
        );
        assert!(calculate("parse\0", &["1"], None).is_err());
        assert_eq!(
            calculate("to_integral_value", &["1E131072"], None).unwrap(),
            "1E+131072"
        );
        assert_eq!(
            calculate("shift", &["1", "92"], None)
                .unwrap_err()
                .to_string(),
            "invalid decimal operation"
        );
    }

    #[test]
    fn contexts_are_isolated_between_threads() {
        let handles: Vec<_> = (0..8)
            .map(|n| {
                std::thread::spawn(move || {
                    let (rounding, expected) = if n % 2 == 0 {
                        ("ROUND_UP", "2")
                    } else {
                        ("ROUND_DOWN", "1")
                    };
                    for _ in 0..40 {
                        assert_eq!(
                            calculate("to_integral_value", &["1.5"], Some(rounding)).unwrap(),
                            expected
                        );
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
    }
}
