//! Bounded hash/crypto admission and work charging before any payload copies.
use super::{VmExecutionError, VmHost, VmValue};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

type Result<T> = std::result::Result<T, VmExecutionError>;
pub(super) const TEXT_LIMIT: usize = 1024 * 1024;
pub(super) const HEX_LIMIT: usize = 2 * TEXT_LIMIT;
const VERIFY_FIXED_WORK: u64 = 95_000;

#[derive(Clone, Copy)]
enum Algorithm {
    Sha256,
    Sha3,
}
#[derive(Clone, Copy)]
enum Input {
    Text,
    Hex,
    Legacy,
}

pub(super) fn dispatch(
    id: &str,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    host: &mut dyn VmHost,
) -> Option<Result<VmValue>> {
    use Algorithm::*;
    use Input::*;
    let hash = match id {
        "hash.sha256_text" => Some((Sha256, Text)),
        "hash.sha3_256_text" => Some((Sha3, Text)),
        "hash.sha256_hex" => Some((Sha256, Hex)),
        "hash.sha3_256_hex" => Some((Sha3, Hex)),
        "hash.sha256_legacy" => Some((Sha256, Legacy)),
        "hash.sha3_256_legacy" => Some((Sha3, Legacy)),
        _ => None,
    };
    if let Some((algorithm, input)) = hash {
        return Some(hash_call(algorithm, input, args, kwargs, host));
    }
    match id {
        "crypto.ed25519_verify" => Some(verify_call(args, kwargs, host)),
        "crypto.key_is_valid" => Some(key_is_valid(args, kwargs)),
        _ => None,
    }
}

fn with_string<T>(value: &VmValue, read: impl FnOnce(&str) -> Result<T>) -> Result<T> {
    match value {
        VmValue::String(value) => read(value),
        VmValue::Reference(value) => value.with_value(|value| with_string(value, read)),
        _ => Err(VmExecutionError::new(format!(
            "expected string value, got {}",
            value.type_name()
        ))),
    }
}

fn limit(length: usize, maximum: usize, label: &str) -> Result<()> {
    if length > maximum {
        return Err(VmExecutionError::new(format!(
            "{label} resource limit exceeded ({maximum} UTF-8 bytes)"
        )));
    }
    Ok(())
}

fn hash_argument<'a>(
    args: &'a [VmValue],
    kwargs: &'a [(String, VmValue)],
    input: Input,
) -> Result<&'a VmValue> {
    match (args, kwargs) {
        ([value], []) => Ok(value),
        ([], [(key, value)]) if matches!(input, Input::Legacy) && key == "hex_str" => Ok(value),
        _ => Err(VmExecutionError::new("hash expects one argument")),
    }
}

fn hash_call(
    algorithm: Algorithm,
    input: Input,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    host: &mut dyn VmHost,
) -> Result<VmValue> {
    let argument = hash_argument(args, kwargs, input)?;
    with_string(argument, |value| {
        host.charge_execution_cost(hash_work(algorithm, input, value.len())?)?;
        let bytes = hash_bytes(value, input)?;
        let digest = match algorithm {
            Algorithm::Sha256 => hex::encode(Sha256::digest(bytes.as_ref())),
            Algorithm::Sha3 => hex::encode(Sha3_256::digest(bytes.as_ref())),
        };
        Ok(VmValue::String(digest))
    })
}

// Caps make every multiplication below bounded well inside u64, independently
// of whether execution metering is enabled.
fn hash_work(algorithm: Algorithm, input: Input, length: usize) -> Result<u64> {
    let maximum = if matches!(input, Input::Text) {
        TEXT_LIMIT
    } else {
        HEX_LIMIT
    };
    limit(length, maximum, "hash input")?;
    let rate = match algorithm {
        Algorithm::Sha256 => 2,
        Algorithm::Sha3 => 4,
    } + if matches!(input, Input::Text) { 0 } else { 2 };
    Ok(length as u64 * rate)
}

fn hash_bytes(value: &str, input: Input) -> Result<std::borrow::Cow<'_, [u8]>> {
    use std::borrow::Cow;
    match input {
        Input::Text => Ok(Cow::Borrowed(value.as_bytes())),
        Input::Hex => strict_hex(value).map(Cow::Owned),
        Input::Legacy => {
            if let Some(length) = visit_legacy_hex(value, |_| {}) {
                limit(length, TEXT_LIMIT, "decoded hash input")?;
                let mut bytes = Vec::with_capacity(length);
                visit_legacy_hex(value, |byte| bytes.push(byte));
                Ok(Cow::Owned(bytes))
            } else {
                limit(value.len(), TEXT_LIMIT, "hash text input")?;
                Ok(Cow::Borrowed(value.as_bytes()))
            }
        }
    }
}

fn strict_hex(value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(VmExecutionError::new(
            "hash hex input must contain whole bytes",
        ));
    }
    hex::decode(value)
        .map_err(|_| VmExecutionError::new("hash hex input must be unprefixed hexadecimal"))
}

// One scanner owns both classification and decoding. Whitespace is accepted
// only between complete byte pairs, matching historical bytes.fromhex.
fn visit_legacy_hex(value: &str, mut emit: impl FnMut(u8)) -> Option<usize> {
    let mut bytes = value.bytes().peekable();
    let mut count = 0;
    loop {
        while bytes
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | 11 | 12))
        {
            bytes.next();
        }
        let Some(high) = bytes.next() else {
            return Some(count);
        };
        let low = bytes.next()?;
        emit((high as char).to_digit(16)? as u8 * 16 + (low as char).to_digit(16)? as u8);
        count += 1;
    }
}

fn verify_call(
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
    host: &mut dyn VmHost,
) -> Result<VmValue> {
    let [key, message, signature] = args else {
        return Err(VmExecutionError::new(
            "crypto.verify() expects three positional arguments",
        ));
    };
    if !kwargs.is_empty() {
        return Err(VmExecutionError::new(
            "crypto.verify() expects three positional arguments",
        ));
    }
    with_string(key, |key| {
        with_string(message, |message| {
            with_string(signature, |signature| {
                limit(key.len(), 64, "verify key")?;
                limit(message.len(), TEXT_LIMIT, "verify message")?;
                limit(signature.len(), 128, "verify signature")?;
                let cost = VERIFY_FIXED_WORK
                    + 4 * message.len() as u64
                    + 2 * (key.len() + signature.len()) as u64;
                host.charge_execution_cost(cost)?;
                verify(key, message, signature).map(VmValue::Bool)
            })
        })
    })
}

fn verify(key: &str, message: &str, signature: &str) -> Result<bool> {
    let Ok(key) = hex::decode(key) else {
        return Ok(false);
    };
    let Ok(signature) = hex::decode(signature) else {
        return Ok(false);
    };
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| VmExecutionError::new("invalid verify key length"))?;
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return Ok(false);
    };
    let Ok(signature) = Signature::try_from(signature.as_slice()) else {
        return Ok(false);
    };
    Ok(key.verify_strict(message.as_bytes(), &signature).is_ok())
}

fn key_is_valid(args: &[VmValue], kwargs: &[(String, VmValue)]) -> Result<VmValue> {
    let [key] = args else {
        return Err(VmExecutionError::new(
            "crypto.key_is_valid() expects one argument",
        ));
    };
    if !kwargs.is_empty() {
        return Err(VmExecutionError::new(
            "crypto.key_is_valid() expects one argument",
        ));
    }
    // V2 accepts only the canonical spelling, so one key has one account name.
    // Archival V1 accepts either hex case.
    let canonical = crate::interpreter::numeric_v2::active();
    with_string(key, |key| {
        Ok(VmValue::Bool(
            key.len() == 64
                && key.bytes().all(|byte| {
                    byte.is_ascii_digit()
                        || (b'a'..=b'f').contains(&byte)
                        || (!canonical && (b'A'..=b'F').contains(&byte))
                }),
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_module_ir, VmExecutionContext, VmInstance};
    use serde_json::{Map, Value};
    use std::collections::HashMap;

    #[derive(Default)]
    struct Meter {
        charges: Vec<u64>,
        refuse: bool,
    }
    impl VmHost for Meter {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<()> {
            self.charges.push(cost);
            if self.refuse {
                Err(VmExecutionError::new("Out of chi."))
            } else {
                Ok(())
            }
        }
    }
    fn run(id: &str, text: &str, meter: &mut Meter) -> Result<VmValue> {
        dispatch(id, &[VmValue::String(text.into())], &[], meter).unwrap()
    }
    fn instance() -> VmInstance {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/time_hash_crypto.json")).unwrap();
        let module = parse_module_ir(&fixture["modules"][0]["ir"].to_string()).unwrap();
        VmInstance::new(module, VmExecutionContext::default()).unwrap()
    }

    #[test]
    fn byte_prices_and_heap_references_are_exact() {
        for (id, rate) in [
            ("hash.sha256_text", 2),
            ("hash.sha3_256_text", 4),
            ("hash.sha256_hex", 4),
            ("hash.sha3_256_hex", 6),
            ("hash.sha256_legacy", 4),
            ("hash.sha3_256_legacy", 6),
        ] {
            let heap = crate::heap::VmHeap::default();
            let value = heap.capture(VmValue::String("ab".repeat(5))).unwrap();
            let mut meter = Meter::default();
            dispatch(id, &[value], &[], &mut meter).unwrap().unwrap();
            assert_eq!(meter.charges, [10 * rate], "{id}");
        }
        let mut meter = Meter::default();
        run("hash.sha256_text", "é猫", &mut meter).unwrap();
        assert_eq!(meter.charges, [10]);
    }

    #[test]
    fn every_route_charges_once_including_raw_ir_and_callbacks() {
        for route in 0..4 {
            let mut instance = instance();
            let mut meter = Meter::default();
            let args = vec![VmValue::String("abc".into())];
            let callable = super::super::VmHostCallable::named("hashlib.sha256_text").unwrap();
            let result = match route {
                0 => instance.dispatch_host_syscall("hash.sha256_text", args, vec![], &mut meter),
                1 => instance.eval_syscall(
                    &Map::new(),
                    "hash.sha256_text",
                    args,
                    vec![],
                    &mut HashMap::new(),
                    &mut meter,
                    None,
                ),
                2 => instance.call_expression_callable_value(
                    &mut meter,
                    VmValue::HostCallable(callable),
                    args,
                    vec![],
                ),
                _ => instance.call_callable_value(
                    &mut meter,
                    VmValue::HostCallable(callable),
                    args,
                    vec![],
                ),
            };
            assert!(result.is_ok(), "{result:?}");
            let expected = if route == 3 { vec![5000, 6] } else { vec![6] };
            assert_eq!(meter.charges, expected, "route {route}");
        }
    }

    #[test]
    fn refusal_precedes_hex_validation_and_legacy_classification() {
        for (id, text, expected) in [
            ("hash.sha256_hex", "z".repeat(10), 40),
            (
                "hash.sha3_256_legacy",
                "a".repeat(TEXT_LIMIT) + "z",
                (TEXT_LIMIT as u64 + 1) * 6,
            ),
        ] {
            let mut meter = Meter {
                refuse: true,
                ..Meter::default()
            };
            assert!(run(id, &text, &mut meter)
                .unwrap_err()
                .to_string()
                .contains("Out of chi"));
            assert_eq!(meter.charges, [expected]);
        }
    }

    #[test]
    fn selected_path_caps_hold_without_a_meter() {
        let mut host = super::super::NoopHost;
        for id in ["hash.sha256_text", "hash.sha3_256_text"] {
            for (value, allowed) in [
                ("é".repeat(TEXT_LIMIT / 2), true),
                ("é".repeat(TEXT_LIMIT / 2) + "a", false),
            ] {
                let result = dispatch(id, &[VmValue::String(value)], &[], &mut host).unwrap();
                assert_eq!(result.is_ok(), allowed, "{id}: {result:?}");
            }
        }
        for id in [
            "hash.sha256_hex",
            "hash.sha3_256_hex",
            "hash.sha256_legacy",
            "hash.sha3_256_legacy",
        ] {
            for (value, allowed) in [
                ("ab".repeat(TEXT_LIMIT), true),
                ("ab".repeat(TEXT_LIMIT) + "00", false),
            ] {
                assert_eq!(
                    dispatch(id, &[VmValue::String(value)], &[], &mut host)
                        .unwrap()
                        .is_ok(),
                    allowed,
                    "{id}"
                );
            }
        }
        assert!(dispatch(
            "hash.sha256_legacy",
            &[VmValue::String(" ".repeat(HEX_LIMIT))],
            &[],
            &mut host
        )
        .unwrap()
        .is_ok());
        let error = dispatch(
            "hash.sha256_legacy",
            &[VmValue::String("a".repeat(TEXT_LIMIT) + "z")],
            &[],
            &mut host,
        )
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("hash text input resource limit"));
    }

    #[test]
    fn legacy_whitespace_and_fallback_are_unchanged() {
        for (input, expected) in [
            ("ab cd", Some(vec![171, 205])),
            ("ab\x0bcd", Some(vec![171, 205])),
            ("ab\x0ccd", Some(vec![171, 205])),
            ("a b", None),
            ("ab z", None),
            ("é", None),
            ("", Some(vec![])),
        ] {
            let mut decoded = vec![];
            let count = visit_legacy_hex(input, |byte| decoded.push(byte));
            assert_eq!(count.map(|_| decoded), expected, "{input:?}");
        }
    }

    #[test]
    fn verify_charges_before_invalid_key_and_preserves_small_input_errors() {
        let args = vec![
            VmValue::String("zz".into()),
            VmValue::String("é".into()),
            VmValue::String("00".into()),
        ];
        let mut meter = Meter {
            refuse: true,
            ..Meter::default()
        };
        assert!(dispatch("crypto.ed25519_verify", &args, &[], &mut meter)
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("Out of chi"));
        assert_eq!(meter.charges, [95_000 + 8 + 8]);
        meter.refuse = false;
        assert_eq!(
            dispatch("crypto.ed25519_verify", &args, &[], &mut meter)
                .unwrap()
                .unwrap(),
            VmValue::Bool(false)
        );
        let args = vec![
            VmValue::String("00".into()),
            VmValue::String("".into()),
            VmValue::String("00".into()),
        ];
        assert!(dispatch("crypto.ed25519_verify", &args, &[], &mut meter)
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("invalid verify key length"));
    }

    #[test]
    fn verify_caps_each_operand_and_key_predicate_has_bounded_work() {
        for (key, message, signature) in [
            ("a".repeat(65), String::new(), String::new()),
            ("a".repeat(64), "x".repeat(TEXT_LIMIT + 1), "a".repeat(128)),
            ("a".repeat(64), String::new(), "a".repeat(129)),
        ] {
            let args = vec![
                VmValue::String(key),
                VmValue::String(message),
                VmValue::String(signature),
            ];
            let mut meter = Meter::default();
            assert!(dispatch("crypto.ed25519_verify", &args, &[], &mut meter)
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("resource limit"));
            assert!(meter.charges.is_empty());
        }
        let mut meter = Meter {
            refuse: true,
            ..Meter::default()
        };
        assert_eq!(
            run(
                "crypto.key_is_valid",
                &"a".repeat(TEXT_LIMIT + 1),
                &mut meter
            )
            .unwrap(),
            VmValue::Bool(false)
        );
        assert!(meter.charges.is_empty());
        assert_eq!(
            run("crypto.key_is_valid", &"a".repeat(64), &mut meter).unwrap(),
            VmValue::Bool(true)
        );
    }

    #[test]
    fn v2_keys_are_canonical_lowercase_hex_and_v1_keeps_any_case() {
        let mut meter = Meter::default();
        let upper = "A".repeat(64);
        let mixed = format!("{}F", "a".repeat(63));
        {
            let _scope = crate::interpreter::numeric_v2::Scope::enter(crate::XIAN_VM_V2_PROFILE);
            for key in [&upper, &mixed] {
                assert_eq!(
                    run("crypto.key_is_valid", key, &mut meter).unwrap(),
                    VmValue::Bool(false)
                );
            }
            assert_eq!(
                run("crypto.key_is_valid", &"0f".repeat(32), &mut meter).unwrap(),
                VmValue::Bool(true)
            );
        }
        let _scope = crate::interpreter::numeric_v2::Scope::enter(crate::XIAN_VM_V1_PROFILE);
        assert_eq!(
            run("crypto.key_is_valid", &upper, &mut meter).unwrap(),
            VmValue::Bool(true)
        );
    }
}
