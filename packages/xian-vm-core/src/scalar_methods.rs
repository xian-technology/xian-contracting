//! Bounded Python 3.12 scalar attributes and methods; dispatch binds keywords.
use crate::interpreter::{MAX_BINARY_ALLOCATION_BYTES, MAX_INTEGER_BITS};
use crate::{VmDecimal, VmExecutionError, VmRange, VmValue};
use num_bigint::{BigInt, Sign};
use num_traits::{Signed, ToPrimitive, Zero};

type Result<T> = std::result::Result<T, VmExecutionError>;

pub(crate) fn supports(value: &VmValue, method: &str) -> bool {
    if is_bool_receiver(value) {
        return false;
    }
    if !is_scalar_receiver(value) {
        return false;
    }
    match value.snapshot() {
        VmValue::Range(_) => matches!(method, "count" | "index"),
        VmValue::Int(_) => matches!(
            method,
            "bit_count"
                | "bit_length"
                | "as_integer_ratio"
                | "conjugate"
                | "is_integer"
                | "to_bytes"
                | "from_bytes"
        ),
        VmValue::Builtin(name) | VmValue::TypeMarker(name) => {
            name == "int" && method == "from_bytes"
        }
        _ => false,
    }
}

/// Scalar methods and attributes apply only to these receivers. Checking
/// first avoids copying a referenced container that cannot match.
fn is_scalar_receiver(value: &VmValue) -> bool {
    resolves_to!(
        value,
        VmValue::Range(_)
            | VmValue::Int(_)
            | VmValue::Bool(_)
            | VmValue::Builtin(_)
            | VmValue::TypeMarker(_)
    )
}

pub(crate) fn attribute(value: &VmValue, name: &str) -> Option<Result<VmValue>> {
    if !is_scalar_receiver(value) {
        return None;
    }
    if matches!(
        (value.snapshot(), name),
        (VmValue::Int(_), "real" | "numerator")
    ) {
        return Some(Ok(value.clone()));
    }
    let attribute = match value.snapshot() {
        VmValue::Range(range) => match name {
            "start" => VmValue::Int(range.start),
            "stop" => VmValue::Int(range.stop),
            "step" => VmValue::Int(range.step),
            _ => return None,
        },
        VmValue::Int(number) => integer_attribute(number, name)?,
        _ => return None,
    };
    Some(Ok(attribute))
}

fn integer_attribute(number: BigInt, name: &str) -> Option<VmValue> {
    Some(VmValue::Int(match name {
        "real" | "numerator" => number,
        "imag" => BigInt::zero(),
        "denominator" => BigInt::from(1),
        _ => return None,
    }))
}

pub(crate) fn call(value: &VmValue, method: &str, args: Vec<VmValue>) -> Result<VmValue> {
    if args.is_empty() {
        match (value.snapshot(), method) {
            (VmValue::Int(_), "conjugate") => return Ok(value.clone()),
            (VmValue::Int(_), "as_integer_ratio") => {
                return Ok(VmValue::Tuple(vec![
                    value.clone(),
                    VmValue::Int(BigInt::from(1)),
                ]))
            }
            _ => {}
        }
    }
    if method == "from_bytes" && supports(value, method) {
        return from_bytes(&args).map(VmValue::Int);
    }
    match value.snapshot() {
        VmValue::Range(range) => range_method(&range, method, &args),
        VmValue::Int(number) => integer_method(number, method, &args),
        _ => Err(VmExecutionError::new("unsupported scalar method")),
    }
}

fn is_bool_receiver(value: &VmValue) -> bool {
    resolves_to!(value, VmValue::Bool(_))
        || resolves_to!(value, VmValue::Builtin(name) | VmValue::TypeMarker(name) if name == "bool")
}

fn integer_method(number: BigInt, method: &str, args: &[VmValue]) -> Result<VmValue> {
    if method == "to_bytes" {
        return to_bytes(&number, args);
    }
    if !args.is_empty() {
        return Err(VmExecutionError::new("numeric method expects no arguments"));
    }
    Ok(match method {
        "bit_length" => VmValue::Int(BigInt::from(number.bits())),
        "bit_count" => VmValue::Int(BigInt::from(
            number
                .iter_u64_digits()
                .map(|word| u64::from(word.count_ones()))
                .sum::<u64>(),
        )),
        "as_integer_ratio" => {
            VmValue::Tuple(vec![VmValue::Int(number), VmValue::Int(BigInt::from(1))])
        }
        "conjugate" => VmValue::Int(number),
        "is_integer" => VmValue::Bool(true),
        _ => return Err(VmExecutionError::new("unsupported integer method")),
    })
}

fn index_integer(value: &VmValue) -> Result<BigInt> {
    value.integer_or("an integer is required")
}

fn byte_order(args: &[VmValue], index: usize) -> Result<bool> {
    match args.get(index).map(VmValue::snapshot) {
        None => Ok(false),
        Some(VmValue::String(order)) if order == "big" => Ok(false),
        Some(VmValue::String(order)) if order == "little" => Ok(true),
        _ => Err(VmExecutionError::new(
            "byteorder must be either 'little' or 'big'",
        )),
    }
}

fn to_bytes(number: &BigInt, args: &[VmValue]) -> Result<VmValue> {
    if args.len() > 3 {
        return Err(VmExecutionError::new("invalid to_bytes arguments"));
    }
    let length = args
        .first()
        .map(index_integer)
        .transpose()?
        .unwrap_or_else(|| BigInt::from(1));
    let length = length
        .to_usize()
        .filter(|n| *n <= MAX_BINARY_ALLOCATION_BYTES)
        .ok_or_else(|| {
            VmExecutionError::new("byte length exceeds allocation limit or is negative")
        })?;
    let little = byte_order(args, 1)?;
    let signed = args.get(2).is_some_and(VmValue::truthy);
    let mut bytes = encoded_integer(number, length, signed)?;
    if !little {
        bytes.reverse();
    }
    Ok(VmValue::Bytes(bytes))
}

fn encoded_integer(number: &BigInt, length: usize, signed: bool) -> Result<Vec<u8>> {
    if number.is_negative() && !signed {
        return Err(VmExecutionError::new(
            "cannot convert negative int to unsigned",
        ));
    }
    if length == 0 {
        if number.is_zero() || (signed && *number == BigInt::from(-1)) {
            return Ok(vec![]);
        }
        return Err(VmExecutionError::new("int too big to convert"));
    }
    let bytes = if signed {
        number.to_signed_bytes_le()
    } else {
        number.to_bytes_le().1
    };
    if bytes.len() > length {
        return Err(VmExecutionError::new("int too big to convert"));
    }
    let mut output = vec![if number.is_negative() { 255 } else { 0 }; length];
    output[..bytes.len()].copy_from_slice(&bytes);
    Ok(output)
}

fn from_bytes(args: &[VmValue]) -> Result<BigInt> {
    if args.is_empty() || args.len() > 3 {
        return Err(VmExecutionError::new("invalid from_bytes arguments"));
    }
    let little = byte_order(args, 1)?;
    let bytes = byte_input(&args[0])?;
    let signed = args.get(2).is_some_and(VmValue::truthy);
    let number = match (signed, little) {
        (true, true) => BigInt::from_signed_bytes_le(&bytes),
        (true, false) => BigInt::from_signed_bytes_be(&bytes),
        (false, true) => BigInt::from_bytes_le(Sign::Plus, &bytes),
        (false, false) => BigInt::from_bytes_be(Sign::Plus, &bytes),
    };
    if number.bits() > MAX_INTEGER_BITS {
        return Err(VmExecutionError::new("integer size limit exceeded"));
    }
    Ok(number)
}

fn byte_input(value: &VmValue) -> Result<Vec<u8>> {
    let bytes = match value.snapshot() {
        VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => bytes,
        VmValue::List(values) | VmValue::Tuple(values) => {
            if values.len() > MAX_BINARY_ALLOCATION_BYTES {
                return Err(VmExecutionError::new("byte input exceeds allocation limit"));
            }
            values
                .iter()
                .map(|value| {
                    index_integer(value)?
                        .to_u8()
                        .ok_or_else(|| VmExecutionError::new("bytes must be in range(0, 256)"))
                })
                .collect::<Result<Vec<_>>>()?
        }
        _ => {
            return Err(VmExecutionError::new(
                "from_bytes requires bytes or an integer iterable",
            ))
        }
    };
    if bytes.len() > MAX_BINARY_ALLOCATION_BYTES {
        return Err(VmExecutionError::new("byte input exceeds allocation limit"));
    }
    Ok(bytes)
}

fn exact_integer(value: &VmValue) -> Result<Option<BigInt>> {
    Ok(match value.snapshot() {
        VmValue::Int(number) => Some(number),
        VmValue::Decimal(number) => {
            let integer = number.to_bigint();
            (VmDecimal::from_vm_value(&VmValue::Int(integer.clone()))? == number).then_some(integer)
        }
        _ => None,
    })
}

fn range_method(range: &VmRange, method: &str, args: &[VmValue]) -> Result<VmValue> {
    if args.len() != 1 {
        return Err(VmExecutionError::new("range method expects one argument"));
    }
    let index = range_index(range, &args[0])?;
    match method {
        "count" => Ok(VmValue::Int(BigInt::from(index.is_some() as u8))),
        "index" => index
            .map(VmValue::Int)
            .ok_or_else(|| VmExecutionError::new("value is not in range")),
        _ => Err(VmExecutionError::new("unsupported range method")),
    }
}

pub(crate) fn range_index(range: &VmRange, needle: &VmValue) -> Result<Option<BigInt>> {
    if range.len().is_zero() {
        return Ok(None);
    }
    Ok(exact_integer(needle)?.and_then(|number| {
        let offset = number - &range.start;
        let index = &offset / &range.step;
        ((&offset % &range.step).is_zero() && !index.is_negative() && index < range.len())
            .then_some(index)
    }))
}

/// Precharge scans and requested output allocation before constructing results.
pub(crate) fn work_cost(value: &VmValue, method: &str, args: &[VmValue]) -> u64 {
    let input = args
        .iter()
        .fold(size(value), |total, item| total.saturating_add(size(item)));
    let output = if method == "to_bytes" {
        args.first()
            .and_then(|v| index_integer(v).ok())
            .and_then(|n| n.to_u64())
            .unwrap_or(1)
            .min(MAX_BINARY_ALLOCATION_BYTES as u64)
    } else {
        0
    };
    let work = input.saturating_add(output);
    if resolves_to!(value, VmValue::Range(_)) {
        work.saturating_mul(work).saturating_mul(32)
    } else {
        work.saturating_mul(32)
    }
}

fn size(value: &VmValue) -> u64 {
    match value {
        VmValue::Reference(reference) => reference.with_value(size),
        VmValue::Int(number) => number.bits().div_ceil(8),
        VmValue::Decimal(number) => number.scaled.bits().div_ceil(8),
        VmValue::Range(range) => range.allocation_bytes() as u64,
        VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => bytes.len() as u64,
        VmValue::String(text) => text.len() as u64,
        VmValue::Tuple(values) | VmValue::List(values) => values.len() as u64,
        _ => 16,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn integer(number: i64) -> VmValue {
        VmValue::Int(number.into())
    }

    #[test]
    fn signed_integer_bytes_round_trip_and_bounds() {
        let bytes = call(
            &integer(-129),
            "to_bytes",
            vec![
                integer(2),
                VmValue::String("little".into()),
                VmValue::Bool(true),
            ],
        )
        .unwrap();
        assert_eq!(bytes, VmValue::Bytes(vec![127, 255]));
        assert_eq!(
            call(
                &integer(0),
                "from_bytes",
                vec![bytes, VmValue::String("little".into()), VmValue::Bool(true)]
            )
            .unwrap(),
            integer(-129)
        );
        assert!(call(
            &integer(128),
            "to_bytes",
            vec![
                integer(1),
                VmValue::String("big".into()),
                VmValue::Bool(true)
            ]
        )
        .is_err());
        assert!(call(
            &integer(1),
            "to_bytes",
            vec![integer(MAX_BINARY_ALLOCATION_BYTES as i64 + 1)]
        )
        .is_err());
        assert_eq!(
            call(
                &integer(-1),
                "to_bytes",
                vec![
                    integer(0),
                    VmValue::String("big".into()),
                    VmValue::Bool(true)
                ]
            )
            .unwrap(),
            VmValue::Bytes(vec![])
        );
    }

    #[test]
    fn booleans_have_no_integer_methods_and_integers_do() {
        let bool_class = VmValue::Builtin("bool".into());
        assert!(!supports(&bool_class, "from_bytes"));
        assert!(!supports(&VmValue::Bool(true), "conjugate"));
        assert!(call(&VmValue::Bool(true), "conjugate", vec![]).is_err());
        assert!(attribute(&VmValue::Bool(true), "numerator").is_none());
        assert_eq!(
            call(
                &VmValue::Builtin("int".into()),
                "from_bytes",
                vec![VmValue::Bytes(vec![2])]
            )
            .unwrap(),
            integer(2)
        );
        assert_eq!(
            call(&integer(-257), "bit_count", vec![]).unwrap(),
            integer(2)
        );
        assert_eq!(
            call(&integer(-257), "bit_length", vec![]).unwrap(),
            integer(9)
        );
        assert_eq!(
            call(&integer(1), "is_integer", vec![]).unwrap(),
            VmValue::Bool(true)
        );
    }

    #[test]
    fn range_search_handles_huge_endpoints_without_iteration() {
        let start = BigInt::from(10).pow(100);
        let range = VmValue::Range(VmRange {
            start: start.clone(),
            stop: &start + 10,
            step: 3.into(),
        });
        assert_eq!(
            call(&range, "index", vec![VmValue::Int(&start + 6)]).unwrap(),
            integer(2)
        );
        assert_eq!(
            call(&range, "count", vec![VmValue::Int(&start + 7)]).unwrap(),
            integer(0)
        );
        assert!(call(&range, "index", vec![integer(1)]).is_err());
    }
}
