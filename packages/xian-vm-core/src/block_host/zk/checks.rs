//! The zk bridge's argument checks (`contracting.stdlib.bridge.zk`), with
//! their exact texts, on the arguments as the Python functions receive them
//! (`vm_to_py`), and the failures the Python host converts for the VM
//! (`host_error`).
use crate::{VmExecutionError, VmValue};
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};

/// `contracting.constants`' zk payload limits.
pub(super) const MAX_PUBLIC_INPUTS: usize = 32;
pub(super) const MAX_VK_HEX_CHARS: usize = 8_192;
pub(super) const MAX_PROOF_HEX_CHARS: usize = 4_096;
/// A payload's limit: four proofs' worth of hex.
pub(super) const MAX_PAYLOAD_HEX_CHARS: usize = MAX_PROOF_HEX_CHARS * 4;
const MAX_VK_ID_CHARS: usize = 128;
/// A 32-byte field element as 0x-prefixed hex.
const FIELD_HEX_CHARS: usize = 66;

/// An argument as the Python checks see it: the Python type `vm_to_py`
/// gives it (a contract handle or type marker becomes its name).
pub(super) enum Py<'a> {
    None,
    Str(&'a str),
    /// An int or a bool (a bool is an int in Python).
    Int(BigInt),
    List(&'a [VmValue]),
    Dict(&'a [(VmValue, VmValue)]),
    Other,
}

pub(super) fn py(value: &VmValue) -> Py<'_> {
    match value {
        VmValue::None => Py::None,
        VmValue::String(text) | VmValue::TypeMarker(text) => Py::Str(text),
        VmValue::ContractHandle(handle) => Py::Str(&handle.module),
        VmValue::Int(number) => Py::Int(number.clone()),
        VmValue::Bool(flag) => Py::Int(BigInt::from(u8::from(*flag))),
        VmValue::List(items) => Py::List(items),
        VmValue::Dict(entries) => Py::Dict(entries),
        _ => Py::Other,
    }
}

/// Whether `vm_to_py` converts `value` (else the Python host fails before
/// the zk function runs, which this port leaves to the Python path).
pub(super) fn convertible(value: &VmValue) -> bool {
    match value {
        VmValue::None
        | VmValue::Bool(_)
        | VmValue::Int(_)
        | VmValue::Float(_)
        | VmValue::Decimal(_)
        | VmValue::RawDecimal(_)
        | VmValue::DateTime(_)
        | VmValue::TimeDelta(_)
        | VmValue::String(_)
        | VmValue::Bytes(_)
        | VmValue::ByteArray(_)
        | VmValue::ContractHandle(_)
        | VmValue::TypeMarker(_) => true,
        VmValue::List(items)
        | VmValue::Tuple(items)
        | VmValue::Set(items)
        | VmValue::FrozenSet(items) => items.iter().all(convertible),
        VmValue::Dict(entries) => entries
            .iter()
            .all(|(key, item)| matches!(key, VmValue::String(_)) && convertible(item)),
        _ => false,
    }
}

/// An `AssertionError` with `message`, as the VM receives it.
pub(super) fn assertion(message: impl Into<String>) -> VmExecutionError {
    raised("AssertionError", message.into())
}

/// A `ValueError` (the native shielded helpers' failure).
pub(super) fn value_error(message: impl Into<String>) -> VmExecutionError {
    raised("ValueError", message.into())
}

fn raised(name: &str, message: String) -> VmExecutionError {
    VmExecutionError::described(name, format!("{name}: {message}"), message)
}

/// Whether the Python function raised an `AssertionError`.
pub(super) fn is_assertion(error: &VmExecutionError) -> bool {
    error
        .exception()
        .is_some_and(|exception| exception.name == "AssertionError")
}

/// `_validate_hex_payload`: 0x-prefixed, non-empty, at most `max_chars`
/// characters, whole bytes of hex.
pub(super) fn hex<'a>(
    name: &str,
    value: &'a VmValue,
    max_chars: usize,
) -> Result<&'a str, VmExecutionError> {
    let Py::Str(text) = py(value) else {
        return Err(assertion(format!("{name} must be a string!")));
    };
    let chars = text.chars().count();
    let refusal = if !text.starts_with("0x") {
        "must be 0x-prefixed hex!"
    } else if chars <= 2 {
        "must not be empty!"
    } else if chars > max_chars {
        "exceeds the maximum size!"
    } else if chars % 2 != 0 {
        "must contain whole bytes of hex!"
    } else if !text[2..].chars().all(|char| char.is_ascii_hexdigit()) {
        "must be valid hex!"
    } else {
        return Ok(text);
    };
    Err(assertion(format!("{name} {refusal}")))
}

/// A 32-byte field element: `hex` with exactly 66 characters.
fn field(name: &str, value: &VmValue) -> Result<String, VmExecutionError> {
    let text = hex(name, value, FIELD_HEX_CHARS)?;
    if text.len() != FIELD_HEX_CHARS {
        return Err(assertion(format!("{name} must be exactly 32 bytes!")));
    }
    Ok(text.to_owned())
}

/// `_validate_public_inputs`.
pub(super) fn public_inputs(value: &VmValue) -> Result<Vec<String>, VmExecutionError> {
    let Py::List(items) = py(value) else {
        return Err(assertion("public_inputs must be a list!"));
    };
    if items.len() > MAX_PUBLIC_INPUTS {
        return Err(assertion("Too many public inputs for zk verification!"));
    }
    items
        .iter()
        .enumerate()
        .map(|(index, item)| field(&format!("public_inputs[{index}]"), item))
        .collect()
}

/// `_validate_field_values` of a list argument.
pub(super) fn field_values(
    label: &str,
    value: &VmValue,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<String>, VmExecutionError> {
    let Py::List(items) = py(value) else {
        return Err(assertion(format!("{label} must be a list!")));
    };
    field_list(label, items, minimum, maximum)
}

/// `_validate_field_values` of `items`.
pub(super) fn field_list(
    label: &str,
    items: &[VmValue],
    minimum: usize,
    maximum: usize,
) -> Result<Vec<String>, VmExecutionError> {
    if !(minimum..=maximum).contains(&items.len()) {
        return Err(assertion(format!("{label} has invalid length!")));
    }
    items
        .iter()
        .enumerate()
        .map(|(index, item)| field(&format!("{label}[{index}]"), item))
        .collect()
}

/// `_validate_vk_id`.
pub(super) fn vk_id(value: &VmValue) -> Result<&str, VmExecutionError> {
    let Py::Str(vk_id) = py(value) else {
        return Err(assertion("vk_id must be a string!"));
    };
    if vk_id.is_empty() {
        return Err(assertion("vk_id must not be empty!"));
    }
    if vk_id.chars().count() > MAX_VK_ID_CHARS {
        return Err(assertion("vk_id exceeds the maximum size!"));
    }
    Ok(vk_id)
}

/// `isinstance(value, str) and value != ""`.
pub(super) fn non_empty_text<'a>(
    value: &'a VmValue,
    refusal: &str,
) -> Result<&'a str, VmExecutionError> {
    match py(value) {
        Py::Str(text) if !text.is_empty() => Ok(text),
        _ => Err(assertion(refusal)),
    }
}

/// `isinstance(value, int) and value >= 0`.
pub(super) fn non_negative(value: &VmValue, refusal: &str) -> Result<BigInt, VmExecutionError> {
    match py(value) {
        Py::Int(number) if !number.is_negative() => Ok(number),
        _ => Err(assertion(refusal)),
    }
}

/// A non-negative int as the native helpers take it (`u64`, or `usize`
/// on a 64-bit node): pyo3 refuses a larger one, and the Python host passes
/// that `OverflowError` on as an opaque failure.
pub(super) fn native_u64(number: &BigInt) -> Result<u64, VmExecutionError> {
    number
        .to_u64()
        .ok_or_else(|| VmExecutionError::new("OverflowError: int too big to convert"))
}

/// `payload_hex is None or payload_hex == ""`.
pub(super) fn absent_payload(value: &VmValue) -> bool {
    matches!(py(value), Py::None | Py::Str(""))
}
