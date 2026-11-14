//! Bounded, deterministic access to the pinned libmpdec in CPython's default
//! context, for the fee and reward arithmetic (`python_decimal`).
use std::ffi::{c_char, c_int, CStr, CString};

use crate::VmExecutionError;

const MAX_INPUT_BYTES: usize = 128 * 1024;
const MAX_OUTPUT_BYTES: usize = MAX_INPUT_BYTES + 64;

extern "C" {
    fn xian_python_decimal_calculate(
        operation: *const c_char,
        arguments: *const *const c_char,
        count: usize,
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

/// `operation` in CPython's default `decimal` context (28 digits, half-even;
/// a trapped signal is an error), the arithmetic node code does with
/// `decimal.Decimal` values.
pub(crate) fn python_calculate(operation: &str, args: &[&str]) -> Result<String, VmExecutionError> {
    run(operation, args, |operation, pointers, count, output| {
        // SAFETY: as `run` documents for its callback.
        unsafe { xian_python_decimal_calculate(operation, pointers, count, output) }
    })
}

/// Validate the operands and call one shim entry point. The callback gets a
/// NUL-terminated operation name and `count` NUL-terminated operand pointers
/// that live across the call; the shim validates arity and owns all C
/// allocations, the output included.
fn run(
    operation: &str,
    args: &[&str],
    call: impl FnOnce(*const c_char, *const *const c_char, usize, *mut *mut c_char) -> c_int,
) -> Result<String, VmExecutionError> {
    if args.is_empty() || args.len() > 3 || operation.len() > 64 {
        return Err(VmExecutionError::new(
            "decimal operand count or operation name exceeds limit",
        ));
    }
    let operation = CString::new(operation)
        .map_err(|_| VmExecutionError::new("invalid decimal operation name"))?;
    let args: Vec<CString> = args
        .iter()
        .map(|value| validated_input(value))
        .collect::<Result<_, _>>()?;
    let pointers: Vec<_> = args.iter().map(|value| value.as_ptr()).collect();
    let mut output = BackendOutput(std::ptr::null_mut());
    let status = call(
        operation.as_ptr(),
        pointers.as_ptr(),
        pointers.len(),
        &mut output.0,
    );
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
