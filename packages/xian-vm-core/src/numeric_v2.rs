//! Arithmetic for the fresh-genesis profile. Fixed values use integer multiples of 10^-30.
use super::*;
use std::cell::Cell;
use std::cmp::Ordering;

use xian_numeric::INTEGER_BITS;
pub(super) const OP_GAS: u64 = 96;

// Collections, callbacks and comparison helpers share an interpreter invocation. Scope
// their semantics to this synchronous call and restore the caller on every exit.
thread_local! { static ACTIVE: Cell<bool> = const { Cell::new(false) }; }

pub(crate) struct Scope(bool);
impl Scope {
    pub(crate) fn enter(profile: &str) -> Self {
        Self(ACTIVE.replace(profile == crate::XIAN_VM_V2_PROFILE))
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.set(self.0);
    }
}
pub(crate) fn active() -> bool {
    ACTIVE.get()
}

pub(crate) fn validate_leaf(value: &VmValue) -> Result<(), VmExecutionError> {
    match value {
        VmValue::Int(value) if value.bits() > INTEGER_BITS => Err(limit()),
        VmValue::Float(_) | VmValue::RawDecimal(_) | VmValue::DecimalTuple(_) => Err(
            VmExecutionError::new("binary float and raw Decimal are unavailable in xian_vm_v2"),
        ),
        _ => Ok(()),
    }
}

pub(crate) fn wire_dict_key(key: &VmValue) -> Result<(), VmExecutionError> {
    if let VmValue::Reference(reference) = key {
        return reference.with_value(wire_dict_key);
    }
    if matches!(key, VmValue::String(name) if !crate::set_member_codec::is_reserved_tag(name)) {
        return Ok(());
    }
    Err(VmExecutionError::new(
        "V2 wire dictionaries require string keys and cannot use reserved codec tags",
    ))
}

fn limit() -> VmExecutionError {
    VmExecutionError::new("integer exceeds the 512-bit magnitude limit")
}

fn checked(value: BigInt) -> Result<VmValue, VmExecutionError> {
    if value.bits() > INTEGER_BITS {
        return Err(limit());
    }
    Ok(VmValue::Int(value))
}

fn integer(v: &VmValue) -> Result<&BigInt, VmExecutionError> {
    match v {
        VmValue::Int(x) => Ok(x),
        _ => Err(VmExecutionError::new("expected an integer")),
    }
}

fn scaled(v: &VmValue) -> Result<BigInt, VmExecutionError> {
    match v {
        VmValue::Int(v) => Ok(v * crate::values::decimal_scale_factor()),
        VmValue::Decimal(v) => Ok(v.scaled.clone()),
        _ => Err(VmExecutionError::new("expected an int or decimal")),
    }
}

pub(crate) fn exact_decimal(text: &str) -> Result<VmDecimal, VmExecutionError> {
    let canonical = xian_numeric::canonical_decimal(text).map_err(VmExecutionError::new)?;
    VmDecimal::from_str_literal(&canonical)
}

pub(super) fn new_decimal(v: &VmValue) -> Result<VmValue, VmExecutionError> {
    let value = match v {
        VmValue::String(s) => {
            crate::work_meter::count(crate::work_meter::searched(s.len()))?;
            exact_decimal(s)?
        }
        VmValue::Decimal(d) => d.clone(),
        VmValue::Int(_) => VmDecimal::from_scaled(scaled(v)?)?,
        _ => {
            return Err(VmExecutionError::new(
                "decimal() requires int, decimal or exact numeric text",
            ))
        }
    };
    Ok(VmValue::Decimal(value))
}

fn is_number(v: &VmValue) -> bool {
    matches!(v, VmValue::Int(_) | VmValue::Decimal(_))
}

pub(super) fn bool_number_pair(a: &VmValue, b: &VmValue) -> bool {
    (matches!(a, VmValue::Bool(_)) && is_number(b))
        || (is_number(a) && matches!(b, VmValue::Bool(_)))
}

pub(super) fn ordering(a: &VmValue, b: &VmValue) -> Option<Result<Ordering, VmExecutionError>> {
    if bool_number_pair(a, b)
        || (matches!(a, VmValue::Decimal(_)) && !is_number(b))
        || (matches!(b, VmValue::Decimal(_)) && !is_number(a))
    {
        return Some(Err(VmExecutionError::new(
            "ordering requires two numbers of compatible types",
        )));
    }
    if (matches!(a, VmValue::Decimal(_)) || matches!(b, VmValue::Decimal(_)))
        && is_number(a)
        && is_number(b)
    {
        return Some(scaled(a).and_then(|x| Ok(x.cmp(&scaled(b)?))));
    }
    None
}

pub(super) fn handles_binary(a: &VmValue, b: &VmValue) -> bool {
    matches!(a, VmValue::Bool(_) | VmValue::Decimal(_))
        || matches!(b, VmValue::Bool(_) | VmValue::Decimal(_))
        || (is_number(a) && is_number(b))
}

pub(super) fn op_cost(op: &str, a: &VmValue, b: &VmValue) -> u64 {
    let a = a.snapshot();
    let b = b.snapshot();
    if !handles_binary(&a, &b) {
        return 0;
    }
    if op == "pow" {
        if let VmValue::Int(exp) = b {
            return OP_GAS * (1 + exp.bits().min(INTEGER_BITS));
        }
    }
    OP_GAS
}

pub(super) fn binary(op: &str, a: &VmValue, b: &VmValue) -> Result<VmValue, VmExecutionError> {
    validate_leaf(a)?;
    validate_leaf(b)?;
    if matches!(a, VmValue::Bool(_)) || matches!(b, VmValue::Bool(_)) {
        return Err(VmExecutionError::new("bool is not an arithmetic operand"));
    }
    if op == "div" || matches!(a, VmValue::Decimal(_)) || matches!(b, VmValue::Decimal(_)) {
        return fixed_binary(op, scaled(a)?, scaled(b)?);
    }
    integer_binary(op, integer(a)?, integer(b)?)
}

fn fixed_binary(op: &str, x: BigInt, y: BigInt) -> Result<VmValue, VmExecutionError> {
    let scale = crate::values::decimal_scale_factor();
    let result = match op {
        "add" => x + y,
        "sub" => x - y,
        "mul" => x * y / scale,
        "div" if y.is_zero() => return Err(VmExecutionError::new("division by zero")),
        "div" => x * scale / y,
        _ => {
            return Err(VmExecutionError::new(format!(
                "operator '{op}' requires integers"
            )))
        }
    };
    VmDecimal::from_scaled(result).map(VmValue::Decimal)
}

fn integer_binary(op: &str, a: &BigInt, b: &BigInt) -> Result<VmValue, VmExecutionError> {
    let result = match op {
        "add" => a + b,
        "sub" => a - b,
        "mul" => a * b,
        "floordiv" => bigint_floor_div(a, b)?,
        "mod" => bigint_modulo(a, b)?,
        "bitand" => a & b,
        "bitor" => a | b,
        "bitxor" => a ^ b,
        "pow" => return power(a, b),
        "lshift" | "rshift" if b.sign() == Sign::Minus => {
            return Err(VmExecutionError::new("negative shift count"))
        }
        "lshift" if a.is_zero() => BigInt::zero(),
        "lshift" if b > &BigInt::from(INTEGER_BITS - a.bits()) => return Err(limit()),
        "lshift" => a << b.to_usize().expect("bounded shift"),
        "rshift" => {
            a >> b
                .to_usize()
                .unwrap_or(usize::MAX)
                .min(INTEGER_BITS as usize)
        }
        _ => {
            return Err(VmExecutionError::new(format!(
                "unsupported integer operator '{op}'"
            )))
        }
    };
    checked(result)
}

fn power(base: &BigInt, exp: &BigInt) -> Result<VmValue, VmExecutionError> {
    if exp.sign() == Sign::Minus {
        return Err(VmExecutionError::new(
            "integer exponent must be nonnegative",
        ));
    }
    if exp.is_zero() {
        return Ok(vm_int(1));
    }
    if base.bits() <= 1 {
        return Ok(if base.sign() == Sign::Minus && !exp.bit(0) {
            vm_int(1)
        } else {
            VmValue::Int(base.clone())
        });
    }
    if exp >= &BigInt::from(INTEGER_BITS) {
        return Err(limit());
    }
    // The result is at least 2^((bits(base)-1)*exp). Bound work before computing.
    let exp = exp.to_u32().expect("bounded exponent");
    if (base.bits() - 1) * u64::from(exp) >= INTEGER_BITS {
        return Err(limit());
    }
    checked(base.pow(exp))
}

pub(super) fn helper(
    name: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    host: &mut dyn VmHost,
) -> Result<VmValue, VmExecutionError> {
    let names: &[&str] = match name {
        "mul_div_floor" | "mul_div_ceil" => &["a", "b", "d"],
        "sqrt" => &["value"],
        "quantize" => &["value", "places", "mode"],
        _ => return Err(VmExecutionError::new("unknown numeric helper")),
    };
    let args = method_signatures::bind_required(name, names, args, kwargs)?;
    match (name, args.as_slice()) {
        ("mul_div_floor" | "mul_div_ceil", [a, b, d]) => {
            host.charge_execution_cost(2 * OP_GAS)?;
            mul_div(name, integer(a)?, integer(b)?, integer(d)?)
        }
        ("quantize", [v, places, VmValue::String(mode)]) => {
            host.charge_execution_cost(OP_GAS)?;
            quantize(v, places, mode)
        }
        ("sqrt", [v]) => {
            host.charge_execution_cost(OP_GAS)?;
            square_root(v)
        }
        _ => Err(VmExecutionError::new(format!(
            "invalid arguments for {name}()"
        ))),
    }
}

fn mul_div(name: &str, a: &BigInt, b: &BigInt, d: &BigInt) -> Result<VmValue, VmExecutionError> {
    if d.sign() != Sign::Plus {
        return Err(VmExecutionError::new(
            "mul_div denominator must be positive",
        ));
    }
    let n = a * b;
    checked(if name == "mul_div_floor" {
        bigint_floor_div(&n, d)?
    } else {
        -bigint_floor_div(&-n, d)?
    })
}

fn quantize(v: &VmValue, places: &VmValue, mode: &str) -> Result<VmValue, VmExecutionError> {
    let places = integer(places)?
        .to_u32()
        .filter(|v| *v <= xian_numeric::DECIMAL_SCALE as u32)
        .ok_or_else(|| VmExecutionError::new("places must be an integer from 0 to 30"))?;
    let d = BigInt::from(10).pow(xian_numeric::DECIMAL_SCALE as u32 - places);
    let n = scaled(v)?;
    let q = match mode {
        "toward_zero" => &n / &d,
        "floor" => bigint_floor_div(&n, &d)?,
        "ceil" => -bigint_floor_div(&-&n, &d)?,
        "half_even" => rounding::round_ratio(&n, &d),
        _ => return Err(VmExecutionError::new("unknown decimal rounding mode")),
    };
    VmDecimal::from_scaled(q * d).map(VmValue::Decimal)
}

fn square_root(v: &VmValue) -> Result<VmValue, VmExecutionError> {
    let n = scaled(v)?;
    if n.sign() == Sign::Minus {
        return Err(VmExecutionError::new("sqrt requires a nonnegative number"));
    }
    VmDecimal::from_scaled((n * crate::values::decimal_scale_factor()).sqrt()).map(VmValue::Decimal)
}

/// Promote exact integer amounts at an ABI boundary. A container is rebuilt only
/// when one of its members changes type.
pub(super) fn bind_numeric_annotation(
    value: &mut VmValue,
    annotation: &str,
    heap: &crate::heap::VmHeap,
) -> Result<(), VmExecutionError> {
    let Some(annotation) = parse_type_annotation(annotation) else {
        return Err(VmExecutionError::new("invalid ABI annotation"));
    };
    if let Some(updated) = promote(value, &annotation)? {
        *value = heap.capture(updated)?;
    }
    Ok(())
}

fn numeric_annotation(t: &TypeAnnotation) -> bool {
    matches!(t.base.as_str(), "int" | "decimal") || t.args.iter().any(numeric_annotation)
}

fn promote(value: &VmValue, t: &TypeAnnotation) -> Result<Option<VmValue>, VmExecutionError> {
    if !numeric_annotation(t) {
        return Ok(None);
    }
    let v = value.snapshot();
    match (t.base.as_str(), &v) {
        ("int", VmValue::Int(_)) | ("decimal", VmValue::Decimal(_)) => Ok(None),
        ("decimal", VmValue::Int(_)) => new_decimal(&v).map(Some),
        ("list", VmValue::List(items))
        | ("set", VmValue::Set(items))
        | ("frozenset", VmValue::FrozenSet(items))
        | ("tuple", VmValue::Tuple(items))
            if t.args.len() == 1 =>
        {
            let mut changed = false;
            let items = items
                .iter()
                .map(|i| promoted_item(i, &t.args[0], &mut changed))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(changed.then(|| match t.base.as_str() {
                "list" => VmValue::List(items),
                "tuple" => VmValue::Tuple(items),
                "set" => VmValue::Set(items),
                _ => VmValue::FrozenSet(items),
            }))
        }
        ("dict", VmValue::Dict(entries)) if t.args.len() == 2 => {
            let mut changed = false;
            let entries = entries
                .iter()
                .map(|(key, item)| {
                    Ok((
                        promoted_item(key, &t.args[0], &mut changed)?,
                        promoted_item(item, &t.args[1], &mut changed)?,
                    ))
                })
                .collect::<Result<Vec<_>, VmExecutionError>>()?;
            Ok(changed.then_some(VmValue::Dict(entries)))
        }
        _ => Err(typecheck_error("ABI value", t, &v)),
    }
}
fn promoted_item(
    value: &VmValue,
    t: &TypeAnnotation,
    changed: &mut bool,
) -> Result<VmValue, VmExecutionError> {
    if let Some(promoted) = promote(value, t)? {
        *changed = true;
        Ok(promoted)
    } else {
        Ok(value.clone())
    }
}
