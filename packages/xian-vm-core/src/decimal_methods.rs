//! Python Decimal's public methods, with one signature and conversion boundary.
use crate::{values::vm_int, VmExecutionError, VmRawDecimal, VmValue};

type Result<T> = std::result::Result<T, VmExecutionError>;

struct Signature {
    parameters: &'static [&'static str],
    required: usize,
    positional_only: bool,
}

fn signature(method: &str) -> Result<Signature> {
    let (parameters, required, positional_only): (&[&str], usize, bool) = match method {
        "adjusted" | "as_integer_ratio" | "as_tuple" | "canonical" | "conjugate" | "copy_abs"
        | "copy_negate" | "is_canonical" | "is_finite" | "is_infinite" | "is_nan" | "is_qnan"
        | "is_signed" | "is_snan" | "is_zero" | "radix" => (&[], 0, false),
        "from_float" => (&["f"], 1, true),
        "compare" | "compare_signal" | "compare_total" | "compare_total_mag" | "copy_sign"
        | "logical_and" | "logical_or" | "logical_xor" | "max" | "max_mag" | "min" | "min_mag"
        | "next_toward" | "remainder_near" | "rotate" | "same_quantum" | "scaleb" | "shift" => {
            (&["other", "context"], 1, false)
        }
        "exp" | "is_normal" | "is_subnormal" | "ln" | "log10" | "logb" | "logical_invert"
        | "next_minus" | "next_plus" | "normalize" | "number_class" | "sqrt" | "to_eng_string" => {
            (&["context"], 0, false)
        }
        "fma" => (&["other", "third", "context"], 2, false),
        "quantize" => (&["exp", "rounding", "context"], 1, false),
        "to_integral" | "to_integral_exact" | "to_integral_value" => {
            (&["rounding", "context"], 0, false)
        }
        _ => {
            return Err(VmExecutionError::new(format!(
                "unsupported Decimal method '{method}()'"
            )))
        }
    };
    Ok(Signature {
        parameters,
        required,
        positional_only,
    })
}

struct Arguments {
    operands: Vec<VmRawDecimal>,
    rounding: Option<String>,
    factory: Option<VmValue>,
}

fn bind(method: &str, args: Vec<VmValue>, kwargs: Vec<(String, VmValue)>) -> Result<Arguments> {
    let signature = signature(method)?;
    let mut values = positional_values(&signature, args, kwargs.is_empty())?;
    bind_keywords(&signature, &mut values, kwargs)?;
    if values[..signature.required].iter().any(Option::is_none) {
        return Err(VmExecutionError::new("missing Decimal method argument"));
    }
    let mut bound = Arguments {
        operands: Vec::new(),
        rounding: None,
        factory: None,
    };
    for (parameter, value) in signature
        .parameters
        .iter()
        .zip(values)
        .filter_map(|(name, value)| value.map(|value| (name, value)))
    {
        bind_parameter(&mut bound, parameter, value)?;
    }
    Ok(bound)
}

fn positional_values(
    signature: &Signature,
    args: Vec<VmValue>,
    keywords_empty: bool,
) -> Result<Vec<Option<VmValue>>> {
    if args.len() > signature.parameters.len() || (signature.positional_only && !keywords_empty) {
        return Err(VmExecutionError::new("invalid Decimal method arguments"));
    }
    let mut values = vec![None; signature.parameters.len()];
    for (index, value) in args.into_iter().enumerate() {
        values[index] = Some(value);
    }
    Ok(values)
}

fn bind_keywords(
    signature: &Signature,
    values: &mut [Option<VmValue>],
    kwargs: Vec<(String, VmValue)>,
) -> Result<()> {
    for (name, value) in kwargs {
        let index = signature
            .parameters
            .iter()
            .position(|parameter| *parameter == name)
            .ok_or_else(|| VmExecutionError::new("unknown Decimal method keyword"))?;
        if values[index].replace(value).is_some() {
            return Err(VmExecutionError::new("duplicate Decimal method argument"));
        }
    }
    Ok(())
}

fn rounding(value: VmValue) -> Result<Option<String>> {
    match value.snapshot() {
        VmValue::None => Ok(None),
        VmValue::String(mode) => Ok(Some(mode)),
        _ => Err(VmExecutionError::new(
            "Decimal rounding must be a rounding mode string",
        )),
    }
}

fn bind_parameter(bound: &mut Arguments, parameter: &str, value: VmValue) -> Result<()> {
    match parameter {
        "context" => {
            if !matches!(value.snapshot(), VmValue::None) {
                return Err(VmExecutionError::new("Decimal context must be None"));
            }
        }
        "rounding" => bound.rounding = rounding(value)?,
        "f" => bound.factory = Some(value),
        _ => bound.operands.push(decimal_operand(&value)?),
    }
    Ok(())
}

fn decimal_operand(value: &VmValue) -> Result<VmRawDecimal> {
    match value.snapshot() {
        VmValue::RawDecimal(value) => Ok(value),
        VmValue::Int(value) => VmRawDecimal::from_integer(value),
        VmValue::Bool(value) => VmRawDecimal::from_integer(u8::from(value).into()),
        _ => Err(VmExecutionError::new(
            "Decimal method requires Decimal or integer operands",
        )),
    }
}

pub(crate) fn call(
    receiver: VmValue,
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue> {
    let bound = bind(method, args, kwargs)?;
    let VmValue::RawDecimal(value) = receiver.snapshot() else {
        return Err(VmExecutionError::new(
            "Decimal method requires a Decimal receiver",
        ));
    };
    if let Some(result) = structural(&receiver, &value, method, &bound)? {
        return Ok(result);
    }
    Ok(VmValue::RawDecimal(value.calculate(
        method,
        &bound.operands,
        bound.rounding.as_deref(),
    )?))
}

fn structural(
    receiver: &VmValue,
    value: &VmRawDecimal,
    method: &str,
    bound: &Arguments,
) -> Result<Option<VmValue>> {
    let result = match method {
        "canonical" | "conjugate" => receiver.clone(),
        "adjusted" => vm_int(value.adjusted()),
        "radix" => VmValue::RawDecimal(VmRawDecimal::from_integer(10.into())?),
        "same_quantum" => VmValue::Bool(same_quantum(value, &bound.operands[0])),
        "number_class" => VmValue::String(number_class(value)),
        "to_eng_string" => VmValue::String(value.engineering()),
        _ => return converted(value, method, bound),
    };
    Ok(Some(result))
}

fn converted(value: &VmRawDecimal, method: &str, bound: &Arguments) -> Result<Option<VmValue>> {
    let result = match method {
        "as_integer_ratio" => {
            let (numerator, denominator) = value.integer_ratio()?;
            VmValue::Tuple(vec![VmValue::Int(numerator), VmValue::Int(denominator)])
        }
        "as_tuple" => decimal_tuple(value)?,
        "from_float" => VmValue::RawDecimal(from_float(
            bound.factory.as_ref().expect("bound required argument"),
        )?),
        _ => return Ok(predicate(value, method).map(VmValue::Bool)),
    };
    Ok(Some(result))
}

fn from_float(value: &VmValue) -> Result<VmRawDecimal> {
    match value.snapshot() {
        VmValue::Float(value) => VmRawDecimal::from_float(value),
        VmValue::Int(value) => VmRawDecimal::from_integer(value),
        VmValue::Bool(value) => VmRawDecimal::from_integer(u8::from(value).into()),
        _ => Err(VmExecutionError::new(
            "Decimal.from_float() requires a float or integer",
        )),
    }
}

fn predicate(value: &VmRawDecimal, method: &str) -> Option<bool> {
    type Predicate = fn(&VmRawDecimal) -> bool;
    const PREDICATES: &[(&str, Predicate)] = &[
        ("is_canonical", |_| true),
        ("is_finite", VmRawDecimal::is_finite),
        ("is_infinite", VmRawDecimal::is_infinite),
        ("is_nan", VmRawDecimal::is_nan),
        ("is_normal", VmRawDecimal::is_normal),
        ("is_qnan", |value| value.is_nan() && !value.is_snan()),
        ("is_signed", VmRawDecimal::is_negative),
        ("is_snan", VmRawDecimal::is_snan),
        ("is_subnormal", VmRawDecimal::is_subnormal),
        ("is_zero", VmRawDecimal::is_zero),
    ];
    PREDICATES
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, predicate)| predicate(value))
}

fn same_quantum(left: &VmRawDecimal, right: &VmRawDecimal) -> bool {
    if left.is_nan() || right.is_nan() {
        left.is_nan() && right.is_nan()
    } else if left.is_infinite() || right.is_infinite() {
        left.is_infinite() && right.is_infinite()
    } else {
        left.exponent == right.exponent
    }
}

fn number_class(value: &VmRawDecimal) -> String {
    if value.is_snan() {
        return "sNaN".into();
    }
    if value.is_nan() {
        return "NaN".into();
    }
    let sign = if value.is_negative() { "-" } else { "+" };
    let class = if value.is_infinite() {
        "Infinity"
    } else if value.is_zero() {
        "Zero"
    } else if value.is_subnormal() {
        "Subnormal"
    } else {
        "Normal"
    };
    format!("{sign}{class}")
}

fn decimal_tuple(value: &VmRawDecimal) -> Result<VmValue> {
    let (sign, digits, exponent, special) = value.tuple_parts();
    let value = crate::VmDecimalTuple::from_parts(sign, digits, exponent, special)?;
    Ok(VmValue::DecimalTuple(value))
}

/// Charge before constructing exact large values or entering bounded C arithmetic.
pub(crate) fn work_cost(
    method: &str,
    receiver: &VmValue,
    args: &[VmValue],
    kwargs: &[(String, VmValue)],
) -> u64 {
    if method == "to_eng_string"
        && args.is_empty()
        && kwargs.is_empty()
        && legacy_engineering(receiver)
    {
        return 0;
    }
    let size = args
        .iter()
        .chain(kwargs.iter().map(|(_, value)| value))
        .fold(operand_size(receiver), |total, value| {
            total.saturating_add(operand_size(value))
        });
    let work = size.saturating_mul(4).max(64);
    if matches!(method, "exp" | "ln" | "log10" | "sqrt") {
        work.saturating_mul(size.max(91))
    } else {
        work
    }
}

// The previously supported bounded operation retains its historical chi.
fn legacy_engineering(receiver: &VmValue) -> bool {
    let VmValue::RawDecimal(value) = receiver.snapshot() else {
        return false;
    };
    value.is_finite()
        && (-190..=100).contains(&value.exponent)
        && value.adjusted() <= 100
        && value.coefficient.bits() <= 303
        && value
            .coefficient
            .to_str_radix(10)
            .trim_start_matches('-')
            .len()
            <= 91
}

fn operand_size(value: &VmValue) -> u64 {
    match value.snapshot() {
        VmValue::RawDecimal(value) => value
            .coefficient
            .bits()
            .saturating_add(value.exponent.unsigned_abs() as u64),
        VmValue::Int(value) => value.bits(),
        VmValue::Float(_) => 4096,
        VmValue::String(value) => value.len() as u64 * 8,
        _ => 64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(text: &str) -> VmValue {
        VmValue::RawDecimal(VmRawDecimal::parse(text).unwrap())
    }

    #[test]
    fn named_parameters_bind_in_signature_order() {
        let result = call(
            raw("2.555"),
            "fma",
            vec![],
            vec![("third".into(), vm_int(1)), ("other".into(), vm_int(2))],
        )
        .unwrap();
        assert!(matches!(result, VmValue::RawDecimal(_)));
        assert_eq!(result.python_repr(), "6.110");
        let result = call(
            raw("2.555"),
            "quantize",
            vec![],
            vec![
                ("context".into(), VmValue::None),
                ("rounding".into(), VmValue::String("ROUND_HALF_EVEN".into())),
                ("exp".into(), raw("0.01")),
            ],
        )
        .unwrap();
        assert!(matches!(result, VmValue::RawDecimal(_)));
        assert_eq!(result.python_repr(), "2.56");
    }

    #[test]
    fn method_boundary_rejects_duplicate_missing_and_wrong_type_arguments() {
        assert!(bind("sqrt", vec![vm_int(1)], vec![]).is_err());
        assert!(bind("copy_abs", vec![], vec![("context".into(), VmValue::None)]).is_err());
        assert!(bind("from_float", vec![], vec![("f".into(), vm_int(1))]).is_err());
        assert!(bind("fma", vec![vm_int(1)], vec![]).is_err());
        assert!(bind("quantize", vec![raw("1")], vec![("exp".into(), raw("1"))]).is_err());
        assert!(bind("quantize", vec![VmValue::String("1".into())], vec![]).is_err());
        assert!(bind(
            "quantize",
            vec![VmValue::Decimal(crate::VmDecimal::zero())],
            vec![]
        )
        .is_err());
        assert!(bind("unknown", vec![], vec![]).is_err());
    }

    #[test]
    fn special_value_predicates_do_not_signal_or_lose_quantum_classes() {
        let nan = VmRawDecimal::parse("-sNaN12").unwrap();
        assert_eq!(number_class(&nan), "sNaN");
        assert_eq!(predicate(&nan, "is_signed"), Some(true));
        assert!(same_quantum(&nan, &VmRawDecimal::parse("NaN").unwrap()));
        assert!(!same_quantum(
            &nan,
            &VmRawDecimal::parse("Infinity").unwrap()
        ));
        assert_eq!(
            number_class(&VmRawDecimal::parse("-1E-190").unwrap()),
            "-Subnormal"
        );
        assert_eq!(
            number_class(&VmRawDecimal::parse("-0.00").unwrap()),
            "-Zero"
        );
    }
}
