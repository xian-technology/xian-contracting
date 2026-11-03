//! Dispatch builtins while preserving shared argument identity where required.
use super::*;

#[path = "type_checks.rs"]
pub(in crate::interpreter) mod type_checks;

impl VmInstance {
    pub(super) fn call_builtin(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if matches!(name, "sorted" | "min" | "max" | "sum") {
            return self.collection_builtin(name, args, kwargs, host);
        }
        if matches!(name, "map" | "filter" | "zip" | "reversed") {
            return crate::iteration::lazy(name, &args, &kwargs, &self.heap);
        }
        if args.len() == 1
            && kwargs.is_empty()
            && matches!(
                (name, args[0].snapshot()),
                ("int", VmValue::Int(_))
                    | ("str", VmValue::String(_))
                    | ("float", VmValue::Float(_))
                    | ("tuple", VmValue::Tuple(_))
                    | ("bytes", VmValue::Bytes(_))
                    | ("frozenset", VmValue::FrozenSet(_))
            )
        {
            return Ok(args[0].clone());
        }
        let shared_args = args.clone();
        let shared_kwargs = kwargs.clone();
        let args = args.iter().map(VmValue::snapshot).collect::<Vec<_>>();
        let kwargs = kwargs
            .into_iter()
            .map(|(k, v)| (k, v.snapshot()))
            .collect::<Vec<_>>();
        match name {
            "Contract" => deployment_handles::constructor(&args, &kwargs),
            "datetime.datetime.strptime" => time_datetime_strptime(args, kwargs, host),
            "len" => self.builtin_len(args, kwargs),
            "range" => self.builtin_range(args, kwargs),
            "str" => self.builtin_str(args, kwargs, shared_args),
            "bytes" | "bytearray" => self.builtin_binary(host, name, args, kwargs, shared_args),
            "set" | "frozenset" => {
                self.builtin_set_constructor(host, name, args, kwargs, shared_args)
            }
            "bool" => {
                if !kwargs.is_empty() || args.len() > 1 {
                    return Err(VmExecutionError::new("bool() expects at most one argument"));
                }
                Ok(VmValue::Bool(args.first().is_some_and(VmValue::truthy)))
            }
            "abs" => self.builtin_abs(args, kwargs),
            "int" => numeric_text::int_value(args, kwargs),
            "pow" => self.builtin_pow(host, args, kwargs),
            "format" => self.builtin_format(host, shared_args, kwargs),
            "float" => self.builtin_float(args, kwargs),
            "ord" => self.builtin_ord(args, kwargs),
            "ascii" => self.builtin_ascii(host, args, kwargs, shared_args),
            "bin" | "hex" | "oct" => self.builtin_integer_repr(name, args, kwargs),
            "chr" => self.builtin_chr(args, kwargs),
            "divmod" => {
                if args.len() != 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new("divmod() expects two arguments"));
                }
                let quotient = apply_binary_operator("floordiv", args[0].clone(), args[1].clone())?;
                let remainder = apply_binary_operator("mod", args[0].clone(), args[1].clone())?;
                Ok(VmValue::Tuple(vec![quotient, remainder]))
            }
            "Exception" => self.builtin_exception(kwargs, shared_args),
            "dict" => self.builtin_dict(host, args, shared_args, shared_kwargs),
            "list" => self.builtin_list(host, args, kwargs, shared_args),
            "tuple" => self.builtin_tuple(host, args, kwargs, shared_args),
            "all" | "any" => self.builtin_all(host, name, args, kwargs, shared_args),
            "isinstance" => {
                if args.len() != 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "isinstance() expects two positional arguments",
                    ));
                }
                Ok(VmValue::Bool(type_checks::isinstance(
                    &shared_args[0],
                    &shared_args[1],
                )?))
            }
            "issubclass" => {
                if args.len() != 2 || !kwargs.is_empty() {
                    return Err(VmExecutionError::new(
                        "issubclass() expects two positional arguments",
                    ));
                }
                Ok(VmValue::Bool(type_checks::issubclass(
                    &shared_args[0],
                    &shared_args[1],
                )?))
            }
            "round" => rounding::call(&args, &kwargs),
            other => Err(VmExecutionError::new(format!(
                "unsupported builtin '{other}'"
            ))),
        }
    }

    fn builtin_len(
        &mut self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() || args.len() != 1 {
            return Err(VmExecutionError::new("len() expects one argument"));
        }
        match &args[0] {
            VmValue::DecimalTuple(_) => Ok(vm_int(3)),
            VmValue::String(value) => Ok(vm_int(value.chars().count())),
            VmValue::Bytes(value) | VmValue::ByteArray(value) => Ok(vm_int(value.len())),
            VmValue::List(values)
            | VmValue::Tuple(values)
            | VmValue::Set(values)
            | VmValue::BuiltinSet(values)
            | VmValue::FrozenSet(values) => Ok(vm_int(values.len())),
            VmValue::Dict(entries) => Ok(vm_int(entries.len())),
            VmValue::Range(range) => {
                let length = range.len();
                if length > BigInt::from(i64::MAX) {
                    return Err(VmExecutionError::new(
                        "range length exceeds platform index limit",
                    ));
                }
                Ok(VmValue::Int(length))
            }
            VmValue::View(view) => Ok(vm_int(view.len())),
            VmValue::MappingProxy(mapping) => match mapping.snapshot() {
                VmValue::Dict(entries) => Ok(vm_int(entries.len())),
                _ => Err(VmExecutionError::new("invalid mapping proxy source")),
            },
            other => Err(VmExecutionError::new(format!(
                "len() does not support {}",
                other.type_name()
            ))),
        }
    }

    fn builtin_range(
        &mut self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() || args.is_empty() || args.len() > 3 {
            return Err(VmExecutionError::new(
                "range() expects between one and three positional arguments",
            ));
        }
        let (start, stop, step) = match args.len() {
            1 => (BigInt::zero(), args[0].as_bigint()?, BigInt::from(1)),
            2 => (args[0].as_bigint()?, args[1].as_bigint()?, BigInt::from(1)),
            3 => (
                args[0].as_bigint()?,
                args[1].as_bigint()?,
                args[2].as_bigint()?,
            ),
            _ => unreachable!(),
        };
        if step.is_zero() {
            return Err(VmExecutionError::new("range() step cannot be zero"));
        }
        Ok(VmValue::Range(crate::VmRange { start, stop, step }))
    }

    fn builtin_str(
        &mut self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        shared_args: Vec<VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() || args.len() > 1 {
            return Err(VmExecutionError::new("str() expects at most one argument"));
        }
        Ok(VmValue::String(
            shared_args
                .first()
                .map(|value| public_string(value, 0))
                .transpose()?
                .unwrap_or_default(),
        ))
    }

    fn builtin_binary(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        shared_args: Vec<VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() || args.len() > 3 {
            return Err(VmExecutionError::new(format!(
                "{name}() expects between zero and three positional arguments"
            )));
        }
        let construct = if name == "bytes" {
            VmValue::Bytes
        } else {
            VmValue::ByteArray
        };
        match args.as_slice() {
            [] => Ok(construct(Vec::new())),
            [VmValue::String(_value)] => {
                Err(VmExecutionError::new("string argument without an encoding"))
            }
            [VmValue::String(value), encoding] | [VmValue::String(value), encoding, _] => {
                let encoding = encoding.as_string()?.to_lowercase();
                match encoding.as_str() {
                    "utf-8" | "utf8" => Ok(construct(value.as_bytes().to_vec())),
                    "ascii" => {
                        if !value.is_ascii() {
                            return Err(VmExecutionError::new(
                                "'ascii' codec can't encode characters outside ASCII range",
                            ));
                        }
                        Ok(construct(value.as_bytes().to_vec()))
                    }
                    other => Err(VmExecutionError::new(format!(
                        "unsupported {name}() encoding '{other}'",
                    ))),
                }
            }
            [VmValue::Int(size)] => {
                if size.sign() == Sign::Minus {
                    return Err(VmExecutionError::new("negative count"));
                }
                let size = bigint_to_usize(size, &format!("{name}() size"))?;
                if size > MAX_BINARY_ALLOCATION_BYTES {
                    return Err(VmExecutionError::new(format!(
                        "{name}() exceeds the maximum allowed allocation size"
                    )));
                }
                Ok(construct(vec![0; size]))
            }
            [_] => Ok(construct(
                self.collect_iterable(&shared_args[0], host)?
                    .iter()
                    .map(byte_from_value)
                    .collect::<Result<_, _>>()?,
            )),
            _ => Err(VmExecutionError::new("encoding without a string argument")),
        }
    }

    fn builtin_set_constructor(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        shared_args: Vec<VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() || args.len() > 1 {
            return Err(VmExecutionError::new(format!(
                "{name}() expects at most one argument"
            )));
        }
        let values = match args.as_slice() {
            [] => Vec::new(),
            [_] => self.collect_iterable(&shared_args[0], host)?,
            _ => unreachable!(),
        };
        crate::decimal_metering::normalization(host, &values)?;
        let values = normalize_set_items(values)?;
        Ok(if name == "set" {
            VmValue::Set(values)
        } else {
            VmValue::FrozenSet(values)
        })
    }

    fn builtin_abs(
        &mut self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() || args.len() != 1 {
            return Err(VmExecutionError::new("abs() expects one argument"));
        }
        match &args[0] {
            VmValue::Bool(value) => Ok(vm_int(if *value { 1 } else { 0 })),
            VmValue::Int(value) => Ok(VmValue::Int(value.abs())),
            VmValue::Float(value) => Ok(VmValue::Float(value.abs())),
            VmValue::RawDecimal(value) => Ok(VmValue::RawDecimal(value.unary("abs")?)),
            VmValue::Decimal(value) => Ok(VmValue::Decimal(VmDecimal::from_scaled(
                if value.scaled.sign() == Sign::Minus {
                    -value.scaled.clone()
                } else {
                    value.scaled.clone()
                },
            )?)),
            other => Err(VmExecutionError::new(format!(
                "abs() does not support {}",
                other.type_name()
            ))),
        }
    }

    fn builtin_pow(
        &mut self,
        host: &mut dyn VmHost,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() || args.len() < 2 || args.len() > 3 {
            return Err(VmExecutionError::new(
                "pow() expects two or three positional arguments",
            ));
        }
        if let Some(modulus) = args.get(2) {
            if args
                .iter()
                .any(|value| matches!(value, VmValue::RawDecimal(_)))
            {
                host.charge_execution_cost(crate::raw_decimal::modular_work_cost(&args))?;
                let values = args
                    .iter()
                    .map(|value| match value {
                        VmValue::RawDecimal(_) | VmValue::Int(_) | VmValue::Bool(_) => {
                            crate::VmRawDecimal::from_value(value)
                        }
                        _ => Err(VmExecutionError::new(
                            "modular Decimal power requires Decimal or integer operands",
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                return Ok(VmValue::RawDecimal(values[0].calculate(
                    "powmod",
                    &values[1..],
                    None,
                )?));
            }
            let base = args[0].as_bigint()?;
            let exponent = args[1].as_bigint()?;
            let modulus = modulus.as_bigint()?;
            if exponent.sign() == Sign::Minus {
                return Err(VmExecutionError::new(
                    "pow() 3rd argument not allowed unless all arguments are integers",
                ));
            }
            if modulus.is_zero() {
                return Err(VmExecutionError::new("pow() 3rd argument cannot be 0"));
            }
            ensure_bigint_bits(&modulus, "modular exponentiation modulus")?;
            if exponent.bits() > MAX_MODULAR_POW_EXPONENT_BITS {
                return Err(integer_limit_error("modular exponentiation exponent"));
            }
            return checked_int_value(base.modpow(&exponent, &modulus), "modular exponentiation");
        }
        if args
            .iter()
            .any(|value| matches!(value, VmValue::RawDecimal(_)))
        {
            host.charge_execution_cost(crate::raw_decimal::work_cost("pow", &args[0], &args[1]))?;
            return apply_binary_operator("pow", args[0].clone(), args[1].clone());
        }
        match (&args[0], &args[1]) {
            (VmValue::Int(base), VmValue::Int(exponent)) => {
                checked_bigint_pow(base, exponent, "integer exponentiation")
            }
            (VmValue::Decimal(base), VmValue::Decimal(exponent)) => {
                Ok(VmValue::Decimal(base.pow(exponent)?))
            }
            (VmValue::Decimal(base), exponent) => Ok(VmValue::Decimal(
                base.pow(&VmDecimal::from_vm_value(exponent)?)?,
            )),
            (base, VmValue::Decimal(exponent)) => Ok(VmValue::Decimal(
                VmDecimal::from_vm_value(base)?.pow(exponent)?,
            )),
            (VmValue::Float(base), VmValue::Float(exponent)) => {
                Ok(VmValue::Float(float_pow(*base, *exponent)))
            }
            (VmValue::Float(base), VmValue::Int(exponent)) => Ok(VmValue::Float(float_pow(
                *base,
                bigint_to_f64(exponent, "pow() exponent")?,
            ))),
            (VmValue::Int(base), VmValue::Float(exponent)) => Ok(VmValue::Float(float_pow(
                bigint_to_f64(base, "pow() base")?,
                *exponent,
            ))),
            (left, right) => Err(VmExecutionError::new(format!(
                "pow() does not support {} and {}",
                left.type_name(),
                right.type_name()
            ))),
        }
    }

    fn builtin_format(
        &mut self,
        host: &mut dyn VmHost,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if args.is_empty() || args.len() > 2 || !kwargs.is_empty() {
            return Err(VmExecutionError::new(
                "format() expects one or two positional arguments",
            ));
        }
        let spec = if let Some(value) = args.get(1) {
            value.as_string()?
        } else {
            String::new()
        };
        host.charge_execution_cost(super::value_formatting::format_work_cost(&args[0], &spec)?)?;
        Ok(VmValue::String(super::value_formatting::format_value(
            &args[0], &spec,
        )?))
    }

    fn builtin_float(
        &mut self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() || args.len() > 1 {
            return Err(VmExecutionError::new(
                "float() expects at most one argument",
            ));
        }
        if args.is_empty() {
            return Ok(VmValue::Float(0.0));
        }
        match &args[0] {
            VmValue::Int(value) => Ok(VmValue::Float(bigint_to_f64(value, "float() input")?)),
            VmValue::Bool(value) => Ok(VmValue::Float(if *value { 1.0 } else { 0.0 })),
            VmValue::Float(value) => Ok(VmValue::Float(*value)),
            VmValue::Decimal(value) => Ok(VmValue::Float(value.to_f64()?)),
            VmValue::RawDecimal(value) => Ok(VmValue::Float(value.float()?)),
            VmValue::String(value) => numeric_text::parse_float(value).map(VmValue::Float),
            VmValue::Bytes(value) | VmValue::ByteArray(value) => {
                let text = std::str::from_utf8(value)
                    .map_err(|_| VmExecutionError::new("invalid float bytes"))?;
                if !text.is_ascii() {
                    return Err(VmExecutionError::new("invalid float bytes"));
                }
                numeric_text::parse_float(text).map(VmValue::Float)
            }
            other => Err(VmExecutionError::new(format!(
                "float() does not support {}",
                other.type_name()
            ))),
        }
    }

    fn builtin_ord(
        &mut self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if args.len() != 1 || !kwargs.is_empty() {
            return Err(VmExecutionError::new("ord() expects one argument"));
        }
        match &args[0] {
            VmValue::String(value) => {
                let mut chars = value.chars();
                let first = chars.next().ok_or_else(|| {
                    VmExecutionError::new("ord() expected a character, but string was empty")
                })?;
                if chars.next().is_some() {
                    return Err(VmExecutionError::new(
                        "ord() expected a character, but string of length > 1 found",
                    ));
                }
                Ok(vm_int(u32::from(first)))
            }
            VmValue::Bytes(value) | VmValue::ByteArray(value) => match value.as_slice() {
                [byte] => Ok(vm_int(*byte)),
                [] => Err(VmExecutionError::new(
                    "ord() expected a character, but string was empty",
                )),
                _ => Err(VmExecutionError::new(
                    "ord() expected a character, but string of length > 1 found",
                )),
            },
            other => Err(VmExecutionError::new(format!(
                "ord() does not support {}",
                other.type_name()
            ))),
        }
    }

    fn builtin_ascii(
        &mut self,
        host: &mut dyn VmHost,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        shared_args: Vec<VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        if args.len() != 1 || !kwargs.is_empty() {
            return Err(VmExecutionError::new("ascii() expects one argument"));
        }
        host.charge_execution_cost(super::value_formatting::format_work_cost(
            &shared_args[0],
            "",
        )?)?;
        super::value_formatting::convert(&shared_args[0], Some('a'))
    }

    fn builtin_integer_repr(
        &mut self,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if args.len() != 1 || !kwargs.is_empty() {
            return Err(VmExecutionError::new(format!(
                "{name}() expects one argument"
            )));
        }
        let (radix, prefix) = match name {
            "bin" => (2, "0b"),
            "hex" => (16, "0x"),
            "oct" => (8, "0o"),
            _ => unreachable!(),
        };
        Ok(VmValue::String(format_integer_builtin(
            &args[0].as_bigint()?,
            radix,
            prefix,
        )))
    }

    fn builtin_chr(
        &mut self,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if args.len() != 1 || !kwargs.is_empty() {
            return Err(VmExecutionError::new("chr() expects one argument"));
        }
        let code_point = bigint_to_u32(&args[0].as_bigint()?, "chr() input")?;
        let character = char::from_u32(code_point).ok_or_else(|| {
            VmExecutionError::new(format!("chr() arg not in range(0x110000): {code_point}"))
        })?;
        Ok(VmValue::String(character.to_string()))
    }

    fn builtin_exception(
        &mut self,
        kwargs: Vec<(String, VmValue)>,
        shared_args: Vec<VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        if !kwargs.is_empty() {
            return Err(VmExecutionError::new(
                "Exception() does not accept keyword arguments",
            ));
        }
        Ok(VmValue::Exception(VmException {
            name: "Exception".to_owned(),
            args: shared_args,
        }))
    }

    fn builtin_dict(
        &mut self,
        host: &mut dyn VmHost,
        args: Vec<VmValue>,
        shared_args: Vec<VmValue>,
        shared_kwargs: Vec<(String, VmValue)>,
    ) -> Result<VmValue, VmExecutionError> {
        if args.len() > 1 {
            return Err(VmExecutionError::new(
                "dict() accepts at most one positional argument",
            ));
        }
        let mut entries = Vec::new();
        if let Some(initial) = shared_args.first() {
            let initial = match initial.snapshot() {
                VmValue::MappingProxy(mapping) => *mapping,
                _ => initial.clone(),
            };
            if let VmValue::Dict(existing) = initial.snapshot() {
                entries = existing;
            } else {
                let iterator = crate::iteration::iter(&initial, &self.heap)?;
                while let Some(item) = self.next_item(&iterator, host)? {
                    let pair = self.collect_iterable(&item, host)?;
                    if pair.len() != 2 {
                        return Err(VmExecutionError::new("dict() expected key/value pairs"));
                    }
                    crate::decimal_metering::comparison(
                        host,
                        &VmValue::Dict(entries.clone()),
                        &pair[0],
                        false,
                    )?;
                    dict_set(&mut entries, pair[0].clone(), pair[1].clone())?;
                }
            }
        }
        for (key, value) in shared_kwargs {
            crate::decimal_metering::comparison(
                host,
                &VmValue::Dict(entries.clone()),
                &VmValue::String(key.clone()),
                false,
            )?;
            dict_set(&mut entries, VmValue::String(key), value)?;
        }
        Ok(VmValue::Dict(entries))
    }

    fn builtin_list(
        &mut self,
        host: &mut dyn VmHost,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        shared_args: Vec<VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        if args.len() > 1 || !kwargs.is_empty() {
            return Err(VmExecutionError::new(
                "list() accepts at most one positional argument",
            ));
        }
        if !args.is_empty() {
            let items = self.collect_iterable(&shared_args[0], host)?;
            Ok(VmValue::List(items))
        } else {
            Ok(VmValue::List(Vec::new()))
        }
    }

    fn builtin_tuple(
        &mut self,
        host: &mut dyn VmHost,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        shared_args: Vec<VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        if args.len() > 1 || !kwargs.is_empty() {
            return Err(VmExecutionError::new(
                "tuple() accepts at most one positional argument",
            ));
        }
        if !args.is_empty() {
            let items = self.collect_iterable(&shared_args[0], host)?;
            Ok(VmValue::Tuple(items))
        } else {
            Ok(VmValue::Tuple(Vec::new()))
        }
    }

    fn builtin_all(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        shared_args: Vec<VmValue>,
    ) -> Result<VmValue, VmExecutionError> {
        if args.len() != 1 || !kwargs.is_empty() {
            return Err(VmExecutionError::new(format!(
                "{name}() expects one argument"
            )));
        }
        let iterator = crate::iteration::iter(&shared_args[0], &self.heap)?;
        while let Some(item) = self.next_item(&iterator, host)? {
            if item.truthy() == (name == "any") {
                return Ok(VmValue::Bool(name == "any"));
            }
        }
        Ok(VmValue::Bool(name == "all"))
    }
}

// Exception.__str__ uses its argument payload; repr/ascii retain the class name.
pub(super) fn public_string(value: &VmValue, depth: usize) -> Result<String, VmExecutionError> {
    if depth > 128 {
        return Err(VmExecutionError::new(
            "exception string traversal limit exceeded",
        ));
    }
    if let VmValue::Reference(reference) = value {
        if reference.with_value(|inner| matches!(inner, VmValue::Exception(_))) {
            return reference.with_value(|inner| public_string(inner, depth));
        }
        // Keep the root identity so the renderer recognizes recursive containers.
        return value.try_python_repr();
    }
    match value {
        VmValue::Exception(exception) => match exception.args.as_slice() {
            [] => Ok(String::new()),
            [argument] => public_string(argument, depth + 1),
            arguments => VmValue::Tuple(arguments.to_vec()).try_python_repr(),
        },
        _ => value.try_python_repr(),
    }
}

#[cfg(test)]
mod public_string_tests {
    use super::*;

    fn exception(args: Vec<VmValue>) -> VmValue {
        VmValue::Exception(VmException {
            name: "Exception".into(),
            args,
        })
    }

    #[test]
    fn exception_strings_use_argument_payloads_and_preserve_repr() {
        let message = VmValue::String("problem".into());
        let one = exception(vec![message.clone()]);
        assert_eq!(public_string(&exception(vec![]), 0).unwrap(), "");
        assert_eq!(public_string(&one, 0).unwrap(), "problem");
        assert_eq!(one.try_python_repr().unwrap(), "Exception('problem')");
        assert_eq!(public_string(&exception(vec![one]), 0).unwrap(), "problem");
        assert_eq!(
            public_string(&exception(vec![message, vm_int(3)]), 0).unwrap(),
            "('problem', 3)"
        );
    }

    #[test]
    fn exception_string_depth_accepts_the_limit_and_rejects_more() {
        let mut value = VmValue::String("end".into());
        for _ in 0..128 {
            value = exception(vec![value]);
        }
        assert_eq!(public_string(&value, 0).unwrap(), "end");
        assert!(public_string(&exception(vec![value]), 0).is_err());
    }
}
