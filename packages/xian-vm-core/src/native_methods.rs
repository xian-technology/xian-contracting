//! Native receiver methods; mutation is returned for the caller to apply.
use super::*;

pub(in crate::interpreter) fn call_native_method_with(
    receiver: VmValue,
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    heap: &crate::heap::VmHeap,
    callback: &mut crate::iteration::Callback<'_>,
) -> Result<NativeMethodResult, VmExecutionError> {
    let receiver = receiver.snapshot();
    if !kwargs.is_empty() {
        return Err(VmExecutionError::new(format!(
            "native method '{}()' does not accept keyword arguments",
            method
        )));
    }

    match receiver {
        VmValue::List(values) => call_list_method(values, method, args, heap, callback),
        VmValue::String(value) => call_string_method(value, method, args, heap, callback),
        VmValue::Bytes(value) => call_bytes_method(value, method, args),
        VmValue::ByteArray(value) => call_bytearray_method(value, method, args, heap, callback),
        VmValue::Set(values) => call_set_method(values, method, args, heap, callback),
        VmValue::FrozenSet(values) => call_frozenset_method(values, method, args, heap, callback),
        VmValue::Dict(entries) => call_dict_method(entries, method, args),
        other => Err(VmExecutionError::new(format!(
            "value of type {} has no native method '{}()'",
            other.type_name(),
            method
        ))),
    }
}

fn call_list_method(
    mut values: Vec<VmValue>,
    method: &str,
    args: Vec<VmValue>,
    heap: &crate::heap::VmHeap,
    callback: &mut crate::iteration::Callback<'_>,
) -> Result<NativeMethodResult, VmExecutionError> {
    match method {
        "append" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new("list.append() expects one argument"));
            }
            values.push(args[0].clone());
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::List(values),
                value: VmValue::None,
            })
        }
        "remove" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new("list.remove() expects one argument"));
            }
            let index = equal_position(values.iter(), &args[0])?
                .ok_or_else(|| VmExecutionError::new("list.remove(x): x not in list"))?;
            values.remove(index);
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::List(values),
                value: VmValue::None,
            })
        }
        "extend" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new("list.extend() expects one argument"));
            }
            values.extend(crate::iteration::collect(&args[0], heap, callback)?);
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::List(values),
                value: VmValue::None,
            })
        }
        "insert" => {
            if args.len() != 2 {
                return Err(VmExecutionError::new("list.insert() expects two arguments"));
            }
            let index = normalize_sequence_insert_index(&args[0], values.len())?;
            values.insert(index, args[1].clone());
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::List(values),
                value: VmValue::None,
            })
        }
        "pop" => {
            let index = match args.as_slice() {
                [] => values
                    .len()
                    .checked_sub(1)
                    .ok_or_else(|| VmExecutionError::new("pop from empty list"))?,
                [index] => normalize_sequence_index(index, values.len())?,
                _ => {
                    return Err(VmExecutionError::new(
                        "list.pop() accepts at most one argument",
                    ))
                }
            };
            let value = values.remove(index);
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::List(values),
                value,
            })
        }
        "count" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new("list.count() expects one argument"));
            }
            let mut count = 0usize;
            for value in &values {
                if vm_values_equal(value, &args[0])? {
                    count += 1;
                }
            }
            Ok(NativeMethodResult::Value(vm_int(count)))
        }
        "index" => match args.as_slice() {
            [needle] | [needle, ..] => {
                let (start, end) = normalize_search_bounds(values.len(), args.get(1), args.get(2))?;
                for (offset, value) in values[start..end].iter().enumerate() {
                    if vm_values_equal(value, needle)? {
                        return Ok(NativeMethodResult::Value(vm_int(start + offset)));
                    }
                }
                Err(VmExecutionError::new("list.index(x): x not in list"))
            }
            _ => Err(VmExecutionError::new(
                "list.index() expects between one and three arguments",
            )),
        },
        "clear" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("list.clear() expects no arguments"));
            }
            values.clear();
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::List(values),
                value: VmValue::None,
            })
        }
        "copy" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("list.copy() expects no arguments"));
            }
            Ok(NativeMethodResult::Value(VmValue::List(values.clone())))
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported list method '{}()'",
            other
        ))),
    }
}

fn call_string_method(
    value: String,
    method: &str,
    args: Vec<VmValue>,
    heap: &crate::heap::VmHeap,
    callback: &mut crate::iteration::Callback<'_>,
) -> Result<NativeMethodResult, VmExecutionError> {
    match method {
        "upper" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::String(
                value.to_uppercase(),
            ))),
            _ => Err(VmExecutionError::new("str.upper() expects no arguments")),
        },
        "lower" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::String(
                value.to_lowercase(),
            ))),
            _ => Err(VmExecutionError::new("str.lower() expects no arguments")),
        },
        "isascii" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::Bool(value.is_ascii()))),
            _ => Err(VmExecutionError::new("str.isascii() expects no arguments")),
        },
        "isalpha" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                !value.is_empty() && value.chars().all(char::is_alphabetic),
            ))),
            _ => Err(VmExecutionError::new("str.isalpha() expects no arguments")),
        },
        "isdigit" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                !value.is_empty() && value.chars().all(char::is_numeric),
            ))),
            _ => Err(VmExecutionError::new("str.isdigit() expects no arguments")),
        },
        "islower" => match args.as_slice() {
            [] => {
                let has_cased = value.chars().any(char::is_alphabetic);
                Ok(NativeMethodResult::Value(VmValue::Bool(
                    has_cased
                        && value
                            .chars()
                            .all(|ch| !ch.is_alphabetic() || ch.is_lowercase()),
                )))
            }
            _ => Err(VmExecutionError::new("str.islower() expects no arguments")),
        },
        "isalnum" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::Bool(
                !value.is_empty() && value.chars().all(char::is_alphanumeric),
            ))),
            _ => Err(VmExecutionError::new("str.isalnum() expects no arguments")),
        },
        "startswith" | "endswith" | "find" | "count" => Ok(NativeMethodResult::Value(
            search_string(&value, method, &args)?,
        )),
        "strip" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::String(
                value.trim().to_owned(),
            ))),
            [chars] => {
                let chars = chars.as_string()?;
                let stripped = if chars.is_empty() {
                    value.clone()
                } else {
                    value.trim_matches(|ch| chars.contains(ch)).to_owned()
                };
                Ok(NativeMethodResult::Value(VmValue::String(stripped)))
            }
            _ => Err(VmExecutionError::new(
                "str.strip() expects zero or one argument",
            )),
        },
        "replace" => match args.as_slice() {
            [old, new] => Ok(NativeMethodResult::Value(VmValue::String(
                value.replace(&old.as_string()?, &new.as_string()?),
            ))),
            [old, new, count] => {
                let count = count.as_bigint()?;
                let replaced = if count < BigInt::zero() {
                    value.replace(&old.as_string()?, &new.as_string()?)
                } else {
                    value.replacen(
                        &old.as_string()?,
                        &new.as_string()?,
                        bigint_to_usize(&count, "str.replace count")?,
                    )
                };
                Ok(NativeMethodResult::Value(VmValue::String(replaced)))
            }
            _ => Err(VmExecutionError::new(
                "str.replace() expects two or three arguments",
            )),
        },
        "join" => match args.as_slice() {
            [items] => {
                let rendered = crate::iteration::collect(items, heap, callback)?
                    .into_iter()
                    .map(|item| item.as_string())
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(NativeMethodResult::Value(VmValue::String(
                    rendered.join(&value),
                )))
            }
            _ => Err(VmExecutionError::new("str.join() expects one argument")),
        },
        "split" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::List(
                split_string(value.as_str(), None, None)?
                    .into_iter()
                    .map(VmValue::String)
                    .collect(),
            ))),
            [separator] => {
                let separator = if matches!(separator, VmValue::None) {
                    None
                } else {
                    Some(separator.as_string()?)
                };
                Ok(NativeMethodResult::Value(VmValue::List(
                    split_string(value.as_str(), separator.as_deref(), None)?
                        .into_iter()
                        .map(VmValue::String)
                        .collect(),
                )))
            }
            [separator, maxsplit] => {
                let separator = if matches!(separator, VmValue::None) {
                    None
                } else {
                    Some(separator.as_string()?)
                };
                let maxsplit = maxsplit.as_bigint()?;
                let limit = if maxsplit.sign() == Sign::Minus {
                    None
                } else {
                    Some(bigint_to_usize(&maxsplit, "str.split maxsplit")?)
                };
                Ok(NativeMethodResult::Value(VmValue::List(
                    split_string(value.as_str(), separator.as_deref(), limit)?
                        .into_iter()
                        .map(VmValue::String)
                        .collect(),
                )))
            }
            _ => Err(VmExecutionError::new(
                "str.split() expects between zero and two arguments",
            )),
        },
        "format" => Ok(NativeMethodResult::Value(VmValue::String(
            render_simple_format(&value, &args)?,
        ))),
        other => Err(VmExecutionError::new(format!(
            "unsupported str method '{}()'",
            other
        ))),
    }
}

fn call_bytes_method(
    value: Vec<u8>,
    method: &str,
    args: Vec<VmValue>,
) -> Result<NativeMethodResult, VmExecutionError> {
    match method {
        "hex" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::String(hex::encode(
                value,
            )))),
            _ => Err(VmExecutionError::new("bytes.hex() expects no arguments")),
        },
        other => Err(VmExecutionError::new(format!(
            "unsupported bytes method '{}()'",
            other
        ))),
    }
}

fn call_bytearray_method(
    mut value: Vec<u8>,
    method: &str,
    args: Vec<VmValue>,
    heap: &crate::heap::VmHeap,
    callback: &mut crate::iteration::Callback<'_>,
) -> Result<NativeMethodResult, VmExecutionError> {
    match method {
        "hex" => match args.as_slice() {
            [] => Ok(NativeMethodResult::Value(VmValue::String(hex::encode(
                &value,
            )))),
            _ => Err(VmExecutionError::new(
                "bytearray.hex() expects no arguments",
            )),
        },
        "append" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new(
                    "bytearray.append() expects one argument",
                ));
            }
            value.push(byte_from_value(&args[0])?);
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::ByteArray(value),
                value: VmValue::None,
            })
        }
        "extend" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new(
                    "bytearray.extend() expects one argument",
                ));
            }
            let bytes = crate::iteration::collect(&args[0], heap, callback)?
                .iter()
                .map(byte_from_value)
                .collect::<Result<Vec<_>, _>>()?;
            value.extend(bytes);
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::ByteArray(value),
                value: VmValue::None,
            })
        }
        "pop" => {
            let index = match args.as_slice() {
                [] => value
                    .len()
                    .checked_sub(1)
                    .ok_or_else(|| VmExecutionError::new("pop from empty bytearray"))?,
                [index] => normalize_sequence_index(index, value.len())?,
                _ => {
                    return Err(VmExecutionError::new(
                        "bytearray.pop() accepts at most one argument",
                    ))
                }
            };
            let popped = value.remove(index);
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::ByteArray(value),
                value: vm_int(popped),
            })
        }
        "clear" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new(
                    "bytearray.clear() expects no arguments",
                ));
            }
            value.clear();
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::ByteArray(value),
                value: VmValue::None,
            })
        }
        "copy" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new(
                    "bytearray.copy() expects no arguments",
                ));
            }
            Ok(NativeMethodResult::Value(VmValue::ByteArray(value.clone())))
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported bytearray method '{}()'",
            other
        ))),
    }
}

fn call_set_method(
    mut values: Vec<VmValue>,
    method: &str,
    args: Vec<VmValue>,
    heap: &crate::heap::VmHeap,
    callback: &mut crate::iteration::Callback<'_>,
) -> Result<NativeMethodResult, VmExecutionError> {
    match method {
        "add" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new("set.add() expects one argument"));
            }
            values.push(args[0].clone());
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::Set(normalize_set_items(values)?),
                value: VmValue::None,
            })
        }
        "remove" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new("set.remove() expects one argument"));
            }
            let remaining = set_difference_values(&values, &args)?;
            if remaining.len() == values.len() {
                return Err(VmExecutionError::new(args[0].python_repr()));
            }
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::Set(remaining),
                value: VmValue::None,
            })
        }
        "discard" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new("set.discard() expects one argument"));
            }
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::Set(set_difference_values(&values, &args)?),
                value: VmValue::None,
            })
        }
        "pop" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("set.pop() expects no arguments"));
            }
            let value = values
                .first()
                .cloned()
                .ok_or_else(|| VmExecutionError::new("pop from an empty set"))?;
            values.remove(0);
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::Set(values),
                value,
            })
        }
        "clear" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("set.clear() expects no arguments"));
            }
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::Set(Vec::new()),
                value: VmValue::None,
            })
        }
        "copy" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("set.copy() expects no arguments"));
            }
            Ok(NativeMethodResult::Value(VmValue::Set(values.clone())))
        }
        "issubset" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new("set.issubset() expects one argument"));
            }
            let other = normalize_set_items(crate::iteration::collect(&args[0], heap, callback)?)?;
            Ok(NativeMethodResult::Value(VmValue::Bool(set_is_subset(
                &values, &other,
            )?)))
        }
        "issuperset" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new(
                    "set.issuperset() expects one argument",
                ));
            }
            let other = normalize_set_items(crate::iteration::collect(&args[0], heap, callback)?)?;
            Ok(NativeMethodResult::Value(VmValue::Bool(set_is_subset(
                &other, &values,
            )?)))
        }
        "isdisjoint" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new(
                    "set.isdisjoint() expects one argument",
                ));
            }
            let other = normalize_set_items(crate::iteration::collect(&args[0], heap, callback)?)?;
            Ok(NativeMethodResult::Value(VmValue::Bool(
                set_intersection_values(&values, &other)?.is_empty(),
            )))
        }
        "union" => {
            let mut merged = values.clone();
            for other in &args {
                merged.extend(crate::iteration::collect(other, heap, callback)?);
            }
            Ok(NativeMethodResult::Value(VmValue::Set(
                normalize_set_items(merged)?,
            )))
        }
        "intersection" => {
            let mut result = values.clone();
            for other in &args {
                let other = normalize_set_items(crate::iteration::collect(other, heap, callback)?)?;
                result = set_intersection_values(&result, &other)?;
            }
            Ok(NativeMethodResult::Value(VmValue::Set(result)))
        }
        "difference" => {
            let mut result = values.clone();
            for other in &args {
                let other = normalize_set_items(crate::iteration::collect(other, heap, callback)?)?;
                result = set_difference_values(&result, &other)?;
            }
            Ok(NativeMethodResult::Value(VmValue::Set(result)))
        }
        "symmetric_difference" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new(
                    "set.symmetric_difference() expects one argument",
                ));
            }
            let other = normalize_set_items(crate::iteration::collect(&args[0], heap, callback)?)?;
            Ok(NativeMethodResult::Value(VmValue::Set(
                normalize_set_items(set_symmetric_difference_values(&values, &other)?)?,
            )))
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported set method '{}()'",
            other
        ))),
    }
}

fn call_frozenset_method(
    values: Vec<VmValue>,
    method: &str,
    args: Vec<VmValue>,
    heap: &crate::heap::VmHeap,
    callback: &mut crate::iteration::Callback<'_>,
) -> Result<NativeMethodResult, VmExecutionError> {
    match method {
        "copy" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new(
                    "frozenset.copy() expects no arguments",
                ));
            }
            Ok(NativeMethodResult::Value(VmValue::FrozenSet(values)))
        }
        "issubset" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new(
                    "frozenset.issubset() expects one argument",
                ));
            }
            let other = normalize_set_items(crate::iteration::collect(&args[0], heap, callback)?)?;
            Ok(NativeMethodResult::Value(VmValue::Bool(set_is_subset(
                &values, &other,
            )?)))
        }
        "issuperset" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new(
                    "frozenset.issuperset() expects one argument",
                ));
            }
            let other = normalize_set_items(crate::iteration::collect(&args[0], heap, callback)?)?;
            Ok(NativeMethodResult::Value(VmValue::Bool(set_is_subset(
                &other, &values,
            )?)))
        }
        "isdisjoint" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new(
                    "frozenset.isdisjoint() expects one argument",
                ));
            }
            let other = normalize_set_items(crate::iteration::collect(&args[0], heap, callback)?)?;
            Ok(NativeMethodResult::Value(VmValue::Bool(
                set_intersection_values(&values, &other)?.is_empty(),
            )))
        }
        "union" => {
            let mut merged = values.clone();
            for other in &args {
                merged.extend(crate::iteration::collect(other, heap, callback)?);
            }
            Ok(NativeMethodResult::Value(VmValue::FrozenSet(
                normalize_set_items(merged)?,
            )))
        }
        "intersection" => {
            let mut result = values.clone();
            for other in &args {
                let other = normalize_set_items(crate::iteration::collect(other, heap, callback)?)?;
                result = set_intersection_values(&result, &other)?;
            }
            Ok(NativeMethodResult::Value(VmValue::FrozenSet(result)))
        }
        "difference" => {
            let mut result = values.clone();
            for other in &args {
                let other = normalize_set_items(crate::iteration::collect(other, heap, callback)?)?;
                result = set_difference_values(&result, &other)?;
            }
            Ok(NativeMethodResult::Value(VmValue::FrozenSet(result)))
        }
        "symmetric_difference" => {
            if args.len() != 1 {
                return Err(VmExecutionError::new(
                    "frozenset.symmetric_difference() expects one argument",
                ));
            }
            let other = normalize_set_items(crate::iteration::collect(&args[0], heap, callback)?)?;
            Ok(NativeMethodResult::Value(VmValue::FrozenSet(
                normalize_set_items(set_symmetric_difference_values(&values, &other)?)?,
            )))
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported frozenset method '{}()'",
            other
        ))),
    }
}

fn call_dict_method(
    entries: Vec<(VmValue, VmValue)>,
    method: &str,
    args: Vec<VmValue>,
) -> Result<NativeMethodResult, VmExecutionError> {
    match method {
        "keys" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("dict.keys() expects no arguments"));
            }
            Ok(NativeMethodResult::Value(VmValue::List(
                entries.iter().map(|(key, _)| key.clone()).collect(),
            )))
        }
        "values" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("dict.values() expects no arguments"));
            }
            Ok(NativeMethodResult::Value(VmValue::List(
                entries.iter().map(|(_, value)| value.clone()).collect(),
            )))
        }
        "items" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("dict.items() expects no arguments"));
            }
            Ok(NativeMethodResult::Value(VmValue::List(
                entries
                    .iter()
                    .map(|(key, value)| VmValue::Tuple(vec![key.clone(), value.clone()]))
                    .collect(),
            )))
        }
        "get" => match args.as_slice() {
            [key] => Ok(NativeMethodResult::Value(
                dict_get(&entries, key)?.unwrap_or(VmValue::None),
            )),
            [key, default] => Ok(NativeMethodResult::Value(
                dict_get(&entries, key)?.unwrap_or_else(|| default.clone()),
            )),
            _ => Err(VmExecutionError::new(
                "dict.get() expects one or two arguments",
            )),
        },
        "pop" => match args.as_slice() {
            [key] => {
                let mut entries = entries;
                let value = dict_pop(&mut entries, key)?.ok_or_else(|| {
                    VmExecutionError::new(format!("missing dict key {}", key.python_repr()))
                })?;
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::Dict(entries),
                    value,
                })
            }
            [key, default] => {
                let mut entries = entries;
                let value = dict_pop(&mut entries, key)?.unwrap_or_else(|| default.clone());
                Ok(NativeMethodResult::Mutated {
                    receiver: VmValue::Dict(entries),
                    value,
                })
            }
            _ => Err(VmExecutionError::new(
                "dict.pop() expects one or two arguments",
            )),
        },
        "clear" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("dict.clear() expects no arguments"));
            }
            Ok(NativeMethodResult::Mutated {
                receiver: VmValue::Dict(Vec::new()),
                value: VmValue::None,
            })
        }
        "copy" => {
            if !args.is_empty() {
                return Err(VmExecutionError::new("dict.copy() expects no arguments"));
            }
            Ok(NativeMethodResult::Value(VmValue::Dict(entries.clone())))
        }
        other => Err(VmExecutionError::new(format!(
            "unsupported dict method '{}()'",
            other
        ))),
    }
}
