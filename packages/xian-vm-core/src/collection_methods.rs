//! Mutating collection methods publish each step before consuming lazy inputs.
use super::*;

type Result<T> = std::result::Result<T, VmExecutionError>;

impl VmInstance {
    pub(super) fn update_dictionary(
        &mut self,
        receiver: &VmValue,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        host: &mut dyn VmHost,
    ) -> Result<VmValue> {
        if args.len() > 1 {
            return Err(VmExecutionError::new(
                "dict.update() accepts at most one positional argument",
            ));
        }
        if let Some(source) = args.first() {
            let mapping = resolves_to!(source, VmValue::Dict(_));
            let iterator = crate::iteration::iter(source, &self.heap)?;
            let mut count = 0;
            while let Some(item) = self.next_item(&iterator, host)? {
                count += 1;
                if count > MAX_SEQUENCE_LENGTH {
                    return Err(VmExecutionError::new("dict.update() input limit exceeded"));
                }
                host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
                let (key, value) = if mapping {
                    crate::decimal_metering::comparison(host, source, &item, false)?;
                    let value = subscript_value(source.clone(), &item)?;
                    (item, value)
                } else {
                    let mut pair = self.collect_iterable(&item, host)?;
                    if pair.len() != 2 {
                        return Err(VmExecutionError::new(
                            "dict.update() requires two-element entries",
                        ));
                    }
                    let value = pair.pop().unwrap();
                    (pair.pop().unwrap(), value)
                };
                dictionary_insert(receiver, key, value, host)?;
            }
        }
        for (key, value) in kwargs {
            dictionary_insert(receiver, VmValue::String(key), value, host)?;
        }
        Ok(VmValue::None)
    }
}

fn dictionary_insert(
    receiver: &VmValue,
    key: VmValue,
    value: VmValue,
    host: &mut dyn VmHost,
) -> Result<()> {
    if let Some(dict) = indexed_dict(receiver) {
        host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
        return dict_object_set(dict, key, value, MAX_SEQUENCE_LENGTH);
    }
    let VmValue::Dict(mut entries) = receiver.snapshot() else {
        unreachable!()
    };
    host.charge_execution_cost(VM_GAS_LOOP_ITERATION + entries.len() as u64)?;
    crate::decimal_metering::comparison(host, receiver, &key, false)?;
    dict_set(&mut entries, key, value)?;
    if entries.len() > MAX_SEQUENCE_LENGTH {
        return Err(VmExecutionError::new(
            "dictionary allocation limit exceeded",
        ));
    }
    replace(receiver, VmValue::Dict(entries))
}

fn replace(receiver: &VmValue, value: VmValue) -> Result<()> {
    let VmValue::Reference(reference) = receiver else {
        return Err(VmExecutionError::new(
            "mutable method requires a heap reference",
        ));
    };
    reference.replace(value)
}

pub(super) fn setdefault(
    receiver: &VmValue,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    host: &mut dyn VmHost,
) -> Result<VmValue> {
    if args.is_empty() || args.len() > 2 || !kwargs.is_empty() {
        return Err(VmExecutionError::new(
            "dict.setdefault() expects one or two positional arguments",
        ));
    }
    if let Some(dict) = indexed_dict(receiver) {
        return indexed_setdefault(receiver, dict, args, host);
    }
    let VmValue::Dict(entries) = receiver.snapshot() else {
        unreachable!()
    };
    host.charge_execution_cost(entries.len() as u64)?;
    if let Some(value) = dict_get(&entries, &args[0])? {
        return Ok(value);
    }
    let value = args.get(1).cloned().unwrap_or(VmValue::None);
    dictionary_insert(receiver, args[0].clone(), value.clone(), host)?;
    Ok(value)
}

/// `get`, `pop` and `popitem` of a V2 dictionary, in place through its index.
pub(super) fn indexed_dict_method(
    dict: &crate::VmReference,
    method: &str,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
) -> Result<VmValue> {
    if !kwargs.is_empty() {
        return Err(VmExecutionError::new(format!(
            "native method '{method}()' does not accept keyword arguments"
        )));
    }
    match method {
        "get" => indexed_get(dict, &args),
        "pop" => indexed_pop(dict, &args),
        _ => indexed_popitem(dict, &args),
    }
}

fn indexed_get(dict: &crate::VmReference, args: &[VmValue]) -> Result<VmValue> {
    let (key, default) = key_and_default(args, "get")?;
    Ok(dict_object_get(dict, key)?.unwrap_or(default))
}

fn indexed_pop(dict: &crate::VmReference, args: &[VmValue]) -> Result<VmValue> {
    let (key, default) = key_and_default(args, "pop")?;
    match dict_object_pop(dict, key)? {
        Some(value) => Ok(value),
        None if args.len() == 2 => Ok(default),
        None => Err(VmExecutionError::new(format!(
            "missing dict key {}",
            key.python_repr()
        ))),
    }
}

fn key_and_default<'a>(args: &'a [VmValue], method: &str) -> Result<(&'a VmValue, VmValue)> {
    match args {
        [key] => Ok((key, VmValue::None)),
        [key, default] => Ok((key, default.clone())),
        _ => Err(VmExecutionError::new(format!(
            "dict.{method}() expects one or two arguments"
        ))),
    }
}

fn indexed_popitem(dict: &crate::VmReference, args: &[VmValue]) -> Result<VmValue> {
    if !args.is_empty() {
        return Err(VmExecutionError::new("dict.popitem() expects no arguments"));
    }
    let (key, value) = dict_object_pop_last(dict)?
        .ok_or_else(|| VmExecutionError::new("popitem(): dictionary is empty"))?;
    Ok(VmValue::Tuple(vec![key, value]))
}

fn indexed_setdefault(
    receiver: &VmValue,
    dict: &crate::VmReference,
    args: Vec<VmValue>,
    host: &mut dyn VmHost,
) -> Result<VmValue> {
    if let Some(value) = dict_object_get(dict, &args[0])? {
        return Ok(value);
    }
    let value = args.get(1).cloned().unwrap_or(VmValue::None);
    dictionary_insert(receiver, args[0].clone(), value.clone(), host)?;
    Ok(value)
}

pub(super) fn reverse(
    receiver: &VmValue,
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    host: &mut dyn VmHost,
) -> Result<VmValue> {
    if !args.is_empty() || !kwargs.is_empty() {
        return Err(VmExecutionError::new("list.reverse() expects no arguments"));
    }
    let VmValue::List(mut values) = receiver.snapshot() else {
        unreachable!()
    };
    host.charge_execution_cost(values.len() as u64)?;
    values.reverse();
    replace(receiver, VmValue::List(values))?;
    Ok(VmValue::None)
}

pub(super) fn fromhex(
    args: Vec<VmValue>,
    kwargs: Vec<(String, VmValue)>,
    host: &mut dyn VmHost,
) -> Result<VmValue> {
    if args.len() != 1 || !kwargs.is_empty() {
        return Err(VmExecutionError::new(
            "bytes.fromhex() expects one positional string",
        ));
    }
    let VmValue::String(text) = args[0].snapshot() else {
        return Err(VmExecutionError::new("bytes.fromhex() requires a string"));
    };
    host.charge_execution_cost(text.len() as u64)?;
    let mut bytes = Vec::new();
    let mut chars = text.bytes();
    while let Some(first) = chars.next() {
        if matches!(first, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
            continue;
        }
        let high = hex_digit(first)?;
        let low = hex_digit(
            chars
                .next()
                .ok_or_else(|| VmExecutionError::new("incomplete hex byte"))?,
        )?;
        if bytes.len() >= MAX_BINARY_ALLOCATION_BYTES {
            return Err(VmExecutionError::new("binary allocation limit exceeded"));
        }
        bytes.push(high * 16 + low);
    }
    Ok(VmValue::Bytes(bytes))
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(VmExecutionError::new("non-hexadecimal digit")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_allocation_boundary() {
        for (size, accepted) in [
            (MAX_BINARY_ALLOCATION_BYTES, true),
            (MAX_BINARY_ALLOCATION_BYTES + 1, false),
        ] {
            let result = fromhex(
                vec![VmValue::String("aB ".repeat(size))],
                vec![],
                &mut NoopHost,
            );
            assert_eq!(result.is_ok(), accepted);
            if let Ok(VmValue::Bytes(bytes)) = result {
                assert_eq!(bytes, vec![0xab; size]);
            }
        }
    }
}
