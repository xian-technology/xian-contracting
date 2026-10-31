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
            let mapping = matches!(source.snapshot(), VmValue::Dict(_));
            let iterator = crate::iteration::iter(source, &self.heap)?;
            let mut count = 0;
            while let Some(item) = self.next_item(&iterator, host)? {
                count += 1;
                if count > MAX_SEQUENCE_LENGTH {
                    return Err(VmExecutionError::new("dict.update() input limit exceeded"));
                }
                host.charge_execution_cost(VM_GAS_LOOP_ITERATION)?;
                let (key, value) = if mapping {
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
    let VmValue::Dict(mut entries) = receiver.snapshot() else {
        unreachable!()
    };
    host.charge_execution_cost(VM_GAS_LOOP_ITERATION + entries.len() as u64)?;
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
