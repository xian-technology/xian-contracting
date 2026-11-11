//! Bounded bytes/bytearray APIs shared by direct and bound method calls.
use super::*;
#[path = "binary_encoding.rs"]
mod encoding;
type Result<T> = std::result::Result<T, VmExecutionError>;
const LIMIT: usize = 128 * 1024;

fn error(message: &str) -> VmExecutionError {
    VmExecutionError::new(message)
}
fn arity(args: &[VmValue], minimum: usize, maximum: usize) -> Result<()> {
    if (minimum..=maximum).contains(&args.len()) {
        Ok(())
    } else {
        Err(error("invalid binary method arguments"))
    }
}
fn integer(value: &VmValue) -> Result<BigInt> {
    match value.snapshot() {
        VmValue::Int(v) => Ok(v),
        VmValue::Bool(v) if !numeric_v2::active() => Ok(u8::from(v).into()),
        _ => Err(error("binary method requires an integer")),
    }
}
fn signed64(value: &VmValue) -> Result<i64> {
    integer(value)?
        .to_i64()
        .ok_or_else(|| error("binary integer argument exceeds signed 64-bit range"))
}
fn signed32(value: &VmValue) -> Result<i32> {
    integer(value)?
        .to_i32()
        .ok_or_else(|| error("binary integer argument exceeds signed 32-bit range"))
}
fn bytes(value: &VmValue) -> Result<Vec<u8>> {
    match value.snapshot() {
        VmValue::Bytes(v) | VmValue::ByteArray(v) if v.len() <= LIMIT => Ok(v),
        VmValue::Bytes(_) | VmValue::ByteArray(_) => Err(error("binary allocation limit exceeded")),
        _ => Err(error("binary method requires a bytes-like object")),
    }
}
fn byte(value: &VmValue) -> Result<u8> {
    integer(value)?
        .to_u8()
        .ok_or_else(|| error("byte must be in range(0, 256)"))
}
fn wrap(value: Vec<u8>, mutable: bool) -> VmValue {
    if mutable {
        VmValue::ByteArray(value)
    } else {
        VmValue::Bytes(value)
    }
}
fn result(value: VmValue) -> Result<NativeMethodResult> {
    Ok(NativeMethodResult::Value(value))
}
fn output(value: Vec<u8>, mutable: bool) -> Result<NativeMethodResult> {
    result(wrap(value, mutable))
}
fn extend(output: &mut Vec<u8>, part: &[u8]) -> Result<()> {
    if output.len().saturating_add(part.len()) > LIMIT {
        return Err(error("binary allocation limit exceeded"));
    }
    output.extend_from_slice(part);
    Ok(())
}
fn count(args: &[VmValue], index: usize, default: usize) -> Result<usize> {
    let Some(value) = args.get(index) else {
        return Ok(default);
    };
    let number = signed64(value)?;
    Ok(if number < 0 {
        usize::MAX
    } else {
        number as usize
    })
}
fn index(value: Option<&VmValue>, length: usize, default: usize, past_end: bool) -> Result<usize> {
    let Some(value) = value else {
        return Ok(default);
    };
    if matches!(value.snapshot(), VmValue::None) {
        return Ok(default);
    }
    let number = integer(value)?;
    let number = if number.is_negative() {
        number + length
    } else {
        number
    };
    if number.is_negative() {
        return Ok(0);
    }
    Ok(number
        .to_usize()
        .unwrap_or(usize::MAX)
        .min(length + usize::from(past_end)))
}
fn codec_args(args: &[VmValue]) -> Result<(String, String)> {
    arity(args, 0, 2)?;
    let name = args
        .first()
        .map(VmValue::as_string)
        .transpose()?
        .unwrap_or_else(|| "utf-8".into());
    let mode = args
        .get(1)
        .map(VmValue::as_string)
        .transpose()?
        .unwrap_or_else(|| "strict".into());
    Ok((name, mode))
}
pub(in crate::interpreter) fn encode(text: &str, args: &[VmValue]) -> Result<VmValue> {
    let (name, mode) = codec_args(args)?;
    Ok(VmValue::Bytes(encoding::encode(text, &name, &mode)?))
}
pub(in crate::interpreter) fn call(
    value: Vec<u8>,
    mutable: bool,
    method: &str,
    args: Vec<VmValue>,
    collect: &mut dyn FnMut(&VmValue) -> Result<Vec<VmValue>>,
) -> Result<NativeMethodResult> {
    if value.len() > LIMIT {
        return Err(error("binary allocation limit exceeded"));
    }
    if matches!(
        method,
        "find" | "rfind" | "index" | "rindex" | "count" | "startswith" | "endswith"
    ) {
        return search(&value, method, &args);
    }
    if matches!(
        method,
        "isalnum"
            | "isalpha"
            | "isascii"
            | "isdigit"
            | "islower"
            | "isupper"
            | "istitle"
            | "isspace"
    ) {
        arity(&args, 0, 0)?;
        return result(VmValue::Bool(predicate(&value, method)));
    }
    if matches!(
        method,
        "lower" | "upper" | "capitalize" | "swapcase" | "title"
    ) {
        arity(&args, 0, 0)?;
        return output(transform(value, method), mutable);
    }
    if mutable
        && matches!(
            method,
            "append" | "extend" | "insert" | "remove" | "pop" | "clear" | "reverse"
        )
    {
        return mutate(value, method, &args, collect);
    }
    producing(value, mutable, method, &args, collect)
}
fn producing(
    value: Vec<u8>,
    mutable: bool,
    method: &str,
    args: &[VmValue],
    collect: &mut dyn FnMut(&VmValue) -> Result<Vec<VmValue>>,
) -> Result<NativeMethodResult> {
    match method {
        "decode" => {
            let (name, mode) = codec_args(args)?;
            result(VmValue::String(encoding::decode(&value, &name, &mode)?))
        }
        "hex" => result(VmValue::String(hexadecimal(&value, args)?)),
        "fromhex" => {
            arity(args, 1, 1)?;
            output(fromhex(&args[0].as_string()?)?, mutable)
        }
        "maketrans" => result(VmValue::Bytes(maketrans(args)?)),
        "join" => {
            arity(args, 1, 1)?;
            output(join(&value, collect(&args[0])?)?, mutable)
        }
        "copy" if mutable => {
            arity(args, 0, 0)?;
            output(value, mutable)
        }
        _ => sequence_result(&value, mutable, method, args),
    }
}
fn sequence_result(
    value: &[u8],
    mutable: bool,
    method: &str,
    args: &[VmValue],
) -> Result<NativeMethodResult> {
    match method {
        "split" | "rsplit" => parts(split(value, method == "rsplit", args)?, mutable, false),
        "splitlines" => parts(splitlines(value, args)?, mutable, false),
        "partition" | "rpartition" => parts(
            partition(value, method == "rpartition", args)?,
            mutable,
            true,
        ),
        "strip" | "lstrip" | "rstrip" => output(strip(value, method, args)?, mutable),
        "removeprefix" | "removesuffix" => output(remove_affix(value, method, args)?, mutable),
        "center" | "ljust" | "rjust" | "zfill" => output(pad(value, method, args)?, mutable),
        "expandtabs" => output(expandtabs(value, args)?, mutable),
        "replace" => output(replace(value, args)?, mutable),
        "translate" => output(translate(value, args)?, mutable),
        _ => Err(error("unsupported binary method")),
    }
}
fn parts(items: Vec<Vec<u8>>, mutable: bool, tuple: bool) -> Result<NativeMethodResult> {
    if items.len() > LIMIT {
        return Err(error("binary sequence allocation limit exceeded"));
    }
    let values = items.into_iter().map(|v| wrap(v, mutable)).collect();
    result(if tuple {
        VmValue::Tuple(values)
    } else {
        VmValue::List(values)
    })
}
fn needle(value: &VmValue) -> Result<Vec<u8>> {
    match value.snapshot() {
        VmValue::Int(_) | VmValue::Bool(_) => Ok(vec![byte(value)?]),
        _ => bytes(value),
    }
}
fn search(value: &[u8], method: &str, args: &[VmValue]) -> Result<NativeMethodResult> {
    arity(args, 1, 3)?;
    let start = index(args.get(1), value.len(), 0, true)?;
    let end = index(args.get(2), value.len(), value.len(), false)?;
    if matches!(method, "startswith" | "endswith") {
        return result(VmValue::Bool(matches_affix(
            value, method, &args[0], start, end,
        )?));
    }
    let pattern = needle(&args[0])?;
    let slice = value.get(start..end);
    if method == "count" {
        return result(vm_int(
            slice.map_or(0, |slice| count_matches(slice, &pattern)),
        ));
    }
    let found = slice
        .and_then(|slice| find(slice, &pattern, method.starts_with('r')))
        .map(|i| i + start);
    search_result(method, found)
}
fn search_result(method: &str, found: Option<usize>) -> Result<NativeMethodResult> {
    if matches!(method, "index" | "rindex") && found.is_none() {
        return Err(error("subsection not found"));
    }
    result(found.map(vm_int).unwrap_or_else(|| vm_int(-1)))
}

fn matches_affix(
    value: &[u8],
    method: &str,
    argument: &VmValue,
    start: usize,
    end: usize,
) -> Result<bool> {
    let candidates = match argument.snapshot() {
        VmValue::Tuple(v) => v,
        _ => vec![argument.clone()],
    };
    for candidate in candidates {
        let candidate = bytes(&candidate)?;
        if start <= end
            && (if method == "startswith" {
                value[start..end].starts_with(&candidate)
            } else {
                value[start..end].ends_with(&candidate)
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn find(value: &[u8], pattern: &[u8], reverse: bool) -> Option<usize> {
    if pattern.is_empty() {
        return Some(if reverse { value.len() } else { 0 });
    }
    if reverse {
        value.windows(pattern.len()).rposition(|w| w == pattern)
    } else {
        value.windows(pattern.len()).position(|w| w == pattern)
    }
}
fn count_matches(mut value: &[u8], pattern: &[u8]) -> usize {
    if pattern.is_empty() {
        return value.len() + 1;
    }
    let mut count = 0;
    while let Some(i) = find(value, pattern, false) {
        count += 1;
        value = &value[i + pattern.len()..];
    }
    count
}
fn is_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}
fn predicate(value: &[u8], method: &str) -> bool {
    match method {
        "isascii" => value.is_ascii(),
        "isalpha" => !value.is_empty() && value.iter().all(u8::is_ascii_alphabetic),
        "isalnum" => !value.is_empty() && value.iter().all(u8::is_ascii_alphanumeric),
        "isdigit" => !value.is_empty() && value.iter().all(u8::is_ascii_digit),
        "isspace" => !value.is_empty() && value.iter().all(|b| is_space(*b)),
        "islower" => {
            value.iter().any(u8::is_ascii_lowercase) && !value.iter().any(u8::is_ascii_uppercase)
        }
        "isupper" => {
            value.iter().any(u8::is_ascii_uppercase) && !value.iter().any(u8::is_ascii_lowercase)
        }
        "istitle" => is_title(value),
        _ => false,
    }
}
fn is_title(value: &[u8]) -> bool {
    let mut previous = false;
    let mut cased = false;
    for byte in value {
        if byte.is_ascii_alphabetic() {
            if byte.is_ascii_uppercase() == previous {
                return false;
            }
            cased = true;
            previous = true;
        } else {
            previous = false;
        }
    }
    cased
}
fn transform(mut value: Vec<u8>, method: &str) -> Vec<u8> {
    let mut previous = false;
    for (index, byte) in value.iter_mut().enumerate() {
        let original = *byte;
        *byte = transform_byte(*byte, method, index, previous);
        previous = original.is_ascii_alphabetic();
    }
    value
}
fn transform_byte(byte: u8, method: &str, index: usize, previous: bool) -> u8 {
    match method {
        "lower" => byte.to_ascii_lowercase(),
        "upper" => byte.to_ascii_uppercase(),
        "capitalize" if index == 0 => byte.to_ascii_uppercase(),
        "capitalize" => byte.to_ascii_lowercase(),
        "swapcase" if byte.is_ascii_lowercase() => byte.to_ascii_uppercase(),
        "swapcase" => byte.to_ascii_lowercase(),
        "title" if previous => byte.to_ascii_lowercase(),
        "title" => byte.to_ascii_uppercase(),
        _ => byte,
    }
}

fn strip(value: &[u8], method: &str, args: &[VmValue]) -> Result<Vec<u8>> {
    arity(args, 0, 1)?;
    let custom = args
        .first()
        .filter(|v| !matches!(v.snapshot(), VmValue::None))
        .map(bytes)
        .transpose()?;
    let mut removable = [false; 256];
    if let Some(custom) = custom {
        for byte in custom {
            removable[byte as usize] = true;
        }
    } else {
        for (byte, slot) in removable.iter_mut().enumerate() {
            *slot = is_space(byte as u8);
        }
    }
    let start = if method == "rstrip" {
        0
    } else {
        value
            .iter()
            .position(|b| !removable[*b as usize])
            .unwrap_or(value.len())
    };
    let end = if method == "lstrip" {
        value.len()
    } else {
        value
            .iter()
            .rposition(|b| !removable[*b as usize])
            .map_or(0, |i| i + 1)
    };
    Ok(value[start..end.max(start)].to_vec())
}
fn remove_affix(value: &[u8], method: &str, args: &[VmValue]) -> Result<Vec<u8>> {
    arity(args, 1, 1)?;
    let affix = bytes(&args[0])?;
    if method == "removeprefix" && value.starts_with(&affix) {
        Ok(value[affix.len()..].to_vec())
    } else if method == "removesuffix" && value.ends_with(&affix) {
        Ok(value[..value.len() - affix.len()].to_vec())
    } else {
        Ok(value.to_vec())
    }
}
fn split(value: &[u8], reverse: bool, args: &[VmValue]) -> Result<Vec<Vec<u8>>> {
    arity(args, 0, 2)?;
    let separator = args
        .first()
        .filter(|v| !matches!(v.snapshot(), VmValue::None))
        .map(bytes)
        .transpose()?;
    if separator.as_ref().is_some_and(Vec::is_empty) {
        return Err(error("empty separator"));
    }
    let limit = count(args, 1, usize::MAX)?;
    if reverse {
        let data: Vec<_> = value.iter().copied().rev().collect();
        let sep = separator.map(|v| v.into_iter().rev().collect::<Vec<_>>());
        let mut parts = split_forward(&data, sep.as_deref(), limit);
        parts.reverse();
        for part in &mut parts {
            part.reverse();
        }
        Ok(parts)
    } else {
        Ok(split_forward(value, separator.as_deref(), limit))
    }
}
fn split_forward(mut value: &[u8], separator: Option<&[u8]>, limit: usize) -> Vec<Vec<u8>> {
    let mut parts = Vec::new();
    if let Some(separator) = separator {
        while parts.len() < limit {
            let Some(i) = find(value, separator, false) else {
                break;
            };
            parts.push(value[..i].to_vec());
            value = &value[i + separator.len()..];
        }
        parts.push(value.to_vec());
        return parts;
    }
    while !value.is_empty() {
        let start = value
            .iter()
            .position(|b| !is_space(*b))
            .unwrap_or(value.len());
        value = &value[start..];
        if value.is_empty() {
            break;
        }
        if parts.len() == limit {
            parts.push(value.to_vec());
            break;
        }
        let end = value
            .iter()
            .position(|b| is_space(*b))
            .unwrap_or(value.len());
        parts.push(value[..end].to_vec());
        value = &value[end..];
    }
    parts
}
fn splitlines(value: &[u8], args: &[VmValue]) -> Result<Vec<Vec<u8>>> {
    arity(args, 0, 1)?;
    let keep = args.first().is_some_and(VmValue::truthy);
    let mut parts = Vec::new();
    let mut start = 0;
    let mut cursor = 0;
    while cursor < value.len() {
        if !matches!(value[cursor], b'\n' | b'\r') {
            cursor += 1;
            continue;
        }
        let end = cursor;
        cursor += 1;
        if value[end] == b'\r' && value.get(cursor) == Some(&b'\n') {
            cursor += 1;
        }
        parts.push(value[start..if keep { cursor } else { end }].to_vec());
        start = cursor;
    }
    if start < value.len() {
        parts.push(value[start..].to_vec());
    }
    Ok(parts)
}
fn partition(value: &[u8], reverse: bool, args: &[VmValue]) -> Result<Vec<Vec<u8>>> {
    arity(args, 1, 1)?;
    let sep = bytes(&args[0])?;
    if sep.is_empty() {
        return Err(error("empty separator"));
    }
    Ok(match find(value, &sep, reverse) {
        Some(i) => vec![
            value[..i].to_vec(),
            sep.clone(),
            value[i + sep.len()..].to_vec(),
        ],
        None if reverse => vec![vec![], vec![], value.to_vec()],
        None => vec![value.to_vec(), vec![], vec![]],
    })
}
fn pad(value: &[u8], method: &str, args: &[VmValue]) -> Result<Vec<u8>> {
    arity(args, 1, if method == "zfill" { 1 } else { 2 })?;
    let width = signed64(&args[0])?;
    let fill = fill_byte(args.get(1))?;
    if width <= value.len() as i64 {
        return Ok(value.to_vec());
    }
    let width = width
        .to_usize()
        .filter(|n| *n <= LIMIT)
        .ok_or_else(|| error("binary allocation limit exceeded"))?;
    if method == "zfill" {
        return Ok(zero_pad(value, width));
    }
    Ok(pad_with_fill(value, method, width, fill))
}
fn pad_with_fill(value: &[u8], method: &str, width: usize, fill: u8) -> Vec<u8> {
    let margin = width - value.len();
    let left = match method {
        "ljust" => 0,
        "rjust" => margin,
        _ => margin / 2 + (margin & width & 1),
    };
    let mut out = vec![fill; width];
    out[left..left + value.len()].copy_from_slice(value);
    out
}
fn fill_byte(value: Option<&VmValue>) -> Result<u8> {
    let Some(value) = value else {
        return Ok(b' ');
    };
    let bytes = bytes(value)?;
    if bytes.len() != 1 {
        return Err(error("fill byte must have length one"));
    }
    Ok(bytes[0])
}
fn zero_pad(value: &[u8], width: usize) -> Vec<u8> {
    let margin = width - value.len();
    let mut out = vec![b'0'; width];
    let offset = usize::from(value.first().is_some_and(|b| matches!(b, b'+' | b'-')));
    out[margin + offset..].copy_from_slice(&value[offset..]);
    if offset == 1 {
        out[0] = value[0];
    }
    out
}

fn expandtabs(value: &[u8], args: &[VmValue]) -> Result<Vec<u8>> {
    arity(args, 0, 1)?;
    let size = args.first().map(signed32).transpose()?.unwrap_or(8).max(0) as usize;
    let mut output = Vec::new();
    let mut column = 0usize;
    for byte in value {
        if *byte == b'\t' {
            let spaces = if size == 0 { 0 } else { size - column % size };
            extend_spaces(&mut output, spaces)?;
            column = column.saturating_add(spaces);
        } else {
            extend(&mut output, &[*byte])?;
            column = if matches!(byte, b'\n' | b'\r') {
                0
            } else {
                column + 1
            };
        }
    }
    Ok(output)
}
fn extend_spaces(output: &mut Vec<u8>, spaces: usize) -> Result<()> {
    if output.len().saturating_add(spaces) > LIMIT {
        return Err(error("binary allocation limit exceeded"));
    }
    output.resize(output.len() + spaces, b' ');
    Ok(())
}

fn replace(value: &[u8], args: &[VmValue]) -> Result<Vec<u8>> {
    arity(args, 2, 3)?;
    let old = bytes(&args[0])?;
    let new = bytes(&args[1])?;
    let limit = count(args, 2, usize::MAX)?;
    if old.is_empty() {
        return replace_empty(value, &new, limit);
    }
    replace_matches(value, &old, &new, limit)
}
fn replace_empty(value: &[u8], new: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut replaced = 0;
    for position in 0..=value.len() {
        if replaced < limit {
            extend(&mut output, new)?;
            replaced += 1;
        }
        if let Some(byte) = value.get(position) {
            extend(&mut output, &[*byte])?;
        }
    }
    Ok(output)
}
fn replace_matches(mut value: &[u8], old: &[u8], new: &[u8], limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut replaced = 0;
    while replaced < limit {
        let Some(i) = find(value, old, false) else {
            break;
        };
        extend(&mut output, &value[..i])?;
        extend(&mut output, new)?;
        value = &value[i + old.len()..];
        replaced += 1;
    }
    extend(&mut output, value)?;
    Ok(output)
}

fn join(separator: &[u8], values: Vec<VmValue>) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    for (index, value) in values.iter().enumerate() {
        let part = bytes(value)?;
        if index > 0 {
            extend(&mut output, separator)?;
        }
        extend(&mut output, &part)?;
    }
    Ok(output)
}
fn maketrans(args: &[VmValue]) -> Result<Vec<u8>> {
    arity(args, 2, 2)?;
    let from = bytes(&args[0])?;
    let to = bytes(&args[1])?;
    if from.len() != to.len() {
        return Err(error("maketrans arguments must have equal length"));
    }
    let mut table = (0..=255).collect::<Vec<u8>>();
    for (a, b) in from.into_iter().zip(to) {
        table[a as usize] = b;
    }
    Ok(table)
}
fn translate(value: &[u8], args: &[VmValue]) -> Result<Vec<u8>> {
    arity(args, 1, 2)?;
    let table = if matches!(args[0].snapshot(), VmValue::None) {
        None
    } else {
        Some(bytes(&args[0])?)
    };
    if table.as_ref().is_some_and(|v| v.len() != 256) {
        return Err(error("translation table must be 256 bytes long"));
    }
    let deleted = args.get(1).map(bytes).transpose()?.unwrap_or_default();
    let mut remove = [false; 256];
    for b in deleted {
        remove[b as usize] = true;
    }
    Ok(value
        .iter()
        .filter(|b| !remove[**b as usize])
        .map(|b| table.as_ref().map_or(*b, |t| t[*b as usize]))
        .collect())
}
fn fromhex(text: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut iter = text.bytes();
    while let Some(first) = iter.next() {
        if is_space(first) {
            continue;
        }
        let high = hex_digit(first)?;
        let low = hex_digit(iter.next().ok_or_else(|| error("incomplete hex byte"))?)?;
        extend(&mut output, &[high * 16 + low])?;
    }
    Ok(output)
}
fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(error("non-hexadecimal digit")),
    }
}
fn hexadecimal(value: &[u8], args: &[VmValue]) -> Result<String> {
    arity(args, 0, 2)?;
    let separator = hex_separator(args.first())?;
    let group = args.get(1).map(signed32).transpose()?.unwrap_or(1);
    let reverse = group < 0;
    let group = group.unsigned_abs() as usize;
    let mut output = Vec::new();
    const HEX: &[u8] = b"0123456789abcdef";
    for (index, byte) in value.iter().enumerate() {
        if let Some(separator) =
            separator.filter(|_| hex_group_boundary(index, value.len(), group, reverse))
        {
            extend(&mut output, &[separator])?;
        }
        extend(
            &mut output,
            &[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]],
        )?;
    }
    String::from_utf8(output).map_err(|_| error("invalid hexadecimal output"))
}
fn hex_group_boundary(index: usize, length: usize, group: usize, reverse: bool) -> bool {
    if index == 0 || group == 0 {
        return false;
    }
    let offset = if reverse { index } else { length - index };
    offset % group == 0
}
fn hex_separator(value: Option<&VmValue>) -> Result<Option<u8>> {
    let Some(value) = value else { return Ok(None) };
    let value = match value.snapshot() {
        VmValue::String(v) => v.into_bytes(),
        VmValue::Bytes(v) => v,
        VmValue::Builtin(v) if v == "__binary_hex_default_sep" => return Ok(None),
        _ => return Err(error("hex separator must be str or bytes")),
    };
    if value.len() != 1 || !value[0].is_ascii() {
        return Err(error("hex separator must be one ASCII character"));
    }
    Ok(Some(value[0]))
}
fn mutate(
    mut value: Vec<u8>,
    method: &str,
    args: &[VmValue],
    collect: &mut dyn FnMut(&VmValue) -> Result<Vec<VmValue>>,
) -> Result<NativeMethodResult> {
    let result = match method {
        "append" => {
            arity(args, 1, 1)?;
            extend(&mut value, &[byte(&args[0])?])?;
            VmValue::None
        }
        "extend" => {
            arity(args, 1, 1)?;
            extend_items(&mut value, collect(&args[0])?)?;
            VmValue::None
        }
        "insert" => {
            insert_byte(&mut value, args)?;
            VmValue::None
        }
        "remove" => {
            remove_byte(&mut value, args)?;
            VmValue::None
        }
        "pop" => pop_byte(&mut value, args)?,
        "clear" => {
            arity(args, 0, 0)?;
            value.clear();
            VmValue::None
        }
        "reverse" => {
            arity(args, 0, 0)?;
            value.reverse();
            VmValue::None
        }
        _ => unreachable!(),
    };
    Ok(NativeMethodResult::Mutated {
        receiver: VmValue::ByteArray(value),
        value: result,
    })
}
fn extend_items(value: &mut Vec<u8>, items: Vec<VmValue>) -> Result<()> {
    for item in items {
        extend(value, &[byte(&item)?])?;
    }
    Ok(())
}
fn insert_byte(value: &mut Vec<u8>, args: &[VmValue]) -> Result<()> {
    arity(args, 2, 2)?;
    signed64(&args[0])?;
    let position = index(Some(&args[0]), value.len(), 0, false)?;
    let byte = byte(&args[1])?;
    if value.len() == LIMIT {
        return Err(error("binary allocation limit exceeded"));
    }
    value.insert(position, byte);
    Ok(())
}
fn remove_byte(value: &mut Vec<u8>, args: &[VmValue]) -> Result<()> {
    arity(args, 1, 1)?;
    let byte = byte(&args[0])?;
    let position = value
        .iter()
        .position(|v| *v == byte)
        .ok_or_else(|| error("value not found in bytearray"))?;
    value.remove(position);
    Ok(())
}
fn pop_byte(value: &mut Vec<u8>, args: &[VmValue]) -> Result<VmValue> {
    arity(args, 0, 1)?;
    let raw = args
        .first()
        .map(integer)
        .transpose()?
        .unwrap_or_else(|| (-1).into());
    let position = if raw.is_negative() {
        raw + value.len()
    } else {
        raw
    };
    let position = position
        .to_usize()
        .filter(|p| *p < value.len())
        .ok_or_else(|| error("pop index out of range"))?;
    Ok(vm_int(value.remove(position)))
}
/// Conservative work estimate charged before binary method allocation/search.
pub(in crate::interpreter) fn work_cost(receiver: &VmValue, method: &str, args: &[VmValue]) -> u64 {
    if has_legacy_work_charge(receiver, method, args) {
        return 0;
    }

    let size = match receiver.snapshot() {
        VmValue::Bytes(v) | VmValue::ByteArray(v) => v.len(),
        VmValue::String(v) => v.len(),
        _ => 0,
    } as u64;
    let operand = args.iter().fold(0u64, |cost, value| {
        let amount = match value.snapshot() {
            VmValue::Tuple(values) if matches!(method, "startswith" | "endswith") => values
                .iter()
                .fold(0u64, |sum, value| sum.saturating_add(operand_size(value))),
            _ => operand_size(value),
        };
        cost.saturating_add(amount)
    });
    if matches!(
        method,
        "find"
            | "rfind"
            | "index"
            | "rindex"
            | "count"
            | "replace"
            | "split"
            | "rsplit"
            | "partition"
            | "rpartition"
    ) {
        size.saturating_mul(operand.max(1))
    } else {
        size.saturating_add(operand).saturating_mul(4)
    }
}

fn has_legacy_work_charge(receiver: &VmValue, method: &str, args: &[VmValue]) -> bool {
    matches!(method, "append" | "extend" | "pop" | "clear" | "copy")
        || (method == "fromhex"
            && (matches!(receiver.snapshot(), VmValue::Bytes(_))
                || matches!(receiver.snapshot(), VmValue::Builtin(ref name) if name == "bytes")))
        || (method == "hex" && args.is_empty())
}

fn operand_size(value: &VmValue) -> u64 {
    match value.snapshot() {
        VmValue::Bytes(v) | VmValue::ByteArray(v) => v.len() as u64,
        VmValue::String(v) => v.len() as u64,
        VmValue::Int(v) => v.to_u64().unwrap_or(0).min(LIMIT as u64),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translation_inputs_obey_binary_limit() {
        let boundary = VmValue::Bytes(vec![b'a'; LIMIT]);
        assert!(call(
            vec![],
            false,
            "maketrans",
            vec![boundary.clone(), boundary],
            &mut |_| unreachable!()
        )
        .is_ok());
        let input = VmValue::Bytes(vec![b'a'; LIMIT + 1]);
        assert!(call(
            vec![],
            false,
            "maketrans",
            vec![input.clone(), input],
            &mut |_| unreachable!()
        )
        .is_err());
    }

    #[test]
    fn maximum_binary_output_and_receiver_are_accepted() {
        assert!(call(
            vec![b'a'; LIMIT],
            false,
            "upper",
            vec![],
            &mut |_| unreachable!()
        )
        .is_ok());
        let args = vec![
            VmValue::Bytes(vec![b'a']),
            VmValue::Bytes(vec![b'b'; LIMIT]),
        ];
        assert!(call(vec![b'a'], false, "replace", args, &mut |_| unreachable!()).is_ok());
    }

    #[test]
    fn new_factories_and_prefix_candidates_are_metered() {
        let args = vec![VmValue::String("41".repeat(32))];
        assert!(work_cost(&VmValue::ByteArray(vec![]), "fromhex", &args) >= 64);
        assert_eq!(work_cost(&VmValue::Bytes(vec![]), "fromhex", &args), 0);
        let prefixes = vec![VmValue::Tuple(vec![VmValue::Bytes(vec![b'a'; 32]); 16])];
        assert!(work_cost(&VmValue::Bytes(vec![b'a']), "startswith", &prefixes) >= 512);
    }

    #[test]
    fn strip_large_custom_set_with_late_matching_byte() {
        let mut custom = vec![0; LIMIT];
        custom[LIMIT - 1] = b'x';
        let args = vec![VmValue::ByteArray(custom)];
        let mut value = vec![b'x'; LIMIT];
        value[LIMIT / 2] = b'y';
        assert_eq!(strip(&value, "strip", &args).unwrap(), b"y");
        assert_eq!(strip(&value, "lstrip", &args).unwrap(), value[LIMIT / 2..]);
        assert_eq!(strip(&value, "rstrip", &args).unwrap(), value[..=LIMIT / 2]);
    }
}
