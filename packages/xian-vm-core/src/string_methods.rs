//! Historically available string operations, with bounded output allocation.
use super::*;
type Result<T> = std::result::Result<T, VmExecutionError>;
const LIMIT: usize = MAX_BINARY_ALLOCATION_BYTES;

fn error(message: &str) -> VmExecutionError {
    VmExecutionError::new(message)
}
fn string(value: String) -> VmValue {
    VmValue::String(value)
}
fn strings(values: Vec<String>) -> VmValue {
    VmValue::List(values.into_iter().map(string).collect())
}
fn check_size(length: usize) -> Result<usize> {
    if length > LIMIT {
        Err(error("string allocation limit exceeded"))
    } else {
        Ok(length)
    }
}
fn append(output: &mut String, text: &str) -> Result<()> {
    check_size(output.len().saturating_add(text.len()))?;
    output.push_str(text);
    Ok(())
}
pub(in crate::interpreter) fn index_integer(value: &VmValue) -> Result<BigInt> {
    match value.snapshot() {
        VmValue::Int(value) => Ok(value),
        VmValue::Bool(value) if !numeric_v2::active() => Ok(BigInt::from(u8::from(value))),
        _ => Err(error("string index argument must be an integer")),
    }
}
pub(in crate::interpreter) fn index_size(value: &VmValue) -> Result<i64> {
    index_integer(value)?
        .to_i64()
        .ok_or_else(|| error("string integer argument exceeds supported index range"))
}

fn width(args: &[VmValue]) -> Result<usize> {
    check_size(index_size(&args[0])?.max(0) as usize)
}
fn arity(method: &str) -> Option<(usize, usize)> {
    Some(match method {
        "capitalize" | "casefold" | "swapcase" | "title" | "isdecimal" | "isidentifier"
        | "isnumeric" | "isprintable" | "isspace" | "istitle" | "isupper" => (0, 0),
        "center" | "ljust" | "rjust" => (1, 2),
        "expandtabs" | "lstrip" | "rstrip" | "splitlines" => (0, 1),
        "index" | "rindex" | "rfind" | "maketrans" => (1, 3),
        "rsplit" => (0, 2),
        "zfill" | "translate" | "partition" | "rpartition" | "removeprefix" | "removesuffix" => {
            (1, 1)
        }
        _ => return None,
    })
}
fn check_arity(method: &str, count: usize) -> Result<()> {
    let (minimum, maximum) = arity(method).ok_or_else(|| error("unsupported string method"))?;
    if (minimum..=maximum).contains(&count) {
        Ok(())
    } else {
        Err(error("invalid number of string method arguments"))
    }
}

pub(in crate::interpreter) fn work_cost(
    value: &str,
    method: &str,
    args: &[VmValue],
) -> Result<u64> {
    if method == "strip" {
        return match args.first().map(VmValue::snapshot) {
            None | Some(VmValue::None) => Ok(0),
            Some(chars) => Ok((value.len() as u64)
                .saturating_add(chars.as_string()?.len() as u64)
                .saturating_mul(32)),
        };
    }
    if method == "encode" {
        return Ok(binary_methods::work_cost(
            &VmValue::String(value.to_owned()),
            method,
            args,
        ));
    }
    if arity(method).is_none() {
        return Ok(0);
    }
    check_arity(method, args.len())?;
    let input = value.len() as u64;
    let expansion = expansion_work(value, method, args)?;
    let arguments = args
        .iter()
        .map(argument_work)
        .fold(0u64, u64::saturating_add);
    Ok(input
        .saturating_add(arguments)
        .saturating_add(expansion)
        .saturating_mul(32)
        .max(32))
}
/// Element work of the historical string methods that `work_cost` leaves at
/// zero (`xvm-gas-5`). Each scans its receiver and text arguments: case
/// mapping, class predicates and whitespace splitting per character, the
/// others as a byte search or copy. `join` and `replace` also count their
/// output where they build it.
pub(in crate::interpreter) fn scan_units(value: &str, method: &str, args: &[VmValue]) -> u64 {
    let text = args
        .iter()
        .map(text_argument_bytes)
        .fold(value.len(), usize::saturating_add);
    let default_separator = args
        .first()
        .is_none_or(|separator| matches!(separator.snapshot(), VmValue::None));
    match method {
        "upper" | "lower" | "isalpha" | "isdigit" | "islower" | "isalnum" => {
            crate::work_meter::characters(text)
        }
        "split" if default_separator => crate::work_meter::characters(text),
        "strip" if !default_separator => 0,
        "isascii" | "startswith" | "endswith" | "find" | "count" | "strip" | "replace"
        | "split" => crate::work_meter::searched(text),
        _ => 0,
    }
}
fn text_argument_bytes(value: &VmValue) -> usize {
    match value.snapshot() {
        VmValue::String(text) => text.len(),
        VmValue::Tuple(items) => items
            .iter()
            .map(text_argument_bytes)
            .fold(0, usize::saturating_add),
        _ => 0,
    }
}
fn expansion_work(value: &str, method: &str, args: &[VmValue]) -> Result<u64> {
    let input = value.len() as u64;
    let expansion = match method {
        "center" | "ljust" | "rjust" | "zfill" => (width(args)? as u64).saturating_mul(4),
        "expandtabs" => (value.bytes().filter(|byte| *byte == b'\t').count() as u64)
            .saturating_mul(tabsize(args)? as u64),
        "lstrip" | "rstrip" => input.saturating_mul(args.first().map_or(1, argument_work)),
        "translate" => translation_work(input, &args[0]),
        "maketrans" => args
            .iter()
            .map(argument_work)
            .sum::<u64>()
            .saturating_mul(args.first().map_or(1, argument_work)),
        _ => input.saturating_mul(3),
    };
    Ok(expansion)
}
fn argument_work(value: &VmValue) -> u64 {
    match value.snapshot() {
        VmValue::String(text) => text.len() as u64,
        VmValue::Dict(values) => values.len() as u64,
        VmValue::List(values) | VmValue::Tuple(values) => values.len() as u64,
        VmValue::Range(value) => value.allocation_bytes() as u64,
        VmValue::MappingProxy(value) => argument_work(&value),
        _ => 1,
    }
}
fn translation_work(input: u64, table: &VmValue) -> u64 {
    match table.snapshot() {
        VmValue::MappingProxy(value) => translation_work(input, &value),
        VmValue::Dict(values) => {
            let replacement = values
                .iter()
                .map(|(_, value)| argument_work(value))
                .max()
                .unwrap_or(1);
            input.saturating_mul((values.len() as u64).saturating_add(replacement))
        }
        VmValue::String(text) => input.saturating_mul(text.len() as u64 + 4),
        VmValue::Range(range) => input.saturating_mul(range.allocation_bytes() as u64 + 4),
        _ => input.saturating_mul(4),
    }
}

pub(in crate::interpreter) fn call(value: &str, method: &str, args: &[VmValue]) -> Result<VmValue> {
    check_arity(method, args.len())?;
    match method {
        "capitalize" | "casefold" | "swapcase" | "title" => transform(value, method),
        "isdecimal" | "isidentifier" | "isnumeric" | "isprintable" | "isspace" | "istitle"
        | "isupper" => Ok(VmValue::Bool(unicode_strings::predicate(method, value))),
        "center" | "ljust" | "rjust" | "zfill" => padding(value, method, args).map(string),
        "expandtabs" => expand_tabs(value, tabsize(args)?).map(string),
        _ => call_search_or_mapping(value, method, args),
    }
}
fn call_search_or_mapping(value: &str, method: &str, args: &[VmValue]) -> Result<VmValue> {
    match method {
        "index" | "rindex" | "rfind" => search(value, method, args),
        "lstrip" | "rstrip" => strip(value, method, args).map(string),
        "removeprefix" | "removesuffix" => remove_affix(value, method, &args[0]).map(string),
        "partition" | "rpartition" => partition(value, method, &args[0]),
        "rsplit" => rsplit(value, args).map(strings),
        "splitlines" => splitlines(value, args).map(strings),
        _ => call_mapping(value, method, args),
    }
}

fn call_mapping(value: &str, method: &str, args: &[VmValue]) -> Result<VmValue> {
    match method {
        "translate" => translate(value, &args[0]).map(string),
        "maketrans" => maketrans(args),
        _ => Err(error("unsupported string method")),
    }
}

fn transform(value: &str, method: &str) -> Result<VmValue> {
    // Calculate exact UTF-8 size before allocation; unchanged large strings do
    // not pay a conservative threefold allocation limit.
    check_size(unicode_strings::transform_length(value, method))?;
    Ok(string(unicode_strings::transform(value, method)))
}
fn fill(args: &[VmValue]) -> Result<char> {
    let value = args
        .get(1)
        .map(VmValue::as_string)
        .transpose()?
        .unwrap_or_else(|| " ".into());
    let mut chars = value.chars();
    let first = chars
        .next()
        .ok_or_else(|| error("fill character must have length one"))?;
    if chars.next().is_some() {
        return Err(error("fill character must have length one"));
    }
    Ok(first)
}
fn padding(value: &str, method: &str, args: &[VmValue]) -> Result<String> {
    let width = width(args)?;
    let character = if method == "zfill" { '0' } else { fill(args)? };
    let margin = width.saturating_sub(value.chars().count());
    check_size(
        value
            .len()
            .saturating_add(margin.saturating_mul(character.len_utf8())),
    )?;
    if method == "zfill" {
        return zero_fill(value, margin);
    }
    let left = match method {
        "ljust" => 0,
        "rjust" => margin,
        _ => margin / 2 + (margin & width & 1),
    };
    let mut output = String::new();
    output.extend(std::iter::repeat_n(character, left));
    output.push_str(value);
    output.extend(std::iter::repeat_n(character, margin - left));
    Ok(output)
}
fn zero_fill(value: &str, margin: usize) -> Result<String> {
    let sign = usize::from(value.starts_with(['+', '-']));
    Ok(format!(
        "{}{}{}",
        &value[..sign],
        "0".repeat(margin),
        &value[sign..]
    ))
}
fn tabsize(args: &[VmValue]) -> Result<usize> {
    let size = args.first().map(index_size).transpose()?.unwrap_or(8);
    let size = i32::try_from(size).map_err(|_| error("tab size exceeds C int range"))?;
    Ok(size.max(0) as usize)
}

fn expand_tabs(value: &str, size: usize) -> Result<String> {
    let mut output = String::new();
    let mut column = 0usize;
    for ch in value.chars() {
        if ch == '\t' {
            let spaces = if size == 0 { 0 } else { size - column % size };
            check_size(output.len().saturating_add(spaces))?;
            output.extend(std::iter::repeat_n(' ', spaces));
            column = column.saturating_add(spaces);
        } else {
            check_size(output.len().saturating_add(ch.len_utf8()))?;
            output.push(ch);
            column = if matches!(ch, '\r' | '\n') {
                0
            } else {
                column + 1
            };
        }
    }
    Ok(output)
}
fn search(value: &str, method: &str, args: &[VmValue]) -> Result<VmValue> {
    let needle = args[0].as_string()?;
    let length = value.chars().count();
    let (start, end) = string_search_bounds(length, args.get(1), args.get(2))?;
    let segment = substring_by_char_bounds(value, start, end);
    let found = if start <= end && start <= length {
        if method == "index" {
            segment.find(&needle)
        } else {
            segment.rfind(&needle)
        }
    } else {
        None
    };
    match found {
        Some(offset) => Ok(vm_int(start + segment[..offset].chars().count())),
        None if method == "rfind" => Ok(vm_int(-1)),
        None => Err(error("substring not found")),
    }
}
pub(in crate::interpreter) fn strip(value: &str, method: &str, args: &[VmValue]) -> Result<String> {
    if args.len() > 1 {
        return Err(error(&format!(
            "str.{method}() expects zero or one argument"
        )));
    }
    let chars = args
        .first()
        .filter(|value| !resolves_to!(value, VmValue::None))
        .map(VmValue::as_string)
        .transpose()?
        .map(|text| text.chars().collect::<std::collections::BTreeSet<_>>());
    let predicate = |ch| {
        chars.as_ref().map_or_else(
            || unicode_strings::is_whitespace(ch),
            |chars| chars.contains(&ch),
        )
    };
    let result = match method {
        "lstrip" => value.trim_start_matches(predicate),
        "rstrip" => value.trim_end_matches(predicate),
        _ => value.trim_matches(predicate),
    };
    Ok(result.to_owned())
}

fn remove_affix(value: &str, method: &str, argument: &VmValue) -> Result<String> {
    let affix = argument.as_string()?;
    Ok(if method == "removeprefix" {
        value.strip_prefix(&affix)
    } else {
        value.strip_suffix(&affix)
    }
    .unwrap_or(value)
    .to_owned())
}
fn partition(value: &str, method: &str, argument: &VmValue) -> Result<VmValue> {
    let separator = argument.as_string()?;
    if separator.is_empty() {
        return Err(error("empty separator"));
    }
    let offset = if method == "partition" {
        value.find(&separator)
    } else {
        value.rfind(&separator)
    };
    let parts = match offset {
        Some(offset) => [
            value[..offset].to_owned(),
            separator.clone(),
            value[offset + separator.len()..].to_owned(),
        ],
        None if method == "partition" => [value.to_owned(), String::new(), String::new()],
        None => [String::new(), String::new(), value.to_owned()],
    };
    Ok(VmValue::Tuple(parts.into_iter().map(string).collect()))
}
fn rsplit(value: &str, args: &[VmValue]) -> Result<Vec<String>> {
    let separator = args
        .first()
        .filter(|value| !resolves_to!(value, VmValue::None))
        .map(VmValue::as_string)
        .transpose()?;
    let limit = args.get(1).map(index_size).transpose()?.unwrap_or(-1);
    let limit = if limit < 0 {
        usize::MAX
    } else {
        limit as usize
    };
    match separator {
        Some(separator) if separator.is_empty() => Err(error("empty separator")),
        Some(separator) => {
            let mut parts: Vec<_> = value
                .rsplitn(limit.saturating_add(1), separator.as_str())
                .map(str::to_owned)
                .collect();
            parts.reverse();
            Ok(parts)
        }
        None => Ok(rsplit_whitespace(value, limit)),
    }
}
fn rsplit_whitespace(value: &str, limit: usize) -> Vec<String> {
    let mut remaining = value.trim_end_matches(unicode_strings::is_whitespace);
    let mut parts = Vec::new();
    while !remaining.is_empty() && parts.len() < limit {
        let Some((boundary, ch)) = remaining
            .char_indices()
            .rfind(|(_, ch)| unicode_strings::is_whitespace(*ch))
        else {
            break;
        };
        parts.push(remaining[boundary + ch.len_utf8()..].to_owned());
        remaining = remaining[..boundary].trim_end_matches(unicode_strings::is_whitespace);
    }
    if !remaining.is_empty() {
        parts.push(remaining.to_owned());
    }
    parts.reverse();
    parts
}
fn splitlines(value: &str, args: &[VmValue]) -> Result<Vec<String>> {
    let keep = args.first().is_some_and(VmValue::truthy);
    let mut parts = Vec::new();
    let mut chars = value.char_indices().peekable();
    let mut start = 0;
    while let Some((index, ch)) = chars.next() {
        if !unicode_strings::is_linebreak(ch) {
            continue;
        }
        let mut end = index + ch.len_utf8();
        if ch == '\r' && chars.peek().is_some_and(|(_, next)| *next == '\n') {
            end += 1;
            chars.next();
        }
        parts.push(value[start..if keep { end } else { index }].to_owned());
        start = end;
    }
    if start < value.len() {
        parts.push(value[start..].to_owned());
    }
    Ok(parts)
}
fn lookup_translation(table: &VmValue, ch: char) -> Result<Option<VmValue>> {
    let code = ch as usize;
    match table {
        VmValue::MappingProxy(value) => lookup_translation(&value.snapshot(), ch),
        VmValue::Dict(entries) => dictionary::dict_get(entries, &vm_int(code)),
        VmValue::List(values) | VmValue::Tuple(values) => Ok(values.get(code).cloned()),
        VmValue::Range(range) => Ok(range.get(&BigInt::from(code))),
        VmValue::DecimalTuple(value) => Ok(value.as_values().get(code).cloned()),
        VmValue::String(text) => Ok(text.chars().nth(code).map(|ch| string(ch.to_string()))),
        VmValue::Bytes(bytes) | VmValue::ByteArray(bytes) => {
            Ok(bytes.get(code).map(|value| vm_int(*value)))
        }
        _ => Err(error("translation table does not support indexed lookup")),
    }
}
fn translate(value: &str, table: &VmValue) -> Result<String> {
    let table = table.snapshot();
    translate_with(value, |ch| lookup_translation(&table, ch))
}

pub(in crate::interpreter) fn translate_with(
    value: &str,
    mut lookup: impl FnMut(char) -> Result<Option<VmValue>>,
) -> Result<String> {
    let mut output = String::new();
    for ch in value.chars() {
        append_translation(&mut output, ch, lookup(ch)?)?;
    }
    Ok(output)
}

fn append_translation(output: &mut String, ch: char, result: Option<VmValue>) -> Result<()> {
    match result.map(|value| value.snapshot()) {
        None => append(output, &ch.to_string()),
        Some(VmValue::None) => Ok(()),
        Some(VmValue::String(text)) => append(output, &text),
        Some(value @ (VmValue::Int(_) | VmValue::Bool(_))) => {
            append(output, &translation_ordinal(&value)?.to_string())
        }
        _ => Err(error("translation result must be integer, string or None")),
    }
}

fn translation_ordinal(value: &VmValue) -> Result<char> {
    value
        .as_bigint()?
        .to_u32()
        .and_then(char::from_u32)
        .ok_or_else(|| error("translation ordinal must be a Unicode scalar value"))
}
fn maketrans(args: &[VmValue]) -> Result<VmValue> {
    let output = if args.len() == 1 {
        maketrans_dict(&args[0])?
    } else {
        maketrans_strings(args)?
    };
    Ok(VmValue::Dict(output))
}
fn maketrans_dict(argument: &VmValue) -> Result<Vec<(VmValue, VmValue)>> {
    let VmValue::Dict(entries) = argument.snapshot() else {
        return Err(error("maketrans single argument must be a dict"));
    };
    let mut output = Vec::new();
    for (key, value) in entries {
        dictionary::dict_set(&mut output, translation_key(key)?, value)?;
    }
    Ok(output)
}
fn maketrans_strings(args: &[VmValue]) -> Result<Vec<(VmValue, VmValue)>> {
    let from = args[0].as_string()?;
    let to = args[1].as_string()?;
    if from.chars().count() != to.chars().count() {
        return Err(error("maketrans arguments must have equal length"));
    }
    let mut output = Vec::new();
    for (from, to) in from.chars().zip(to.chars()) {
        dictionary::dict_set(&mut output, vm_int(from as u32), vm_int(to as u32))?;
    }
    add_deletions(&mut output, args.get(2))?;
    Ok(output)
}

fn add_deletions(output: &mut Vec<(VmValue, VmValue)>, delete: Option<&VmValue>) -> Result<()> {
    if let Some(delete) = delete {
        for ch in delete.as_string()?.chars() {
            dictionary::dict_set(output, vm_int(ch as u32), VmValue::None)?;
        }
    }
    Ok(())
}

fn translation_key(key: VmValue) -> Result<VmValue> {
    match key.snapshot() {
        VmValue::Int(_) | VmValue::Bool(_) => Ok(key),
        VmValue::String(text) => {
            let mut chars = text.chars();
            let first = chars
                .next()
                .filter(|_| chars.next().is_none())
                .ok_or_else(|| error("maketrans string keys must have length one"))?;
            Ok(vm_int(first as u32))
        }
        _ => Err(error(
            "maketrans keys must be integers or single characters",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn text(value: &str) -> VmValue {
        string(value.to_owned())
    }
    #[test]
    fn padding_and_tabs_preserve_character_counts() {
        assert_eq!(
            call("abc", "center", &[vm_int(6), text("中")]).unwrap(),
            text("中abc中中")
        );
        assert_eq!(call("ab", "center", &[vm_int(5)]).unwrap(), text("  ab "));
        assert_eq!(call("-42", "zfill", &[vm_int(6)]).unwrap(), text("-00042"));
        assert_eq!(
            call("a\tb\n\tc", "expandtabs", &[vm_int(4)]).unwrap(),
            text("a   b\n    c")
        );
        assert!(call("x", "center", &[vm_int(4), text("ab")]).is_err());
        assert_eq!(
            call("", "center", &[vm_int(LIMIT)])
                .unwrap()
                .as_string()
                .unwrap()
                .len(),
            LIMIT
        );
        assert!(call("x", "center", &[VmValue::Decimal(VmDecimal::one())]).is_err());
        assert!(work_cost("x", "center", &[vm_int(LIMIT + 1)]).is_err());
        assert!(call("\t", "expandtabs", &[vm_int(LIMIT + 1)]).is_err());
    }
    #[test]
    fn right_search_and_split_preserve_boundaries() {
        assert_eq!(
            call("abc", "rfind", &[text(""), vm_int(4)]).unwrap(),
            vm_int(-1)
        );
        assert_eq!(
            call("abcabc", "rindex", &[text("bc"), vm_int(0), vm_int(5)]).unwrap(),
            vm_int(1)
        );
        assert_eq!(
            call(" a b c ", "rsplit", &[VmValue::None, vm_int(1)]).unwrap(),
            strings(vec![" a b".into(), "c".into()])
        );
        assert_eq!(
            call(" a b c ", "rsplit", &[VmValue::None, vm_int(0)]).unwrap(),
            strings(vec![" a b c".into()])
        );
        assert_eq!(
            call("a:b:c", "rpartition", &[text(":")]).unwrap(),
            VmValue::Tuple(vec![text("a:b"), text(":"), text("c")])
        );
        assert_eq!(
            call("a\r\nb\n", "splitlines", &[VmValue::Bool(true)]).unwrap(),
            strings(vec!["a\r\n".into(), "b\n".into()])
        );
    }
    #[test]
    fn translation_deletes_expands_and_validates_only_used_entries() {
        let proxy = VmValue::MappingProxy(Box::new(VmValue::Dict(vec![(vm_int(97), text("X"))])));
        assert_eq!(call("ab", "translate", &[proxy]).unwrap(), text("Xb"));
        let table = VmValue::Dict(vec![
            (vm_int(97), text("XX")),
            (vm_int(98), VmValue::None),
            (vm_int(99), vm_int(100)),
            (vm_int(999), VmValue::List(vec![])),
        ]);
        assert_eq!(call("abca", "translate", &[table]).unwrap(), text("XXdXX"));
        let table = VmValue::Dict(vec![(vm_int(97), VmValue::List(vec![]))]);
        assert!(call("a", "translate", &[table]).is_err());
        let table = VmValue::Dict(vec![(text("a"), text("XX")), (vm_int(98), VmValue::None)]);
        assert_eq!(
            call("", "maketrans", &[table]).unwrap(),
            VmValue::Dict(vec![(vm_int(97), text("XX")), (vm_int(98), VmValue::None)])
        );
        assert_eq!(
            call("", "maketrans", &[text("aba"), text("XYZ"), text("b")]).unwrap(),
            VmValue::Dict(vec![(vm_int(97), vm_int(90)), (vm_int(98), VmValue::None)])
        );
    }
    #[test]
    fn custom_strip_shares_scalar_membership_without_normalization() {
        let chars = text(&("a".repeat(20000) + "中"));
        let value = "中".repeat(10000) + "value" + &"中".repeat(10000);
        assert_eq!(
            strip(&value, "strip", std::slice::from_ref(&chars)).unwrap(),
            "value"
        );
        assert_eq!(
            strip(&value, "lstrip", std::slice::from_ref(&chars))
                .unwrap()
                .chars()
                .count(),
            10005
        );
        assert_eq!(
            strip(&value, "rstrip", &[chars]).unwrap().chars().count(),
            10005
        );
        assert_eq!(strip("é", "strip", &[text("e\u{0301}")]).unwrap(), "é");
        assert_eq!(strip(" x ", "strip", &[text("")]).unwrap(), " x ");
        assert_eq!(
            strip("\u{001C}x\u{001F}", "strip", &[VmValue::None]).unwrap(),
            "x"
        );
    }

    #[test]
    fn work_is_charged_for_new_expansions_and_legacy_costs_stay_zero() {
        assert_eq!(work_cost("abc", "lower", &[]).unwrap(), 0);
        assert_eq!(work_cost("abc", "strip", &[]).unwrap(), 0);
        assert_eq!(work_cost("abc", "strip", &[VmValue::None]).unwrap(), 0);
        assert_eq!(work_cost("abc", "strip", &[text("a")]).unwrap(), 128);
        assert!(work_cost("\t", "expandtabs", &[vm_int(10000)]).unwrap() >= 320000);
        let table = VmValue::Dict(vec![(vm_int(97), text(&"x".repeat(10000)))]);
        assert!(work_cost("a", "translate", &[table]).unwrap() >= 320000);
    }

    #[test]
    fn historical_methods_scan_receiver_and_text_arguments() {
        let long = "a".repeat(800);
        assert_eq!(scan_units(&long, "lower", &[]), 400);
        assert_eq!(scan_units(&long, "split", &[]), 400);
        assert_eq!(scan_units(&long, "split", &[VmValue::None]), 400);
        assert_eq!(scan_units(&long, "split", &[text(",")]), 100);
        assert_eq!(scan_units(&long, "find", &[text(&long)]), 200);
        let prefixes = VmValue::Tuple(vec![text(&long), text(&long)]);
        assert_eq!(scan_units(&long, "startswith", &[prefixes]), 300);
        assert_eq!(scan_units(&long, "strip", &[]), 100);
        // Custom strip characters and expanding methods keep their own charge.
        assert_eq!(scan_units(&long, "strip", &[text("a")]), 0);
        assert_eq!(scan_units(&long, "center", &[vm_int(900)]), 0);
    }
}
