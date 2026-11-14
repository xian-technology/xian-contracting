//! The canonical JSON spelling of a transaction document.
//!
//! Nesting needs no limit of its own here: the JSON reader refuses documents
//! nested 128 containers deep ("recursion limit exceeded"), so a decoded
//! document is at most 127 levels deep.
use crate::{AdmissionError, Result};
use serde_json::Value;

/// Sorted keys, no whitespace, non-ASCII text kept as UTF-8.
pub fn canonical_json(value: &Value) -> Result<String> {
    let mut output = String::new();
    write_value(value, &mut output)?;
    Ok(output)
}

fn write_value(value: &Value, output: &mut String) -> Result<()> {
    match value {
        Value::String(raw) => write_string(raw, output),
        Value::Array(items) => write_array(items, output),
        Value::Object(items) => write_object(items, output),
        scalar => {
            output.push_str(&scalar.to_string());
            Ok(())
        }
    }
}

fn write_string(text: &str, output: &mut String) -> Result<()> {
    let quoted =
        serde_json::to_string(text).map_err(|error| AdmissionError::new(error.to_string()))?;
    output.push_str(&quoted);
    Ok(())
}

fn write_array(items: &[Value], output: &mut String) -> Result<()> {
    output.push('[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write_value(item, output)?;
    }
    output.push(']');
    Ok(())
}

fn write_object(items: &serde_json::Map<String, Value>, output: &mut String) -> Result<()> {
    output.push('{');
    let mut keys: Vec<&String> = items.keys().collect();
    keys.sort();
    for (index, key) in keys.into_iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write_string(key, output)?;
        output.push(':');
        write_value(&items[key], output)?;
    }
    output.push('}');
    Ok(())
}
