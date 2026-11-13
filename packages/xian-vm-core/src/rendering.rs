//! Bounded Python-style rendering, including shared and recursive containers.
use crate::{VmExecutionError, VmValue};
#[derive(Default)]
struct Renderer {
    output: String,
    active: crate::heap::AddressSet,
    nodes: usize,
}

pub(crate) fn render(value: &VmValue) -> Result<String, VmExecutionError> {
    let mut renderer = Renderer::default();
    renderer.value(value, false, 0)?;
    Ok(renderer.output)
}

pub(crate) fn render_repr(value: &VmValue) -> Result<String, VmExecutionError> {
    let mut renderer = Renderer::default();
    renderer.value(value, true, 0)?;
    Ok(renderer.output)
}

impl Renderer {
    fn push(&mut self, text: &str) -> Result<(), VmExecutionError> {
        if self.output.len() + text.len() > 128 * 1024 {
            return Err(VmExecutionError::new(
                "VM rendered value exceeds allocation limit",
            ));
        }
        self.output.push_str(text);
        Ok(())
    }

    fn value(
        &mut self,
        value: &VmValue,
        nested: bool,
        depth: usize,
    ) -> Result<(), VmExecutionError> {
        self.nodes += 1;
        if depth > 128 || self.nodes > 128 * 1024 {
            return Err(VmExecutionError::new(
                "VM rendering traversal limit exceeded",
            ));
        }
        if let VmValue::Reference(reference) = value {
            let id = reference.id();
            if !self.active.insert(id) {
                return self.push(match reference.value() {
                    VmValue::Dict(_) => "{...}",
                    VmValue::Tuple(_) => "(...)",
                    _ => "[...]",
                });
            }
            let result = self.value(&reference.value(), nested, depth);
            self.active.remove(&id);
            return result;
        }
        self.contents(value, nested, depth)
    }

    fn contents(
        &mut self,
        value: &VmValue,
        nested: bool,
        depth: usize,
    ) -> Result<(), VmExecutionError> {
        if let Some((items, open, close)) = sequence_parts(value) {
            return self.sequence(items, open, close, depth);
        }
        match value {
            VmValue::RawDecimal(value) if nested => self.push(&format!("Decimal('{value}')")),
            VmValue::String(text) if nested => self.push(&quoted(text)?),
            VmValue::Dict(entries) => self.dictionary(entries, depth),
            VmValue::MappingProxy(mapping) => {
                self.push("mappingproxy(")?;
                self.value(mapping, true, depth + 1)?;
                self.push(")")
            }
            VmValue::DecimalTuple(tuple) => {
                let fields = tuple.as_values();
                self.push("DecimalTuple(sign=")?;
                self.value(&fields[0], true, depth + 1)?;
                self.push(", digits=")?;
                self.value(&fields[1], true, depth + 1)?;
                self.push(", exponent=")?;
                self.value(&fields[2], true, depth + 1)?;
                self.push(")")
            }
            VmValue::Exception(exception) => {
                self.push(&exception.name)?;
                self.sequence(&exception.args, "(", ")", depth)
            }
            other => self.push(&other.python_repr_atom()),
        }
    }

    fn dictionary(
        &mut self,
        entries: &[(VmValue, VmValue)],
        depth: usize,
    ) -> Result<(), VmExecutionError> {
        self.push("{")?;
        for (index, (key, value)) in entries.iter().enumerate() {
            if index > 0 {
                self.push(", ")?;
            }
            self.value(key, true, depth + 1)?;
            self.push(": ")?;
            self.value(value, true, depth + 1)?;
        }
        self.push("}")
    }

    fn sequence(
        &mut self,
        values: &[VmValue],
        open: &str,
        close: &str,
        depth: usize,
    ) -> Result<(), VmExecutionError> {
        self.push(open)?;
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                self.push(", ")?;
            }
            self.value(value, true, depth + 1)?;
        }
        self.push(close)
    }
}

fn quoted(value: &str) -> Result<String, VmExecutionError> {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut result = String::new();
    result.push(quote);
    for ch in value.chars() {
        escape_character(&mut result, ch, quote);
        if result.len() + 1 > 128 * 1024 {
            return Err(VmExecutionError::new(
                "VM rendered value exceeds allocation limit",
            ));
        }
    }
    result.push(quote);
    Ok(result)
}

fn sequence_parts(value: &VmValue) -> Option<(&[VmValue], &str, &str)> {
    match value {
        VmValue::List(items) => Some((items, "[", "]")),
        VmValue::Tuple(items) => Some((items, "(", if items.len() == 1 { ",)" } else { ")" })),
        VmValue::Set(items) | VmValue::BuiltinSet(items) => Some((
            items,
            if items.is_empty() { "set(" } else { "{" },
            if items.is_empty() { ")" } else { "}" },
        )),
        VmValue::FrozenSet(items) => Some((
            items,
            if items.is_empty() {
                "frozenset("
            } else {
                "frozenset({"
            },
            if items.is_empty() { ")" } else { "})" },
        )),
        _ => None,
    }
}

fn escape_character(result: &mut String, ch: char, quote: char) {
    match ch {
        '\\' => result.push_str("\\\\"),
        '\n' => result.push_str("\\n"),
        '\r' => result.push_str("\\r"),
        '\t' => result.push_str("\\t"),
        ch if ch == quote => {
            result.push('\\');
            result.push(ch);
        }
        ch if !crate::interpreter::python_is_printable(ch) => {
            let code = ch as u32;
            match code {
                0..=255 => result.push_str(&format!("\\x{code:02x}")),
                256..=65535 => result.push_str(&format!("\\u{code:04x}")),
                _ => result.push_str(&format!("\\U{code:08x}")),
            }
        }
        ch => result.push(ch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_builder_never_returns_an_oversized_intermediate() {
        let limit = 128 * 1024;
        assert_eq!(quoted(&"a".repeat(limit - 2)).unwrap().len(), limit);
        assert!(quoted(&"a".repeat(limit - 1)).is_err());
        assert!(quoted(&"\0".repeat(limit / 4)).is_err());
        assert_eq!(quoted("\0").unwrap(), "'\\x00'");
        assert_eq!(quoted("don't").unwrap(), "\"don't\"");
    }
}
