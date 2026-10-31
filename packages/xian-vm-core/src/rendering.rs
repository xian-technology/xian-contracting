//! Bounded Python-style rendering, including shared and recursive containers.
use crate::{VmExecutionError, VmValue};
use std::collections::HashSet;

#[derive(Default)]
struct Renderer {
    output: String,
    active: HashSet<usize>,
    nodes: usize,
}

pub(crate) fn render(value: &VmValue) -> Result<String, VmExecutionError> {
    let mut renderer = Renderer::default();
    renderer.value(value, false, 0)?;
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
            VmValue::String(text) if nested => self.push(&quoted(text)),
            VmValue::Dict(entries) => self.dictionary(entries, depth),
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

fn quoted(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut result = String::new();
    result.push(quote);
    for ch in value.chars() {
        escape_character(&mut result, ch, quote);
    }
    result.push(quote);
    result
}

fn sequence_parts(value: &VmValue) -> Option<(&[VmValue], &str, &str)> {
    match value {
        VmValue::List(items) => Some((items, "[", "]")),
        VmValue::Tuple(items) => Some((items, "(", if items.len() == 1 { ",)" } else { ")" })),
        VmValue::Set(items) => Some((
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
        ch if ch.is_control() => result.push_str(&format!("\\x{:02x}", ch as u32)),
        ch => result.push(ch),
    }
}
