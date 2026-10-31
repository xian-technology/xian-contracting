//! Bounded replacement fields share normal VM attribute/index semantics.
use super::*;
use std::collections::BTreeMap;
use std::iter::Peekable;
use std::str::Chars;

type Result<T> = std::result::Result<T, VmExecutionError>;
const LIMIT: usize = 128 * 1024;

fn error(message: &str) -> VmExecutionError {
    VmExecutionError::new(format!("str.format(): {message}"))
}

#[derive(Default)]
struct Numbering {
    automatic: Option<bool>,
    next: usize,
}

impl Numbering {
    fn positional(&mut self, field: &str) -> Result<Option<usize>> {
        let index = if field.is_empty() {
            Some(self.next)
        } else {
            decimal_index(field)?.map(|n| n.to_usize().unwrap_or(usize::MAX))
        };
        if index.is_some() {
            let automatic = field.is_empty();
            if self.automatic.is_some_and(|previous| previous != automatic) {
                return Err(error("cannot mix automatic and manual field numbering"));
            }
            self.automatic = Some(automatic);
            self.next += usize::from(automatic);
        }
        Ok(index)
    }
}

struct Arguments {
    positional: Vec<VmValue>,
    keywords: BTreeMap<String, VmValue>,
    mapping: Option<VmValue>,
    numbering: Numbering,
}

impl Arguments {
    fn new(
        host: &mut dyn VmHost,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        map_only: bool,
    ) -> Result<Self> {
        if map_only && (args.len() != 1 || !kwargs.is_empty()) {
            return Err(error("format_map expects one positional argument"));
        }
        if kwargs.len() > MAX_SEQUENCE_LENGTH {
            return Err(error("keyword allocation limit exceeded"));
        }
        let key_bytes = kwargs.iter().fold(0u64, |size, (key, _)| {
            size.saturating_add(key.len() as u64 + 1)
        });
        host.charge_execution_cost(key_bytes.saturating_mul(tree_work(kwargs.len())))?;
        let mut keywords = BTreeMap::new();
        for (key, value) in kwargs {
            if keywords.insert(key, value).is_some() {
                return Err(error("duplicate keyword"));
            }
        }
        let mapping = map_only.then(|| args[0].clone());
        Ok(Self {
            positional: args,
            keywords,
            mapping,
            numbering: Numbering::default(),
        })
    }

    fn root(&mut self, name: &str, vm: &mut VmInstance, host: &mut dyn VmHost) -> Result<VmValue> {
        if let Some(index) = self.numbering.positional(name)? {
            if self.mapping.is_some() {
                return Err(error("format_map does not accept positional fields"));
            }
            return self
                .positional
                .get(index)
                .cloned()
                .ok_or_else(|| error("positional index out of range"));
        }
        if let Some(mapping) = &self.mapping {
            return vm.read_subscript(mapping.clone(), &VmValue::String(name.to_owned()), host);
        }
        self.keyword(name, host)
    }

    fn keyword(&self, name: &str, host: &mut dyn VmHost) -> Result<VmValue> {
        host.charge_execution_cost(
            (name.len() as u64 + 1).saturating_mul(tree_work(self.keywords.len())),
        )?;
        self.keywords
            .get(name)
            .cloned()
            .ok_or_else(|| error("missing keyword field"))
    }
}

fn tree_work(length: usize) -> u64 {
    u64::from(length.checked_ilog2().unwrap_or(0) + 1).saturating_mul(4)
}

struct Field {
    name: String,
    conversion: Option<char>,
    spec: String,
}

fn field_name(chars: &mut Peekable<Chars<'_>>) -> Result<(String, char)> {
    let mut name = String::new();
    let mut bracket = false;
    for character in chars.by_ref() {
        if !bracket && "!:}".contains(character) {
            return Ok((name, character));
        }
        if !bracket && character == '{' {
            return Err(error("unexpected opening brace in field"));
        }
        match character {
            '[' if !bracket => bracket = true,
            ']' => bracket = false,
            _ => {}
        }
        name.push(character);
    }
    Err(error("missing closing brace"))
}

fn field_spec(chars: &mut Peekable<Chars<'_>>) -> Result<String> {
    let mut nesting = 1usize;
    let mut spec = String::new();
    for character in chars.by_ref() {
        match character {
            '{' => nesting += 1,
            '}' => nesting -= 1,
            _ => {}
        }
        if nesting == 0 {
            return Ok(spec);
        }
        spec.push(character);
    }
    Err(error("missing closing brace"))
}

fn field_conversion(
    chars: &mut Peekable<Chars<'_>>,
    delimiter: char,
) -> Result<(Option<char>, char)> {
    if delimiter == '!' {
        let conversion = chars.next().ok_or_else(|| error("missing conversion"))?;
        if !"sra".contains(conversion) {
            return Err(error("unknown conversion"));
        }
        let delimiter = chars.next().ok_or_else(|| error("missing closing brace"))?;
        Ok((Some(conversion), delimiter))
    } else {
        Ok((None, delimiter))
    }
}

fn parse_field(chars: &mut Peekable<Chars<'_>>) -> Result<Field> {
    let (name, delimiter) = field_name(chars)?;
    let (conversion, delimiter) = field_conversion(chars, delimiter)?;
    let spec = match delimiter {
        ':' => field_spec(chars)?,
        '}' => String::new(),
        _ => return Err(error("invalid conversion syntax")),
    };
    Ok(Field {
        name,
        conversion,
        spec,
    })
}

fn decimal_index(text: &str) -> Result<Option<BigInt>> {
    let normalized = numeric_text::normalized_digits(text);
    if normalized.is_empty() || !normalized.bytes().all(|ch| ch.is_ascii_digit()) {
        return Ok(None);
    }
    // Python field indices are bounded by Py_ssize_t, including subscript fields.
    let significant = normalized.trim_start_matches('0');
    if significant.len() > 19 {
        return Err(error("field index is too large"));
    }
    let value: BigInt = if significant.is_empty() {
        BigInt::from(0)
    } else {
        significant
            .parse()
            .map_err(|_| error("invalid field index"))?
    };
    if value > BigInt::from(i64::MAX) {
        return Err(error("field index is too large"));
    }
    Ok(Some(value))
}

fn checked_append(output: &mut String, text: &str) -> Result<()> {
    if output.len().saturating_add(text.len()) > LIMIT {
        return Err(error("formatted output exceeds allocation limit"));
    }
    output.push_str(text);
    Ok(())
}

impl VmInstance {
    pub(super) fn format_string(
        &mut self,
        host: &mut dyn VmHost,
        template: &str,
        args: Vec<VmValue>,
        kwargs: Vec<(String, VmValue)>,
        map_only: bool,
    ) -> Result<VmValue> {
        if template.len() > LIMIT {
            return Err(error("template exceeds allocation limit"));
        }
        let mut arguments = Arguments::new(host, args, kwargs, map_only)?;
        Ok(VmValue::String(self.render_template(
            host,
            template,
            &mut arguments,
            0,
        )?))
    }

    fn render_template(
        &mut self,
        host: &mut dyn VmHost,
        template: &str,
        arguments: &mut Arguments,
        depth: usize,
    ) -> Result<String> {
        if depth > 2 {
            return Err(error("format specification nesting limit exceeded"));
        }
        host.charge_execution_cost(template.len() as u64)?;
        let mut output = String::new();
        let mut chars = template.chars().peekable();
        while let Some(character) = chars.next() {
            let text = self.template_piece(host, character, &mut chars, arguments, depth)?;
            checked_append(&mut output, &text)?;
        }
        Ok(output)
    }

    fn template_piece(
        &mut self,
        host: &mut dyn VmHost,
        character: char,
        chars: &mut Peekable<Chars<'_>>,
        arguments: &mut Arguments,
        depth: usize,
    ) -> Result<String> {
        match character {
            '{' | '}' if chars.peek() == Some(&character) => {
                chars.next();
                Ok(character.to_string())
            }
            '{' => self.render_field(host, parse_field(chars)?, arguments, depth),
            '}' => Err(error("unmatched closing brace")),
            _ => Ok(character.to_string()),
        }
    }

    fn render_field(
        &mut self,
        host: &mut dyn VmHost,
        field: Field,
        arguments: &mut Arguments,
        depth: usize,
    ) -> Result<String> {
        let value = self.resolve_field(host, &field.name, arguments)?;
        host.charge_execution_cost(value_formatting::format_work_cost(&value, "")?)?;
        let value = value_formatting::convert(&value, field.conversion)?;
        let spec = self.render_template(host, &field.spec, arguments, depth + 1)?;
        host.charge_execution_cost(value_formatting::format_work_cost(&value, &spec)?)?;
        value_formatting::format_value(&value, &spec)
    }

    fn resolve_field(
        &mut self,
        host: &mut dyn VmHost,
        name: &str,
        arguments: &mut Arguments,
    ) -> Result<VmValue> {
        let root_end = name.find(['.', '[']).unwrap_or(name.len());
        let mut value = arguments.root(&name[..root_end], self, host)?;
        let mut tail = &name[root_end..];
        while !tail.is_empty() {
            host.charge_execution_cost(VM_GAS_EXPR_SUBSCRIPT)?;
            let (next, remaining) = self.field_selector(host, value, tail)?;
            value = next;
            tail = remaining;
        }
        Ok(value)
    }

    fn field_selector<'a>(
        &mut self,
        host: &mut dyn VmHost,
        value: VmValue,
        tail: &'a str,
    ) -> Result<(VmValue, &'a str)> {
        if let Some(tail) = tail.strip_prefix('.') {
            return self.field_attribute(host, value, tail);
        }
        let tail = tail
            .strip_prefix('[')
            .ok_or_else(|| error("invalid field selector"))?;
        let end = tail
            .find(']')
            .ok_or_else(|| error("missing closing bracket"))?;
        let token = &tail[..end];
        if token.is_empty() {
            return Err(error("empty subscript field"));
        }
        let key = decimal_index(token)?
            .map(VmValue::Int)
            .unwrap_or_else(|| VmValue::String(token.to_owned()));
        Ok((self.read_subscript(value, &key, host)?, &tail[end + 1..]))
    }

    fn field_attribute<'a>(
        &mut self,
        host: &mut dyn VmHost,
        value: VmValue,
        tail: &'a str,
    ) -> Result<(VmValue, &'a str)> {
        let end = tail.find(['.', '[']).unwrap_or(tail.len());
        let attribute = &tail[..end];
        if attribute.is_empty() || attribute.starts_with('_') || attribute.ends_with('_') {
            return Err(error("private or empty attribute is forbidden"));
        }
        Ok((self.read_attribute(value, attribute, host)?, &tail[end..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Budget {
        left: u64,
        charged: u64,
    }
    impl VmHost for Budget {
        fn charge_execution_cost(&mut self, cost: u64) -> Result<()> {
            if cost > self.left {
                return Err(error("test budget exhausted"));
            }
            self.left -= cost;
            self.charged += cost;
            Ok(())
        }
    }

    #[test]
    fn keyword_index_and_lookups_charge_before_work() {
        let duplicates = vec![("x".into(), vm_int(1)), ("x".into(), vm_int(2))];
        let denied = Arguments::new(&mut Budget::default(), vec![], duplicates.clone(), false);
        assert!(denied
            .err()
            .unwrap()
            .to_string()
            .contains("budget exhausted"));
        assert!(Arguments::new(&mut NoopHost, vec![], duplicates, false).is_err());
        let values = (0..128)
            .map(|index| (format!("key{index}"), vm_int(index)))
            .collect();
        let mut budget = Budget {
            left: 100_000,
            charged: 0,
        };
        let args = Arguments::new(&mut budget, vec![], values, false).unwrap();
        assert!(budget.charged >= 128);
        assert!(args.keyword("key127", &mut Budget::default()).is_err());
        let before = budget.charged;
        assert_eq!(args.keyword("key127", &mut budget).unwrap(), vm_int(127));
        assert!(budget.charged > before);
    }

    #[test]
    fn field_parser_distinguishes_selectors_conversions_and_nested_specs() {
        for (source, name, conversion, spec) in [
            ("name}", "name", None, ""),
            ("0[a!b:}]}tail", "0[a!b:}]", None, ""),
            ("value!r:>{width}}", "value", Some('r'), ">{width}"),
            ("value:{{}}}", "value", None, "{{}}"),
        ] {
            let field = parse_field(&mut source.chars().peekable()).unwrap();
            assert_eq!(
                (field.name.as_str(), field.conversion, field.spec.as_str()),
                (name, conversion, spec)
            );
        }
        for source in ["x", "x[}", "x{y}", "x!q}", "x!rr}", "x:{y}", "x!"] {
            assert!(
                parse_field(&mut source.chars().peekable()).is_err(),
                "{source}"
            );
        }
    }

    #[test]
    fn field_numbering_ignores_names_and_rejects_mixed_modes() {
        let mut automatic = Numbering::default();
        assert_eq!(automatic.positional("").unwrap(), Some(0));
        assert_eq!(automatic.positional("name").unwrap(), None);
        assert_eq!(automatic.positional("").unwrap(), Some(1));
        assert!(automatic.positional("0").is_err());
        let mut manual = Numbering::default();
        assert_eq!(manual.positional("00").unwrap(), Some(0));
        assert_eq!(manual.positional("١").unwrap(), Some(1));
        assert!(manual.positional("").is_err());
    }

    #[test]
    fn indices_and_output_obey_exact_bounds() {
        assert_eq!(decimal_index("-1").unwrap(), None);
        assert_eq!(decimal_index("1_0").unwrap(), None);
        assert_eq!(decimal_index("9²").unwrap(), None);
        assert_eq!(
            decimal_index("9223372036854775807").unwrap(),
            Some(BigInt::from(i64::MAX))
        );
        assert!(decimal_index("9223372036854775808").is_err());
        assert!(decimal_index(&"9".repeat(10000)).is_err());
        assert_eq!(
            decimal_index(&"0".repeat(10000)).unwrap(),
            Some(BigInt::from(0))
        );
        let mut output = "x".repeat(131071);
        checked_append(&mut output, "x").unwrap();
        assert_eq!(output.len(), 131072);
        assert!(checked_append(&mut output, "x").is_err());
        assert_eq!(output.len(), 131072);
    }
}
