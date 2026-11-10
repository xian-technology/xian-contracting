use serde_json::Value;
use xian_compiler_core::{
    compile_contract_artifact, normalize_source, parse_to_syntax, validate_contract_artifact,
    CompileOptions, SourceUnit,
};

fn without_locations(mut value: Value) -> Value {
    match &mut value {
        Value::Object(fields) => {
            fields.remove("span");
            fields.remove("source_sha256");
            for child in fields.values_mut() {
                *child = without_locations(child.take());
            }
        }
        Value::Array(values) => {
            for child in values {
                *child = without_locations(child.take());
            }
        }
        _ => {}
    }
    value
}

fn syntax(source: &str) -> Value {
    let unit = SourceUnit::new("con_fstring", source).unwrap();
    without_locations(serde_json::to_value(parse_to_syntax(&unit).unwrap()).unwrap())
}

fn roundtrip(expression: &str) {
    let source = format!("@export\ndef render(value: int, data: dict):\n    return {expression}\n");
    let normalized = normalize_source("con_fstring", &source, &CompileOptions::default()).unwrap();
    assert_eq!(
        syntax(&source),
        syntax(&normalized),
        "{expression} -> {normalized}"
    );
    let artifact = compile_contract_artifact("con_fstring", &source, &CompileOptions::default())
        .unwrap_or_else(|error| panic!("{expression}: {error:?}"));
    validate_contract_artifact(&artifact, "con_fstring", Some(&source)).unwrap();
    assert_eq!(artifact.source, normalized);
    assert_eq!(
        normalize_source("con_fstring", &normalized, &CompileOptions::default()).unwrap(),
        normalized
    );
}

#[test]
fn interpolation_string_quotes_stay_expression_code() {
    for expression in [
        r#"f"{data['key']}""#,
        r#"f"{'hello'}""#,
        r#"f"{str('hello')}""#,
        r#"f"{data['key']!r}""#,
        r#"f"{data['key']!a}""#,
        r#"f"{data['key']!s}""#,
    ] {
        roundtrip(expression);
    }
}

#[test]
fn literal_and_expression_quotes_are_escaped_separately() {
    for expression in [
        r#"f"literal 'quote' {data['key']}""#,
        r#"f'''literal "quote" {data['key']}'''"#,
        r#"f'''{data["a'b"]}'''"#,
        r#"f'''both ' and " {data['key']}'''"#,
        r#"f"line\n\t\\{data['key']} {{literal}}""#,
    ] {
        roundtrip(expression);
    }
}

#[test]
fn nested_fstrings_preserve_interpolation() {
    for expression in [
        r#"f"outer {f'{value}'}""#,
        r#"f'''{f"{data['key']}"}'''"#,
        r#"f"{value:{data['width']}}""#,
        r#"f"{value!r:>{data['width']}}""#,
    ] {
        roundtrip(expression);
    }
}

#[test]
fn backslashes_in_expression_strings_do_not_gain_another_escape_layer() {
    for expression in [
        r#"f"{'line\n'}""#,
        r#"f"{'slash\\n'}""#,
        r#"f"{data['line\n']}""#,
    ] {
        roundtrip(expression);
    }
}

#[test]
fn leading_dictionary_braces_are_not_literal_escapes() {
    for expression in [
        r#"f"{ {1: value} }""#,
        r#"f"{ {'key': value} }""#,
        r#"f"{ {item: value for item in [1, 2]} }""#,
        r#"f"{ {1: value}!r}""#,
    ] {
        roundtrip(expression);
    }
}

#[test]
fn established_fstring_canonical_source_is_unchanged() {
    for (expression, expected) in [
        (r#"f"value={value}""#, "f'value={value}'"),
        (r#"f"{{value}}={value}""#, "f'{{value}}={value}'"),
        (r#"f"line\n{value}""#, "f'line\\n{value}'"),
        (r#"f"slash\\n{value}""#, "f'slash\\\\n{value}'"),
        (r#"f"apostrophe's {value}""#, "f'apostrophe\\'s {value}'"),
        (r#"f"{value:#06x}""#, "f'{value:#06x}'"),
        (r#"f"{value:0{6}d}""#, "f'{value:0{6}d}'"),
    ] {
        roundtrip(expression);
        let source = format!("@export\ndef render(value: int):\n    return {expression}\n");
        let normalized =
            normalize_source("con_fstring", &source, &CompileOptions::default()).unwrap();
        assert_eq!(
            normalized,
            format!("@export\ndef render(value: int):\n    return {expected}")
        );
    }
}

#[test]
fn literal_controls_remain_escaped_in_canonical_source() {
    for expression in [
        r#"f"nul\x00{value}""#,
        r#"f"backspace\b{value}""#,
        r#"f"control\x1f\x7f\u0085{value}""#,
    ] {
        roundtrip(expression);
        let source = format!("@export\ndef render(value: int):\n    return {expression}\n");
        let normalized =
            normalize_source("con_fstring", &source, &CompileOptions::default()).unwrap();
        assert!(!normalized.chars().any(|ch| ch.is_control() && ch != '\n'));
    }
}

#[test]
fn multiline_string_values_keep_backslashes_and_controls() {
    for source in [
        "@export\ndef render():\n    \"\"\"first\nC:\\\\new\"\"\"\n    return 1\n",
        "@export\ndef render():\n    value = 1\n    \"\"\"first\nC:\\\\new\"\"\"\n    return value\n",
        "@export\ndef render():\n    \"\"\"first\n\\x00\"\"\"\n    return 1\n",
        "@export\ndef render():\n    '''first\ncontains \"\"\" and \\\\n'''\n    return 1\n",
    ] {
        let normalized = normalize_source("con_fstring", source, &CompileOptions::default()).unwrap();
        assert_eq!(syntax(source), syntax(&normalized), "{normalized}");
        assert!(!normalized.contains('\0'));
        assert_eq!(normalize_source("con_fstring", &normalized, &CompileOptions::default()).unwrap(), normalized);
        compile_contract_artifact("con_fstring", source, &CompileOptions::default()).unwrap();
    }
}

#[test]
fn established_multiline_string_canonical_source_is_unchanged() {
    let source = "@export\ndef render():\n    \"\"\"first\nsecond\"\"\"\n    return 1\n";
    let normalized = normalize_source("con_fstring", source, &CompileOptions::default()).unwrap();
    assert_eq!(normalized, source.trim_end());
}

#[test]
fn multiline_literal_trailing_quotes_cannot_merge_with_the_delimiter() {
    for count in 1..=6 {
        for prefix in ["", "    value = 1\n"] {
            let source = format!(
                "@export\ndef render():\n{prefix}    '''first\nends{}'''\n    return 1\n",
                "\"".repeat(count)
            );
            let normalized =
                normalize_source("con_fstring", &source, &CompileOptions::default()).unwrap();
            assert_eq!(
                syntax(&source),
                syntax(&normalized),
                "suffix {count}: {normalized}"
            );
            assert_eq!(
                normalize_source("con_fstring", &normalized, &CompileOptions::default()).unwrap(),
                normalized
            );
            compile_contract_artifact("con_fstring", &source, &CompileOptions::default()).unwrap();
        }
    }
}

#[test]
fn ambiguous_literal_format_specs_fail_during_compilation() {
    for expr in [
        r#"f"{value:\x7b<4}""#,
        r#"rf"{value:\x7b<4}""#,
        r#"'tag' f"{value:\u0030{value}d}""#,
        r#"f"{value:{value}\x7b}""#,
        r#"f"{value:{value}\x7d}""#,
        r#"f'{value:"<4}'"#,
        r#"f"{value:'<4}""#,
        "f\"{value:\t<4}\"",
    ] {
        let source = format!("@export\ndef render(value: int):\n    return {expr}\n");
        let errors = compile_contract_artifact("con_fstring", &source, &CompileOptions::default())
            .expect_err(expr);
        assert!(
            errors.iter().any(|error| error.code
                == "xian.syntax.unsupported_expression.format_spec_literal"),
            "{expr}: {errors:?}"
        );
    }
}

#[test]
fn ordinary_format_specs_and_escapes_outside_the_spec_roundtrip() {
    for expr in [
        r#"f"\x7b{value:02d}\x7d""#,
        r#"f"{value:.{data['digits']}f}""#,
        r#"f"{value:{data['line\n']}}""#,
        r#"f"{value:·<4}""#,
    ] {
        roundtrip(expr);
    }
}
