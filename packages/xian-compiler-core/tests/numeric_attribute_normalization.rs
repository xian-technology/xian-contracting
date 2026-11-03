use xian_compiler_core::{compile_contract_artifact, normalize_source, CompileOptions};

fn artifact_expression(expression: &str, normalized_expression: &str) {
    let source = format!("@export\ndef probe():\n    return {expression}\n");
    let options = CompileOptions::default();
    let artifact = compile_contract_artifact("con_numeric_attribute", &source, &options)
        .unwrap_or_else(|error| panic!("{expression}: {error:?}"));
    assert_eq!(
        artifact.source,
        format!("@export\ndef probe():\n    return {normalized_expression}")
    );
    assert_eq!(
        normalize_source("con_numeric_attribute", &artifact.source, &options).unwrap(),
        artifact.source
    );
}

#[test]
fn integer_attribute_receivers_remain_lexically_separated_from_decimal_points() {
    for (source, expected) in [
        ("(0).bit_length()", "(0).bit_length()"),
        ("(1).real", "(1).real"),
        ("(0xff).bit_count()", "(255).bit_count()"),
        ("(0b101).numerator", "(5).numerator"),
        ("(0o77).denominator", "(63).denominator"),
        (
            "(18446744073709551616).bit_length()",
            "(18446744073709551616).bit_length()",
        ),
        ("(7).real.bit_length()", "(7).real.bit_length()"),
    ] {
        artifact_expression(source, expected);
    }
}

#[test]
fn integer_attribute_formatting_preserves_other_receiver_precedence() {
    for expression in ["(-1).bit_length()", "1.0.as_integer_ratio()", "True.real"] {
        artifact_expression(expression, expression);
    }
}

#[test]
fn integer_attributes_inside_interpolation_remain_expressions() {
    artifact_expression("f'{(0).bit_length()}'", "f'{(0).bit_length()}'");
}
