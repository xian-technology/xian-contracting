use serde_json::{json, Value};
use xian_compiler_core::{compile_contract_artifact, validate_contract_artifact, CompileOptions};

fn options() -> CompileOptions {
    CompileOptions {
        vm_profile: "xian_vm_v2".into(),
        lint: true,
    }
}

#[test]
fn exact_literals_survive_artifact_generation_and_validation() {
    for (literal, value) in [
        ("9_007_199_254_740_993.125_0", "9007199254740993.125"),
        ("1e-30", "0.000000000000000000000000000001"),
        ("3.00e+2", "300"),
        (".1250", "0.125"),
        ("0e-99999999999999", "0"),
    ] {
        let source = format!("@export\ndef value(x: decimal):\n    return {literal}\n");
        let artifact = compile_contract_artifact("con_numeric", &source, &options()).unwrap();
        let validated =
            validate_contract_artifact(&artifact, "con_numeric", Some(&source)).unwrap();
        let node = &validated.vm_ir["functions"][0]["body"][0]["value"];
        assert_eq!(node["value_type"], "decimal");
        assert_eq!(node["value"], json!(value));
        assert_eq!(node.get("literal"), None);
    }
}

#[test]
fn v2_rejects_unrepresentable_numbers_and_retired_numeric_apis() {
    let over_limit = format!("0x1{}", "0".repeat(128));
    for expression in [
        "1e-31",
        "1e61",
        &over_limit,
        "float(1)",
        "decimal.Decimal('1')",
        "round(1, 0)",
    ] {
        let source = format!("@export\ndef value():\n    return {expression}");
        assert!(
            compile_contract_artifact("con_numeric", &source, &options()).is_err(),
            "{expression}"
        );
    }
}

#[test]
fn quoted_nested_float_and_raw_decimal_annotations_are_rejected() {
    for annotation in ["list['float']", "'dict[str,float]'", "list['decimal.Decimal']"] {
        let source = format!("@export\ndef probe(x: {annotation}):\n    return x");
        assert!(compile_contract_artifact("con_numeric", &source, &options()).is_err());
    }
}

#[test]
fn decimal_literals_in_interpolation_keep_the_original_digits() {
    let source = "@export\ndef value():\n    return f'π {9007199254740993.000001}'";
    let artifact = compile_contract_artifact("con_numeric", source, &options()).unwrap();
    let parsed: Value = serde_json::from_str(&artifact.vm_ir_json).unwrap();
    assert!(parsed
        .to_string()
        .contains(r#""value":"9007199254740993.000001""#));
    validate_contract_artifact(&artifact, "con_numeric", Some(source)).unwrap();
}

#[test]
fn normalized_decimal_spelling_preserves_context_and_literal_type() {
    let literal = "9007199254740993.000000000000000000000000000001";
    for expr in [
        format!("f'prefix: π\\n{{{literal}:.3f}}' f'{{{literal}}}'"),
        format!("f'''{{f\"inner {{{literal}}}\"}}'''"),
        format!("({literal} + .25) / 2"),
        format!("{{'x': [{literal}, 0e+3]}}"),
    ] {
        let source = format!("@export\r\ndef value():\r\n    return {expr}\r\n");
        let artifact = compile_contract_artifact("con_context", &source, &options()).unwrap();
        let validated =
            validate_contract_artifact(&artifact, "con_context", Some(&source)).unwrap();
        assert!(validated
            .vm_ir
            .to_string()
            .contains(&format!(r#""value":"{literal}""#)));
    }
}

#[test]
fn integer_limit_and_artifact_profile_are_enforced() {
    let maximum = format!("0x{}", "f".repeat(128));
    let source = format!("@export\ndef probe(a: decimal) -> decimal:\n    return {maximum} / a");
    let mut artifact = compile_contract_artifact("con_profile", &source, &options()).unwrap();
    let parsed: Value = serde_json::from_str(&artifact.vm_ir_json).unwrap();
    assert_eq!(
        parsed["functions"][0]["parameters"][0]["annotation"],
        "decimal"
    );
    assert_eq!(parsed["functions"][0]["returns"], "decimal");
    artifact.vm_profile = "xian_vm_v1".into();
    assert!(validate_contract_artifact(&artifact, "con_profile", Some(&source)).is_err());
}

#[test]
fn omitted_compiler_options_preserve_numeric_source_digits() {
    let fixture: Value = serde_json::from_str(include_str!("fixtures/con_numeric_v2.json")).unwrap();
    let source = fixture["input_source"].as_str().unwrap();
    let module = fixture["module_name"].as_str().unwrap();
    let unit = xian_compiler_core::SourceUnit::new(module, source).unwrap();
    assert_eq!(unit.vm_profile(), "xian_vm_v2");
    for options in [CompileOptions::default(), serde_json::from_str("{}").unwrap()] {
        let result = compile_contract_artifact(module, source, &options).unwrap();
        assert_eq!(serde_json::to_value(result).unwrap(), fixture["artifact"]);
    }
}
