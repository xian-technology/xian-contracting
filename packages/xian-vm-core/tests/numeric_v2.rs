use num_bigint::BigInt;
use serde_json::{json, Value};
use xian_vm_core::{ModuleIr, VmDecimal, VmExecutionError, VmHost, VmInstance, VmValue};

struct Host;
impl VmHost for Host {}

fn execute(op: &str, lhs: VmValue, rhs: VmValue) -> Result<VmValue, VmExecutionError> {
    let span = json!({"line":1,"col":0,"end_line":1,"end_col":1});
    let name = |id: &str| json!({"node":"name","id":id,"span":span});
    let param = |id: &str| json!({"name":id,"kind":"positional_or_keyword","annotation":null,"default":null,"span":span});
    let op = json!({"node":"bin_op","operator":op,"left":name("a"),"right":name("b"),"span":span});
    let module: ModuleIr = serde_json::from_value(json!({
        "ir_version":"xian_ir_v1","vm_profile":"xian_vm_v2","host_catalog_version":"xian_vm_v1_host_v1",
        "module_name":"probe","source_hash":"0".repeat(64),"docstring":Value::Null,"imports":[],
        "global_declarations":[],"module_body":[],"host_dependencies":[],
        "functions":[{"node":"function","span":span,"name":"probe","visibility":"export","decorator":null,
        "docstring":null,"parameters":[param("a"),param("b")],"returns":null,
        "body":[{"node":"return","span":span,"value":op}]}]
    })).unwrap();
    VmInstance::new(module, Default::default())?.call_function(
        &mut Host,
        "probe",
        vec![lhs, rhs],
        vec![],
    )
}

fn int(v: i64) -> VmValue {
    VmValue::Int(v.into())
}
fn dec(v: &str) -> VmValue {
    VmValue::Decimal(VmDecimal::from_str_literal(v).unwrap())
}

#[test]
fn ratios_use_wide_exact_intermediates_and_one_truncation() {
    let large = VmValue::Int(BigInt::from(10).pow(65));
    assert_eq!(execute("div", large.clone(), large).unwrap(), dec("1"));
    assert_eq!(
        execute("div", int(-1), int(3)).unwrap(),
        dec("-0.333333333333333333333333333333")
    );
    assert_eq!(
        execute("div", dec("0.000000000000000000000000000001"), int(2)).unwrap(),
        dec("0")
    );
    assert!(execute("div", int(1), int(0)).is_err());
}

#[test]
fn signs_types_and_integer_bounds() {
    assert_eq!(execute("floordiv", int(-7), int(3)).unwrap(), int(-3));
    assert_eq!(execute("mod", int(-7), int(3)).unwrap(), int(2));
    assert!(execute("add", VmValue::Bool(true), int(1)).is_err());
    assert!(execute("div", VmValue::Float(1.0), int(1)).is_err());
    assert!(execute("mod", dec("2.5"), int(2)).is_err());
    assert!(execute("pow", int(2), int(512)).is_err());
    assert!(execute("pow", int(2), int(-1)).is_err());
    assert!(execute("pow", dec("2"), int(1)).is_err());
}
