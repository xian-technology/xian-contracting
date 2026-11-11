//! Element access on a referenced list must not copy the whole list.
//!
//! The fixture is compiled from its embedded `source` by the canonical compiler.
//! Results are fixed and costs follow the `xvm-gas-4` schedule (including
//! element work). The time bound only separates linear from quadratic work:
//! the implementation that copied the list on every access needed minutes.
use serde_json::Value;
use std::time::{Duration, Instant};
use xian_vm_core::{ModuleIr, VmExecutionError, VmHost, VmInstance, VmValue};

#[derive(Default)]
struct MeteredHost {
    raw_cost: u64,
}

impl VmHost for MeteredHost {
    fn charge_execution_cost(&mut self, cost: u64) -> Result<(), VmExecutionError> {
        self.raw_cost += cost;
        Ok(())
    }
}

fn call(function: &str, args: Vec<VmValue>) -> (Result<VmValue, VmExecutionError>, u64) {
    let fixture: Value =
        serde_json::from_str(include_str!("vectors/container_access_ir.json")).unwrap();
    let module: ModuleIr = serde_json::from_value(fixture["ir"].clone()).unwrap();
    let mut host = MeteredHost::default();
    let mut instance = VmInstance::new(module, Default::default()).unwrap();
    let result = instance.call_function(&mut host, function, args, vec![]);
    (result, host.raw_cost)
}

fn int(value: i64) -> VmValue {
    VmValue::Int(value.into())
}

fn bounded(function: &str, n: i64) -> (VmValue, u64) {
    let started = Instant::now();
    let (result, cost) = call(function, vec![int(n)]);
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{function}({n}) took {:?}",
        started.elapsed()
    );
    (result.unwrap(), cost)
}

const N: i64 = 50_000;

#[test]
fn appends_keep_linear_time_and_fixed_cost() {
    let (result, cost) = bounded("appended", N);
    assert_eq!(result, VmValue::List(vec![int(N), int(0), int(N - 1)]));
    assert_eq!(cost, 262_811_176);
}

#[test]
fn indexed_reads_and_writes_keep_linear_time_and_alias_semantics() {
    let (result, cost) = bounded("indexed", N);
    assert_eq!(
        result,
        VmValue::List(vec![
            int(N * (N - 1)),
            VmValue::String("last".into()),
            int(N)
        ])
    );
    assert_eq!(cost, 61_222_792);
}

#[test]
fn truthiness_of_a_large_list_keeps_linear_time() {
    let (result, cost) = bounded("method_dispatch", N);
    assert_eq!(result, int(N));
    assert_eq!(cost, 27_615_672);
}

#[test]
fn in_place_item_assignment_keeps_identity_and_bounds() {
    let (result, _) = call("self_reference", vec![]);
    assert_eq!(
        result.unwrap(),
        VmValue::List(vec![VmValue::Bool(true), int(2)])
    );
    let (error, _) = call("out_of_range", vec![]);
    assert_eq!(
        error.unwrap_err().to_string(),
        "sequence index out of bounds"
    );
}
