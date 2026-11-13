//! Dictionary operations through every entry point, in V2 (hash index, in
//! place) and archival V1 (linear scan, copy and replace).
//!
//! The fixture is compiled from its embedded `source` by the canonical
//! compiler for both profiles. Results are the same in both profiles except
//! where V2 equality keeps `True` and `1` apart. V1 costs are pinned to the
//! values of `xvm-execution-11`: V1 must not change. V2 costs follow
//! `xvm-gas-6`; the time bound separates linear from quadratic work.
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

fn call(
    profile_ir: &str,
    function: &str,
    args: Vec<VmValue>,
) -> (Result<VmValue, VmExecutionError>, u64) {
    let fixture: Value = serde_json::from_str(include_str!("vectors/dict_index_ir.json")).unwrap();
    let module: ModuleIr = serde_json::from_value(fixture[profile_ir].clone()).unwrap();
    let mut host = MeteredHost::default();
    let mut instance = VmInstance::new(module, Default::default()).unwrap();
    let result = instance.call_function(&mut host, function, args, vec![]);
    (result, host.raw_cost)
}

fn int(value: i64) -> VmValue {
    VmValue::Int(value.into())
}

fn text(value: &str) -> VmValue {
    VmValue::String(value.into())
}

fn items(entries: &[(&str, i64)]) -> VmValue {
    VmValue::List(
        entries
            .iter()
            .map(|(key, value)| VmValue::Tuple(vec![text(key), int(*value)]))
            .collect(),
    )
}

fn expected_operations(mixed: VmValue) -> VmValue {
    let t = VmValue::Bool(true);
    let f = VmValue::Bool(false);
    let final_items = [("a", 11), ("c", 3), ("e", 5), ("f", 6), ("g", 7), ("h", 8)];
    VmValue::List(vec![
        int(10),
        t.clone(),
        f.clone(),
        t.clone(),
        t.clone(),
        int(2),
        int(-1),
        int(2),
        int(-2),
        VmValue::Tuple(vec![text("d"), int(4)]),
        int(10),
        int(5),
        items(&final_items),
        items(&[("a", 1), ("b", 2)]),
        t,
        VmValue::List(vec![
            items(&[
                ("a", 12),
                ("c", 3),
                ("e", 5),
                ("f", 6),
                ("g", 7),
                ("h", 8),
                ("i", 9),
            ]),
            items(&[("a", 22), ("f", 12), ("g", 14), ("h", 16)]),
            items(&[("x", 2), ("y", 3)]),
        ]),
        VmValue::List(vec![
            items(&[("p", 0), ("q", 0)]),
            items(&[
                ("a", 13),
                ("c", 3),
                ("e", 5),
                ("f", 6),
                ("g", 7),
                ("h", 8),
                ("j", 10),
            ]),
            items(&[
                ("a", 11),
                ("c", 3),
                ("e", 5),
                ("f", 6),
                ("g", 7),
                ("h", 8),
                ("k", 11),
            ]),
        ]),
        mixed,
    ])
}

#[test]
fn every_entry_point_keeps_python_dictionary_semantics() {
    let (v2, v2_cost) = call("ir", "operations", vec![]);
    let (v1, v1_cost) = call("ir_v1", "operations", vec![]);
    // V2 keeps True and 1 apart; V1 merges them as Python does.
    assert_eq!(
        v2.unwrap(),
        expected_operations(VmValue::List(vec![
            text("int"),
            text("bool"),
            text("tuple"),
            text("set"),
            int(4)
        ]))
    );
    assert_eq!(
        v1.unwrap(),
        expected_operations(VmValue::List(vec![
            text("bool"),
            text("bool"),
            text("tuple"),
            text("set"),
            int(3)
        ]))
    );
    assert_eq!((v2_cost, v1_cost), (324_466, 316_744));
}

#[test]
fn errors_are_unchanged() {
    for ir in ["ir", "ir_v1"] {
        for (kind, message) in [
            ("missing", "missing dict key z"),
            ("unhashable", "unhashable type: 'list'"),
            ("pop", "missing dict key z"),
            ("popitem", "popitem(): dictionary is empty"),
        ] {
            let (result, _) = call(ir, "errors", vec![text(kind)]);
            assert_eq!(result.unwrap_err().to_string(), message, "{ir} {kind}");
        }
    }
}

#[test]
fn v2_dictionaries_scale_linearly() {
    const N: i64 = 20_000;
    let started = Instant::now();
    let (result, cost) = call("ir", "scale", vec![int(N)]);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        result.unwrap(),
        VmValue::List(vec![int(N * (N - 1) / 2), int(0)])
    );
    let (_, small) = call("ir", "scale", vec![int(N / 10)]);
    // Linear: ten times the keys cost about ten times as much.
    assert!(cost < 11 * small, "{cost} vs {small}");
}

#[test]
fn v1_dictionary_costs_are_unchanged() {
    let (result, cost) = call("ir_v1", "scale", vec![int(300)]);
    assert_eq!(
        result.unwrap(),
        VmValue::List(vec![int(300 * 299 / 2), int(0)])
    );
    assert_eq!(cost, 6_610_092);
}
