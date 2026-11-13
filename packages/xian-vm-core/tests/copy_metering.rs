//! Copying a referenced binary payload is charged per 64 bytes.
//!
//! Indexing a `bytearray` resolves its reference by copying the payload, so
//! each access costs one element-work unit per 64 bytes. The fixture is
//! compiled from its embedded `source` by the canonical compiler. Comparing
//! the extra cost of ten more accesses on a 6400-byte and a 64-byte buffer
//! cancels every per-access cost except the copy itself.
use serde_json::Value;
use xian_vm_core::{ModuleIr, VmExecutionError, VmHost, VmInstance, VmValue};

/// Raw chi per element-work unit under `xvm-gas-5`.
const ELEMENT_WORK: u64 = 24;

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

fn cost(bytes: i64, accesses: i64) -> u64 {
    let fixture: Value =
        serde_json::from_str(include_str!("vectors/copy_metering_ir.json")).unwrap();
    let module: ModuleIr = serde_json::from_value(fixture["ir"].clone()).unwrap();
    let mut host = MeteredHost::default();
    let mut instance = VmInstance::new(module, Default::default()).unwrap();
    let result = instance.call_function(
        &mut host,
        "index",
        vec![VmValue::Int(bytes.into()), VmValue::Int(accesses.into())],
        vec![],
    );
    assert_eq!(result.unwrap(), VmValue::Int(0.into()));
    host.raw_cost
}

#[test]
fn each_access_to_a_referenced_bytearray_pays_its_copy_per_64_bytes() {
    let small = cost(64, 11) - cost(64, 1);
    let large = cost(6400, 11) - cost(6400, 1);
    // Ten extra accesses, each copying (6400 - 64) / 64 = 99 more units.
    assert_eq!(large - small, 10 * 99 * ELEMENT_WORK);
}
