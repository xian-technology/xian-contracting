//! Every item an iterator yields from a `bytes` or `bytearray` is charged.
//!
//! Iterating a binary payload creates one integer per byte. Before
//! revision 14 only the payload copy was charged (one element-work unit per
//! 64 bytes), so a builtin consumer (`bytearray(b)`, `bytes(reversed(b))`,
//! `bytes(map(abs, b))`) turned a 128 KiB payload into 128 Ki items for
//! about two thousand units: 60 to 400 times the CPU time per chi of plain
//! interpreter work. Each yielded byte now costs one unit, as each item of
//! a list or string copy does. Comparing a payload `EXTRA` bytes longer
//! cancels every per-call cost except the per-item work.
use xian_compiler_core::{lower_source_to_ir, CompileOptions};
use xian_vm_core::{ModuleIr, VmExecutionError, VmHost, VmInstance, VmValue};

/// Raw chi per element-work unit.
const ELEMENT_WORK: u64 = 24;
const BASE: i64 = 64;
const EXTRA: i64 = 6_400;

const SOURCE: &str = r#"
@export
def construct(n: int):
    return len(bytearray(b'a' * n))

@export
def reverse(n: int):
    return len(bytes(reversed(b'a' * n)))

@export
def mapped(n: int):
    return len(bytes(map(abs, b'a' * n)))

@export
def filtered(n: int):
    return len(bytes(filter(None, bytearray(n))))

@export
def listed(n: int):
    return len(list(b'a' * n))
"#;

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

fn module() -> ModuleIr {
    let ir = lower_source_to_ir("con_bytes", SOURCE, &CompileOptions::default()).unwrap();
    serde_json::from_value(ir).unwrap()
}

fn cost(module: &ModuleIr, function: &str, bytes: i64) -> u64 {
    let mut host = MeteredHost::default();
    let mut instance = VmInstance::new(module.clone(), Default::default()).unwrap();
    instance
        .call_function(
            &mut host,
            function,
            vec![VmValue::Int(bytes.into())],
            vec![],
        )
        .unwrap();
    host.raw_cost
}

#[test]
fn each_byte_an_iterator_yields_is_one_unit_of_work() {
    let module = module();
    for function in ["construct", "reverse", "mapped", "filtered", "listed"] {
        let extra = cost(&module, function, BASE + EXTRA) - cost(&module, function, BASE);
        assert!(
            extra >= EXTRA as u64 * ELEMENT_WORK,
            "{function}: {EXTRA} more bytes cost only {extra} raw chi"
        );
    }
}
