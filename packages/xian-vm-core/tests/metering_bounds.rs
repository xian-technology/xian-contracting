//! CPU time per charged chi stays within a fixed factor of a plain loop.
//!
//! Each probe repeats one container operation whose work grows with the
//! container (comparison, membership, search, copy, dictionary access,
//! rendering). `xvm-gas-4` charges that element work, so the time per raw chi
//! unit of every probe stays close to the time per unit of an arithmetic loop.
//! Before element work was charged these ratios ranged from hundreds to tens of
//! thousands. The fixture is compiled from its embedded `source`.
use serde_json::Value;
use std::time::Instant;
use xian_vm_core::{ModuleIr, VmExecutionError, VmHost, VmInstance, VmValue};

/// Allowed time per raw chi unit, relative to the arithmetic baseline loop.
const MAX_RELATIVE_COST: f64 = 40.0;
const PROBES: &[&str] = &[
    "eq",
    "lt",
    "contains",
    "index",
    "count",
    "dictbuild",
    "dictlookup",
    "dicteq",
    "concat",
    "slice",
    "listcopy",
    "tuplecopy",
    "strlist",
    "reverse",
    "insert0",
    "pop0",
    "mul",
    "sortedl",
    "summ",
    "joins",
    "dictcopy",
    "length",
    "setops",
    "extend",
    "strindex",
    "keys",
    "anyall",
    "zipl",
];

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
    let fixture: Value =
        serde_json::from_str(include_str!("vectors/metering_bounds_ir.json")).unwrap();
    serde_json::from_value(fixture["ir"].clone()).unwrap()
}

/// Best of three runs, in seconds per raw chi unit. A probe may stop at a
/// resource limit; its charged work up to that point still counts.
fn seconds_per_unit(module: &ModuleIr, function: &str, n: i64, k: i64) -> f64 {
    (0..3)
        .map(|_| {
            let mut host = MeteredHost::default();
            let mut instance = VmInstance::new(module.clone(), Default::default()).unwrap();
            let started = Instant::now();
            let _ = instance.call_function(
                &mut host,
                function,
                vec![VmValue::Int(n.into()), VmValue::Int(k.into())],
                vec![],
            );
            started.elapsed().as_secs_f64() / host.raw_cost.max(1) as f64
        })
        .fold(f64::INFINITY, f64::min)
}

#[test]
fn container_work_is_charged_in_proportion_to_cpu_time() {
    let module = module();
    let baseline = seconds_per_unit(&module, "base", 2_000, 40);
    let mut failures = Vec::new();
    for probe in PROBES {
        let relative = seconds_per_unit(&module, probe, 2_000, 40) / baseline;
        if relative > MAX_RELATIVE_COST {
            failures.push(format!("{probe}: {relative:.1}x"));
        }
    }
    assert!(failures.is_empty(), "under-metered probes: {failures:?}");
}
