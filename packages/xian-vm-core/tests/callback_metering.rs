//! A builtin that calls a function once per element pays each call's dispatch.
//!
//! `f(x)` written in a contract pays the call dispatch (5000 raw chi) before
//! the callee runs. `map`, `filter`, `sorted(key=...)`, `min`/`max(key=...)`
//! call their function from the host once per element; those calls paid no
//! dispatch unless the callee was a host callable, so `map(abs, data)` cost
//! about a twelfth of the equivalent loop per unit of CPU time. Comparing an
//! input `EXTRA` elements longer cancels every per-call cost except the
//! per-element work.
use xian_compiler_core::{lower_source_to_ir, CompileOptions};
use xian_vm_core::{ModuleIr, VmExecutionError, VmHost, VmInstance, VmValue};

/// Raw chi of one call dispatch.
const CALL_DISPATCH: u64 = 5_000;
const BASE: i64 = 4;
const EXTRA: i64 = 100;

const SOURCE: &str = r#"
def ident(x):
    return x

@export
def mapped(n: int):
    return len(tuple(map(abs, range(n))))

@export
def mapped_local(n: int):
    return len(tuple(map(ident, range(n))))

@export
def filtered(n: int):
    return len(tuple(filter(abs, range(n))))

@export
def keyed_sort(n: int):
    return len(sorted(range(n), key=abs))

@export
def keyed_max(n: int):
    return max(range(n), key=ident)
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
    let ir = lower_source_to_ir("con_callbacks", SOURCE, &CompileOptions::default()).unwrap();
    serde_json::from_value(ir).unwrap()
}

fn cost(module: &ModuleIr, function: &str, elements: i64) -> u64 {
    let mut host = MeteredHost::default();
    let mut instance = VmInstance::new(module.clone(), Default::default()).unwrap();
    instance
        .call_function(
            &mut host,
            function,
            vec![VmValue::Int(elements.into())],
            vec![],
        )
        .unwrap();
    host.raw_cost
}

#[test]
fn each_callback_call_pays_a_call_dispatch() {
    let module = module();
    for function in [
        "mapped",
        "mapped_local",
        "filtered",
        "keyed_sort",
        "keyed_max",
    ] {
        let extra = cost(&module, function, BASE + EXTRA) - cost(&module, function, BASE);
        assert!(
            extra >= EXTRA as u64 * CALL_DISPATCH,
            "{function}: {EXTRA} more callback calls cost only {extra} raw chi"
        );
    }
}
