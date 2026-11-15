//! Compile work grows with the program, not with its square: contracts that
//! drove the earlier fixpoint inference (and handle-source lowering) into
//! minutes of unmetered work compile, or are refused, at once, with the same
//! result as before.
use std::time::{Duration, Instant};

use serde_json::Value;
use xian_compiler_core::{compile_contract_source, CompileOptions, CompiledSource};

/// Far above what these programs need now (milliseconds, also unoptimized)
/// and far below what they needed before (seconds to minutes).
const PROMPT: Duration = Duration::from_secs(3);

fn compile(source: &str) -> (Result<CompiledSource, String>, Duration) {
    let started = Instant::now();
    let result = compile_contract_source("con_bound", source, &CompileOptions::default()).map_err(
        |diagnostics| {
            diagnostics
                .iter()
                .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
                .collect::<Vec<_>>()
                .join("\n")
        },
    );
    (result, started.elapsed())
}

fn contract_targets(node: &Value, output: &mut Vec<Value>) {
    match node {
        Value::Object(fields) => {
            if let Some(target) = fields.get("contract_target") {
                output.push(target.clone());
            }
            fields
                .values()
                .for_each(|value| contract_targets(value, output));
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| contract_targets(value, output)),
        _ => {}
    }
}

fn targets_of(compiled: &CompiledSource) -> Vec<Value> {
    let ir: Value = serde_json::from_str(&compiled.vm_ir_json).expect("IR is JSON");
    let mut targets = Vec::new();
    contract_targets(&ir, &mut targets);
    targets
}

/// `F{i}` returns its parameter; `U{i}` passes `F{i-1}(con_token)` to it, so
/// each factory needs one more whole-program pass than the one before.
fn alternating_factories(count: usize) -> String {
    let mut source = String::from("import con_token\n");
    for index in 0..count {
        let argument = if index == 0 {
            "con_token".to_owned()
        } else {
            format!("F{}(con_token)", index - 1)
        };
        source.push_str(&format!(
            "def F{index}(p):\n    return p\ndef U{index}():\n    return F{index}({argument})\n"
        ));
    }
    source.push_str("@export\ndef go():\n    return 1\n");
    source
}

#[test]
fn a_long_local_alias_chain_compiles_promptly() {
    // a{n} = a{n-1}, ..., a1 = con_token: each in-order sweep binds one more.
    let links = 2_000;
    let mut source = String::from("import con_token\n@export\ndef go():\n");
    for index in (2..=links).rev() {
        source.push_str(&format!("    a{index} = a{}\n", index - 1));
    }
    source.push_str(&format!(
        "    a1 = con_token\n    return a{links}.balance_of(address='x')\n"
    ));

    let (result, elapsed) = compile(&source);
    let compiled = result.expect("the chain compiles");
    assert!(elapsed < PROMPT, "took {elapsed:?}");
    let targets = targets_of(&compiled);
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0]["kind"], "local_handle");
    assert_eq!(targets[0]["binding"], format!("a{links}"));
    assert_eq!(targets[0]["source"]["id"], format!("a{}", links - 1));
}

#[test]
fn alternating_factories_compile_promptly_up_to_the_pass_limit() {
    let (result, elapsed) = compile(&alternating_factories(510));
    assert!(result.is_ok(), "{result:?}");
    assert!(elapsed < PROMPT, "took {elapsed:?}");

    // One more needs pass 513 of the earlier inference: refused as before.
    let (result, elapsed) = compile(&alternating_factories(511));
    assert_eq!(
        result.expect_err("over the pass limit"),
        "xian.ir.lowering_error: contract handle inference exceeded the maximum of 512 passes"
    );
    assert!(elapsed < PROMPT, "took {elapsed:?}");
}

#[test]
fn a_local_handle_is_bound_by_the_first_ready_assignment_of_the_earliest_sweep() {
    // The first sweep cannot bind `x = y` (y is not bound yet) but binds
    // `y = con_token` and then `x = con_token`: x's source is con_token.
    // (Spans are lines of the normalized source, one line further down.)
    let source = "import con_token\n@export\ndef go():\n    x = y\n    y = con_token\n    \
                  x = con_token\n    x.transfer(amount=1, to='a')\n    \
                  return y.balance_of(address='a')\n";
    let (result, _) = compile(source);
    let targets = targets_of(&result.expect("compiles"));
    let sources: Vec<_> = targets
        .iter()
        .map(|target| {
            (
                target["binding"].clone(),
                target["source"]["id"].clone(),
                target["source"]["span"]["line"].clone(),
            )
        })
        .collect();
    assert_eq!(
        sources,
        [
            ("x".into(), "con_token".into(), 7.into()),
            ("y".into(), "con_token".into(), 6.into()),
        ]
    );
}

#[test]
fn module_aliases_of_aliases_resolve_in_any_order() {
    let source = "b = a\na = hashlib\n@export\ndef go(value: str):\n    return b.sha3(value)\n";
    let (result, _) = compile(source);
    let ir: Value = serde_json::from_str(&result.expect("compiles").vm_ir_json).expect("JSON");
    let call = &ir["functions"][0]["body"][0]["value"];
    assert_eq!(call["syscall_id"], "hash.sha3_256_legacy");
}

#[test]
fn many_copies_of_a_large_handle_source_are_refused_promptly_at_the_ir_limit() {
    // Every use of `h` carries a copy of its source `mk([...])` in the IR.
    let argument = (0..1_000)
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let mut source = format!(
        "import con_token\ndef mk(a):\n    return con_token\n@export\ndef go():\n    h = mk([{argument}])\n"
    );
    for _ in 0..1_000 {
        source.push_str("    h.f()\n");
    }
    source.push_str("    return 1\n");

    let (result, elapsed) = compile(&source);
    assert_eq!(
        result.expect_err("the IR is far over 1 MiB"),
        "xian.limit.ir_json_bytes: contract IR exceeds the maximum of 1048576 UTF-8 bytes"
    );
    assert!(elapsed < PROMPT, "took {elapsed:?}");
}
