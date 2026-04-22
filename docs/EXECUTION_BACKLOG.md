# Execution Backlog

## Current Default

The default Xian execution path should remain:

- pure Python
- self-contained
- easy to install as a standalone library
- usable outside the full blockchain stack

Future execution backends must not compromise that default.

## Current Tracer Hardening Backlog

The current Python tracer is deterministic and protects the runtime from the
worst instruction-callback DoS paths, but it still has precision limits.

Recent hardening already landed:

- fixed Python 3.14 line metadata handling
- kept per-code tracer metadata warm across executions
- split tracer event ceilings by backend semantics
- made the opcode default-cost set explicit and test-guarded
- added workload tests for branch-heavy and loop-heavy tracer cases
- forbade ternary expressions, semicolons, and one-line compound statements
  in contract source

Remaining useful hardening steps:

- forbid lambdas
- restrict or forbid complex comprehensions if they create poor line-cost
  precision
- reject lines whose compiled bytecode bucket exceeds a configured threshold
- keep gas schedule changes versioned and explicit across supported CPython
  minors
- extend workload tests further with contracts designed to probe tracer blind
  spots beyond the current branch-heavy coverage

These changes are intended to reduce opportunities to game line-based charging
without changing the pure-Python default execution model.

## Return Value Metering

Return values are part of execution output and should not be free.

Current rule:

- meter the encoded return payload size
- reject return values larger than `MAX_RETURN_VALUE_SIZE`

This should remain deterministic and versioned as part of the execution policy.

## Future Native Tracer

`native_instruction_v1` now exists as an optional Rust-backed backend via the
`xian-tech-native-tracer` package.

What remains true:

- the pure-Python tracer remains the default
- `xian-contracting` keeps working without native extensions
- the native backend is optional and must be selected explicitly
- startup must fail loudly if a caller selects `native_instruction_v1` without
  the package installed

The remaining native-tracer backlog is about hardening, packaging, and policy.

Design direction:

- language: Rust
- Python binding layer: PyO3/maturin
- backend name: `native_instruction_v1`

Why Rust:

- strong safety properties relative to C
- good performance
- mature Linux/macOS packaging story for Python extensions
- simpler long-term maintenance than a niche toolchain

## Tracer Backend Policy

Tracer choice must be treated as execution policy, not a per-node preference,
when it changes gas semantics.

Suggested network-level execution config shape:

```yaml
execution:
  tracer:
    mode: python_line_v1
    gas_schedule: xian-2026-01
```

Possible modes:

- `python_line_v1`
- `native_instruction_v1`

Rules:

- all validators on a network must use the same tracer mode when gas semantics
  differ
- no silent fallback between tracer implementations
- gas schedule changes must be explicitly versioned

## Parallel Transaction Processing

Parallel execution now has a reusable `contracting.execution.parallel`
primitive for raw contract-call batches:

- `ExecutionRequest`
- `ExecutionAccess`
- `ParallelExecutionPlanner`
- `ParallelBatchExecutor`

It still must not become naive concurrent mutation.

Current safety model:

- keep canonical block transaction order unchanged
- execute transactions speculatively on snapshots
- collect deterministic read/write/event metadata per transaction
- validate speculative results against prior committed writes in canonical order
- commit serially in canonical order
- re-execute conflicting transactions serially

This keeps final semantics equivalent to serial execution.

Important distinction:

- tracer backend choice is consensus policy when it changes gas semantics
- parallel speculative execution can remain a local optimization if it is
  provably serial-equivalent

Required safeguards:

- deterministic scheduler
- bounded worker count
- conflict threshold and fallback rules
- read/write-set capture
- conservative first version with narrow eligibility
- workload tests designed to force conflicts and verify identical final state

Remaining useful work:

- harden multi-worker process-pool lifecycle behavior under long-running node
  workloads
- add broader performance coverage for high-conflict and mixed-conflict batches
- integrate only the generic runtime primitive into higher layers; keep ABCI
  decoding, nonce policy, rewards, and result shaping outside this repo
- keep proving serial equivalence with integration tests before enabling wider
  production usage

## Rollout Order

1. Keep the pure-Python tracer as the stable default.
2. Keep tightening the current tracer with targeted language restrictions and
   workload coverage.
3. Keep the tracer backend abstraction explicit and policy-versioned.
4. Harden the optional Rust native tracer further for long-term network use.
5. Treat speculative parallel execution as a local optimization and expand it
   only when serial-equivalence coverage and workload data justify it.
