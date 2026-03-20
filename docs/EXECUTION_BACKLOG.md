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

Potential hardening steps for the current tracer:

- forbid multiple statements per line in contract source
- forbid ternary expressions
- forbid lambdas
- restrict or forbid complex comprehensions if they create poor line-cost
  precision
- reject lines whose compiled bytecode bucket exceeds a configured threshold
- add explicit metering and limits for returned payloads
- keep gas schedule changes versioned and explicit
- extend workload tests to include contracts designed to probe tracer blind
  spots

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
`xian-native-tracer` package.

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

Parallel execution is not trivial and should not be implemented as naive
concurrent mutation.

Safe direction:

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

## Rollout Order

1. Keep the pure-Python tracer as the stable default.
2. Harden the current tracer with language restrictions and workload coverage.
3. Define a tracer backend abstraction.
4. Add an optional Rust native tracer backend later.
5. Prototype speculative parallel execution only after the execution model and
   workload harness are stronger.
