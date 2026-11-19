# Backlog

This is the stable backlog entrypoint for `xian-contracting`.

Current deeper notes:

- `../tests/surface/README.md` — reviewed runtime surface, direct behavioral
  cases, explicit missing members and the coverage expansion workflow
- `EXECUTION_BACKLOG.md`
- `COMPILE_TIME_EXTENDS.md`
- `RUST_COMPILER_CORE.md`
- `ZK_PRIVACY_OPTIMIZATION_PLAN.md`

Current themes:

- keep native VM metering and local-client behavior covered by standalone tests
- keep VM conformance, metering calibration, and authored fixture coverage moving
- simplify storage/runtime internals only when deterministic behavior is
  unchanged and regression coverage is clear
- keep compiler cleanup behind behavior parity and measurable justification;
  use `RUST_COMPILER_CORE.md` as the migration plan if compiler ownership moves
  from Python to Rust

## Source parser compatibility

RustPython 0.4 does not implement
all PEP 701 same-delimiter f-strings; the tracer-era ban on single-line compound
bodies is retained, but does not consistently catch inline `else` bodies.
Decide whether that restriction remains part of VM source admission before
changing it. Historical acceptance alone is not evidence to bypass current
capability or resource boundaries.

## Transaction Throughput

- [Transaction throughput optimization plan](../../xian-meta/docs/TRANSACTION_THROUGHPUT_OPTIMIZATION_PLAN.md): proposed staged work
  on measurement, bounded immutable admission reuse, proposal scans, live
  admission and receipt costs. Preserve current execution semantics and
  remeasure before pursuing parallel contract execution.
