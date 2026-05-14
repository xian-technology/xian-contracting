# Backlog

This is the stable backlog entrypoint for `xian-contracting`.

Current deeper notes:

- `EXECUTION_BACKLOG.md`
- `COMPILE_TIME_EXTENDS.md`
- `RUST_COMPILER_CORE.md`
- `ZK_PRIVACY_OPTIMIZATION_PLAN.md`

Current themes:

- keep hardening local harness metering policy for standalone tests
- keep parallel execution serial-equivalent while improving integration and
  workload coverage
- keep VM conformance, metering calibration, and authored fixture coverage moving
- simplify storage/runtime internals only when deterministic behavior is
  unchanged and regression coverage is clear
- keep compiler cleanup behind behavior parity and measurable justification;
  use `RUST_COMPILER_CORE.md` as the migration plan if compiler ownership moves
  from Python to Rust
