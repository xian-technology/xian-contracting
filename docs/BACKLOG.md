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

## Binary-float operator compatibility

Explicit binary-float values currently reject floor division, remainder and
`divmod` (for example `divmod(float('1'), float('0.1'))`). The determinism corpus
records these as explicit unsupported-operation boundaries, not Python parity.
A separate compatibility change needs signed-zero, negative quotient/remainder,
subnormal and rounding-boundary cases plus historical and cross-platform evidence.
NaN-payload constructor syntax is also rejected; canonical NaN values remain
separately tested.

Current code executes only V2, which exposes bounded integers and exact
fixed-point decimals rather than binary-float values. (Archival V1 binary-float
power belongs to the pinned older release that still executes V1.)
