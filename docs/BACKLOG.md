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

- keep hardening local harness metering policy for standalone tests
- keep parallel execution serial-equivalent while improving integration and
  workload coverage
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

## Python harness aggregate f-string allocation

Runtime-only formatting guards bound individual f-string fields and cumulative
`str.format` / `format_map` output. Python's surrounding `JoinedStr` still uses
host string joining: two individually allowed 70,000-byte fields can produce a
140,000-byte f-string, exceeding the native 131,072-byte aggregate cap.
A bounded builder must preserve evaluation order and stop before evaluating
later fields once an append exceeds the cap. A post-join length check does not
prevent the allocation. Add paired failure/side-effect/rollback tests for nested
specifications and aggregate growth before replacing this execution-only AST
operation. Stored source, canonical artifacts and the native VM need no change.

## Binary-float operator compatibility

Explicit binary-float values currently reject floor division, remainder and
`divmod` (for example `divmod(float('1'), float('0.1'))`). The determinism corpus
records these as explicit unsupported-operation boundaries, not Python parity.
A separate compatibility change needs signed-zero, negative quotient/remainder,
subnormal and rounding-boundary cases plus historical and cross-platform evidence.
NaN-payload constructor syntax is also rejected; canonical NaN values remain
separately tested.

The authoritative native VM uses pinned software binary-float power under
execution5. The optional Python harness still delegates binary-float power to
host Python/libm; it is not an exact cross-platform oracle for those values.
Aligning that harness needs a shared portable math binding or a reviewed Python
implementation, not a tolerance that hides divergent stored values. Native
platform campaigns remain the release evidence for binary-float powers.
