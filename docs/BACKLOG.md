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

Escapes in f-string format specifications need a source-aware parser repair.
For example, `f"{value:\x7b<4}"` should use `{` as the fill character, but
RustPython 0.4 retains the escape spelling in its AST. Repeated normalization
then grows the backslashes, and an artifact can fail validation immediately
after compilation. Fixing only the normalizer would hide the unstable artifact
without restoring the intended value. Preserve raw-string prefixes and adjacent
literal boundaries, then test normal/raw escapes, named Unicode escapes,
dynamic specifications, canonical idempotence and artifact self-validation.
This remains an open bug; the execution-4 quote/dictionary/control-character
normalization fixes do not resolve it.

Other admission decisions remain separate: RustPython 0.4 does not implement
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
