# Safety Invariants

This file records the runtime properties that must hold before a
`xian-contracting` release is considered safe.

## Contract Execution

- Failed execution must not persist writes, events, or partially mutated nested
  state.
- Contract Python globals must not leak across transactions.
- Prefix scans and collection helpers must not hand out live mutable references
  into stored state.
- Submission metadata and compiled artifacts must stay deterministic for the
  same source input.

## Metering

- Metering must never under-charge relative to the native-instruction tracer
  audit baseline.
- Transaction-byte and host-write costs must remain deterministic across
  validators.
- Native helper paths may over-charge conservatively, but they must not
  under-meter.

## VM Parity

- `xian_vm_v1` execution must match the Python runtime for result, writes,
  events, and failure mode across the curated conformance matrix.
- Stateful contract sequences must preserve the same committed state in both
  runtimes, including rollback after deliberate post-write failure.
- Deployment-artifact validation must reject malformed or incompatible VM IR.

## Release Gate

Use `./scripts/validate-release.sh` before release. The gate covers:

- lint and format checks
- default pytest coverage
- Rust package checks for the native tracer, zk package, and VM core
- zk Python tests
- optional-native tracer / zk / VM parity tests
- stateful Python-vs-native VM fuzz coverage

The existing security tests in `tests/security/` and the VM parity tests in
`tests/integration/` are the enforcement surface for these invariants.
