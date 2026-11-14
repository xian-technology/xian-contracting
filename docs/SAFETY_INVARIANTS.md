# Safety Invariants

This file records the runtime properties that must hold before a
`xian-contracting` release is considered safe.

## Contract Execution

- Failed execution must not persist writes, events, or partially mutated nested
  state.
- Contract module globals must not leak across transactions.
- Prefix scans and collection helpers must not hand out live mutable references
  into stored state.
- Submission metadata and validator-derived VM IR must stay deterministic for
  the same source input.
- A stored contract owner must match the immediate caller at both transaction
  entry and nested contract calls.
- Only the executing submission contract may invoke deployment and metadata
  mutation syscalls; constructors do not inherit submission's authority.
- Recursive execution is limited to 128 active interpreter frames across local
  calls, expression/block evaluation, assignments, comprehensions, lazy iterators,
  module initialization, cross-contract calls and constructors. Nested executors
  share the transaction's counter even when metering is disabled; every exit
  releases its frames.
- Aggregate f-string output is bounded to 128 KiB in UTF-8 bytes before each
  append, including literals and formatted fields.

## Signature Verification

- Native admission and VM `crypto.verify` reject small-order public keys and
  signature points using strict Ed25519 verification.
- Transaction admission exists once, in Rust (`xian-fastpath-core` linked into
  `xian-vm-core`), and rejects adversarial signatures, including identity-point
  forgeries and noncanonical scalars. Any change to what it admits must leave
  `xian-abci/tests/fixtures/admission_parity.json` unchanged or come with a new
  transaction admission revision.
- Signature-policy changes require a coordinated validator release. SDK
  verification must apply compatible rejection rules.

## Metering

- Metering must follow the versioned native VM instruction and host-operation
  cost schedule.
- Transaction-byte and host-write costs must remain deterministic across
  validators.
- Native helper paths may over-charge conservatively, but they must not
  under-meter.
- Entry execution, host costs, and serial or nested constructors share one
  transaction budget. Zero and oversized metered budgets are capped at the
  profile's ceiling: 1,000,000 chi (1,000,000,000 raw) for V2, reported as
  `runtime_info()["max_tx_chi"]`, and the historical 50,000,000 chi
  (50,000,000,000 raw) for archival V1.
- Failure rolls back state, not the cost of work already performed. Failed
  constructor costs remain in the transaction's charge and attribution.

## VM Conformance

- With no profile selected, a local compiler or test client must produce the same V2
  artifacts and contract results as explicit fresh-chain execution.
- Public `ContractingClient` execution is V2-only; explicit V1 profiles and
  injected V1 drivers fail before creating client state.
- Low-level native `xian_vm_v1` historical verification must retain strict
  comparisons of results, writes, events and failures with immutable,
  provenance-checked Python observations.
- Stateful contract sequences must agree with independent semantic models,
  including committed state and rollback after deliberate post-write failure.
- Native deployment must reject client-supplied IR artifacts and derive VM IR
  from submitted source before staging contract writes.

## Host Independence

- Importing or executing native contracts must not load a Python contract
  executor, install Python import hooks or activate a CPython line tracer.
- Native host calls use only explicit execution context. A previous host value
  must never supply a missing transaction seed or block field.
- The node forwards its transaction input hash into native random seeding.
- Protocol write and cost maps have stable key ordering; nested authored
  dictionaries preserve their language-defined insertion order.
- Exact determinism campaigns retain value types, float bits, decimal cohorts,
  ordering, costs, outcomes, artifacts and persisted state. Normalization must
  not hide a difference in an observable contract value.
- The same recorded corpus must pass across supported native platforms. Host
  perturbation and cross-platform equality complement semantic oracles; neither
  alone establishes correctness for untested inputs.

## Release Gate

Use `./scripts/validate-release.sh` before release. The gate covers:

- lint and format checks
- default pytest coverage
- Rust package checks for the zk package and VM core
- zk Python tests
- optional-native zk / VM conformance tests
- stateful model-based VM fuzz coverage

The existing security tests in `tests/security/` and the VM conformance tests in
`tests/integration/` are the enforcement surface for these invariants.
