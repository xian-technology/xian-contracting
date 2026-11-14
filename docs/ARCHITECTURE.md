# Architecture

`xian-contracting` owns two related but separate surfaces:

- the compiler/artifact surface, which turns authored source into canonical
  IR tagged with the selected profile (V2 by default) and optional offline artifacts
- the local harness surface, which lets developers test contracts against
  deterministic storage and stdlib behavior without running a node

The public local client compiles and executes contracts with the same Rust
compiler and V2 VM as validators. Its storage and call context are local to
the test. `ContractingClient` rejects V1 profiles, including V1 profiles
selected by an injected driver.

Every contract call runs in Rust: blocks in `xian_vm_core.BlockExecutor`, single
calls (local client, simulations, views, genesis deploys) in
`xian_vm_core.execute_tx`, with the same preparation, entry checks, host
syscalls and metering. There is no Python execution host. V1 compilation, IR
validation and stored-value encoding remain for migration and archival tooling;
current code does not execute V1. Immutable historical observations, frozen
golden outputs and independent semantic models provide conformance evidence.

Main areas:

- `src/contracting/compilation/`: compiler, linter, parser, and allowlists
- `src/contracting/artifacts/`: public source compiler, artifact builder, and
  validator
- `src/contracting/local/`: local test harness entrypoint
- `src/contracting/execution/`: execution-error classification
- `src/contracting/storage/`: LMDB-backed state, key encoding, contract
  artifacts, and ORM helpers
- `src/contracting/stdlib/`: the stdlib manifest and host-side helpers
  (hashing, crypto, and the zk helpers node tooling uses for shielded
  preverification)
- `packages/`: separately publishable packages:
  `xian-tech-runtime-types`, `xian-tech-accounts`,
  `xian-tech-compiler-core`, `xian-tech-vm-core`, and `xian-tech-zk`; the
  Rust-only crate `xian-fastpath-core` (transaction wire decoding and static
  admission) is linked into `xian-tech-vm-core`
- `scripts/`: VM/runtime audit tools and pinned historical capture tooling
- `tests/`: unit, integration, security, and performance coverage

This repo is consensus-sensitive. Changes to compilation output, execution
semantics, storage encoding, metering, import restrictions, or stdlib behavior
should be treated as protocol-affecting.

## Boundary Rules

- SDK and CLI deployment flows must submit cleartext source. Validators compile
  that source and persist canonical IR.
- The local harness derives exported-call proxies from contract metadata; it
  executes canonical VM IR rather than transformed Python source.
- Validators derive the stored executable payload, `vm_ir_json`, from submitted
  source under their configured execution profile.
- The Rust compiler core is the compiler/artifact authority behind public APIs.
  Python source inspection and archival V1 IR tooling must not compile or
  execute contract source as CPython bytecode.
- Execution-error classification must be importable without a Python
  execution engine, import hook or line tracer.
- Historical Python observers run only with their pinned archived package in
  isolated capture environments; they are not an alternate current runtime.
