# Architecture

`xian-contracting` owns two related but separate surfaces:

- the compiler/artifact surface, which turns authored source into canonical
  IR tagged with the selected profile (V2 by default) and optional offline artifacts
- the local harness surface, which lets developers test contracts against
  deterministic storage and stdlib behavior without running a node

The public local client compiles and executes contracts with the same Rust
compiler and V2 VM as validators. Its storage and call context are local to
the test. `ContractingClient` and `ParallelBatchExecutor` reject V1 profiles,
including V1 profiles selected by an injected driver.

Low-level native V1 bindings, artifact tools and storage remain available for
historical verification and migration. Immutable historical observations and
independent semantic models provide conformance evidence. Authored contract code
executes in the native VM rather than as CPython bytecode; Python host bindings
continue to provide explicit context, storage and bridge operations.

Main areas:

- `src/contracting/compilation/`: compiler, linter, parser, and allowlists
- `src/contracting/artifacts/`: public source compiler, artifact builder, and
  validator
- `src/contracting/local/`: local test harness entrypoint
- `src/contracting/execution/`: shared native host context and execution-error
  classification, plus speculative parallel batch execution primitives
- `src/contracting/storage/`: LMDB-backed state, key encoding, contract
  artifacts, and ORM helpers
- `src/contracting/stdlib/`: deterministic contract stdlib bridge modules
- `packages/`: separately publishable packages:
  `xian-tech-runtime-types`, `xian-tech-accounts`,
  `xian-tech-compiler-core`, `xian-tech-fastpath-core`,
  `xian-tech-vm-core`, and `xian-tech-zk`
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
- Shared host context and execution-error classification must be importable
  without a Python execution engine, import hook or line tracer.
- Historical Python observers run only with their pinned archived package in
  isolated capture environments; they are not an alternate current runtime.
