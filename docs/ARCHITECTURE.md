# Architecture

`xian-contracting` owns two related but separate surfaces:

- the compiler/artifact surface, which turns authored source into canonical
  IR tagged with the selected profile (V2 by default) and optional offline artifacts
- the local harness surface, which lets developers test contracts against
  deterministic storage and stdlib behavior without running a node

The default local client compiles and executes contracts with the same Rust
compiler and V2 VM as validators. Its storage and call context are local to
the test. The explicit V1 harness also serves as a compatibility oracle.

Main areas:

- `src/contracting/compilation/`: compiler, linter, parser, and allowlists
- `src/contracting/artifacts/`: public source compiler, artifact builder, and
  validator
- `src/contracting/local/`: local test harness entrypoint
- `src/contracting/execution/`: runtime, executor, module loading, local
  tracing, and speculative parallel batch execution primitives
- `src/contracting/storage/`: LMDB-backed state, key encoding, contract
  artifacts, and ORM helpers
- `src/contracting/stdlib/`: deterministic contract stdlib bridge modules
- `packages/`: separately publishable packages:
  `xian-tech-runtime-types`, `xian-tech-accounts`,
  `xian-tech-compiler-core`, `xian-tech-fastpath-core`,
  `xian-tech-vm-core`, and `xian-tech-zk`
- `scripts/`: VM/runtime audit tools and parity fixture generation
- `tests/`: unit, integration, security, and performance coverage

This repo is consensus-sensitive. Changes to compilation output, execution
semantics, storage encoding, metering, import restrictions, or stdlib behavior
should be treated as protocol-affecting.

## Boundary Rules

- SDK and CLI deployment flows must submit cleartext source. Validators compile
  that source and persist canonical IR.
- The local harness may derive transient Python source/proxies for tests, but
  that output is not a deployable chain artifact.
- Validators derive the stored executable payload, `vm_ir_json`, from submitted
  source under their configured execution profile.
- The Rust compiler core is the compiler/artifact authority behind public APIs;
  the Python transformer is limited to local-harness execution support.
