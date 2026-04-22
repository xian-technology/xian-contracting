# Architecture

`xian-contracting` owns contract compilation, execution, storage, tracing, and
deterministic runtime semantics.

Main areas:

- `src/contracting/compilation/`: compiler, linter, parser, and allowlists
- `src/contracting/execution/`: runtime, executor, module loading, tracer
  backends, and speculative parallel batch execution primitives
- `src/contracting/storage/`: LMDB-backed state, key encoding, contract
  artifacts, and ORM helpers
- `src/contracting/stdlib/`: deterministic contract stdlib bridge modules
- `packages/`: separately publishable packages:
  `xian-tech-runtime-types`, `xian-tech-accounts`,
  `xian-tech-fastpath-core`, `xian-tech-native-tracer`,
  `xian-tech-vm-core`, and `xian-tech-zk`
- `scripts/`: VM/runtime audit tools and parity fixture generation
- `tests/`: unit, integration, security, and performance coverage

This repo is consensus-sensitive. Changes to compilation output, execution
semantics, storage encoding, metering, import restrictions, or stdlib behavior
should be treated as protocol-affecting.
