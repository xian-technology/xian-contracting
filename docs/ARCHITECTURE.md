# Architecture

`xian-contracting` owns contract compilation, execution, storage, tracing, and deterministic runtime semantics.

Main areas:

- `src/contracting/compilation/`: compiler, linter, parser, and allowlists
- `src/contracting/execution/`: runtime, executor, module loading, and tracers
- `src/contracting/storage/`: LMDB-backed state, encoding, and ORM helpers
- `packages/`: shared runtime packages such as `xian-runtime-types` and the
  published `xian-tech-native-tracer`
- `tests/`: unit, integration, security, and performance coverage

This repo is consensus-sensitive. Changes to execution semantics, storage encoding, or metering should be treated as protocol-affecting.
