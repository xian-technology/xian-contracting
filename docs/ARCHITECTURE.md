# Architecture

`xian-contracting` owns two related but separate surfaces:

- the compiler/artifact surface, which turns authored source into
  `xian_vm_v1` deployment artifacts
- the local harness surface, which lets developers test contracts against
  deterministic storage and stdlib behavior without running a node

Network execution is owned by the Xian VM. The local harness is a developer
tool and parity oracle; it is not a second chain runtime.

Main areas:

- `src/contracting/compilation/`: compiler, linter, parser, and allowlists
- `src/contracting/artifacts/`: public deployment artifact builder and
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

- SDK and CLI deployment flows should use deployment artifacts, not local harness
  internals.
- The local harness may derive transient Python source/proxies for tests, but
  that output is not a deployable chain artifact.
- `vm_ir_json` is the executable payload for `xian_vm_v1`; `source` is retained
  for auditability, dashboards, BDS, and future source-to-IR validation.
- Any future Rust compiler core should replace the compiler/artifact authority
  behind the public artifact APIs before SDKs depend on it directly.
