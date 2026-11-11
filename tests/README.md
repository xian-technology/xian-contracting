# Tests

This folder contains the verification surface for the contract engine.

## Contents

- `unit/`: isolated compiler, runtime, storage, stdlib, VM, and package tests
- `integration/`: multi-component contract execution behavior
- `security/`: adversarial runtime and import/metering safety tests
- `performance/`: local benchmarks that are not part of the default CI path

Default validation:

```bash
uv run pytest
```

The default suite deselects `optional_native` tests because they require Rust
extension packages. Focused native/zk/VM validation follows the commands in the
root [`README.md`](../README.md). Run targeted integration/security tests
whenever a change touches execution semantics, import restrictions, metering, or
storage encoding. The optional-native release gate includes the stateful
local-harness-vs-VM fuzz coverage in
`integration/test_vm_stateful_fuzz.py`.

## State Isolation

Each test receives a private `test_home`, with `node_home` at
`test_home/.cometbft` and default contract storage at `node_home/xian`.
The autouse fixture sets `HOME` and `contracting.constants.STORAGE_HOME`
consistently, so a subprocess inheriting the test environment opens the same
default storage as its parent. Tests that need independent stores should pass
their own `tmp_path` subdirectories explicitly.

Collection-time imports use a separate temporary home for each pytest process.
The original environment and working directory are restored through pytest's
cleanup hooks. Tests must keep mutable files inside their provided temporary
directories; checked-in contract sources and fixtures remain read-only inputs.
