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

Focused native/zk validation follows the commands in the root
[`README.md`](../README.md). Run targeted integration/security tests whenever a
change touches execution semantics, import restrictions, metering, or storage
encoding.
