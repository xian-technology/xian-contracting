# contracting

## Purpose
- This package contains the core Xian contract engine.

## Contents
- `compilation/`: parser, compiler, linter, allowlists
- `execution/`: runtime, executor, tracers, module loading
- `storage/`: LMDB-backed storage and encoding
- `contracts/`: built-in/system contract assets

## Notes
- This package is consensus-sensitive. Favor small, test-backed changes.

