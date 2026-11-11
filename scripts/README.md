# Scripts

This directory contains local audit and fixture-generation tools for
runtime/VM work. They are not node operation scripts.

## Current Scripts

- `validate-release.sh`: release-grade validation gate for the local runtime,
  zk, and Xian VM paths.
- `audit_authored_conformance.py`: scans authored contracts against the
  contract-language conformance matrix.
- `audit_vm_compatibility.py`: reports whether contract sources fit a selected
  VM compatibility profile.
- `audit_vm_ir_lowering.py`: lowers contract sources to the current VM IR and
  reports lowering failures plus host dependency counts.
- `audit_compiler_core_parity.py`: compares Rust compiler-core artifacts
  against the Python reference compiler across authored contracts and lint
  modes.
- `generate_compiler_fixtures.py`: records authoritative Rust compiler source,
  normalization, artifact, IR, hash, and rejection behavior through the Python
  binding as `xian.compiler_fixture.v1` JSON.
- `capture-compatibility-baseline.py` and `capture-application-baseline.py`: run
  immutable observers with the pinned pre-VM Python installation, separately
  from current native execution. See `tests/compatibility/README.md`.

## Notes

- Most scripts expect to run from the repository root through `uv run`.
- Historical V1 parity fixtures are retained as evidence. The retired Python
  fixture generator is available from the pinned pre-retirement Git revision;
  see [historical regeneration](../tests/compatibility/historical/README.md).
  The current VM must not generate its own expected parity results.
- Do not put node lifecycle, genesis, or operator workflow scripts here; those
  belong in `xian-stack`, `xian-cli`, or `xian-abci`.
