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
- `generate_compiler_fixtures.py`: records current Python compiler source,
  normalization, artifact, IR, hash, and rejection behavior as
  `xian.compiler_fixture.v1` JSON for the Rust compiler migration.
- `generate_vm_parity_fixtures.py`: regenerates curated VM conformance fixtures
  from current local harness behavior and selected authored contract sources in
  the wider Xian workspace.

## Notes

- Most scripts expect to run from the repository root through `uv run`.
- VM fixture generation depends on sibling repos such as `xian-contracts`,
  `xian-configs`, and `xian-stable-protocol` being present under the same
  workspace root. DEX fixtures use the pinned bundle from the sibling `xian-dex` repo by
  default. Set `XIAN_WORKSPACE_ROOT` to point at a different workspace root, or
  `XIAN_DEX_BUNDLE` / `XIAN_DEX_SRC_DIR` for DEX-specific overrides.
- Do not put node lifecycle, genesis, or operator workflow scripts here; those
  belong in `xian-stack`, `xian-cli`, or `xian-abci`.
