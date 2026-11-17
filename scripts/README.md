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
  against the Python reference compiler across authored contracts.
- `generate_compiler_fixtures.py`: records authoritative Rust compiler source,
  normalization, artifact, IR, hash, and rejection behavior through the Python
  binding as `xian.compiler_fixture.v1` JSON.
- `capture-compatibility-baseline.py` and `capture-application-baseline.py`: run
  immutable observers with the pinned pre-VM Python installation, separately
  from current native execution. See `tests/compatibility/README.md`.

## Notes

- Most scripts expect to run from the repository root through `uv run`.
- The historical V1 parity fixtures were removed with the interpreter's V1
  execution (they remain in Git history). The retired Python fixture generator
  is available from the pinned pre-retirement Git revision; see
  [historical regeneration](../tests/compatibility/historical/README.md).
  The current VM must not generate its own expected parity results.
- Do not put node lifecycle, genesis, or operator workflow scripts here; those
  belong in `xian-stack`, `xian-cli`, or `xian-abci`.

## Release backfills

To recover an existing package tag after a release-infrastructure failure:

```bash
gh workflow run release.yml --ref main -f release_tag=compiler-core-v0.2.1
```

The workflow uses the current release infrastructure, checks out the requested
`refs/tags/...` source in every validation/build job, validates it again, and
publishes artifacts under that same tag. Do not move an existing release tag.
Native wheels use `macos-15` for ARM and `macos-15-intel` for Intel.
