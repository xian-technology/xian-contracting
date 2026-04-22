# Scripts

This directory contains local audit and fixture-generation tools for
runtime/VM work. They are not node operation scripts.

## Current Scripts

- `audit_authored_conformance.py`: scans authored contracts against the
  Python-vs-Xian-VM conformance matrix.
- `audit_python_vm_compatibility.py`: checks whether authored contracts can be
  compiled/executed by the Python VM compatibility path.
- `audit_vm_compatibility.py`: reports whether contract sources fit a selected
  VM compatibility profile.
- `audit_vm_ir_lowering.py`: lowers contract sources to the current VM IR and
  reports lowering failures plus host dependency counts.
- `audit_vm_metering.py`: compares Python native-instruction metering against
  `xian_vm_v1` metering for parity fixtures.
- `generate_vm_parity_fixtures.py`: regenerates curated VM parity fixtures from
  current Python runtime behavior and selected authored contract sources in the
  wider Xian workspace.

## Notes

- Most scripts expect to run from the repository root through `uv run`.
- VM fixture generation depends on sibling repos such as `xian-contracts`,
  `xian-configs`, and `xian-stable-protocol` being present under the same
  workspace root.
- Do not put node lifecycle, genesis, or operator workflow scripts here; those
  belong in `xian-stack`, `xian-cli`, or `xian-abci`.
