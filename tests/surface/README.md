# Contract surface coverage

This suite separates discovery, implementation and behavioral evidence. A name
appearing in a test or an implementation match arm is not proof of correctness.

- `catalog.json` records the builtin whitelist, public environment exports, host
  bindings, annotation names and public members of 26 value families. The drift
  test fails when those discovered names change without a reviewed update.
- `builtin-cases.json` gives every callable builtin nominal, boundary and invalid
  input cases. Expectations are explicit; the Xian restriction on negative
  modular exponents is recorded separately from ordinary Python behavior.
- `value-cases.json` covers the implemented value-method/attribute surface and
  representative value protocols. The catalog also keeps missing native members
  visible; they are not counted as supported merely because Python exposes them.
- `test_vm_surface_matrix.py` runs identical authored source in Python and the
  native VM, independently checking explicit typed results, status, writes and
  events. The observer distinguishes bool/int/float, list/tuple and Decimal
  types. Its set encoding does not prove iteration order; dedicated float-set
  tests return ordered observations from inside the contract.

Run from the repository root:

```sh
uv run --no-sync pytest tests/unit/test_runtime_surface_catalog.py tests/integration/test_vm_surface_matrix.py
uv run --no-sync pytest -m optional_native tests/integration/test_vm_surface_matrix.py
uv run --no-sync python scripts/audit_runtime_surface.py > .artifacts/runtime-surface.json
```

The native extension must be rebuilt after Rust changes. The full
`scripts/validate-release.sh` gate installs the actual local wheel and runs these
tests automatically; a cached or ignored older extension is not valid evidence.

## Interpreting the report

The initial inventory has 476 entries and 319 direct cases. All 37 callable
builtins have three behavioral dimensions. Of 302 public Python value members,
161 lack matching native dispatch. These are member entries, not 161 distinct
bugs: inherited methods repeat across types, and `Decimal.from_number` was
introduced after the pinned Python 3.12 historical baseline. Public attribute
syntax is admitted broadly; it is not a promise that every Python method is a
supported Xian method. Missing members require implementation or an explicit
language-policy decision, not silent exclusion from the inventory.

`existing_test_files` are source-search navigation references. They are **not**
verified per-member assertions and do not increase direct-case coverage.
`present` means native dispatch exists, while `declared` means an exported or
catalogued interface exists; neither means every argument combination works.
The report lists exact direct case IDs and dimensions so those limits are visible.

## Completing coverage

For each supported operation, expand the matrix with meaningful cases for:

1. Typical values, empty/singleton inputs, limits, invalid types and signatures.
2. Mutation, aliases, identity, iterator consumption and evaluation order.
3. Ordered results, exceptions, persisted state, events and rollback/recovery.
4. Allocation and chi exhaustion before expensive work.
5. Seeded property tests and metamorphic relations appropriate to the operation.
6. Historical differential checks and cross-platform/network execution.

The historical corpus, numerical vectors, stateful fuzzing, metering/security
tests and five-node flows remain complementary gates. Do not turn every unit
case into a network transaction: use unit/native tests for breadth and selected
representative interactions for consensus and recovery checks.

Finite tests cannot prove correctness for all inputs or all contract programs.
Known gaps must remain documented, and a new public function needs both an
inventory decision and behavioral evidence. Do not regenerate expected results
from a failing native implementation.
