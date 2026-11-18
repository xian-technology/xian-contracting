# Contract surface coverage

The executable matrix checks authored source against reviewed expectations on
the native V2 engine. `catalog.load_v2_cases()` excludes `V1_ONLY_CASES`:
historical binary floats, raw Decimal operations, bool-as-int and other
V1-specific expectations. Retained cases and catalog entries are archival
evidence, not current language support.

## Files

- `catalog.json`: discovered builtin, environment, annotation and value-member
  names. The drift test requires review when discovery changes.
- `builtin-cases.json`, `builtin-set-cases.json` and `value-cases.json`: nominal,
  boundary, invalid-input and explicit policy expectations.
- `catalog.py`: discovery, case loading, the V1 exclusion list and coverage report.
- `test_vm_surface_matrix.py` under `tests/integration/`: compiles each selected
  source, executes it, and checks admission, status, typed results, writes and events.

Run from the repository root:

```sh
uv run --no-sync pytest tests/unit/test_runtime_surface_catalog.py
uv run --no-sync pytest -m optional_native tests/integration/test_vm_surface_matrix.py
mkdir -p .artifacts
uv run --no-sync python scripts/audit_runtime_surface.py > .artifacts/runtime-surface.json
```

Rebuild the native extension after Rust changes. The full
`scripts/validate-release.sh` gate installs the local wheel; an older cached
extension is not valid evidence.

## Interpret coverage

The report describes the retained inventory, including historical V1 members;
it is not a V2 support list or a test-execution result. `present` means a native
dispatch name was found, and `declared` means an exported/catalogued name was
found. Neither proves every argument combination works. `existing_test_files`
are source-search references, not verified per-member assertions.

Cases marked `native_only` state an intentional restriction with a
`policy_reason`; they do not waive unexpected failures. Typed observation
encoding preserves distinctions and dictionary insertion order. Sorted set
encoding alone does not prove iteration order; dedicated authored checks must
return ordered observations.

For current number and value behavior, use V2 language documentation and
execution tests, rather than retained float/Decimal/NaN catalog entries.
[Historical evidence](../compatibility/README.md) has separate pinned capture
and provenance checks.

## Extend the matrix

Add meaningful cases for ordinary and invalid inputs, empty values and limits,
mutation/aliasing, ordering, exceptions, rollback/recovery and allocation/chi
exhaustion. Keep expected results independent of the implementation under test.
Interface-subject, storage, numeric, metering and security tests complement
this matrix; cross-platform and five-node replay are separate validation gates.

Finite cases establish their recorded behavior, not correctness for all
programs. Keep restrictions visible and require an explicit inventory decision
plus behavioral evidence for each new public operation.

## Builtin sets and wrapper sets

`set`/`frozenset` constructors produce deterministic wrappers. Dictionary-view
algebra produces the distinct `builtin_set` family, with Python-style method
signatures and additional mutation methods. `isinstance(value, set)` checks the
wrapper family. Builtin sets cannot cross public result or storage boundaries,
including nested values; convert explicitly with `set(value)` within the
wrapper's admitted member domain. Dedicated tests cover kind-sensitive equality,
execution-local callable keys, deterministic order and rollback.

## Metadata-only interface predicates

`importlib.enforce_interface` can call an instance's custom `is_of` predicate
with an immutable `InterfaceSubject`. Its readable fields are:

- `kind`: `"function"` or `"storage"`.
- `name`: canonical function code name (including a private prefix) or storage name.
- `args`: positional function parameter names as a tuple, or `None` for storage.
- `storage_type`: `Variable`, `Hash`, `ForeignVariable`, `ForeignHash` or
  `LogEvent` as text, or `None` for functions.

The subject grants metadata access, not a callable target or storage authority.
Standard `Func.is_of`/`Var.is_of` accept it. Local predicates run in the
inspector's frame with its transaction budget; truthiness decides the match
and errors propagate. Missing/None and ordinary scalar members retain their
normal checks without invoking a callback.

Subjects cannot be mutated, stored, returned publicly or passed across contract
boundaries, including nested retention. Copying ordinary metadata fields is
allowed; inspecting a private function does not make it callable. The authored
`test_vm_interface_subjects.py`, `test_vm_interface_subject_boundaries.py` and
`test_vm_interface_callback_boundaries.py` cover these rules and rollback.
