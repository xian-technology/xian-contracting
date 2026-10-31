# Contract surface coverage

This suite separates discovery, implementation and behavioral evidence. A name
appearing in a test or an implementation match arm is not proof of correctness.

- `catalog.json` records the builtin whitelist, public environment exports, host
  bindings, annotation names and public members of 28 value families. The drift
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
- Cases with `native_only` are explicit language-policy rejection checks, with a
  required `policy_reason`. They are skipped in the current Python oracle, whose
  broader API is not the consensus definition. The report counts these separately
  from shared compatibility cases; a rejected member is not reported as supported.

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

The inventory has 486 entries and 565 direct cases: 560 shared compatibility
cases and five native-only policy checks. All 37 callable builtins have three
behavioral dimensions. There are 307 public Python value members, including the
live read-only mapping views exposed through dictionary views. Member entries
are not counts of distinct bugs: inherited methods repeat across types.
Native implementations and successful shared cases cover 302 of those members;
the remaining five have the explicit policy dispositions below.

`float.from_number`, `Decimal.from_number` and `bytearray.resize` postdate the
pinned Python 3.12 historical baseline and are explicitly deferred. Exception
note mutation is separately deferred; traceback access is intentionally excluded.
Those dispositions remain in the inventory and have native rejection checks.
Ordinary exception argument access is a separate member. Public attribute syntax
is admitted broadly; it is not a promise that every Python method is supported.
Missing members require implementation or an explicit language-policy decision,
not silent exclusion from the inventory.

The report separates intentional deferred/excluded members from unresolved
missing implementations so an explicit restriction does not hide unfinished work.
Method presence does not waive approved encoding, Unicode, formatting, time or
allocation restrictions. Bound methods and read-only mapping proxies are local
to an execution and cannot be persisted or returned across host boundaries.

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

One known protocol gap is not an absent method: Python view algebra produces
builtin sets distinct from the contract's deterministic `ContractingSet` wrapper,
whereas native values currently share one set representation. Cross-family
equality/type behavior is not fully compatible. Keep this representation gap
explicit even when all ordinary member entries have direct passing cases.
