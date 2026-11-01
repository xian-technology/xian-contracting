# Contract surface coverage

This suite separates discovery, implementation and behavioral evidence. A name
appearing in a test or an implementation match arm is not proof of correctness.

- `catalog.json` records the builtin whitelist, public environment exports, host
  bindings, annotation names and public members of 29 value families. The drift
  test fails when those discovered names change without a reviewed update.
- `builtin-cases.json` gives every callable builtin nominal, boundary and invalid
  input cases. Expectations are explicit; the Xian restriction on negative
  modular exponents is recorded separately from ordinary Python behavior.
- `builtin-set-cases.json` separately covers builtin sets produced by dictionary
  view algebra, their methods, kind-sensitive protocols, and boundary policy.
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
  from shared compatibility cases. Missing/deferred APIs and restrictions on an
  implemented value protocol have different inventory dispositions.

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

The inventory has 507 entries and 595 direct cases: 586 shared compatibility
cases and nine native-only policy checks. All 37 callable builtins have three
behavioral dimensions. There are 324 public Python value members, including
live read-only mapping proxies and the distinct builtin-set family. Member
entries are not counts of distinct bugs: inherited methods repeat across types.
Native implementations and successful shared cases cover 319 of those members;
the remaining five have the explicit API dispositions below. A separate
unresolved protocol entry records callable-valued builtin-set members.

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

## Builtin sets and wrapper sets

The `set` and `frozenset` families describe Contracting's deterministic wrapper
constructors. The `builtin_set` family describes values produced by dictionary
keys/items view algebra. It has 17 methods, including `update`,
`intersection_update`, `difference_update` and `symmetric_difference_update`,
which the wrapper set does not expose. Builtin methods use their own positional
signatures; wrapper methods retain their existing named parameters.

Builtin set kind remains distinct through method results, nested containers and
cross-contract calls. Comparison and mixed-operator rules follow that distinction:
a builtin set can equal its source view while comparing unequal to a wrapper set
with the same members. Authored `isinstance(value, set)` checks the wrapper family.
Set iteration and `pop()` retain the VM's approved deterministic canonical order
and NaN identity policy rather than Python's process-dependent hash order.

Builtin sets cannot be persisted or returned as serialized public results,
including when nested in another value. Explicit `set(value)` conversion creates
a wrapper value for those boundaries, subject to the wrapper's admitted member
domain. The inventory marks this implemented protocol as `restricted`, with four
native-only rejection cases and a successful shared explicit-conversion case;
it is not counted as a missing implementation. Dedicated set-kind tests also
check rollback/follow-up recovery and cross-contract alias preservation.

`protocol.builtin_set.callable_members` remains an unresolved domain limitation:
Python admits bound methods, functions and classes as builtin-set members, while
the native canonical normalizer rejects those callable-valued members even when
the dictionary key is admitted. This requires a deterministic execution identity
and ordering policy coordinated with callable ownership. Passing cases for all
17 method names do not claim full member-domain parity or resolve that gap.
