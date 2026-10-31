# Historical compatibility baseline

`legacy_baseline.json` records actual execution of `cases.json` under
`xian-contracting@3b82001f2d587bbfb51f3d9235a2a8dcd0078a9a`, before the Rust VM
implementation. The historical compiler, linter, executor and runtime types
come from that revision, with its dependency lock and Python 3.12.10.

Regenerate from the repository root:

```sh
python scripts/capture-compatibility-baseline.py
```

The script exports the pinned Git object into a temporary directory, installs
its locked dependencies using `uv`, checks the imported package location and
runs the shared observer with that environment's Python. It needs the Git
object and cached dependencies or network access. It never changes the working
checkout or uses today's compiler to admit the historical source. Review
snapshot changes; do not regenerate them from the current runtime. The snapshot
records the revision, Python version, lock digest, corpus digest and observer
digest. Temporary environments are removed when capture completes.

Run today's Python checks with the normal test suite. Run the native checks
with the native extension installed:

```sh
uv run pytest -m optional_native tests/integration/test_vm_legacy_compatibility.py
```

Each case first checks admission separately, then compares success/failure,
typed returns, writes and events. Dictionary entries remain ordered key/value
pairs; keys never become strings, and bool/int/float and list/tuple remain
distinct. Errors retain their original diagnostic and Python type as evidence;
cross-engine assertions compare failure status and effects rather than message
spelling. Set contents are sorted for recording, so this corpus does **not**
establish set iteration-order compatibility. The older conformance suite is a
separate comparison against today's Python harness.

The initial corpus covers representative language execution, private calls,
decimal/time values, ORM writes, events, rollback, source rejection, dictionary
key eligibility, insertion order, duplicates, nested equality, frozen-set keys,
list removal and exact large-integer/float comparison. Dictionary keys have a
different eligibility rule from deterministic set members: decimal and time
objects are unhashable dictionary keys in Python, even though deterministic
sets accept them. Empty `dict.pop(key, default)` follows the historical
short-circuit behavior and returns the default before validating the key.

Known differences are visible in the test report. The historical
`hashlib.sha256` alias is absent from both current engines; its admission,
failure status and empty effects are asserted before reporting the expected
failure. Removing the gap requires an explicit decision about historical aliases
versus migration to `sha256_text`/`sha256_hex`.

This is an extensible baseline, not a full replacement certificate. It does not
yet cover the complete historical grammar, constructors, all standard-library
bridges, metering equivalence, or iterator lifetime. The reference corpus covers
aliases, shallow copies, function arguments/returns, imported calls, identity,
temporary receivers, receiver evaluation order and deterministic shuffling.

Storage isolation is an intentional historical difference: writes snapshot their
inputs and reads return detached copies. The historical fixture records its old
shared-storage result; current-engine assertions require isolated storage instead.
Native-only boundary tests additionally require cyclic or oversized results and
writes to fail with rollback, while in-memory cycles remain usable.
