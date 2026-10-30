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
yet cover the complete historical grammar, constructors, inter-contract imports,
all standard-library bridges, metering equivalence, aliasing/identity, or iterator
lifetime. Mutating temporary or call-result receivers remains part of the
reference-semantics review. Extend the corpus when those gaps are addressed.
