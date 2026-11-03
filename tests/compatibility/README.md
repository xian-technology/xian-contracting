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
different eligibility rule from deterministic set members: contract decimal wrappers and time
objects are unhashable dictionary keys in Python, even though deterministic
sets accept them. Raw Decimal results from explicit-digit rounding are a distinct,
hashable type. Empty `dict.pop(key, default)` follows the historical
short-circuit behavior and returns the default before validating the key.

Historical `hashlib.sha256` and `hashlib.sha3` calls preserve hexadecimal-first
input handling, including ASCII whitespace between complete byte pairs and UTF-8
fallback on invalid hex. The corpus covers both aliases and keyword arguments.
The explicit text/hex APIs remain preferable for newly authored messages.

The current Python harness retains its oversized-range guard. Its bounded
exception is asserted for the large-range probe; native ranges support lazy
iteration and enforce allocation limits when materialized. This deliberate
resource-policy difference is separate from language result comparisons.

This is an extensible baseline, not a full replacement certificate. It does not
yet cover the complete historical grammar, constructors, all standard-library
bridges or metering equivalence. The reference corpus covers
aliases, shallow copies, function arguments/returns, imported calls, identity,
temporary receivers, receiver evaluation order, deterministic shuffling,
default-definition scope/identity, keyword order, live collection iteration,
iterator consumption, lazy callbacks, short-circuiting, dictionary views and
iterator-consuming constructors.

Storage isolation is an intentional historical difference: writes snapshot their
inputs and reads return detached copies. The historical fixture records its old
shared-storage result; current-engine assertions require isolated storage instead.
Native-only boundary tests additionally require cyclic or oversized results and
writes to fail with rollback, while in-memory cycles remain usable.

The expanded corpus includes at least one call to every callable allowed builtin
(excluding the exception constructor, whose failure behavior is tested separately).
The additional numeric probes pin ties-to-even integer/float rounding, exact
binary64 inputs such as2.675, negative zero, extreme ndigits and Contracting's
ROUND_DOWN decimal policy when ndigits is supplied. Native boundary tests cover
huge negative integer ndigits without asking the historical interpreter to
allocate an unbounded power. Random choice/choices probes verify selected-object
identity after seeding, using a singleton population so PRNG algorithm changes
do not affect the expected selection.

The expanded corpus also covers ordered ordinary module rebinding,
starred calls/literals/targets, Unicode 15.0 decimal digits, dictionary insertion
slots during same-size mutation, streaming updates, setdefault, list reversal,
hex decoding, and raw Decimal quantum/type behavior. Decimal cases check signed
zero, general fractional powers, Infinity and quiet NaN, exact float conversion,
all 53 public Decimal methods reachable through the historical raw results,
formatting, calls and storage. Method-name coverage does not establish every
argument/context combination or complete Python Decimal compatibility.

Raw Decimal arithmetic uses vendored libmpdec 4.0.0 with an explicit 91-digit,
ROUND_DOWN, Emin=-100, Emax=100 context. Exact construction preserves digits
outside arithmetic precision until an operation applies its context. Custom
context objects are not admitted; supported context parameters accept None.
Non-finite values can be returned or used in memory, but direct and nested
storage writes reject them. Signaling-NaN behavior is tested at native value
boundaries; no public authored constructor was found in the pinned runtime.
`as_tuple()` returns a DecimalTuple with named fields and tuple behavior;
serialization uses the ordinary tuple/JSON-array representation. A cached write
retains the named tuple until storage serialization.

Deterministic sets retain their documented canonical ordering, rather than
historical Python set iteration order. Within the raw Decimal category, the
order is negative Infinity, finite numeric values, positive Infinity, then
quiet NaNs ordered by sign and payload; equal sort keys retain insertion order.
Distinct NaN objects remain distinct members; a repeated object deduplicates.
Signaling NaNs are not hashable.

Within the float category, sets and frozen sets sort numerically from negative
infinity through finite values to positive infinity, followed by NaNs. Equal
zeros retain the first inserted representation. All NaN signs and payloads share
one final sort key, so distinct NaNs preserve their insertion order while a
repeated object deduplicates. Tuple and frozen-set keys apply this recursively.
This is an explicit deterministic policy, not historical Python set iteration
order. `tests/integration/test_vm_float_sets.py` compares authored programs in
both current engines; Rust tests include binary64 boundaries and seeded bit
patterns. Ordinary numeric equality remains independent of canonical sort keys.

Resource limits are intentional: input text is at most 128 KiB, coefficient
length and raw exponent magnitude are bounded at 131072, and transcendental
and power operations accept at most 4096 coefficient digits and at most 4096
for coefficient-digit count plus exponent. Ordinary power additionally limits
both operand coefficients to 1024 digits. Integer exponents passed to power
and modular-power operations additionally have a coefficient-digit count plus
exponent limit of 512. Rendering and expanded integer ratios have separate
allocation bounds. These limits supplement VM metering.
Historical differential tests do not themselves prove cross-architecture
consensus; ARM64/x86-64 execution and replay evidence is a separate gate.

Bulk Hash tests live in `tests/integration/test_vm_storage_bulk.py`: `clone_from`
was absent from the pinned historical runtime, so its oracle is the current ORM.
The historical `clear` write-set omission is deliberately fixed rather than
preserved. Resource limits and rollback have additional current-engine tests.
CI and release validation run all optional-native tests after installing the VM,
so new regression modules do not require a separate hand-maintained test list.

## Published application workflows

The separate [application corpus](applications/README.md) runs 68 observations
across token/allowance, nameservice, staking and DEX workflows using five
byte-pinned sources from `xian-contracts@45d1334ac4de44c67afc46b68b435dca7d711281`.
Its real pre-VM oracle is the same runtime revision and Python version documented
above. These sequences are newly authored tests, not historical transactions.

Run the standalone observer from the repository root with an installed runtime:

```sh
python tests/compatibility/application_runner.py --engine native-metered --check --output /tmp/applications.json
```

It compares typed results, writes, events, complete fixture application state,
failure rollback and follow-up calls, reopening storage between calls. The
historical snapshot is retained unchanged. Two existing policies—child
constructor authority context and fixed-scaled square root—account for 110
explicit expected leaf differences; there is no numerical tolerance or blanket
workflow exemption. Historical gas prices and production submission metadata
are outside this comparison.

Use `scripts/capture-application-baseline.py` to regenerate only the application
snapshot. It verifies the historical installed package bytes as well as source,
lock and interpreter provenance. See the application guide for capture commands,
the trusted bootstrap adapter, exact policy values and coverage limits.

## Protocol write order under execution 5

Native transaction write maps and per-contract cost maps use sorted storage or
contract keys. This removes host HashMap iteration from exposed protocol outputs;
contract-authored dictionaries retain their insertion order. The historical
`quantum_storage` fixture records Variable-before-Hash writes. Its native
comparison checks the exact historical shape and exchanges only those two
top-level entries. The historical capture, values, result and events stay intact.
