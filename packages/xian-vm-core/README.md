# xian-vm-core

`xian-vm-core` is the first Rust-side consumer of the frozen `xian_vm_v1`
compiler IR emitted by `xian-contracting`.

Current scope:

- deserialize the structural JSON IR
- validate its top-level invariants and recursive node shapes
- instantiate validated modules and execute a first direct-IR interpreter slice
- provide one Rust-owned contract for the Python frontend to target
- expose a minimal Python-facing native capability surface for `xian-abci`
  probing via `xian_vm_core._native`

Current execution coverage is intentionally narrow but real:

- local function calls and builtin calls such as `len`, `range`, `str`, and
  `isinstance`
- aggregate/container helpers such as `sorted`, `sum`, `min`, `max`, `all`,
  `any`, `reversed`, and `zip`
- explicit storage ops for `Variable` and `Hash`
- foreign storage reads for `ForeignVariable` and `ForeignHash`
- arbitrary-precision integer values instead of `i64`-only VM integers
- fixed-precision `decimal(...)` construction and arithmetic
- native `datetime.datetime` / `datetime.timedelta` values, including
  `datetime.datetime.strptime(...)`, arithmetic, comparison, and common field
  access
- bigint-oriented builtins needed by the shielded contracts, including
  `int(..., base)`, `pow(base, exp, mod)`, and `format(value, "064x")`
- `hashlib.sha3(...)` and `hashlib.sha256(...)`
- `crypto.verify(...)` and `crypto.key_is_valid(...)`
- `LogEvent` emission
- static-import and dynamic-import contract export calls
- native container method calls used by contracts today, including
  `dict.keys()`, `dict.values()`, `dict.items()`, `dict.get()`, and the common
  mutable list helpers `append`, `extend`, `insert`, `remove`, and `pop`
- native string helpers used by the shielded contracts, including
  `lower()`, `isalnum()`, `startswith(...)`, and `join(...)`
- Python-style subscript slicing for `list`, `tuple`, and `str`, including
  the `value[2:]` helper pattern used in the shielded contracts
- sequence repetition for `list`, `tuple`, and `str`
- host-delegated `zk.*` syscalls, which remain explicit runtime boundary calls
  instead of Rust-local protocol logic

It is not the full executor yet.

The crate now also includes curated parity fixtures generated from the current
Python runtime. Those fixtures are checked from Rust so the VM can match actual
runtime behavior on a controlled contract subset instead of only passing
hand-written executor tests.

Metering is no longer only a placeholder:

- storage reads, writes, transaction bytes, and return-value bytes are charged
  directly in the VM host path
- execution cost is now driven by an explicit `xian_vm_v1` gas schedule over
  VM statements, expressions, calls, and loop iterations instead of the earlier
  coarse `step` / `function_call` fallback
- module initialization is now metered too, so first-load authored contracts do
  not get free global-declaration and module-body execution
- `contract.exists(...)`, `contract.has_export(...)`, `contract.info(...)`, and
  related contract metadata syscalls now resolve directly against the driver/IR
  in the native host bridge, so metered native execution no longer depends on
  Python runtime globals for those checks
- authored contract storage now persists `__xian_ir_v1__`, and the native host
  requires that artifact for `xian_vm_v1` execution; stored `__source__`
  remains available for dashboards, BDS, and other inspection tooling, but it
  is no longer an execution fallback
- deployment artifacts are now validated against canonical compiler output,
  not only against self-declared hashes, so forged source/runtime/IR bundles
  are rejected before they reach native deployment
- native deployment now requires explicit deterministic `now` context from the
  caller; the host does not fall back to local wall-clock time for submission
  metadata
  this hardening currently reuses the compiler frontend to recompute canonical
  runtime/IR from source, so deploy execution stays native while artifact
  validation is not yet fully Rust-native

There is now also a calibration/audit tool:

- `scripts/audit_vm_metering.py`

It runs the full authored parity corpus through both:

- `native_instruction_v1` in the current Python runtime
- `xian_vm_v1` metering in the Rust VM

and reports the current ratio envelope instead of relying on intuition.

Current calibration state on this branch:

- no fixture in the parity corpus is under-metered relative to
  `native_instruction_v1`
- the authored-contract subset is currently within roughly `1.02x` to `2.35x`
  of `native_instruction_v1`
- the full mixed corpus, which still includes intentionally synthetic helper
  fixtures, is currently within roughly `1.02x` to `2.50x`

That parity corpus now covers:

- storage/event flows
- range/list/dict control-flow helpers
- foreign storage reads
- fixed-precision decimal semantics
- datetime/timedelta behavior
- bigint parsing, modular arithmetic, hex formatting, and shielded-style helper
  flows
- hashing and ed25519 verification helpers
- static-import and dynamic-import nested contract calls
- real authored shielded contract sources for `shielded-note-token` and
  `shielded-commands`, including constructor-seeded state snapshots and
  hash-helper exports
- real authored token, registry, game, and oracle flows across repos, including:
  `currency.transfer(...)`, `stable_token.burn(...)`,
  `reflection_token.transfer(...)`, `profile_registry.create_channel(...)`,
  `turn_based_games.join_match(...)`, and `oracle.price_info(...)`

The intent is to keep the Xian VM implementation Rust-first for performance,
while still freezing semantics in the Python compiler frontend before runtime
execution work starts.

The crate now also ships a small PyO3/maturin surface for integration work:

- `runtime_info()` / `runtime_info_json()`
- `supports_execution_policy(...)`
- `validate_module_ir(...)` / `validate_module_ir_json(...)`

That surface is intentionally narrow. It is there so node-side code can probe
the VM runtime honestly before transaction execution is wired through the Rust
engine.

The biggest remaining runtime gap is no longer integer width or basic authored
shielded execution. The VM now has a broader authored parity corpus and a
fixture generator that can model real pre-call setup flows. The next real step
is to keep tightening the remaining metering drift on the heaviest authored
flows and then decide which host operations should stay delegated versus move
into Rust-owned implementations.
