# Parallel Execution

`xian-contracting` owns the reusable speculative parallel execution primitive
for native V2 contract-call batches. Higher layers can use it without duplicating
the runtime conflict model.

Workers use separate native runtime and storage contexts. The acceptance model
keeps execution ownership and commit order explicit:

- one active in-process execution per Python process
- speculative parallelism through separate worker processes
- canonical acceptance in serial request order

## Runtime Surface

The implementation lives in `src/contracting/execution/parallel.py` and is
exported lazily from `contracting.execution`.

Primary types:

- `ExecutionRequest`: one raw contract call
- `ExecutionAccess`: deterministic read/write/prefix-read metadata
- `ParallelExecutionPlanner`: conservative contiguous-stage planner
- `SpeculativeExecutionController`: serial-equivalence acceptance controller
- `ParallelBatchExecutor`: process-worker implementation for the native V2
  executor
- `ParallelExecutionStats`: accepted/speculated/fallback counters

`ContractingClient.build_parallel_executor(...)` creates a
`ParallelBatchExecutor` for local callers and tests. Both require `xian_vm_v2`.
`ParallelBatchExecutor` rejects an executor backed by a V1 driver before worker
setup, including when parallel execution is disabled. Archival V1 verification uses
the low-level native VM bindings separately.

Call `close()` on the batch executor when its work is complete. With `workers=1`,
each executor owns a private worker driver and releases it on close. The worker is
reused while the storage home and default metering configuration match; changing
either closes the previous worker before creating its replacement. Callers retain
ownership of the main executor's driver.

## Acceptance Model

The main process:

- optionally estimates deterministic access sets before speculation
- snapshots the current driver pending-write overlay
- runs eligible requests speculatively against committed LMDB state plus that
  overlay
- validates speculative access metadata in canonical order
- applies accepted writes to the main driver's pending state
- serially executes requests that cannot be safely speculated
- optionally commits after the batch is complete

The final state must match ordinary serial execution.

When `use_access_estimates` is enabled, only requests with known estimates enter
speculative waves. Unknown requests execute through the existing serial path.
Estimates are scheduling hints only; actual read/write metadata is still
validated before speculative writes are accepted.

## Guardrails

Callers can cap speculative retry work with:

- `max_speculative_waves`: after this many waves, the remaining suffix runs
  serially
- `min_wave_acceptance_ratio`: when a large wave accepts too little of its
  prefix, the remaining suffix runs serially
- `low_acceptance_min_wave_size`: minimum wave size before the low-acceptance
  rule applies

These guardrails keep hot-key blocks from repeatedly speculating the same
conflicting tail. Accepted speculative writes are kept; only the unaccepted
canonical suffix falls back to serial execution.

## Conflict Rules

The first implementation is deliberately conservative:

- same sender in one speculative wave stops the wave
- read-after-write conflicts fall back
- write-after-read conflicts fall back
- write-after-write conflicts fall back
- prefix scans conflict with writes under the scanned prefix
- worker/runtime failure falls back to serial execution
- speculative workers execute with `auto_commit=False`

Additive writes are represented in the access model but default to empty for the
raw-call executor. Node-specific additive-write policy belongs above this
runtime library.

## Non-Goals

This repo should not absorb ABCI-only policy:

- CometBFT transaction decoding
- nonce validation
- block result shaping
- reward distribution
- node logging and metrics wiring

Those stay in `xian-abci` or the caller layer.

## Validation

Core coverage:

- `tests/unit/test_parallel_planner.py`
- `tests/integration/test_parallel_batch_executor.py`
- `tests/performance/benchmark_parallel_tps.py`

Use the performance benchmark only for local measurement; it is not part of the
default CI path.
