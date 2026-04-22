# Parallel Execution

`xian-contracting` now owns the reusable speculative parallel execution
primitive for raw contract-call batches. Higher layers can use it without
duplicating the runtime conflict model.

This is not unsafe in-process threading inside one contract runtime. Contract
execution mutates process-global Python import hooks and module caches, so the
safe model remains:

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
- `ParallelBatchExecutor`: process-worker implementation for
  `contracting.execution.Executor`
- `ParallelExecutionStats`: accepted/speculated/fallback counters

`ContractingClient.build_parallel_executor(...)` creates a
`ParallelBatchExecutor` for local callers and tests.

## Acceptance Model

The main process:

- snapshots the current driver pending-write overlay
- runs eligible requests speculatively against committed LMDB state plus that
  overlay
- validates speculative access metadata in canonical order
- applies accepted writes to the main driver's pending state
- serially executes requests that cannot be safely speculated
- optionally commits after the batch is complete

The final state must match ordinary serial execution.

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
