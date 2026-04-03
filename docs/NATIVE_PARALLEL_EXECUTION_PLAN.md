# Native Parallel Execution Plan

## Goal

Move speculative parallel execution down into `xian-contracting` so the
serial-equivalence machinery is a reusable runtime primitive rather than an
ABCI-only feature.

This does **not** mean unsafe in-process threading inside one contract runtime.
The runtime still mutates process-global Python import hooks and module caches,
so the safe execution model remains:

- one active in-process execution per Python process
- speculative parallelism via separate worker processes
- canonical acceptance in serial block/call order

## Why Move It Here

`xian-contracting` already owns the execution semantics that make safe
speculation possible:

- deterministic execution
- read tracking
- write tracking
- prefix-read tracking for collection scans
- transaction rollback semantics
- storage buffering and commit behavior

Keeping the speculative executor only in `xian-abci` duplicates consensus-hot
logic at the wrong layer. The runtime library should own the conflict model,
worker isolation model, and serial-equivalence checks.

## Non-Goals

The first move into `xian-contracting` should **not** absorb ABCI-only policy:

- CometBFT transaction decoding
- nonce validation
- block result shaping
- reward distribution policy
- node logging / metrics wiring

Those stay above the runtime library.

## Target Architecture

### Library Primitive

Add a reusable speculative batch executor to `contracting.execution`.

First-class concepts:

- `ExecutionRequest`: one raw contract call
- `ExecutionAccess`: deterministic access metadata for one request
- `ParallelExecutionPlanner`: conservative conflict planner
- `ParallelBatchExecutor`: worker-pool speculation plus serial acceptance

### Worker Model

Workers are separate processes, each with:

- its own `Driver`
- its own `Executor`
- its own runtime/tracer state

Workers execute requests with `auto_commit=false` and must never write
speculative state to disk.

### Acceptance Model

The main process:

1. snapshots the current base pending-write overlay
2. runs requests speculatively on workers against the committed LMDB state plus
   that base overlay
3. revalidates each speculative result in canonical order
4. applies accepted writes to the main driver's pending state
5. re-executes conflicting requests serially
6. optionally commits after the batch is complete

That keeps the final state equivalent to ordinary serial execution.

## Security Rules

The runtime must fail closed:

- no speculative disk commits
- same-sender reuse forces serial fallback
- read-after-write conflicts force serial fallback
- write-after-read conflicts force serial fallback
- write-after-write conflicts force serial fallback
- tracked prefix-read overlap forces serial fallback
- worker/runtime failures fall back to full serial execution

The library must preserve deterministic tracer selection too. Worker runtimes
must use the same tracer mode and execution posture as the parent executor.

## Efficiency Requirements

To keep the feature fast enough to matter:

- reuse worker runtimes across batches
- keep workers on `bypass_cache=True`
- ship only request payloads plus the current base pending-write overlay
- apply accepted speculative writes directly into the main driver's
  `pending_writes` without re-metering them
- avoid rebuilding process pools for each request

## Phase Plan

### Phase 1

Implement native runtime primitives in `xian-contracting`:

- speculative worker pool
- access dataclasses and planner
- serial-equivalence checks
- base pending-write overlay support
- generic raw-call batch API

This phase can execute plain contract calls in parallel safely.

### Phase 2

Refactor `xian-abci` to consume the library primitive:

- keep ABCI tx decoding and tx-result shaping in `xian-abci`
- keep reward policy in `xian-abci`
- reuse the shared planner, worker model, and fallback logic

### Phase 3

If we want full migration later, add optional post-processing hooks to the
library so higher layers can define:

- additive-write classes
- transformed write materialization
- richer acceptance metadata

That would let `xian-abci` keep reward semantics without re-owning the
speculative executor.

## First Implementation Boundary

The first implementation in this repo should stay intentionally narrow:

- raw contract call requests only
- additive writes default to empty
- stats expose how much speculation was accepted vs. replayed
- no ABCI imports

That is enough to make `xian-contracting` the owner of native speculative
parallel execution while still keeping node-specific policy above it.
