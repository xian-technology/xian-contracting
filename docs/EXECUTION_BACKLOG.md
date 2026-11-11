# Execution Backlog

## Current Default

The chain and public local clients execute `xian_vm_v2`.

`xian-contracting` remains usable as a standalone library outside the full
blockchain stack. Compilation and artifact building require the canonical
`xian-compiler-core` Rust package. `ContractingClient` and
`ParallelBatchExecutor` execute through the native V2 VM and reject V1 drivers.
Low-level native V1 tooling is reserved for historical verification and
migration. Historical Python evidence comes from immutable observers run with
pinned archived packages, rather than a maintained Python contract executor.

## Return Value Metering

Return values are part of execution output and should not be free.

Current rule:

- meter the encoded return payload size
- reject return values larger than `MAX_RETURN_VALUE_SIZE`

This should remain deterministic and versioned as part of the execution policy.

## Parallel Transaction Processing

Parallel execution now has a reusable `contracting.execution.parallel`
primitive for raw contract-call batches:

- `ExecutionRequest`
- `ExecutionAccess`
- `ParallelExecutionPlanner`
- `ParallelBatchExecutor`

It still must not become naive concurrent mutation.

Current safety model:

- keep canonical block transaction order unchanged
- execute transactions speculatively on snapshots
- collect deterministic read/write/event metadata per transaction
- validate speculative results against prior committed writes in canonical order
- commit serially in canonical order
- re-execute conflicting transactions serially

This keeps final semantics equivalent to serial execution.

Important distinction:

- the Xian VM and its gas schedule are consensus policy
- parallel speculative execution can remain a local optimization if it is
  provably serial-equivalent

Required safeguards:

- deterministic scheduler
- bounded worker count
- conflict threshold and fallback rules
- read/write-set capture
- conservative first version with narrow eligibility
- workload tests designed to force conflicts and verify identical final state

Remaining useful work:

- harden multi-worker process-pool lifecycle behavior under long-running node
  workloads
- add broader performance coverage for high-conflict and mixed-conflict batches
- integrate only the generic runtime primitive into higher layers; keep ABCI
  decoding, nonce policy, rewards, and result shaping outside this repo
- keep proving serial equivalence with integration tests before enabling wider
  production usage

## Rollout Order

1. Keep native V2 as the public local-client and network execution target.
2. Preserve independent semantic models and immutable historical observations
   while expanding native workload coverage.
3. Keep native V1 tooling isolated to historical verification and migration.
4. Expand speculative parallel execution only when serial-equivalence coverage
   and workload data justify it.
