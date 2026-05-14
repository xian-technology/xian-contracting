# Execution Backlog

## Current Default

The default Xian network execution path is `xian_vm_v1`.

`xian-contracting` still needs to remain:

- pure Python
- self-contained
- easy to install as a standalone library
- usable outside the full blockchain stack

Those properties apply to the compiler, artifact builder, and local test
harness. They do not imply a second network VM.

## Local Harness Metering Backlog

The local harness tracer is deterministic and useful for development-time
checks, but it is no longer consensus policy. The Xian VM owns network
execution and metering.

Recent hardening already landed:

- fixed Python 3.14 line metadata handling
- kept per-code tracer metadata warm across executions
- split event ceilings by execution surface
- made the opcode default-cost set explicit and test-guarded
- added workload tests for branch-heavy and loop-heavy tracer cases
- forbade ternary expressions, semicolons, and one-line compound statements
  in contract source

Remaining useful harness hardening steps:

- forbid lambdas
- restrict or forbid complex comprehensions if they create poor line-cost
  precision
- reject lines whose compiled bytecode bucket exceeds a configured threshold
- keep local harness metering changes versioned and explicit across supported
  CPython minors
- extend workload tests further with contracts designed to probe tracer blind
  spots beyond the current branch-heavy coverage

These changes are intended to reduce opportunities to game local-test metering
without changing network execution, which is owned by the Xian VM.

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

1. Keep the local harness tracer as standalone test infrastructure.
2. Keep tightening that harness with targeted language restrictions and
   workload coverage.
3. Keep the Xian VM as the only network execution target.
4. Treat speculative parallel execution as a local optimization and expand it
   only when serial-equivalence coverage and workload data justify it.
