# Execution Backlog

## Current Default

The chain and public local clients execute `xian_vm_v2`.

`xian-contracting` remains usable as a standalone library outside the full
blockchain stack. Compilation and artifact building require the canonical
`xian-compiler-core` Rust package. `ContractingClient` executes through the
native V2 VM and rejects V1 drivers.
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

Blocks execute serially in canonical order. Validators run whole blocks in the
Rust `BlockExecutor` in `packages/xian-vm-core`. The former speculative
process-pool executor (`contracting.execution.parallel`) was removed once
serial Rust execution outran it. Any future parallel design (Block-STM-style
execution in Rust) is tracked in
`xian-meta/docs/XIAN_VM_PARALLEL_EXECUTION_PLAN.md`. It must produce results
identical to serial block order.

## Rollout Order

1. Keep native V2 as the public local-client and network execution target.
2. Preserve independent semantic models and immutable historical observations
   while expanding native workload coverage.
3. Keep native V1 tooling isolated to historical verification and migration.
