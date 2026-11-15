# Execution Backlog

## Current Default

The chain and public local clients execute `xian_vm_v2`.

`xian-contracting` remains usable as a standalone library outside the full
blockchain stack. Compilation and artifact building require the canonical
`xian-compiler-core` Rust package. `ContractingClient` executes through the
native V2 VM and rejects V1 drivers. Current code does not execute V1; V1
compilation, IR validation and encoding remain for migration and archival
tooling. Historical Python evidence comes from immutable observers run with
pinned archived packages, rather than a maintained Python contract executor.

## Return Value Metering

Return values are part of execution output and should not be free.

Current rule (execution revision 14): the receipt carries the entry's return
value as it carries the state writes, so a return value is priced and capped
like a write:

- meter the encoded return payload at the write price (25 raw units per byte)
- reject return values of `VM_WRITE_MAX_BYTES` (128 KiB) or more

Without the price, a 500k chi block could carry about 500 MB of receipts that
every node builds, sends to CometBFT and stores (one 105 MB receipt stalled a
localnet block for about 14 s).

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
3. Keep V1 tooling to compilation, IR validation and encoding for migration;
   V1 execution stays with the pinned older release.
