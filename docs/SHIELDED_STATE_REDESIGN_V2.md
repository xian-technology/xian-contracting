# Shielded State Redesign V2

## Why Another Redesign Pass

Xian already removed raw encrypted note payload bytes from consensus state, but
shielded transactions still carry too much on-chain historical baggage for what
consensus actually needs.

Current research and deployed privacy systems keep pointing in the same
direction:

- Zcash-style systems keep correctness around commitment roots and nullifiers,
  not a rich on-chain note catalog.
- Firo Spark emphasizes private addresses, view keys, and modular upgrade
  surfaces rather than making full note history consensus-critical.
- Aztec treats note discovery and wallet sync as an indexing problem, not a
  consensus-storage problem.

For Xian, that means the right next step is not "charge less for the same work".
It is: reduce the real validator work and move historical convenience reads into
indexed services.

## Decision

The shielded contracts should keep only correctness-critical state in
consensus:

- current tree frontier / root state
- recent accepted roots
- spent nullifiers
- note count and commitment ordering
- public / shielded supply or escrow invariants

The shielded contracts should stop mirroring historical note metadata and relay
execution history in contract storage when that information already exists in
transaction payloads and emitted events.

## V2 Scope

This redesign round does two things:

1. removes more non-critical shielded history from consensus state
2. adds BDS-side shielded output tag indexing for selective wallet retrieval
3. moves shielded tree append and relay-digest hot paths into native `xian-zk`
   bindings so chi cost reflects native execution instead of Python MiMC loops

## Consensus Changes

### Shielded note outputs

The contracts no longer store per-commitment metadata such as:

- commitment -> note index
- commitment -> payload hash

Instead, output metadata is emitted as events:

- `ShieldedOutputsCommitted`
  - new_root
  - note_index_start
  - output_count
  - packed commitments
  - packed payload hashes
  - action

This keeps note ordering observable for indexers while removing redundant
contract writes and avoids re-emitting per-output event metadata.

### Relay / command receipts

The contracts no longer store full relay or command execution receipt maps in
consensus state.

Instead, the execution receipt now lives in emitted events:

- relayer
- binding / execution tag
- nullifier digest
- fee / public amount
- roots
- output counts
- expiry

Replay safety still comes from nullifier spend tracking and proof binding, not
from a second historical receipt table in consensus.

## BDS Changes

`xian-abci` BDS now extracts both `sync_hint` and `discovery_tag` values from
shielded output payloads and stores them in a dedicated indexed table:

- `shielded_output_tags`

Each row links:

- tag kind / tag value
- tx hash / block height / tx index
- contract / function / action
- output index / note index
- commitment
- new root
- payload hash

This gives wallets a selective retrieval path without forcing consensus to
retain a searchable note catalog.

## Security Model

This redesign does **not** weaken the proof model.

The chain still enforces:

- accepted-root membership
- nullifier non-reuse
- canonical commitment insertion order
- proof-committed payload hashes
- public / shielded supply invariants

What changes is where historical convenience data lives:

- consensus keeps spend-validity state
- BDS keeps retrieval-oriented history

## Benchmark Result

The first storage-only redesign slice improved architecture but barely changed
chi cost. The real bottleneck was Python execution inside the contracts,
especially MiMC tree updates and command-binding digests.

After moving those hot paths into native `xian-zk` bindings and metering them
explicitly through the `zk` stdlib bridge, the current local shielded benchmark
in `xian-abci/scripts/benchmark_shielded_chi.py` reports:

- deposit with 2 outputs: `3,347` chi
- transfer with 2 inputs / 2 outputs: `3,600` chi
- withdraw with 1 input / 1 output: `3,128` chi
- exact withdraw with no new output note: `2,175` chi
- relayed hidden-sender transfer: `5,288` chi

April 2026 baseline before the native tree/digest path:

- deposit with 2 outputs: `87,622`
- transfer with 2 inputs / 2 outputs: `87,896`
- withdraw with 1 input / 1 output: `45,081`
- exact withdraw with no new output note: `2,107`
- relayed hidden-sender transfer: `113,839`

So the meaningful cost improvement came from reducing real validator compute,
not just moving metadata out of consensus state.

## Why This Matches External Research

- Firo Spark's direction reinforces that privacy products should stay modular
  around addressability, viewing, and discovery.
- Aztec's note-discovery model reinforces that wallet sync should use indexed
  discovery hints rather than brute-force scans over broad history.
- Zcash Orchard reinforces that roots and nullifiers are the real consensus
  core, not a large note metadata table.

## Follow-Up Work

After this redesign slice, the next steps are:

1. teach clients and wallets to prefer BDS `shielded_output_tags` queries
2. keep measuring against the benchmark harness as circuit/runtime work changes
3. evaluate whether commitment listings can also leave consensus state in a
   later phase
4. evaluate block-local batch verification once shielded transaction volume is
   high enough
