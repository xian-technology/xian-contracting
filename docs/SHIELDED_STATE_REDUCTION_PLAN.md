# Shielded State Reduction Plan

## Problem

The current shielded contracts are charging far more for state growth than for
proof verification.

Measured localnet receipts from the April 4, 2026 5-validator run:

- simple public `currency.transfer`: `48` stamps
- 2-output `deposit_shielded`: `87,622` stamps
- 2-output `transfer_shielded`: `87,896` stamps
- 1-output `withdraw_shielded`: `45,081` stamps
- exact withdraw with no new output: `2,107` stamps

That spread shows the cost explosion is not the Groth16 verifier itself. The
verifier is roughly low-thousands of stamps. The expensive part is the current
contract-side note persistence model:

- encrypted note payload bytes are written into consensus state
- per-note metadata is duplicated into consensus state
- note delivery and note correctness are coupled together

## Current Consensus State

Today the shielded contracts keep all of the following in consensus state:

- note commitment frontier / tree state
- accepted root window
- spent nullifiers
- note existence
- note commitment index history
- per-note metadata
  - index
  - root
  - created_at
  - payload
  - payload_hash

Only some of that is consensus-critical.

## Design Goal

Keep only the state required for correctness and double-spend protection in
consensus. Move note delivery and historical convenience reads off the consensus
path.

## V1: Minimal Consensus State

This is the immediate implementation target.

Consensus keeps:

- current tree frontier / root state
- recent accepted roots
- spent nullifiers
- note existence
- note commitment-by-index history
- minimal per-note metadata
  - index
  - payload_hash

Consensus no longer keeps:

- raw encrypted payload bytes
- per-note `created_at`
- per-note `root`

Wallet delivery moves to indexed transaction payloads:

- `output_payloads` already travel in the transaction kwargs
- BDS already stores decoded transaction payload JSON
- wallets can reconstruct note records from indexed contract transactions in
  canonical block order
- `xian_zk` now exposes `note_records_from_transactions(...)` and
  `ShieldedWallet.sync_transactions(...)` for that path

This keeps proof correctness unchanged because the proof still commits to
`output_payload_hashes`.

## Why V1 Is Safe

- proof verification is unchanged
- note commitment insertion order is unchanged
- root acceptance logic is unchanged
- nullifier spend tracking is unchanged
- wallets still verify that decrypted payloads match the commitment
- the payload hash remains committed inside the proof and available on-chain

The only thing being removed from consensus state is bulky delivery data, not
the spend-validity state.

## V1 Tradeoff

Wallet note discovery now depends on an indexed transaction feed instead of a
contract state query that returned payload bytes directly.

That is acceptable because:

- the payload bytes were already part of the transaction submitted to the chain
- BDS already persists the decoded tx payload
- note delivery is an indexing concern, not a consensus concern
- tx bytes must still be metered, but at a network/indexing rate rather than a
  state-growth rate

## Expected V1 Impact

The biggest expected win is removing raw payload writes from consensus state.

Observed sample payloads in the localnet shielded flow were roughly `1.1 KB` per
payload. At the current `25 stamps / byte` storage-write rate, payload storage
alone is tens of thousands of stamps per output note.

So V1 should materially reduce:

- `deposit_shielded`
- `transfer_shielded`
- `withdraw_shielded` when it produces a change output

Exact-withdraw flows with no new output note should change much less, because
they are already near the verifier-floor plus minimal state writes.

## V2: Root-Only Shielded State

The longer-term target is stronger than V1.

Consensus should eventually hold only commitment roots / frontiers and spentness
commitments, not per-note history.

That model looks like:

- note commitment root or frontier
- nullifier commitment / set commitment
- recent root window
- public / shielded supply invariants

The proving system would carry more of the membership-update logic, and the
contract would verify a root transition instead of mutating a note catalog in
Python.

That is the serious path toward constant-size consensus state.

## Why Not V2 Immediately

V2 is a proving-system and contract-model redesign:

- circuits need to own more state-transition logic
- wallet sync and indexing move fully off-chain
- contract interfaces and tests change more deeply

So V1 is the right first move:

- large cost reduction
- minimal correctness risk
- preserves the current proving model

## Follow-Up Work After V1

- document and harden the optional relayed hidden-sender transfer path
- benchmark relayed shielded transfers against direct shielded transfers
- document that shielded note delivery is off-chain indexed data
- benchmark the new shielded stamp profile against the April 4, 2026 baseline
- evaluate whether note existence / note index history can also leave
  consensus state
- evaluate a V2 root-only shielded state model

## Optional Hidden-Sender Path

The note-token stack now also supports an optional relayed transfer path for
users who want the public L1 sender to be a relayer rather than the hidden note
owner.

That path is intentionally additive, not a new default token model:

- normal `transfer_shielded(...)` remains available
- `relay_transfer_shielded(...)` reuses the existing shielded command proof
  family for a note-token-specific statement
- the proof binds the relayer, chain id, expiry, and relayer fee
- the relayer submits the public transaction and receives the exact bound fee
  from shielded value

This gives Xian a concrete privacy mode for account-to-account transfers where
the hidden note owner is not the public transaction sender, without forcing that
model onto every token interaction.
