# xian-tech-zk

Small native zero-knowledge verification and proving primitives for the Xian
workspace.

## Purpose
- This package exposes the narrow verifier surface used by the Xian runtime.
- It also now exposes the first external proving toolkit for the
  shielded-note-token development flow.
- It is still intentionally small. It is not a general-purpose zk framework.

## Current Scope
- Groth16 verification
- BN254
- Python bindings for runtime integration
- A pure Rust verifier core for cargo-level testing and fixtures
- Shielded-note proving circuits and proof generation helpers
- Deterministic dev bundle generation for local shielded-note workflows
- Note math helpers for commitments, nullifiers, asset ids, and Merkle roots
- Trusted local prover-service support for note, command, and relay proof generation

## API

Python module `xian_zk` exposes:

- raw and prepared Groth16 BN254 verification
- native public-input, payload-hash, tree, and command digest helpers
- shielded note request/result/prover/wallet types
- shielded command request/result/prover/wallet types
- shielded relay transfer request/result/prover/wallet types
- registry manifest helpers for note, command, and relay verifying keys
- note encryption/decryption, discovery-tag, sync-hint, and wallet sync helpers
- local prover service clients and `ShieldedZkProverService`

CLI entrypoints:

- `uv run xian-zk-shielded-bundle generate-note --output-dir ...`
- `uv run xian-zk-shielded-bundle generate-command --output-dir ...`
- `uv run xian-zk-shielded-bundle import-note --bundle ... --output-dir ...`
- `uv run xian-zk-shielded-bundle import-command --bundle ... --output-dir ...`
- `uv run xian-zk-shielded-bundle validate-note --bundle ...`
- `uv run xian-zk-shielded-bundle validate-command --bundle ...`
- `uv run xian-zk-prover-service --host 127.0.0.1 --port 8787 ...`

The Rust crate exposes the verifier core, shielded fixture builders, and proof
generation helpers used by the Python bindings and tests.

## Encoding
- Verifying keys: compressed canonical bytes as `0x`-prefixed hex
- Proofs: compressed canonical bytes as `0x`-prefixed hex
- Public inputs: 32-byte big-endian field elements as `0x`-prefixed hex

## Validation
- `cargo test --manifest-path packages/xian-zk/Cargo.toml --no-default-features`
- `cargo run --manifest-path packages/xian-zk/Cargo.toml --no-default-features --example generate_test_vector`
- `cargo run --manifest-path packages/xian-zk/Cargo.toml --no-default-features --example generate_shielded_note_fixture`
- `cd packages/xian-zk && uv sync --group dev && uv run maturin develop && uv run pytest -q`
- `cd packages/xian-zk && uv run pytest -q -m slow`

## Notes
- The runtime-facing verifier surface is still intentionally narrow.
- The shielded-note proving helpers are the first external proving toolkit
  slice, not a broad proving framework.
- The shielded-note circuits now use Merkle auth paths instead of witnessing
  the whole leaf set, and the shipped dev bundle / fixture ids are `v2`.
- Shielded outputs are now addressed to `owner_public`, not to the recipient's
  spending secret. That lets senders create recipient outputs without learning
  the recipient's private shielded spend key.
- The Python toolkit now separates spending and viewing authority. A wallet can
  disclose note contents by sharing only a viewing key or by adding explicit
  extra viewers to an encrypted note payload without exposing the spend key.
- The Python toolkit now also ships a first-class `ShieldedWallet` abstraction
  for seed backup, state snapshots, record sync, note selection, and request
  planning for deposit / transfer / withdraw flows.
- The package now also ships a deployment CLI that generates a random
  shielded-note proving bundle plus a public registry manifest. Keep the
  bundle private; only the manifest should be used for `zk_registry`
  registration.
- The encrypted payload format now supports owner delivery plus optional
  disclosed viewers inside a single on-chain payload blob.
- The encrypted payload format uses anonymous per-viewer discovery tags and
  ephemeral keys for new payloads, so recipient viewing keys are no longer
  embedded in cleartext.
- `ShieldedWallet.sync_records(...)` now prefilters candidate payloads before
  full decryption, and note records now expose `payload_tags` so indexers can
  persist discovery metadata for later selective queries.
- `xian-zk-prover-service` is a trusted local proving companion, not a true
  split-prover protocol. It improves deployability and wallet ergonomics, but
  the service still sees witness material.
- Exact withdraws no longer need a forced change note. A withdraw can spend a
  note set down to zero shielded outputs when value conservation closes exactly.
- The proving requests separate `old_root` from `append_state`, which lets a
  client prove against a recent accepted root while still projecting the
  canonical post-state from the current append frontier.
- Python `pytest` now excludes the slow proof-generation tests by default.
  Run `pytest -m slow` explicitly when you want the proving-toolkit path.
- The contract runtime prefers registry-backed verification by `vk_id`; this
  package exposes the lower-level raw and prepared-key verifier primitives that
  runtime builds on.
- `ShieldedNoteProver.build_insecure_dev_bundle()` is for local development and
  tests only. Its deterministic setup seed exposes toxic waste and must never
  be used for a real network.
- `ShieldedNoteProver.build_random_bundle(...)` and
  `xian-zk-shielded-bundle generate-note` generate a single-party random
  trusted setup. That is appropriate for deployment tooling, but it is still
  not an MPC ceremony.
- Proof generation uses real randomness even when the proving bundle is a
  deterministic dev bundle.
