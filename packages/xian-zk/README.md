# xian-zk

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

## API
- Python:
  - `xian_zk.prepare_groth16_bn254_vk(vk_hex) -> PreparedGroth16Bn254Key`
  - `xian_zk.verify_groth16_bn254(vk_hex, proof_hex, public_inputs) -> bool`
  - `xian_zk.verify_groth16_bn254_prepared(prepared_vk, proof_hex, public_inputs) -> bool`
  - `xian_zk.ShieldedNoteProver.build_insecure_dev_bundle()`
  - `xian_zk.ShieldedNoteProver.build_random_bundle(contract_name=..., vk_id_prefix=...)`
  - `xian_zk.ShieldedNoteProver.prove_deposit(...)`
  - `xian_zk.ShieldedNoteProver.prove_transfer(...)`
  - `xian_zk.ShieldedNoteProver.prove_withdraw(...)`
  - `xian_zk.ShieldedKeyBundle.generate()`
  - `xian_zk.ShieldedKeyBundle.from_parts(owner_secret=..., viewing_private_key=...)`
  - `xian_zk.ShieldedWallet.generate(asset_id)`
  - `xian_zk.ShieldedWallet.from_parts(asset_id=..., owner_secret=..., viewing_private_key=...)`
  - `xian_zk.ShieldedWallet.from_json(snapshot_json)`
  - `xian_zk.ShieldedWallet.from_seed_json(seed_json)`
  - `xian_zk.ShieldedWallet.sync_records(records) -> ShieldedWalletSyncResult`
  - `xian_zk.ShieldedWallet.build_deposit(...)`
  - `xian_zk.ShieldedWallet.build_transfer(...)`
  - `xian_zk.ShieldedWallet.build_withdraw(...)`
  - `xian_zk.ShieldedViewingKeyBundle.generate()`
  - `xian_zk.owner_public(owner_secret) -> str`
  - `xian_zk.output_commitment(asset_id, owner_public, amount, rho, blind) -> str`
  - `xian_zk.generate_field_hex() -> str`
  - `xian_zk.generate_owner_secret() -> str`
  - `xian_zk.encrypt_note_message(...) -> str`
  - `xian_zk.decrypt_note_message(...) -> ShieldedNoteMessage`
  - `xian_zk.recover_encrypted_notes(...) -> list[ShieldedDiscoveredNote]`
  - `xian_zk.recover_viewable_notes(...) -> list[ShieldedViewableNote]`
  - `xian_zk.shielded_registry_manifest(bundle) -> dict`
  - `xian_zk.asset_id_for_contract(contract_name) -> str`
  - `xian_zk.merkle_root(commitments) -> str`
  - `xian_zk.tree_state(commitments) -> ShieldedTreeState`
  - `xian_zk.scan_notes(asset_id=..., commitments=..., notes=...)`
  - CLI: `uv run xian-zk-shielded-bundle --output-dir ...`
- Rust:
  - `prepare_groth16_bn254_vk(...)`
  - `verify_groth16_bn254(...)`
  - `verify_groth16_bn254_prepared(...)`
  - `build_demo_vector()`
  - `build_shielded_note_fixture()`
  - `build_insecure_dev_shielded_note_bundle()`
  - `prove_shielded_deposit(...)`
  - `prove_shielded_transfer(...)`
  - `prove_shielded_withdraw(...)`

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
  `xian-zk-shielded-bundle` generate a single-party random trusted setup. That
  is appropriate for deployment tooling, but it is still not an MPC ceremony.
- Proof generation uses real randomness even when the proving bundle is a
  deterministic dev bundle.
