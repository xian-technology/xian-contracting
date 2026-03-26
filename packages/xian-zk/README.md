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
  - `xian_zk.ShieldedNoteProver.prove_deposit(...)`
  - `xian_zk.ShieldedNoteProver.prove_transfer(...)`
  - `xian_zk.ShieldedNoteProver.prove_withdraw(...)`
  - `xian_zk.asset_id_for_contract(contract_name) -> str`
  - `xian_zk.merkle_root(commitments) -> str`
  - `xian_zk.scan_notes(asset_id=..., commitments=..., notes=...)`
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

## Notes
- The runtime-facing verifier surface is still intentionally narrow.
- The shielded-note proving helpers are the first external proving toolkit
  slice, not a broad proving framework.
- The contract runtime prefers registry-backed verification by `vk_id`; this
  package exposes the lower-level raw and prepared-key verifier primitives that
  runtime builds on.
- `ShieldedNoteProver.build_insecure_dev_bundle()` is for local development and
  tests only. Its deterministic setup seed exposes toxic waste and must never
  be used for a real network.
- Proof generation uses real randomness even when the proving bundle is a
  deterministic dev bundle.
