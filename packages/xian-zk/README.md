# xian-zk

Small native zero-knowledge verification primitives for the Xian workspace.

## Purpose
- This package exposes a narrow verifier surface for the Xian runtime.
- It is validator-facing infrastructure, not a proving toolkit.

## Current Scope
- Groth16 verification
- BN254
- Python bindings for runtime integration
- A pure Rust verifier core for cargo-level testing and fixtures

## API
- Python:
  - `xian_zk.prepare_groth16_bn254_vk(vk_hex) -> PreparedGroth16Bn254Key`
  - `xian_zk.verify_groth16_bn254(vk_hex, proof_hex, public_inputs) -> bool`
  - `xian_zk.verify_groth16_bn254_prepared(prepared_vk, proof_hex, public_inputs) -> bool`
- Rust:
  - `prepare_groth16_bn254_vk(...)`
  - `verify_groth16_bn254(...)`
  - `verify_groth16_bn254_prepared(...)`
  - `build_demo_vector()`

## Encoding
- Verifying keys: compressed canonical bytes as `0x`-prefixed hex
- Proofs: compressed canonical bytes as `0x`-prefixed hex
- Public inputs: 32-byte big-endian field elements as `0x`-prefixed hex

## Validation
- `cargo test --manifest-path packages/xian-zk/Cargo.toml --no-default-features`
- `cargo run --manifest-path packages/xian-zk/Cargo.toml --no-default-features --example generate_test_vector`
- `cd packages/xian-zk && uv sync --group dev && uv run maturin develop && uv run pytest -q`

## Notes
- The package is intentionally narrow.
- It is not a proving toolkit and it is not a general-purpose zk framework.
- The contract runtime prefers registry-backed verification by `vk_id`; this
  package exposes the lower-level raw and prepared-key verifier primitives that
  runtime builds on.
