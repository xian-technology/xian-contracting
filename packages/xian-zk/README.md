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
  - `xian_zk.verify_groth16_bn254(vk_hex, proof_hex, public_inputs) -> bool`
- Rust:
  - `verify_groth16_bn254(...)`
  - `build_demo_vector()`

## Encoding
- Verifying keys: compressed canonical bytes as `0x`-prefixed hex
- Proofs: compressed canonical bytes as `0x`-prefixed hex
- Public inputs: 32-byte big-endian field elements as `0x`-prefixed hex

## Validation
- `cargo test --manifest-path packages/xian-zk/Cargo.toml --no-default-features`
- `cargo run --manifest-path packages/xian-zk/Cargo.toml --no-default-features --example generate_test_vector`
- `uv run --project packages/xian-zk pytest -q`

## Notes
- The package is intentionally narrow.
- It is not a proving toolkit and it is not a general-purpose zk framework.
