# xian-tech-fastpath-core

Optional Rust fast paths for:

- transaction wire decode and static validation
- payload extraction from decoded transaction JSON

This package is intentionally separate from the default Python path so both
`xian-contracting` and `xian-abci` remain usable without native extensions.

Integration note:

- `xian-abci` uses the combined decode + static validation fast path.
- `xian-abci` also uses the native payload extractor from Python decode paths.
- Planner and accepted-prefix helpers were removed after benchmarks on
  2026-04-04 showed the PyO3 boundary cost outweighed the Rust
  implementation for planner-sized payloads.

## API

- `decode_and_validate_transaction_static(raw, chain_id)`
- `extract_payload_string(json_str)`
- `NativeFastpathValidationError`

## Validation

```bash
cargo check --manifest-path packages/xian-fastpath-core/Cargo.toml
```
