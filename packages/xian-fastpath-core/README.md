# xian-fastpath-core

Rust crate with the transaction admission rules:

- wire decoding: hex text, UTF-8, JSON within the depth limit and the canonical
  spelling (`decode_transaction`)
- the static rules: exact key sets, field formats, the strict Ed25519 signature
  over the signed payload, the chain id and the submission name
  (`validate_transaction_static`)
- `ADMISSION_REVISION`, the rule revision nodes fence on at startup

It has no Python binding of its own. `xian-vm-core` links it and exposes
`decode_and_validate_transaction(raw, chain_id)`, which adds the V2 wire
grammar of the payload (the stored-value reader) and is the one admission
implementation CheckTx, PrepareProposal, ProcessProposal and FinalizeBlock use.
Changing what it admits requires a new admission revision; the golden corpus in
`xian-abci/tests/fixtures/admission_parity.json` shows every change.

## Validation

```bash
cargo test --manifest-path packages/xian-fastpath-core/Cargo.toml
```
