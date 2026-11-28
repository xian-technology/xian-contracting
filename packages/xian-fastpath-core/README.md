# xian-fastpath-core

Rust crate with the transaction admission rules:

- wire decoding: hex text, UTF-8, JSON within the depth limit and the canonical
  spelling (`decode_transaction`)
- the static rules: exact key sets, field formats, the strict Ed25519 signature
  over the signed payload, the chain id and the submission name
  (`validate_transaction_static`)
- `compact_account::decode` reads the strict ordinary-spend tag, fixed
  signature frame and canonical UTF-8 payload
- `validate_account_candidate` and `validate_account_payload` apply static
  shape checks before the node resolves the current authority
- `ADMISSION_REVISION`, the rule revision nodes fence on at startup

It has no Python binding of its own. `xian-vm-core` links it and exposes
`decode_and_validate_transaction(raw, chain_id)`, which adds the V2 wire
grammar of the payload (the stored-value reader) for legacy envelopes.
`decode_account_candidate(raw, chain_id)` handles hybrid envelopes. It returns
an unauthenticated document. The node verifies proofs against the registry in
CheckTx, PrepareProposal, ProcessProposal and FinalizeBlock.
Changing what it admits requires a new admission revision; the golden corpus in
`xian-abci/tests/fixtures/admission_parity.json` shows every change.

## Validation

```bash
cargo test --manifest-path packages/xian-fastpath-core/Cargo.toml
```
