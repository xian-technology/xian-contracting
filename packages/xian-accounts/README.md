# xian-tech-accounts

Small shared account and signing primitives for the Xian workspace.

Wallets and nodes share the Ed25519 helpers and the hybrid account wire
protocol from this package.

## API

- `generate_private_key()`
- `public_key_from_private_key(private_key)`
- `sign_message(private_key, message)`
- `verify_message(public_key, message, signature)`
- `is_valid_ed25519_key(key)`
- `Ed25519Account.generate()`
- `Ed25519Account.sign_message(message)`
- `Ed25519Account.verify_message(message, signature)`

Keys are exactly 32 bytes encoded as 64 hexadecimal characters. Lowercase,
uppercase and mixed-case hex are accepted; whitespace and non-string values
are invalid. Account construction validates the key before retaining it.

`sign_msg(...)` and `verify_msg(...)` remain small aliases for wallet-style
callers in the wider Xian workspace.

Install `xian-tech-accounts[hybrid]` for the `xian_account_v1` protocol.
`xian_accounts.hybrid` signs role-separated messages with Ed25519 and
ML-DSA-65 and requires both signatures. The caller supplies canonical payload
bytes and obtains the keys and epoch from trusted account state. Use
`compact_transaction(payload, signature)` for ordinary strict-policy spends. New account
addresses commit to the initial active and recovery key pairs through
`account_address(record)`. An enrolled legacy account retains its address.

## Validation

```bash
cd packages/xian-accounts
uv run --extra hybrid --with pytest pytest -q
```
