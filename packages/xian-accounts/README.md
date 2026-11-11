# xian-tech-accounts

Small shared account and signing primitives for the Xian workspace.

This package is intentionally narrow. It is the neutral home for reusable
Ed25519 key, signing, and verification helpers that should not live in the
external SDK and should not be mixed into deterministic runtime types.

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

## Validation

```bash
cd packages/xian-accounts
uv run pytest -q
```
