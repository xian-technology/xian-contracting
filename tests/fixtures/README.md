# Shared transaction fixtures

`transaction_wire.json` is the common normalized-wire contract tested by
`xian-js`, `xian-py`, and `xian-abci`. All three read this single file from the
sibling checkout, which their CI already provides.

Each case pins the payload, canonical signing string, Ed25519 signature, and
complete JSON transaction. Submitted CometBFT bytes are the ASCII hex encoding
of that JSON's UTF-8 bytes. The private key is synthetic test material.

The golden strings were calculated independently using Python's sorted JSON
serializer and PyNaCl, without calling SDK normalization. Do not regenerate
expected outputs automatically from the implementation under test. Add reviewed
cases when changing protocol encoding, and run all three consumers.

The cases cover numeric-looking keys, own `__proto__` data, Unicode code-point
ordering, nested runtime wrappers, and integer boundaries. Native runtime-value
normalization is also tested in `tests/unit/test_encode.py` and SDK tests.

# Stored-value readings

`stored_value_readings.json` pins how Python reads V2 stored values
(`xian_runtime_types.encoding.decode` followed by the VM boundary conversion):
each case is the stored bytes (hex) and the resulting `VmValue` as Rust `Debug`
text, or `null` when Python rejects the value. The Rust stored-value reader in
`xian-vm-core` must give the same reading for every case. The Python side is the
reference here, so `tests/integration/test_stored_value_reader.py` regenerates
the file (run it as a script) and its tests fail when the file is stale.
