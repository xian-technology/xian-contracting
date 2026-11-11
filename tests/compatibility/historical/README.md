# Immutable historical observers

The Python files in this directory are byte-identical copies from
`xian-contracting@fd1ceb07b2a32e23a90457fe0cfa5dafd69f62a5`. They are archival
observers, not a supported execution path for the current package.
`manifest.json` records their source revision and byte digests.

The language and application snapshots pin `runner.py` and
`application_runner.py` by SHA-256. Those snapshots and digests remain unchanged.
Capture scripts verify the archived bytes before executing them with
`xian-contracting@3b82001f2d587bbfb51f3d9235a2a8dcd0078a9a` and Python 3.12.10.
The application capture stages these files and an unchanged corpus into a
temporary observer directory so their relative imports and fixture paths work
without modifying historical code. Current compatibility runners execute native
V1 directly and do not import these observers.

Use the capture commands in the [compatibility guide](../README.md) to recapture
historical snapshots. Do not run these archived observers against the current
installation, change their bytes, or substitute current native output for
historical evidence.

## Retired parity-fixture generator

The maintained `scripts/generate_vm_parity_fixtures.py` was a Python-engine
oracle. Its output fixtures under `packages/xian-vm-core/tests/fixtures/` are
retained unchanged; native tests verify them independently. Rewriting the
generator to call the native VM would make the VM generate its own expected
results.

The exact generator remains in the pre-retirement Git revision above, with
SHA-256 `ef4d2f9bcc174ceb271cc305b9ebf38c697572c4f8d0a3d30cbf379202886413`.
For archival investigation, export the complete pinned tree into a separate
directory and use its Python 3.14 environment, lockfile and native dependencies:

```sh
archive_dir=$(mktemp -d)
git archive --format=tar fd1ceb07b2a32e23a90457fe0cfa5dafd69f62a5 > "$archive_dir/source.tar"
tar -xf "$archive_dir/source.tar" -C "$archive_dir"
cd "$archive_dir"
uv sync --frozen --python 3.14 --group dev
XIAN_WORKSPACE_ROOT=/absolute/path/to/xian uv run --no-sync python scripts/generate_vm_parity_fixtures.py
```

This generator requires the pre-retirement runtime; the older 3b82001 capture
runtime does not supply its APIs. A usable Rust toolchain is required to build
the pinned native dependencies. Record the actual interpreter/toolchain and
inputs with any regenerated candidate; the script alone is not complete
provenance for a new fixture capture.

The sibling Git objects used by the default generator inputs are:

| Repository | Revision |
| --- | --- |
| xian-configs | `da1ceceeb4dee5bbb4742c44c49508a6a379acd2` |
| xian-contracts | `dd500b037bd5e22b06ce1b8f202070f41433f5ae` |
| xian-dex | `f42ff874e43f6c4fd9eae76b1708910ae8303279` |
| xian-stable-protocol | `8c1383b0501b84160a25a079e9c50c0490f8ab24` |

Those objects must exist without switching sibling working checkouts. DEX source
overrides and other external inputs require their own recorded hashes. Review
candidate observations before accepting any fixture change; retaining these
instructions does not continue support for the retired Python executor.
