# Compiler Package Release

This checklist keeps the central Rust compiler as one packaged dependency for
Python, JavaScript, the CLI, and the browser IDE.

## What Users Should Need

End users of `xian-tech-contracting`, `xian-py`, `xian-cli`, `xian-js`, and
`xian-ide-web` should install published packages only. They should not need a
Rust toolchain, `wasm-pack`, `maturin`, or a sibling checkout just to compile or
deploy contracts from source.

Rust, `wasm-pack`, `maturin`, and npm are maintainer/CI requirements for
building and publishing the compiler packages.

## Maintainer Prerequisites

- Rust toolchain with the `wasm32-unknown-unknown` target installed.
- `wasm-pack` on `PATH`.
- `uv` for Python release validation.
- `npm` authenticated for the `@xian-tech` organization.
- PyPI publishing credentials or trusted publishing configured for
  `xian-tech-compiler-core`.

## Validation

Run the release gate from this repository:

```bash
./scripts/validate-release.sh
```

The gate checks Python tests, Rust tests, native-extension builds, and the
browser/Node WASM compiler package build.

Run downstream consumers before publishing a breaking compiler change:

```bash
npm --prefix ../xian-js test
npm --prefix ../xian-ide-web test
npm --prefix ../xian-ide-web run build
uv run --project ../xian-py pytest
uv run --project ../xian-cli pytest
```

Run the 5-node E2E path from `xian-stack` after the packages are wired locally.

## Publish Order

1. Publish `xian-tech-compiler-core` to PyPI by pushing a
   `compiler-core-vX.Y.Z` tag from `xian-contracting`.
2. Publish `@xian-tech/compiler` to npm from
   `packages/xian-compiler-core/npm`.
3. Publish `xian-tech-contracting`, which depends on
   `xian-tech-compiler-core`.
4. Publish dependent Python tools: `xian-py` and `xian-cli`.
5. Publish dependent JavaScript tools: `xian-js`.
6. Build/deploy `xian-ide-web` against the published `@xian-tech/compiler`
   package.

## Python Compiler Core

Build the native Python binding locally before tagging:

```bash
uvx maturin build \
  --release \
  --manifest-path packages/xian-compiler-core/Cargo.toml \
  --features python-extension
```

The GitHub Actions release workflow publishes through PyPI Trusted Publishing.
Configure the PyPI pending publisher with project `xian-tech-compiler-core`,
owner `xian-technology`, repository `xian-contracting`, workflow
`release.yml`, and environment `pypi-xian-compiler-core`.

## JavaScript/WASM Compiler

Build and publish the WASM package:

```bash
cd packages/xian-compiler-core/npm
npm run build
npm publish --access public
```

The published package must include only the package metadata, README, generated
TypeScript declarations, generated JavaScript glue, and WASM binary under
`dist/`.

## Versioning Rules

- Bump the compiler core whenever accepted source, diagnostics, normalized
  source, IR JSON, hashes, or artifact validation behavior changes.
- Keep `xian_contract_artifact_v1` stable unless the protocol deployment shape
  changes intentionally.
- Do not publish SDKs that depend on unpublished local compiler paths.
- Do not keep compatibility aliases in SDKs for removed deployment APIs.
