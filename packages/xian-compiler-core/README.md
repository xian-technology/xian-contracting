# xian-compiler-core

This crate is the Rust/WASM compiler core described in
`../../docs/RUST_COMPILER_CORE.md`.

The crate owns the artifact model, hashing rules, diagnostics, source
units, parser adapter, Xian-owned syntax tree, semantic linting, source
normalization, structural `xian_ir_v1` lowering, and compiler fixture loader.
The checked-in compiler fixtures are generated from the current Python compiler
and act as the parity oracle during the compiler transition.

## Current Surface

- `SourceUnit`: validated source/module/profile input wrapper
- `ContractArtifact`: typed `xian_contract_artifact_v1` deployment artifact
- `build_contract_artifact(...)`: construct artifact metadata from canonical
  source and canonical IR bytes
- `validate_contract_artifact(...)`: verify artifact format, profile, hashes,
  JSON IR, and embedded IR identity fields
- `CompilerDiagnostic`: stable structured diagnostic payload
- `parse_source(...)`: RustPython-backed parser adapter for the current
  Python-like contract syntax, returning an opaque parsed module
- `parse_diagnostics(...)`: deterministic parser diagnostic adapter with
  source ranges
- `parse_to_syntax(...)`: parse source and convert it into a compact Xian-owned
  syntax tree
- `build_syntax_tree(...)`: convert an existing parsed module into Xian syntax
- `SyntaxModule`, `SyntaxStatement`, `SyntaxExpression`: Rust-owned syntax data
  model used by later lint/normalize/lower stages
- `lint_syntax(...)`: semantic lint rules over `SyntaxModule`
- `normalize_syntax(...)`: deterministic formatter over the Xian syntax tree
- `normalize_source(...)`: parse, optionally lint, and return canonical source
- `lower_syntax_to_ir(...)`: lower a validated syntax tree into structural
  `xian_ir_v1`
- `lower_source_to_ir(...)`: normalize, parse, optionally lint, and lower source
  into structural `xian_ir_v1`
- `lower_source_to_ir_json(...)`: return canonical JSON for the lowered IR
- `compile_contract_artifact(...)`: normalize, lower, and build a hash-checked
  `xian_contract_artifact_v1`
- `describe_vm_host_surface()`: expose the `xian_vm_v1_host_v1` host catalog
- `diagnose_contract(...)`: first high-level compiler entrypoint; currently
  validates source/profile, parser diagnostics, unsupported syntax nodes, and
  semantic lint diagnostics when `lint` is enabled
- `compiler_version()`: machine-readable version and schema metadata
- `CompilerFixture`: typed representation of `xian.compiler_fixture.v1`
- `parse_compiler_fixture_json(...)`: load a fixture JSON document
- `CompilerFixture::validate_basic()`: deterministic structural checks for
  accepted and rejected fixture records

Fixtures are generated from the current Python compiler with:

```bash
uv run python scripts/generate_compiler_fixtures.py \
  packages/xian-compiler-core/tests/sources
```

Run the Rust fixture checks with:

```bash
cargo test --manifest-path packages/xian-compiler-core/Cargo.toml
```

Check the optional binding layers with:

```bash
cargo check --manifest-path packages/xian-compiler-core/Cargo.toml \
  --features python-extension
cargo check --manifest-path packages/xian-compiler-core/Cargo.toml \
  --features wasm
```

Build the Python package locally with:

```bash
uv run python -c "import xian_compiler_core"
```

Build the WASM package from `packages/xian-compiler-core/npm` with:

```bash
npm run build
```

The WASM build requires `wasm-pack` and a Rust toolchain with the
`wasm32-unknown-unknown` standard library installed. The generated npm package
is consumed by browser apps such as `xian-ide-web` and by JS callers that want
to compile source locally.
