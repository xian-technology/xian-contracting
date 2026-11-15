# xian-compiler-core

This crate is the Rust/WASM compiler core described in
`../../docs/RUST_COMPILER_CORE.md`.

The crate owns the artifact model, hashing rules, diagnostics, source
units, parser adapter, Xian-owned syntax tree, semantic linting, source
normalization, structural `xian_ir_v1` lowering, bounded compile admission, and
compiler fixture loader. The checked-in accepted and rejected fixtures are the
shared parity oracle for Rust, Python, WASM/JavaScript, linter, and node
admission surfaces.

Rust, Python and WASM default to the fresh-chain profile `xian_vm_v2`. V2 reads decimal literals from their UTF-8 source digits and emits canonical decimal strings. Use `decimal` for exported fixed-point values. To reproduce a historical artifact, pass `vm_profile="xian_vm_v1"` in Python or `{"vm_profile":"xian_vm_v1"}` in WASM options JSON. Both profiles use the `xian_ir_v1` envelope.

## Current Surface

- `SourceUnit`: validated source/module/profile input wrapper
- `ContractArtifact`: typed `xian_contract_artifact_v1` deployment artifact
- `build_contract_artifact(...)`: construct artifact metadata from canonical
  source and canonical IR bytes
- `validate_contract_artifact(...)`: verify artifact format, profile (and the
  expected execution profile when given), hashes, JSON IR, embedded IR identity
  fields, and that re-lowering the source reproduces the IR exactly (which also
  rejects non-canonical source)
- `CompilerDiagnostic`: stable structured diagnostic payload
- `CompilerLimits`: consensus defaults for source bytes, syntax nodes/depth,
  total tokens, and logical-line tokens
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
- `normalize_source(...)`: parse, lint, and return canonical source
- `lower_syntax_to_ir(...)`: lower a validated syntax tree into structural
  `xian_ir_v1`
- `lower_source_to_ir(...)`: normalize, parse, lint, and lower source
  into structural `xian_ir_v1`
- `lower_source_to_ir_json(...)`: return canonical JSON for the lowered IR
- `compile_contract_artifact(...)`: normalize, lower, and build a hash-checked
  `xian_contract_artifact_v1`
- `compile_contract_source(...)`: the pair a node deploys for submitted source,
  `CompiledSource { source, vm_ir_json }` (normalized source plus the canonical
  IR lowered from it); vm-core's deploy path and `contracting.artifacts` use it
- `SUPPORTED_VM_PROFILES`, `DEFAULT_VM_PROFILE`, `XIAN_VM_V1_PROFILE`,
  `XIAN_VM_V2_PROFILE`, `CONTRACT_ARTIFACT_FORMAT_V1`: the profile and format
  names, defined here once
- `describe_vm_host_surface()`: expose the `xian_vm_v1_host_v1` host catalog
- `diagnose_contract(...)`: authoritative high-level compiler entrypoint;
  validates the complete source-to-IR path and returns stable diagnostics
- `compiler_version()`: machine-readable version and schema metadata
- `CompilerFixture`: typed representation of `xian.compiler_fixture.v1`
- `parse_compiler_fixture_json(...)`: load a fixture JSON document
- `CompilerFixture::validate_basic()`: deterministic structural checks for
  accepted and rejected fixture records

## One Implementation For Every Caller

Artifact assembly (normalization, hashes, IR identity, canonical re-lowering,
the expected-profile check), the deploy compile pair and the profile constants
live only in this crate. The bindings expose the same operations:

| Operation | Python (`xian_compiler_core`) | WASM (`@xian-tech/compiler`) |
| --- | --- | --- |
| diagnostics | `diagnose_contract` | `diagnoseContractJson` |
| artifact | `compile_contract_artifact` | `compileContractArtifactJson` |
| deploy pair | `compile_contract_source` | `compileContractSourceJson` |
| validation | `validate_contract_artifact(..., vm_profile=)` | `validateContractArtifactJson(name, json, inputSource?, vmProfile?)` |
| profiles | `SUPPORTED_VM_PROFILES`, `DEFAULT_VM_PROFILE`, ... | `compilerVersionJson()` |

Both return the same artifact JSON (the Python binding parses the same
`serde_json` string the WASM binding returns), and compiler errors use one
message format (`<code>: <message>` followed by the diagnostics JSON).
xian-linter and `xian contract build-artifacts` call the Python binding
directly; `contracting.artifacts` is a thin delegation that also checks the
native host catalog against the contract runtime's host bindings; xian-ide-web,
xian-playground-web and xian-js use the WASM package. Structural IR validation
stays in vm-core (`xian_vm_core.validate_module_ir_json`), the VM's own
admission rules; the linter calls it on the compiled IR.

Every entrypoint always runs the lint rules; they are part of admission. The
only compile option is `vm_profile`, and unknown options (such as `lint`) are
rejected.

Fixtures are refreshed through the authoritative Python binding with:

```bash
uv run python scripts/generate_compiler_fixtures.py \
  --profile xian_vm_v1 packages/xian-compiler-core/tests/sources
```

To regenerate the default V2 fixtures, use the sources in
`packages/xian-compiler-core/tests/sources_v2`.

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
