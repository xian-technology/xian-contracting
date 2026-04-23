# xian-contracting

`xian-contracting` is the Python contract runtime for Xian. It owns contract
compilation, secure execution, storage semantics, metering, and the runtime
rules that contracts must obey.

The published package is `xian-tech-contracting`. The import package remains
`contracting`.

## Quick Start

Install the default pure-Python runtime:

```bash
pip install xian-tech-contracting
```

Optional native packages are split out so the default install stays small:

```bash
pip install 'xian-tech-contracting[native]'
pip install 'xian-tech-contracting[zk]'
```

Submit and call a contract:

```python
from contracting.client import ContractingClient

client = ContractingClient()
client.submit(name="con_token", code=contract_source)
token = client.get_contract("con_token")
token.transfer(amount=100, to="bob")
```

Access storage directly:

```python
from contracting.storage.driver import Driver

driver = Driver()
driver.set("example.key", "value")
print(driver.get("example.key"))
```

## Principles

- Contracts use Python syntax, but execution rules are consensus-sensitive and
  intentionally narrower than general Python.
- Metering, storage encoding, import restrictions, and runtime helpers must
  stay version-aligned across validators.
- Optional native tracing is an implementation detail. The contract model and
  runtime rules should remain understandable without it.
- Built-in helpers should serve the execution model, not grow into a general
  convenience framework.

## Key Directories

- `src/contracting/`: runtime, storage, compilation, and stdlib bridge code
- `packages/`: shared packages for deterministic runtime types, accounts,
  native tracing, fast-path validation, VM work, and zk tooling
- `scripts/`: audit and fixture-generation tools used by VM/runtime work
- `tests/`: unit, integration, and security coverage
- `docs/`: architecture, backlog, current-state notes, and active design drafts
- `examples/`: notebook examples plus a non-Jupyter validation script

## What It Covers

- compilation and linting
- runtime execution and metering
- storage drivers and encoding
- contract-side runtime helpers
- optional native tracing backend
- speculative parallel batch execution primitives
- native zero-knowledge verifier building blocks
- Xian VM IR generation, validation, parity fixtures, and early native VM work

## Validation

The default CI path is:

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest --cov=contracting --cov-report=term-missing --cov-report=xml
```

The default pytest configuration intentionally deselects tests marked
`optional_native`; those tests require Rust extension packages that are not part
of the pure-Python install.

The native CI path is:

```bash
./scripts/validate-release.sh
```

If you change metering, tracing, storage encoding, or import restrictions, run
the relevant `tests/security/` and `tests/integration/` paths explicitly too.

`./scripts/validate-release.sh` is the release gate for this repo. It runs the
default suite, the native tracer / zk / VM checks, the optional-native parity
and fuzz coverage, and the Rust package checks used by release CI.

## Related Docs

- [AGENTS.md](AGENTS.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/BACKLOG.md](docs/BACKLOG.md)
- [docs/PARALLEL_EXECUTION.md](docs/PARALLEL_EXECUTION.md)
- [docs/SAFETY_INVARIANTS.md](docs/SAFETY_INVARIANTS.md)
- [docs/TRACER_BACKENDS.md](docs/TRACER_BACKENDS.md)
- [docs/README.md](docs/README.md)
