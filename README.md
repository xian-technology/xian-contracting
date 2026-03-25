# xian-contracting

`xian-contracting` is the Python contract runtime for Xian. It owns contract
compilation, secure execution, storage semantics, metering, and the runtime
rules that contracts must obey.

## Quick Start

Install the runtime:

```bash
pip install xian-contracting
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
- `packages/`: shared packages such as `xian-runtime-types`, `xian-contract-tools`, and the native tracer
- `tests/`: unit, integration, and security coverage
- `docs/`: architecture, backlog, and execution notes

## What It Covers

- compilation and linting
- runtime execution and metering
- storage drivers and encoding
- contract-side runtime helpers
- optional native tracing backend

## Validation

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

If you change metering, tracing, storage encoding, or import restrictions, run
the relevant `tests/security/` and `tests/integration/` paths explicitly too.

## Related Docs

- [AGENTS.md](AGENTS.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- [docs/BACKLOG.md](docs/BACKLOG.md)
- [docs/README.md](docs/README.md)
