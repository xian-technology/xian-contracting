# xian-contracting

`xian-contracting` is the Python contract runtime for Xian. It owns contract
compilation, secure execution, storage semantics, metering, and the runtime
rules that contracts must obey.

## Scope

This repo owns:

- compilation and linting
- runtime execution, tracing, and metering
- storage drivers, encoding, and contract-side runtime helpers
- packaged shared runtime types and the optional native tracer backend

This repo does not own:

- node orchestration or Compose flows
- operator lifecycle commands
- ABCI request handling

## Key Directories

- `src/contracting/`: main runtime, storage, compilation, and stdlib bridge code
- `packages/`: shared runtime packages such as `xian-runtime-types` and the
  optional native tracer
- `tests/`: unit, integration, and security coverage
- `docs/`: architecture, backlog, and execution notes

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

## Installation

```bash
pip install xian-contracting
```

## Core Interfaces

Minimal client example:

```python
from contracting.client import ContractingClient

client = ContractingClient()
client.submit(name="con_token", code=contract_source)
token = client.get_contract("con_token")
token.transfer(amount=100, to="bob")
```

Direct storage access:

```python
from contracting.storage.driver import Driver

driver = Driver()
driver.set("example.key", "value")
value = driver.get("example.key")
```

## Runtime Notes

- contracts use Python syntax with Xian-specific decorators such as
  `@construct` and `@export`
- metering is tied to the active CPython minor version, so validators must stay
  version-aligned
- restricted imports, storage semantics, and encoding behavior are
  consensus-sensitive and should not change casually
