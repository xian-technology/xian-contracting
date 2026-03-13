# xian-contracting

`xian-contracting` is the Python contract runtime for Xian. It owns contract
compilation, secure execution, storage behavior, metering, and related runtime
semantics. This repo is security-sensitive and should stay narrowly focused on
execution correctness.

## Ownership

This repo owns:

- compilation and linting under `src/contracting/compilation/`
- runtime, executor, and tracing under `src/contracting/execution/`
- storage drivers and encoding under `src/contracting/storage/`
- built-in contract assets under `src/contracting/contracts/`

This repo does not own:

- node orchestration or Compose flows
- operator lifecycle commands
- ABCI request handling

## Installation

```bash
pip install xian-contracting
```

## Development

```bash
uv sync --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest
```

The test suite uses a repo-local home directory via `tests/conftest.py`, so it
does not require host access to `~/.cometbft`.

If you change metering, tracing, storage encoding, or import restrictions, run
the relevant `tests/security/` and `tests/integration/` paths explicitly.

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

- Contracts use Python syntax with Xian-specific decorators such as `@construct`
  and `@export`.
- Metering, memory limits, and restricted imports are part of the runtime
  contract and should not change casually.
- Built-in contracts and runtime helpers should stay aligned with the execution
  model rather than growing into general convenience utilities.
