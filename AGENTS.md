# Repository Guidelines

## Scope
- `xian-contracting` owns contract compilation, execution, storage, metering, and runtime security semantics.
- Keep node orchestration, genesis distribution, and operator workflow out of this repo.
- This repo is security-sensitive. Favor small, well-tested changes.

## Project Layout
- `src/contracting/compilation/`: parser, compiler, linter, and whitelist logic.
- `src/contracting/execution/`: runtime, executor, module loading, and tracing.
- `src/contracting/storage/`: drivers, ORM helpers, encoder, and HDF5 support.
- `src/contracting/contracts/`: built-in and system contract assets.
- `tests/`: unit, integration, security, and performance coverage.

## Workflow
- `master` is the only working branch for this repo right now. Stay on `master` unless explicitly told otherwise.
- Preserve runtime behavior deliberately. If a fix changes execution semantics, add regression tests in the same change.
- Avoid cross-repo orchestration changes here unless the ABCI or CLI layer requires a new importable primitive.

## Validation
- Preferred setup: `uv sync --group dev`
- Lint: `uv run ruff check .`
- Format check: `uv run ruff format --check .`
- Tests: `uv run pytest`
- If you touch security boundaries or metering, run the relevant `tests/security/` and `tests/integration/` paths explicitly.

## Notes
- The test suite now uses a repo-local HOME via `tests/conftest.py`, so it does not need host access to `~/.cometbft`.
- Review `examples/` and release helpers critically before expanding them; do not add convenience tooling that belongs in `xian-cli` or `xian-stack`.
