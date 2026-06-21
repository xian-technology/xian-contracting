# Repository Guidelines

## Scope
- `xian-contracting` owns contract compilation, execution, storage, metering, and runtime security semantics.
- Keep node orchestration, genesis distribution, and operator workflow out of this repo.
- This repo is security-sensitive. Favor small, well-tested changes.

## Shared Convention
- Follow the shared repo convention in `xian-meta/docs/REPO_CONVENTIONS.md`.
- Keep this repo aligned with that standard for stable root docs, backlog notes, and folder-level entrypoints.
- Follow the shared change workflow in `xian-meta/docs/CHANGE_WORKFLOW.md`.
- Before push, review downstream impact on `xian-abci`, `xian-py`, and `xian-docs-web`, and run the local validation path from this file.

## Project Layout
- `src/contracting/compilation/`: parser, compiler, linter, and whitelist logic.
- `src/contracting/execution/`: runtime, executor, module loading, and tracing.
- `src/contracting/storage/`: drivers, ORM helpers, encoder, and LMDB-backed state storage.
- `src/contracting/contracts/`: package-local contract assets such as the
  built-in submission contract.
- `tests/`: unit, integration, security, and performance coverage.

## Workflow
- `main` is the primary working branch for this repo. Stay on `main` unless explicitly told otherwise.
- Preserve runtime behavior deliberately. If a fix changes execution semantics, add regression tests in the same change.
- Avoid cross-repo orchestration changes here unless the ABCI or CLI layer requires a new importable primitive.
- Keep built-in contracts and storage/runtime helpers aligned with the execution model. Do not treat this repo like a general utilities package.

## Validation
- Preferred setup: `uv sync --group dev`
- Lint: `uv run ruff check .`
- Format check: `uv run ruff format --check .`
- Tests: `uv run pytest`
- If you touch security boundaries or metering, run the relevant `tests/security/` and `tests/integration/` paths explicitly.

## Notes
- The test suite now uses a repo-local HOME via `tests/conftest.py`, so it does not need host access to `~/.cometbft`.
- Review `examples/` and release helpers critically before expanding them; do not add convenience tooling that belongs in `xian-cli` or `xian-stack`.
- If you touch metering, tracing, imports, or storage encoding, assume the change is consensus-sensitive and test accordingly.

## Shared Agent Practices
- Keep changes clean, modular, and professional. Prefer small, cohesive modules, clear naming, explicit boundaries, and tests over quick patches.
- When code behavior, public APIs, user workflows, operator workflows, or configuration semantics change, check whether `../xian-docs-web` needs corresponding documentation updates. If this repo is `xian-docs-web`, update the relevant published docs in place. Write durable user/developer documentation, not a changelog entry.
- For code changes, use graphify when available to check cross-repo impact before finishing: query the local `graphify-out/graph.json`, inspect paths with `graphify path` or `graphify explain`, and refresh with `graphify update .` after structural changes when useful.
- If graphify or dependency analysis shows affected sibling repos, update those repos in the same change when the impact is real and the fix is in scope.
- Treat `graphify-out/` as a generated local artifact. Do not commit it.
