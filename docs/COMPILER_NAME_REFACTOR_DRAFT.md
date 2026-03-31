# Compiler Name Resolution Draft

This note captures an unfinished refactor idea for
`src/contracting/compilation/compiler.py`.

Status:

- draft only
- not implemented
- not validated
- not ready to merge

## Goal

The current compiler still uses an awkward post-pass rename flow:

- collect every visited `ast.Name` node in `visited_names`
- collect private function names and ORM declaration names separately
- walk the collected nodes after traversal and mutate matching names

Current code path:

- `ContractingCompiler.parse(...)`
- `ContractingCompiler.visit_FunctionDef(...)`
- `ContractingCompiler.visit_Assign(...)`
- `ContractingCompiler.visit_Name(...)`

Why this is worth revisiting:

- it mixes collection and transformation concerns
- it stores AST nodes that only exist to support a later rename pass
- it is harder to reason about than a cleaner collection/transform split
- the compiler still contains a TODO acknowledging this awkwardness

## Candidate Refactor Direction

The intended direction is a deliberate two-phase compiler flow:

1. Run a collection pass over the parsed AST to gather:
   - private function names
   - ORM variable/hash/event names that should be privatized
2. Run the existing transform pass with those name sets already known, so
   `visit_Name(...)` can privatize immediately instead of storing nodes for a
   later mutation pass.

What should stay true:

- exported functions still rewrite to `@__export("<module>")`
- `@construct` still rewrites the function name to `____`
- ORM declarations still get injected `contract=` and `name=` keywords
- private function definitions and all their call sites still rewrite to the
  private-prefixed name
- float literal handling remains exactly as it is today

## Risks

This is not a mechanical cleanup. It touches consensus-sensitive compilation
behavior and can easily create subtle output differences.

High-risk areas:

- private function call rewriting
- ORM declaration rewriting
- name collisions between private functions and local variables
- behavior inside nested expression trees
- preservation of current `ast.unparse(...)` output where tests rely on it

The proposal from the older fork branch should not be cherry-picked directly.
Our current compiler has already diverged, and any refactor must be written
against the current implementation.

## Minimum Test Plan Before Merge

Do not merge this refactor without adding or extending tests for all of the
following:

1. Private function renaming:
   - private definition is renamed
   - public functions calling private helpers are rewritten correctly
   - private helpers calling other private helpers are rewritten correctly

2. ORM declaration rewriting:
   - `Variable`, `Hash`, and `LogEvent` still receive injected `contract=` and
     `name=`
   - `ForeignVariable` and `ForeignHash` stay unchanged

3. Decorator rewriting:
   - `@export` still rewrites exactly to `@__export("<module>")`
   - `@construct` still renames to `____`

4. Float literal behavior:
   - regular float literals still preserve source precision
   - float defaults in parameter lists still compile to `decimal(...)`

5. Output parity:
   - existing compiler integration tests still pass without broad fixture churn

6. Performance validation:
   - a simple benchmark or at least a scripted comparison on larger contract
     inputs should show a real reason to take the refactor

## Suggested Validation Commands

At minimum:

```bash
uv run pytest -q tests/unit/test_parser.py tests/unit/test_linter.py \
  tests/integration/test_senecaCompiler_integration.py \
  tests/integration/test_executor_submission_process.py
```

Prefer also running a small benchmark harness against representative contract
sources before merge.

## Draft PR Guidance

If this work is resumed later, keep the PR as draft until:

- the refactor is implemented against current `main`
- the regression coverage above exists
- the behavior is shown to be output-compatible
- the performance justification is demonstrated
