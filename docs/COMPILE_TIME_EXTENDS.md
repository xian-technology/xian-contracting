# Compile-Time `extends` Design

## Goal

Add a reusable inheritance-like authoring feature without changing runtime
execution semantics.

The design target is:

- developers can write a contract that reuses a base contract
- the deployed artifact is still a single flattened contract
- runtime context, storage ownership, metering, and event attribution remain
  exactly as they work today

This is intentionally not runtime inheritance and not a `delegatecall` model.

## Why Compile-Time Only

`contracting` currently executes contracts as isolated modules with strict
context switching on cross-contract calls. When contract `A` calls contract
`B`, the callee runs with:

- `ctx.this = "B"`
- `ctx.caller = "A"`

That is a good security property for composition, but it is the wrong semantic
model for inheritance. A runtime inheritance feature would immediately need new
rules for:

- whose storage is being written
- whose owner guard applies
- whose events are emitted
- whose metering bucket is charged

A compile-time flattener avoids all of that by producing ordinary single-module
contract code before the existing compiler and linter run.

## Proposed Authoring Model

Use a source-level pragma instead of new Python syntax:

```python
# extends: xsc001_base@sha256:<source-hash>
```

Notes:

- keep it on the first non-empty line
- support exactly one base contract in v1
- require a pinned source hash or code hash
- reject unpinned `extends`

The child contract is flattened with the base source before normal submission.

## Resolution Rules

1. Load the child source.
2. Parse the `# extends:` pragma if present.
3. Resolve the base source from an approved source locator.
4. Verify the pinned hash matches the resolved base source.
5. Recursively flatten the base chain.
6. Merge base and child ASTs into one final module.
7. Run the existing linter/compiler on the flattened output.

Approved source locators should be narrow in v1:

- local source file during development
- submitted contract source by exact name plus exact pinned hash

Do not allow unpinned network lookups or dynamic runtime imports.

## Merge Rules

### 1. Module-Level State

ORM declarations are part of storage layout and must be treated as ABI.

- duplicate ORM names are an error
- no automatic renaming for `Variable`, `Hash`, or `LogEvent`
- the child may reference base ORM names directly after flattening

This keeps storage layout explicit and prevents hidden state aliasing.

### 2. Private Helpers

Private helpers are implementation details and may collide.

- auto-rename base private function names with a deterministic prefix
- auto-rename base private local helper references to match
- do not auto-rename exported functions

A practical prefix is:

```text
__extends_<base_contract_name>_<original_name>
```

### 3. Exported Functions

Exported functions define the child ABI.

- child exported functions may override base exported functions
- multiple base/child exports with the same name are resolved in favor of the
  child
- duplicate exports within the same inheritance level are an error

The flattened output should contain only one final exported definition per
name.

### 4. Constructors

Keep constructor chaining explicit.

- if the base has `@construct`, rewrite it to a private helper during
  flattening
- if the child has `@construct`, it may call the rewritten base constructor
  helper explicitly
- if the child has no `@construct`, inherit the base constructor as the final
  constructor

Do not auto-run multiple constructors implicitly in v1.

## Security Invariants

The feature should preserve these invariants:

- no runtime link to mutable external code after deployment
- no writes to another contract's storage
- no new context model beyond today's single-contract execution
- no new bypass around owner checks
- no hidden export surface introduced by the base

To enforce that last point, the flattener should emit a manifest of inherited
exports and overrides in normalized source metadata or deployment diagnostics.

## Non-Goals For V1

- multiple inheritance
- diamond inheritance
- trait linearization
- `super()` syntax
- runtime method dispatch
- inheriting from arbitrary remote code without pinning

These are not needed for the initial reuse problem and make auditability worse.

## Suggested Implementation Shape

Add a preprocessing phase before `ContractingCompiler.parse()`:

1. `resolve_extends(source) -> FlattenResult`
2. `FlattenResult.source` becomes the input to the existing linter/compiler
3. `FlattenResult.metadata` captures:
   - base chain
   - pinned hashes
   - renamed private helpers
   - overridden exports

Useful follow-up APIs:

- `compiler.flatten_source(source)`
- `compiler.explain_flatten(source)`

Those would make the feature testable without deployment.

## Recommended Tests

- flatten a child with one base and no overrides
- override one exported function
- reject duplicate ORM names
- rename colliding private helpers deterministically
- inherit a base constructor when the child has none
- support explicit child-to-base constructor call
- reject unpinned bases
- reject base hash mismatch
- show stable normalized output for identical inputs

## Recommendation

If this feature moves forward, keep the first implementation deliberately
minimal:

- one base only
- hash-pinned only
- flatten to plain source
- reuse the current linter and runtime unchanged

That gives most of the ergonomics benefit while avoiding a new execution model.
