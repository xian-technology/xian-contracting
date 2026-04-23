# Docs

This folder contains internal design and backlog notes for `xian-contracting`.
Files here are not user-facing docs; they are implementation context for the
runtime, VM, tracer, zk, and backlog work.

Current-state docs:

- `ARCHITECTURE.md`
- `BACKLOG.md`
- `EXECUTION_BACKLOG.md`
- `PARALLEL_EXECUTION.md`
- `SAFETY_INVARIANTS.md`
- `SHIELDED_STATE_REDESIGN_V2.md`
- `TRACER_BACKENDS.md`

Active design / roadmap notes:

- `COMPILE_TIME_EXTENDS.md`
- `COMPILER_NAME_REFACTOR_DRAFT.md`
- `ZK_PRIVACY_OPTIMIZATION_PLAN.md`

Removed obsolete docs:

- The old shielded state reduction V1 plan was removed because its implemented
  work is now covered by `SHIELDED_STATE_REDESIGN_V2.md` and the remaining
  privacy work is tracked in `ZK_PRIVACY_OPTIMIZATION_PLAN.md`.
