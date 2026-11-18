# Historical compatibility baseline

This directory preserves V1 language and application evidence. Current code
executes only V2 in Rust; these fixtures do not establish compatibility of the
current runtime with historical V1 execution.

## Contents

- `cases.json` and `legacy_baseline.json`: language observations from
  `xian-contracting@3b82001f2d587bbfb51f3d9235a2a8dcd0078a9a` with Python 3.12.10.
- [applications/](applications/README.md): 68 observations over five byte-pinned
  published contract sources, with exact historical policy differences recorded.
- [historical/](historical/README.md): immutable observers and their digests.
- `runner.py`: typed observation encoding and current native V2 surface helpers.
  It does not replay the archived V1 corpus on the current engine.

Snapshots retain typed returns, writes and events. Dictionary keys and insertion
order, bool/int/float and list/tuple distinctions remain observable. Set contents
are sorted for recording, so the corpus does not establish historical set
iteration-order compatibility. Historical float and raw Decimal behavior is
archival evidence, not part of the current V2 number model.

## Verify provenance

From the repository root:

```sh
uv run pytest tests/integration/test_vm_legacy_compatibility.py tests/integration/test_vm_application_compatibility.py
```

These tests check corpus/baseline digests, observation coverage and typed
encoding; they do not execute the V1 workflows. Replaying V1 requires a pinned
older installation that still supports it, as described in the application
guide. Current V2 execution, metering, storage and rollback are tested separately
under `tests/integration/` and `packages/xian-vm-core/tests/`.

## Recapture the historical oracle

```sh
python scripts/capture-compatibility-baseline.py
# Review a candidate without replacing the checked-in snapshot:
python scripts/capture-compatibility-baseline.py --output /tmp/language-baseline-candidate.json
python scripts/capture-application-baseline.py
```

Capture exports the pinned historical Git object into temporary storage,
installs its locked dependencies with `uv`, verifies interpreter/package and
observer provenance, and executes the archived observers. It requires the Git
objects and cached dependencies or network access. It never uses today's VM
as its own oracle or switches the working checkout. Review candidates before
replacing evidence; do not edit archived observer bytes.

The corpus is representative, not a complete grammar, metering or
cross-architecture consensus certificate. See the application and observer
guides for precise capture inputs, deviations and coverage limits.
