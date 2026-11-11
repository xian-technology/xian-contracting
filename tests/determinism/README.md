# Native contracting determinism campaign

This campaign checks whether the same admitted contract programs produce exactly
the same observations across host environments and native architectures. It runs
the historical V1 allowed-surface corpus, plus reproducibly
generated programs with explicit expected results and failures, and 32 fixed
binary-float edge cases under V1. Generated integer, collection, Unicode, time,
and stateful programs run on V2. The generated raw-decimal/binary-float and
random-float families select V1. The same campaign includes all 26 V2 numeric
conformance vectors, including signed division, wide intermediates, rounding,
square root, overflow and rollback. Each profile is selected explicitly for
artifact generation, execution, storage and reopen checks. Every case uses
the native compiler/VM, metering, fresh storage and fixed contract context.

**Determinism is not correctness or an exhaustive proof.** Identical outputs can
still be identically wrong. The existing case oracles and generated semantic
expectations catch some such errors; Python compatibility tests and application
workflows supply separate correctness evidence. Finite generated cases and
selected environment scenarios cannot cover every program, input, platform or
combination of settings. A green local run is not a cross-platform result.

## Observations and checks

The observer checks authored status/result/error expectations independently of
the baseline output. These checks use explicit raises rather than removable
Python assert statements. It then compares:

- Canonical source/IR digests and relevant artifact metadata.
- Exact typed return values, error type/message/arguments, ordered writes and
  events, raw cost, chi usage and per-contract costs.
- Committed state before/after execution, failure rollback, and state after
  closing and reopening storage.

The typed encoder preserves float bits, including signed zero, integer values,
decimal components, container type/order, aliases and cycles where observed.
Storage keys are sorted for comparison; contract-visible collection order is
preserved. Persistence is checked at the documented codec boundary, including
its intentional canonicalization of supported values. Host descriptions are
recorded as evidence but excluded from contract-observation equality.

Each campaign writes its exact generated workload and a corpus digest. The
comparison rejects missing fields, different corpus digests, empty observations,
and any difference in the observed values. A failed case cannot stand in for a
successful determinism observation.

## Environment scenarios

Each scenario starts a separate Python process with a fresh temporary HOME.
The default eight scenarios cover baseline execution and changes to Python hash
seed, timezone, Decimal precision/rounding, warmed formatting/ambient runtime
state, case order plus storage reopen boundaries, allocator, and locale.
`--extended` adds high-precision Decimal, a second hash seed, and a combined
perturbation, for eleven scenarios. These are selected comparisons,
not the Cartesian product of every setting.

A separate preflight starts `python -O` and verifies that importing the runtime
fails closed because optimization strips consensus assertions. The campaign
records this check in `optimized-rejection.json`; it does not execute contracts
under optimization. All eight default and eleven extended execution scenarios
use optimization level zero.

Contract context, sources and kwargs stay fixed across scenarios. Only host
conditions vary. Generated cases use a private seeded generator, and their
arithmetic oracles use explicit contexts where needed. The saved seed and
workload let a failure be reproduced without choosing fresh inputs.

## Local use

Use the repository's Python 3.14 environment with native dependencies installed:

```sh
uv sync --group dev --extra native --extra zk
uv pip install --no-deps ./packages/xian-vm-core
.venv/bin/python -m tests.determinism.campaign \
  --output .artifacts/determinism-local --seed 20261103 --generated 32
```

The output directory must **not already exist**. Use a fresh path for every run;
the campaign does not overwrite previous evidence. For the larger campaign:

```sh
.venv/bin/python -m tests.determinism.campaign \
  --output .artifacts/determinism-extended --seed 20261103 \
  --generated 256 --extended
```

`--generated` adds cases to the full surface corpus; it never replaces that
corpus. The local CLI accepts 0 through 4096 generated cases. CI deliberately uses
a narrower 1-through-1024 range for manual inputs. A failed run retains logs,
completed reports and failure information in its output directory.

The principal files are `optimized-rejection.json`, `workload.json`,
`summary.json`, `baseline.json`, and a JSON report/log for each scenario. `summary.json` records the seed, exact corpus
digest, scenario configuration, completed scenarios and success status. Keep the
whole directory when reporting a failure.

## Three-platform CI

[Contract Determinism](../../.github/workflows/determinism.yml) uses native
Linux x86-64 (`ubuntu-24.04`), Linux ARM64 (`ubuntu-24.04-arm`), and macOS ARM64
(`macos-15`) jobs. The labels follow GitHub's
[hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners);
each job also checks its actual OS and Python process architecture before running.

| Trigger | Generated cases | Scenarios | Seed |
| --- | ---: | ---: | --- |
| Push / pull request | 32 | 8 | 20261103 |
| Nightly schedule | 256 | 11 |UTC date as `YYYYMMDD` |
| Manual dispatch | 256 by default; 1–1024 accepted | 11 by default; 8 when extended is false |Explicit unsigned 32-bit integer |

A single configuration job chooses and validates the settings before the matrix
starts, so even jobs crossing midnight receive the same seed. Manual defaults
are seed 20261103, generated 256, extended enabled. The actual configuration and
source revision are retained in `runner.json`; the nightly seed is also written
to the workflow summary.

Each platform uploads its entire `.artifacts/determinism/` directory, even after
failure, as `determinism-<platform>`. `runner.json` and `campaign.log` are at the
artifact root; campaign reports are under `campaign/`. The final comparison job
requires successful campaigns and **exactly all three** platform baseline files,
then checks the same corpus and exact observations. Missing architectures,
partial runs and different generated corpora cannot count as cross-platform
success. The comparison job uses only Python's standard library; it does not
install or execute the native runtime.

To compare downloaded artifacts locally:

```sh
python -m tests.determinism.campaign --compare \
  artifacts/determinism-linux-x86_64/campaign/baseline.json \
  artifacts/determinism-linux-arm64/campaign/baseline.json \
  artifacts/determinism-macos-arm64/campaign/baseline.json
```

CI bounds manual counts, subprocess timeouts and job duration. Increasing a seed
range or case count increases sampled coverage; it does not turn the result into
a proof. Preserve any discovered failing program as a focused regression rather
than relying on the random generator to rediscover it.

This workflow does not start a five-node network or change branch protection.
It complements `xian-stack`'s five-node E2E, exact block replay and published
application workflows: those exercise node integration, accounting and consensus
behavior that this compiler/runtime campaign does not model.

The local `scripts/validate-release.sh` gate also runs the extended campaign
with 256 generated programs and seed 20261103 after installing the current native
wheel. It retains the exact inputs and reports under a fresh
`.artifacts/determinism-release.*/campaign/` directory. Passing this local gate
does not replace the three-platform CI comparison.
