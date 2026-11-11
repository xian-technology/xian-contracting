# Published application compatibility corpus

These are newly authored, bounded workflows over **unchanged published contract
sources**, not a replay of historical chain transactions. The five source files
come from `xian-contracts@45d1334ac4de44c67afc46b68b435dca7d711281` (2025-10-26).
`manifest.json` records each original path, Git blob and SHA-256. No license file
was present at that revision; the manifest does not infer a license. The `.py.txt`
suffix keeps formatters from rewriting historical source bytes.

| Workflow | Observations including deployment | Covered behavior |
| --- | ---: | --- |
| Reflection token | 14 | transfer, allowance consumption, over-allowance rejection and follow-up, fees/burn/reflection, operator permission |
| Nameservice | 19 | currency allowance, mint, duplicate rejection, nested data, owner/approval transfers, reverse-name cleanup, expiry and remint |
| Staking | 18 | pool creation, reward funding, entry fee, duplicate stake, timed reward calculation, early penalty and mature withdrawal, pause permission/recovery |
| DEX | 17 | two tokens, pair creation, liquidity mint, quote, swap, slippage rejection, liquidity approval/burn, failure after nested transfers and recovery |

There are 68 observations, including nine real constructor deployments and ten
business failures. A small trusted bootstrap contract invokes each runtime's
submission helper (`__Contract` historically, `Contract` today). Only this
adapter bypasses ordinary linting; application sources use normal deployment
admission. Native bootstrap artifacts use the production Rust
`build_contract_artifacts` path; real native child deployments use `NativeVmHost`
canonical Rust compilation.
No application source is rewritten, no balances are seeded directly,
and constructors run. This is application/constructor-state evidence, not a
certificate that historical deployment metadata or submission APIs are identical.

## Run against an installed runtime

From the repository root, without installing or rebuilding anything:

```sh
python tests/compatibility/application_runner.py --engine native --check --output /tmp/applications.json
python tests/compatibility/application_runner.py --engine native-metered --check
```

`--sequence dex_liquidity_swap` selects one workflow; unknown names fail. Each
run uses fresh temporary storage and fixed sender/time/context inputs. The
metered native mode has a 100,000,000 raw-chi per-call ceiling. Historical gas
prices are deliberately not compared. Existing optional-native CI/release
selection automatically includes `test_vm_application_compatibility.py`.

The maintained native runner needs `application_runner.py`,
`application_expectations.py`, `runner.py` and this directory. Its dependencies come from the installed runtime;
it does not import pytest. This allows the same corpus to run on supported
Apple Silicon macOS, Linux x86-64 and Linux ARM64 installations. A successful
local run alone does not prove cross-platform consensus. Windows is unsupported.

## Historical oracle and observation rules

`legacy_baseline.json` was captured with the real pre-VM
`xian-contracting@3b82001f2d587bbfb51f3d9235a2a8dcd0078a9a` runtime and Python
3.12.10. Regenerate it only from that runtime:

```sh
python scripts/capture-application-baseline.py
# Or reuse an existing installation after strict byte verification:
python scripts/capture-application-baseline.py --oracle-directory /path/to/pinned/checkout
```

The capture script stages the exact archived observers from
`../historical/` beside a byte-identical corpus copy. The maintained runner
accepts only `native` and `native-metered`; historical Python is executed only by
the pinned capture workflow. The capture script verifies the executed installed `contracting` and
`xian_runtime_types` Python files, including absence of extra Python files,
against the pinned Git objects; it also checks the source copies, dependency
lock, interpreter version and import origins. The baseline records package,
lock, observer, encoder, manifest and sequence digests. The capture process uses
an isolated HOME and never replaces the working installation.

Each observation records typed results, status, writes, events and **all data
state in every fixture contract namespace**. Top-level write/state maps sort
storage keys; nested dictionary order and key types remain observable. Bool,
int, float, Decimal, list and tuple remain distinct. Error diagnostics are
retained as evidence; business-specific message fragments are independently
required, while cross-engine comparison does not demand identical exception
class/message spelling. Unexpected failures cannot count as successful parity.

Every failure must return no writes/events and preserve a typed snapshot of the
entire driver, including other namespaces and compiler/deployment metadata.
Successful writes are applied and committed, and storage is closed/reopened
before the next call and after the final call. This checks persisted encoding
and deletion, not just in-memory driver caches. Compiler/source/administrative
metadata are excluded only from successful application-data comparisons using
an explicit key list; arbitrary underscore-prefixed application keys are retained.

## Two deliberate historical differences

The raw historical capture remains unchanged. `current_policy_deviations.json`
contains exact scenario/step/typed-field replacements, each with literal
historical and current values. It permits **110 observed leaf differences from
two underlying policies**, not 110 independent bugs:

1. **Constructor authority context** (89 repeated key locations): commit
   `e020d23a` runs constructors with the child's `this`/owner. The old runtime ran
   them in the submission frame. Reflection-token initialization consequently
   excludes its own address today, rather than `submission`. This difference was
   independently reproduced through both runtimes' actual shipped submission
   contracts, not only the corpus bootstrap adapter.
2. **Fixed-scaled square root** (21 result/write/state locations): commit
   `c9bb1ac2797f79d004c27452df42eaa74786bd6d` replaced the fixed Decimal square-root
   path with integer square-root arithmetic. `sqrt(1000000)` is exactly 1000;
   initial DEX liquidity is therefore `999.99999999`. The historical general
   Decimal-power path undershot before quantization, yielding
   `999.999999989999999999999999999999`. The native compatibility check requires this exact result. Raw Decimal
   general power remains a separate operation and is not exempted here.

Every replacement checks that the original historical leaf still has exactly
the documented value. Duplicate replacements fail. All remaining fields compare
strictly; there is no numeric tolerance, ignored extra-write list, source patch
or blanket per-workflow exemption. Updating the historical snapshot or exception
map requires reviewing the evidence, not accepting current output automatically.
