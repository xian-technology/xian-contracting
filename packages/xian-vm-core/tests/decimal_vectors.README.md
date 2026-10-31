# Historical Decimal regression corpus

`decimal_vectors.json` contains 2,266 ordered cases captured from **CPython
3.12.10 using libmpdec 4.0.0** on 2026-10-31. Each JSON array row is
`[operation, [operand_text, ...], [status, result_text]]`; one case occupies one
line. Status 0 means success, 1 InvalidOperation, 2 DivisionByZero, and 3
Overflow. Failed cases have empty result text.

The backend unit test `matches_pinned_historical_decimal_vectors` compares
exact result strings and exception categories. There are 1,982 successful
results and 284 expected exceptions, covering 42 operation names, including
1,254 power cases. The complete nine-test isolated backend suite took 0.22s
on the development ARM64 Mac; the corpus alone took 0.24s in a separate run.
These timings are observations, not CI performance assertions.

## Oracle and sampling

The context is precision 91, ROUND_DOWN, Emin=-100, Emax=100, capitals=1,
clamp=0, with InvalidOperation, DivisionByZero and Overflow trapped. Exact
Decimal construction happens before context operations. Operation-specific
rounding is supplied by historical libmpdec, including HALF_EVEN for sqrt,
exp, ln and log10. Results preserve signed zero, quantum and non-finite
payload spelling.

The first 1,008 cases sample 24 inputs for each of 42 operations with
`random.Random(71031)`. The extension uses `random.Random(171031)` for 1,200
finite fractional powers, then exercises near-one operands with up to 1,075
coefficient digits. Exactly five power cases above the final 1,024-digit
power coefficient cap are excluded, yielding 2,266 in-budget cases. Separate
backend tests cover rejected input/work bounds; the corpus does not redefine
those bounds or silently round oversized operands.

The checked-in values and their ordering are unchanged from the original
review artifact; only JSON whitespace changed. SHA256 evidence:

- Original single-line artifact: `bea1ad668eb2559bf5b599d29074f20d239e013f145235cc20c584f537010afd`
- This one-case-per-line corpus: `4042198aa30680a7c5dc1a5eaa15a1b1a26f3a8f182f5b9c6a3fd7f89dd857b6`

The original interpreter was the local uv-managed CPython 3.12.10 macOS ARM64
build; `decimal.__libmpdec_version__` reported 4.0.0. Do not infer the library
version merely from the Python version: CPython distributions can link a
different bundled or external libmpdec.

## Reproduce

From this package directory, select an interpreter with both pinned versions:

```sh
DECIMAL_ORACLE_PYTHON=/path/to/pinned/python3.12
"$DECIMAL_ORACLE_PYTHON" tests/capture_decimal_vectors.py --check
```

The script refuses other Python/libmpdec versions and prints the corpus
checksum. It invokes only the Python oracle, never the Rust backend. Omit
`--check` to recapture the file, or use `--output /path/to/capture.json` to
write a separate candidate for review. Changing the oracle or fixture is a
consensus-sensitive compatibility change, not routine snapshot maintenance.

Run the Rust regression with:

```sh
cargo test matches_pinned_historical_decimal_vectors
```

The same final corpus matched on macOS ARM64, Linux ARM64 and Linux x86-64
**under Docker emulation on ARM64**, and passed AddressSanitizer and
UndefinedBehaviorSanitizer checks. Native x86 hardware and Windows numerical
parity were not verified by that review. This corpus supplies regression
evidence, not an exhaustive proof of all Decimal inputs.
