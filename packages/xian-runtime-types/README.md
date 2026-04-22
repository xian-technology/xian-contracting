# xian-tech-runtime-types

Shared deterministic runtime types for the Xian stack.

## Contents

- `decimal.py`: fixed-precision `ContractingDecimal` and decimal bounds
- `time.py`: deterministic `Datetime` and `Timedelta`
- `collections.py`: deterministic set and frozenset implementations
- `encoding.py`: JSON encoding/decoding for runtime storage values

These types are used by `xian-contracting` and other packages that need the
same deterministic value semantics without importing the full contract runtime.

## Validation

The package is covered by the root test suite:

```bash
uv run pytest -q tests/unit/test_decimal.py tests/unit/test_datetime.py \
  tests/unit/test_timedelta.py tests/unit/test_contracting_collections.py \
  tests/unit/test_encode.py
```
