# xian-tech-runtime-types

Shared deterministic runtime types for the Xian stack.

## Contents

- `decimal.py`: fixed-precision `ContractingDecimal` and decimal bounds
- `time.py`: deterministic `Datetime` and `Timedelta`
- `collections.py`: deterministic set and frozenset implementations
- `encoding.py`: JSON encoding/decoding for runtime storage values

These types are used by `xian-contracting` and other packages that need the
same deterministic value semantics without importing the full contract runtime.

The encoder and `convert_dict` normalize nested lists and dictionaries recursively.
Large integers use `__big_int__` at every depth; booleans retain their JSON type.

## Fresh-genesis numbers

The public encoder and decoder APIs default to `xian_vm_v2`. Use `encode_wire`
for SDK and transaction JSON and `encode` / `decode` for stored values.
Select `vm_profile="xian_vm_v1"` explicitly for historical state. Bare JSON integers range
from `-(2**53 - 1)` to `2**53 - 1`. Larger magnitudes use a canonical signed
decimal string under `__big_int__`, with magnitude below `2**512`. Decimals
use `{"__fixed__": "1.25"}` at every depth. Wire spelling uses plain ASCII
digits, a leading minus for negative values, and no redundant zeros. The
smallest unit is `10**-30` and the absolute value must be below `10**61`.
`canonical_fixed` converts exact Python decimal values, strings and integers
to this form. Binary float, nonfinite values and unrepresentable input fail.

`normalize_wire_numbers` turns typed input into a JSON tree, and
`loads_wire_json` parses incoming JSON while retaining its tags and rejecting
noncanonical numeric tokens such as `-0`, `1.0` and `1e-400`.
`decode_wire_numbers` checks and decodes the resulting wire tree. Numeric tags
already supplied as JSON must be canonical. V2 stored dictionaries and
wire objects use string keys. Numeric members of the existing versioned set
codec support integers and fixed decimals. V2 sets preserve distinct boolean
and integer members, including inside tuples and nested frozen sets.

For off-chain contract arguments, construct Python `int` and `decimal.Decimal`
values from integers or strings and pass them through the current codecs.
`str()` and `repr()` of a `ContractingDecimal` give the same plain fixed-point
text as `canonical_fixed` and the V2 VM's `str(decimal)`: no exponent, no
trailing fractional zeros, `0` for zero (`1000`, not `1E+3`). Format specs such
as `f"{amount:.4f}"` apply to that plain value as V2 `format(decimal, spec)`
does. `ContractingDecimal` and the wrapper collection classes also implement legacy
CPython operations for archival replay. The native VM executes V2 contract
arithmetic and determines the types returned to the client.

## Validation

The package is covered by the root test suite:

```bash
uv run pytest -q tests/unit/test_decimal.py tests/unit/test_datetime.py \
  tests/unit/test_timedelta.py tests/unit/test_contracting_collections.py \
  tests/unit/test_encode.py tests/unit/test_set_codec.py tests/unit/test_wire_encoding.py
```

## Persistent wrapper sets (`xian-set-1`)

New `ContractingSet` and `ContractingFrozenSet` writes retain the outer
`__set__` / `__frozenset__` tag and contain an explicit member envelope:

```json
{"__set__":{"codec":"xian-set-1","items":[["tuple",[["int","1"],["int","2"]]]]}}
```

Members use a closed typed grammar. V2 supports the following member tags, with
two additional historical tags available only through explicit V1 decoding.

| Node | Payload |
| --- | --- |
| `["none"]` | No payload |
| `["bool", value]` | JSON boolean |
| `["int", digits]` | Canonical signed decimal integer string |
| `["float", bits]` | V1 only. Exactly 16 lowercase hexadecimal IEEE754 binary64 bits |
| `["fixed", scaled]` | Canonical integer string at the existing `10**30` scale |
| `["raw_decimal", sign, digits, exponent]` | V1 only. Sign 0/1, unsigned coefficient string, exact base-10 exponent |
| `["str", text]` | Unicode scalar string |
| `["bytes", hex]` | Lowercase hexadecimal byte string |
| `["datetime", parts]` | Year, month, day, hour, minute, second, microsecond |
| `["timedelta", seconds]` | Canonical signed integer seconds string |
| `["tuple", members]` | Typed child nodes |
| `["frozenset", members]` | Canonically ordered typed child nodes |

Mutable sets, lists, mappings, callables, proxies and non-finite numbers cannot
be members. The existing deterministic wrapper normalization defines order and
deduplication; decoding rejects noncanonical new envelopes instead of silently
rewriting them. Ordinary scalar/container encodings outside wrapper sets retain
their existing representation.

The codec bounds each wrapper payload to depth 64, 131,072 typed nodes and an
8 MiB conservative JSON byte cap, measured with Python-compatible ASCII escapes.
Astral characters count as two six-byte surrogate escapes for this cap. The VM's
metering representation remains compact UTF-8 JSON, so this conservative cap is
not the gas byte-count formula. Existing transaction/write limits can be stricter.
V2 integer members have at most 512 bits of magnitude. In V1, the integer
limit is 1,048,576 bits and raw Decimal digits, canonical text and absolute
exponent are bounded by 131,072. The sum of squared cardinalities
of every wrapper set/frozen set in one persistence payload must not exceed
8,388,608, checked before normalization. A single set can therefore contain at
most 2,896 members; nesting and multiple wrapper roots share that work budget.
Explicit V1 decoding shares the same budget across object-hook constructions without
counting an already reconstructed nested wrapper twice.

Before serialization, `encode`, `Encoder` and `validate_persistent_value` also
bound the ordinary value tree to depth 128 (root depth zero) and 1,048,576
visited values. Dictionary keys and values count separately, and repeated
references count at each occurrence. Wrapper sets use the separate member
limits above. This validation rejects cycles, non-finite numbers and reserved
dictionary tags even when a payload contains no sets. SDK transaction kwargs
that use this encoder receive the same checks before signing.

These serializer ceilings do not guarantee node acceptance. The node checks
depth 128 on the complete transaction JSON, including its outer envelope; the
VM independently bounds external values to depth 128 and 131,072 visited
values. Transaction sizes, execution budgets and storage limits also apply.

Select V1 to read a legacy list-shaped set envelope. Arrays that occur as legacy
set members are restored recursively as tuples; ordinary JSON arrays elsewhere
remain lists. Legacy `__fixed__` values retain their historical fixed type because
old writes cannot recover already-lost raw Decimal quantum.

The public helpers exported by `xian_runtime_types.encoding` are:

- `is_wrapper_set(value)` identifies the deterministic wrapper families.
- `encode_set_value(value)` returns a plain versioned JSON object.
- `decode_set_value(tag, payload)` reads the typed V2 envelope. Pass `exact_numbers=False` to either set helper for the historical V1 representation.
- `validate_persistent_value(value)` checks finite values, bounded traversal,
  cycles, unsupported objects and reserved-key collisions before serialization.

New ordinary persisted dictionaries cannot contain any reserved runtime codec
key, even with siblings or inside another container. This covers every key in
`encoding.TYPES`, not just set tags. Actual typed objects remain valid. Trusted
wire data must be decoded with `decode`/`convert_dict` before re-encoding; feeding
an already-tagged ordinary dictionary to `encode` intentionally fails. Explicit V1 reads retain historical tag recognition.

## Wire documents and persistent values

Use `encode_wire(value)` for transaction kwargs, envelopes and genesis/config
documents that may already contain canonical codec tags. A tagged value must
use the complete representation for its type. The default V2 decoder rejects
malformed wrappers, alternate numeric spellings and extra sibling keys.

Use `encode(value)`, `Encoder` or `validate_persistent_value` when working
with typed storage and effect values. They reject ordinary dictionaries that
contain reserved codec keys. Both storage and transaction objects require
string keys. For an archived V1 document, select `vm_profile="xian_vm_v1"`
explicitly. Its historical wire encoder preserves opaque tags and its decoder
accepts legacy set-array representations.
