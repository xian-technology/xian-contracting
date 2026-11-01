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

Members use a closed typed grammar. This preserves tuple hashability, finite
binary64 bits including negative zero, raw Decimal precision/quantum, and the
fixed-versus-raw Decimal distinction.

| Node | Payload |
| --- | --- |
| `["none"]` | No payload |
| `["bool", value]` | JSON boolean |
| `["int", digits]` | Canonical signed decimal integer string |
| `["float", bits]` | Exactly 16 lowercase hexadecimal IEEE754 binary64 bits |
| `["fixed", scaled]` | Canonical integer string at the existing `10**30` scale |
| `["raw_decimal", sign, digits, exponent]` | Sign 0/1, unsigned coefficient string, exact base-10 exponent |
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
Integer members have at most 1,048,576 bits; raw Decimal digits, canonical text
and absolute exponent are bounded by 131,072. The sum of squared cardinalities
of every wrapper set/frozen set in one persistence payload must not exceed
8,388,608, checked before normalization. A single set can therefore contain at
most 2,896 members; nesting and multiple wrapper roots share that work budget.
Legacy decoding shares the same budget across object-hook constructions without
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

Legacy list-shaped set envelopes remain readable. Arrays that occur as legacy
set members are restored recursively as tuples; ordinary JSON arrays elsewhere
remain lists. Legacy `__fixed__` values retain their historical fixed type because
old writes cannot recover already-lost raw Decimal quantum.

The public helpers exported by `xian_runtime_types.encoding` are:

- `is_wrapper_set(value)` identifies the deterministic wrapper families.
- `encode_set_value(value)` returns a plain versioned JSON object.
- `decode_set_value(tag, payload)` reads a new envelope or legacy list payload.
- `validate_persistent_value(value)` checks finite values, bounded traversal,
  cycles, unsupported objects and reserved-key collisions before serialization.

New ordinary persisted dictionaries cannot contain any reserved runtime codec
key, even with siblings or inside another container. This covers every key in
`encoding.TYPES`, not just set tags. Actual typed objects remain valid. Trusted
wire data must be decoded with `decode`/`convert_dict` before re-encoding; feeding
an already-tagged ordinary dictionary to `encode` intentionally fails. Legacy
read behavior remains available, including historical tag recognition.

## Wire documents and persistent values

Use `xian_runtime_types.encoding.encode_wire(value)` for transaction kwargs,
transaction envelopes and loaded genesis/config JSON that may already contain
codec tags. It preserves these dictionaries as opaque JSON, including payload
quantum, order and sibling keys; it does not decode or validate their codec
meaning. The consuming decoder and node enforce semantic validity. Wire object
keys must be strings.

Wire serialization retains the same compact ASCII escaping and bigint wrapping
as `encode`. Actual runtime objects still receive their typed encoding, and
actual wrapper sets share the aggregate normalization budget. Generic depth,
visit-count, cycle, unsupported-object and finite-number checks apply to the
whole wire value. A string inside a raw tag is opaque data; an actual non-finite
float or Decimal is rejected.

Keep `encode`, `Encoder` and `validate_persistent_value` at storage and effect
boundaries. They reject ordinary dictionaries containing reserved codec tags.
Never use `encode_wire` to bypass persistence validation.
