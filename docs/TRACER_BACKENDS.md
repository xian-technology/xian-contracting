# Tracer Backends

Xian currently ships two contract metering backends:

- `python_line_v1`
- `native_instruction_v1`

## Default

The default remains `python_line_v1`.

This keeps `xian-contracting`:

- pure Python by default
- self-contained
- easy to install as a standalone library
- usable outside the full Xian node stack

## Native Backend

`native_instruction_v1` is provided by the optional
`xian-native-tracer` package in `packages/xian-native-tracer`.

Characteristics:

- Rust implementation with PyO3/maturin packaging
- instruction-level charging using the same opcode cost schedule source as the
  Python tracer
- explicit opt-in
- no silent fallback if selected but unavailable

Local install examples:

```bash
uv sync --group dev --extra native
```

or

```bash
python -m pip install "xian-contracting[native]"
```

## Selection

Library users can select the backend through the execution runtime:

```python
from contracting.execution import runtime

runtime.rt.set_tracer_mode("native_instruction_v1")
```

Supported modes live in `contracting.execution.tracer.SUPPORTED_TRACER_MODES`.

`xian-abci` also exposes this as node config:

```toml
[xian]
tracer_mode = "python_line_v1"
```

## Semantics

The two backends do not have identical gas semantics:

- `python_line_v1` charges deterministic precomputed line buckets
- `native_instruction_v1` charges exact executed instruction buckets

Because of that, tracer mode is execution policy. A network should choose one
mode and keep it consistent across validators.

## Validation

The contracting repo validates both:

- full suite on the default Python backend
- focused native backend tests plus Rust crate build in CI
