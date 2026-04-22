# xian-tech-native-tracer

Optional Rust-backed instruction metering backend for `xian-contracting`.

This package is intentionally separate from the default pure-Python execution
path so that `xian-contracting` remains easy to install and use standalone.

## Runtime Surface

- Python module: `xian_native_tracer`
- Native extension: `xian_native_tracer._native`
- Main class: `InstructionMeter`
- Error types: `NativeChiExceededError`, `NativeCallLimitExceededError`

The backend is selected through `contracting.execution.runtime` with
`native_instruction_v1`. There is no silent fallback if the package is missing.

## Validation

```bash
cargo check --manifest-path packages/xian-native-tracer/Cargo.toml
uv run pytest -q tests/unit/test_tracer.py tests/unit/test_native_tracer.py \
  tests/unit/test_runtime.py tests/integration/test_chi_deduction.py
```
