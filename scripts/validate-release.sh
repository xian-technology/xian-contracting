#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
uv_cache_dir="${UV_CACHE_DIR:-/tmp/uv-cache}"
python_version="${XIAN_CONTRACTING_VALIDATE_PYTHON:-3.14}"

if command -v uv >/dev/null 2>&1; then
  uv_bin="uv"
elif [[ -x "${repo_root}/.venv/bin/uv" ]]; then
  uv_bin="${repo_root}/.venv/bin/uv"
elif [[ -x "${repo_root}/../xian-cli/.venv/bin/uv" ]]; then
  uv_bin="${repo_root}/../xian-cli/.venv/bin/uv"
else
  printf 'uv is required but was not found\n' >&2
  exit 1
fi

cd "${repo_root}"

UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" sync \
  --python "${python_version}" \
  --group dev \
  --extra native \
  --extra zk

UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" ruff check .
UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" ruff format --check .
UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" pytest

cargo check --manifest-path packages/xian-native-tracer/Cargo.toml
cargo check --manifest-path packages/xian-zk/Cargo.toml --features python-extension
cargo check --manifest-path packages/xian-vm-core/Cargo.toml --features python-extension
cargo test --manifest-path packages/xian-zk/Cargo.toml --no-default-features

(
  cd packages/xian-zk
  UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" pytest -q
)

UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" pytest -q \
  tests/unit/test_runtime.py \
  tests/unit/test_zk_stdlib.py \
  tests/integration/test_chi_deduction.py \
  tests/security/test_runtime_security.py

UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" pytest -q -m optional_native \
  tests/unit/test_native_tracer.py \
  tests/integration/test_tracer_workloads.py \
  tests/integration/test_zk_bridge.py

UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" \
  --refresh-package xian-tech-vm-core \
  --with ./packages/xian-vm-core \
  python -m pytest -q -m optional_native \
  tests/integration/test_vm_language_conformance.py \
  tests/integration/test_vm_metering_audit.py \
  tests/integration/test_vm_stateful_fuzz.py
