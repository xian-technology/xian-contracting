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

# Respect the caller's native Rust toolchain. The WASM build script selects
# rustup separately; forcing its default here can replace a newer native cargo.

for required_bin in cargo npm wasm-pack; do
  if ! command -v "${required_bin}" >/dev/null 2>&1; then
    printf '%s is required but was not found\n' "${required_bin}" >&2
    exit 1
  fi
done

if command -v rustup >/dev/null 2>&1; then
  rustup target add wasm32-unknown-unknown
else
  printf 'rustup is required to install the wasm32-unknown-unknown target\n' >&2
  exit 1
fi

cd "${repo_root}"

UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" sync \
  --python "${python_version}" \
  --group dev \
  --reinstall-package xian-tech-compiler-core \
  --reinstall-package xian-tech-vm-core \
  --extra zk

UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" ruff check .
UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" ruff format --check .
UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" pytest

cargo test --manifest-path packages/xian-compiler-core/Cargo.toml
cargo test --manifest-path packages/xian-fastpath-core/Cargo.toml
cargo check --manifest-path packages/xian-compiler-core/Cargo.toml --features python-extension
cargo check --manifest-path packages/xian-compiler-core/Cargo.toml --features wasm
cargo check --manifest-path packages/xian-zk/Cargo.toml --features python-extension
cargo check --manifest-path packages/xian-vm-core/Cargo.toml --features python-extension
cargo test --manifest-path packages/xian-vm-core/Cargo.toml
cargo test --manifest-path packages/xian-zk/Cargo.toml --no-default-features
npm --prefix packages/xian-compiler-core/npm test

(
  cd packages/xian-zk
  UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" pytest -q
)

UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" pytest -q \
  tests/unit/test_runtime.py \
  tests/unit/test_zk_stdlib.py \
  tests/integration/test_chi_deduction.py \
  tests/security/test_runtime_security.py

UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" --no-sync \
  python -m pytest -q -m optional_native

# Keep the exact corpus and observations for reproducing any release mismatch.
mkdir -p "${repo_root}/.artifacts"
determinism_dir="$(mktemp -d "${repo_root}/.artifacts/determinism-release.XXXXXX")"
UV_CACHE_DIR="${uv_cache_dir}" "${uv_bin}" run --python "${python_version}" --no-sync \
  python -m tests.determinism.campaign --output "${determinism_dir}/campaign" \
  --seed 20261103 --generated 256 --extended
printf 'Determinism evidence: %s\n' "${determinism_dir}/campaign"
