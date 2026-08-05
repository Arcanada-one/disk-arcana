#!/usr/bin/env bash
# Build release `disk` CLI for macOS (arm64 + x86_64) and optionally sign/notarize.
#
# Run on a Mac (operator machine or macOS CI runner). Produces release asset names
# consumed by scripts/install.sh: disk-macos-arm64, disk-macos-x86_64.
#
# Environment:
#   DISK_SIGN_IDENTITY / DISK_NOTARY_KEYCHAIN_PROFILE — forwarded to sign-macos-cli.sh
#   DISK_SKIP_SIGN=1 — build only (unsigned); default when identity unset
#
# Usage:
#   ./scripts/build-macos-release.sh
#   DISK_VERSION=v0.1.0 ./scripts/build-macos-release.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${REPO_ROOT}/dist/macos"
VERSION="${DISK_VERSION:-$(grep '^version' "${REPO_ROOT}/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: macOS release build must run on Darwin (got $(uname -s))" >&2
  echo "hint: arcana-devs is Linux-only; use operator Mac or a macOS CI runner" >&2
  exit 1
fi

command -v cargo >/dev/null 2>&1 || { echo "error: cargo not found" >&2; exit 1; }

mkdir -p "$OUT_DIR"

build_target() {
  local target="$1"
  local asset="$2"
  echo "==> cargo build --release -p disk-cli --bin disk --target $target"
  cargo build --release -p disk-cli --bin disk --target "$target"
  local bin="${REPO_ROOT}/target/${target}/release/disk"
  if [[ ! -f "$bin" ]]; then
    echo "error: missing $bin" >&2
    exit 1
  fi
  if [[ -z "${DISK_SKIP_SIGN:-}" && -n "${DISK_SIGN_IDENTITY:-${APPLE_SIGNING_IDENTITY:-}}" ]]; then
    "${SCRIPT_DIR}/sign-macos-cli.sh" "$bin"
  else
    echo "==> signing skipped (set DISK_SIGN_IDENTITY to sign)"
  fi
  install -m 0755 "$bin" "${OUT_DIR}/${asset}"
  echo "    -> ${OUT_DIR}/${asset}"
}

rustup target add aarch64-apple-darwin x86_64-apple-darwin 2>/dev/null || true

build_target aarch64-apple-darwin "disk-macos-arm64"
build_target x86_64-apple-darwin "disk-macos-x86_64"

echo ""
echo "Built Disk Arcana CLI ${VERSION} for macOS:"
ls -la "${OUT_DIR}"/disk-macos-*
