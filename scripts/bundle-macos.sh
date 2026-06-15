#!/usr/bin/env bash
# bundle-macos.sh — build Disk Arcana.app for macOS.
#
# cargo-bundle 0.11 resolves icon paths relative to the *current working
# directory*, not the package root, when invoked with -p from the workspace
# root. Run from crates/disk-gui/ to ensure assets/disk-arcana.icns resolves
# correctly, then surface the bundle output path back to the caller.
#
# Prerequisites: cargo-bundle (cargo install cargo-bundle)
# Usage: bash scripts/bundle-macos.sh [--release]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CRATE_DIR="${REPO_ROOT}/crates/disk-gui"

PROFILE_FLAG="--release"
if [[ "${1:-}" == "" ]]; then
  PROFILE_FLAG="--release"
elif [[ "${1:-}" == "--release" ]]; then
  PROFILE_FLAG="--release"
elif [[ "${1:-}" == "--debug" ]]; then
  PROFILE_FLAG=""
fi

command -v cargo-bundle >/dev/null 2>&1 || {
  echo "ERROR: cargo-bundle not found. Run: cargo install cargo-bundle" >&2
  exit 1
}

echo "Bundling from: ${CRATE_DIR}"
cd "${CRATE_DIR}"
cargo bundle ${PROFILE_FLAG}

BUNDLE_DIR="${REPO_ROOT}/target/release/bundle/osx"
echo ""
echo "Bundle output: ${BUNDLE_DIR}/Disk Arcana.app"
echo "DMG output:    ${REPO_ROOT}/target/release/bundle/dmg/Disk Arcana.dmg"
