#!/usr/bin/env bash
# Bootstrap a C linker on heterogeneous self-hosted runners that lack gcc/cc.
# No-op when `cc` is already on PATH. Uses zig as a portable fallback (no root).
set -euo pipefail

if command -v cc >/dev/null 2>&1; then
  cc --version | head -1
  exit 0
fi

ZIG_VER=0.13.0
ZIG_DIR="${RUNNER_TEMP:-/tmp}/zig-${ZIG_VER}"
mkdir -p "$ZIG_DIR"
curl -fsSL "https://ziglang.org/download/${ZIG_VER}/zig-linux-x86_64-${ZIG_VER}.tar.xz" \
  | tar -xJ -C "$ZIG_DIR" --strip-components=1
echo "$ZIG_DIR" >> "${GITHUB_PATH:-/dev/null}"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "CC=${ZIG_DIR}/zig cc"
    echo "CXX=${ZIG_DIR}/zig c++"
  } >> "$GITHUB_ENV"
fi
export CC="${ZIG_DIR}/zig cc"
export CXX="${ZIG_DIR}/zig c++"
"$ZIG_DIR/zig" version
