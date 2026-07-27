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
BIN_DIR="${RUNNER_TEMP:-/tmp}/ci-cc-bin"
mkdir -p "$ZIG_DIR" "$BIN_DIR"

if [[ ! -x "${ZIG_DIR}/zig" ]]; then
  curl -fsSL "https://ziglang.org/download/${ZIG_VER}/zig-linux-x86_64-${ZIG_VER}.tar.xz" \
    | tar -xJ -C "$ZIG_DIR" --strip-components=1
fi

cat > "${BIN_DIR}/cc" <<EOF
#!/usr/bin/env bash
exec "${ZIG_DIR}/zig" cc "\$@"
EOF
cat > "${BIN_DIR}/c++" <<EOF
#!/usr/bin/env bash
exec "${ZIG_DIR}/zig" c++ "\$@"
EOF
chmod +x "${BIN_DIR}/cc" "${BIN_DIR}/c++"

echo "$BIN_DIR" >> "${GITHUB_PATH:-/dev/null}"
echo "$ZIG_DIR" >> "${GITHUB_PATH:-/dev/null}"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "CC=${BIN_DIR}/cc"
    echo "CXX=${BIN_DIR}/c++"
  } >> "$GITHUB_ENV"
fi
export PATH="${BIN_DIR}:${ZIG_DIR}:${PATH}"
export CC="${BIN_DIR}/cc"
export CXX="${BIN_DIR}/c++"
"${ZIG_DIR}/zig" version
"${BIN_DIR}/cc" --version | head -1
