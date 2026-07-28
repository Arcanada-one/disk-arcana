#!/usr/bin/env bash
# Bootstrap a C linker for `cargo install` / `cargo clippy` on runners that lack `cc`.
# MUST run in the same workflow step as the cargo command that needs a linker —
# do not export CC to GITHUB_ENV (poisons later cargo test/clippy on cache-cold runners).
set -euo pipefail

if command -v cc >/dev/null 2>&1; then
  cc --version | head -1
  exit 0
fi

if command -v gcc >/dev/null 2>&1; then
  export CC="$(command -v gcc)"
  gcc --version | head -1
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

cat > "${BIN_DIR}/cc" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
args=()
while (($#)); do
  case "$1" in
    --target=*) args+=(-target "${1#--target=}"); shift ;;
    --target) args+=(-target "$2"); shift 2 ;;
    *) args+=("$1"); shift ;;
  esac
done
exec "$ZIG_BIN" cc "${args[@]}"
WRAPPER
sed -i "s|\$ZIG_BIN|${ZIG_DIR}/zig|g" "${BIN_DIR}/cc"
chmod +x "${BIN_DIR}/cc"

export PATH="${BIN_DIR}:${PATH}"
export CC="${BIN_DIR}/cc"
"${ZIG_DIR}/zig" version
