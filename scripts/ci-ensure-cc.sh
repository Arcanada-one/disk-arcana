#!/usr/bin/env bash
# Bootstrap a C linker for `cargo install` on runners that lack gcc/cc.
# Only used before cargo install steps — main workspace builds rely on rust-cache
# from runners that already have a native toolchain.
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

# cc-rs passes `--target=x86_64-unknown-linux-gnu`; zig cc wants `-target x86_64-linux-gnu`.
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

echo "$BIN_DIR" >> "${GITHUB_PATH:-/dev/null}"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "CC=${BIN_DIR}/cc" >> "$GITHUB_ENV"
fi
export PATH="${BIN_DIR}:${PATH}"
export CC="${BIN_DIR}/cc"
"${ZIG_DIR}/zig" version
