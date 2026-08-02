#!/usr/bin/env bash
# Bootstrap a C linker for `cargo install` / `cargo clippy` on runners that lack `cc`.
# MUST be sourced in the same workflow step as the cargo command that needs a
# linker (`source scripts/ci-ensure-cc.sh`, not `bash …`) — subshell exports
# do not propagate. Do not write CC to GITHUB_ENV (poisons later steps).
set -euo pipefail

_done() {
  if [[ -n "${GITHUB_ENV:-}" && -n "${CI_LINKER_BOOTSTRAP:-}" ]]; then
    echo "CI_LINKER_BOOTSTRAP=${CI_LINKER_BOOTSTRAP}" >>"$GITHUB_ENV"
  fi
  if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    exit 0
  fi
}

# A prior workflow step may have selected the Zig fallback and persisted its
# capability marker. Its `cc` wrapper is intentionally on PATH, so do not
# mistake that wrapper for a native linker when this file is sourced again.
if [[ "${CI_LINKER_BOOTSTRAP:-}" == "zig" ]]; then
  if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    exit 0
  fi
  return 0
fi

if command -v cc >/dev/null 2>&1; then
  cc --version | head -1
  export CI_LINKER_BOOTSTRAP=native
  _done
  return 0
fi

if command -v gcc >/dev/null 2>&1; then
  export CC="$(command -v gcc)"
  if command -v g++ >/dev/null 2>&1; then
    export CXX="$(command -v g++)"
  fi
  gcc --version | head -1
  export CI_LINKER_BOOTSTRAP=native
  # Expose gcc as cc for steps that only look up `cc` on PATH.
  if [[ -n "${GITHUB_PATH:-}" ]] && ! command -v cc >/dev/null 2>&1; then
    _cc_bin="${RUNNER_TEMP:-/tmp}/ci-cc-bin"
    mkdir -p "$_cc_bin"
    ln -sf "$(command -v gcc)" "${_cc_bin}/cc"
    if command -v g++ >/dev/null 2>&1; then
      ln -sf "$(command -v g++)" "${_cc_bin}/c++"
    fi
    echo "${_cc_bin}" >>"$GITHUB_PATH"
  fi
  _done
  return 0
fi

# Self-hosted cc-less pool: prefer real gcc (zig cc breaks zstd .S assembly).
if command -v apt-get >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
  sudo -n apt-get update -qq
  sudo -n apt-get install -y -qq gcc build-essential
fi

if command -v gcc >/dev/null 2>&1; then
  export CC="$(command -v gcc)"
  if command -v g++ >/dev/null 2>&1; then
    export CXX="$(command -v g++)"
  fi
  gcc --version | head -1
  export CI_LINKER_BOOTSTRAP=native
  _done
  return 0
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
    --target=*)
      t="${1#--target=}"
      case "$t" in
        x86_64-unknown-linux-gnu) t=x86_64-linux-gnu ;;
        aarch64-unknown-linux-gnu) t=aarch64-linux-gnu ;;
      esac
      args+=(-target "$t")
      shift
      ;;
    --target)
      t="$2"
      case "$t" in
        x86_64-unknown-linux-gnu) t=x86_64-linux-gnu ;;
        aarch64-unknown-linux-gnu) t=aarch64-linux-gnu ;;
      esac
      args+=(-target "$t")
      shift 2
      ;;
    *) args+=("$1"); shift ;;
  esac
done
exec "$ZIG_BIN" cc "${args[@]}"
WRAPPER
sed -i "s|\$ZIG_BIN|${ZIG_DIR}/zig|g" "${BIN_DIR}/cc"
chmod +x "${BIN_DIR}/cc"

for tool in ar ranlib; do
  llvm_tool="$(find "${ZIG_DIR}" -type f -name "llvm-${tool}" 2>/dev/null | head -1 || true)"
  if [[ -n "${llvm_tool}" && -x "${llvm_tool}" ]]; then
    ln -sf "${llvm_tool}" "${BIN_DIR}/${tool}"
  else
    cat > "${BIN_DIR}/${tool}" <<WRAPPER
#!/usr/bin/env bash
set -euo pipefail
exec "${ZIG_DIR}/zig" ${tool} "\$@"
WRAPPER
    chmod +x "${BIN_DIR}/${tool}"
  fi
done

cat > "${BIN_DIR}/c++" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
args=()
while (($#)); do
  case "$1" in
    --target=*)
      t="${1#--target=}"
      case "$t" in
        x86_64-unknown-linux-gnu) t=x86_64-linux-gnu ;;
        aarch64-unknown-linux-gnu) t=aarch64-linux-gnu ;;
      esac
      args+=(-target "$t")
      shift
      ;;
    --target)
      t="$2"
      case "$t" in
        x86_64-unknown-linux-gnu) t=x86_64-linux-gnu ;;
        aarch64-unknown-linux-gnu) t=aarch64-linux-gnu ;;
      esac
      args+=(-target "$t")
      shift 2
      ;;
    *) args+=("$1"); shift ;;
  esac
done
exec "$ZIG_BIN" c++ "${args[@]}"
WRAPPER
sed -i "s|\$ZIG_BIN|${ZIG_DIR}/zig|g" "${BIN_DIR}/c++"
chmod +x "${BIN_DIR}/c++"

export PATH="${BIN_DIR}:${PATH}"
export CC="${BIN_DIR}/cc"
export CXX="${BIN_DIR}/c++"
export AR="${BIN_DIR}/ar"
export RANLIB="${BIN_DIR}/ranlib"
export CI_LINKER_BOOTSTRAP=zig
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "${BIN_DIR}" >>"$GITHUB_PATH"
fi
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "CI_LINKER_BOOTSTRAP=zig" >>"$GITHUB_ENV"
fi
"${ZIG_DIR}/zig" version
