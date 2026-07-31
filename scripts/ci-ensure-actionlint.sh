#!/usr/bin/env bash
# INFRA-0370: checksum-verified actionlint bootstrap and runner.

set -euo pipefail

ACTIONLINT_VERSION="1.7.12"
ACTIONLINT_SHA256="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
ACTIONLINT_URL="https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_linux_amd64.tar.gz"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
TEMP_ROOT="${RUNNER_TEMP:-/tmp}"
INSTALL_DIR="$TEMP_ROOT/actionlint-$ACTIONLINT_VERSION"
ACTIONLINT_BIN="$INSTALL_DIR/actionlint"

bootstrap() {
  local archive actual_hash

  if [[ -x "$ACTIONLINT_BIN" ]]; then
    "$ACTIONLINT_BIN" -version
    return
  fi

  mkdir -p "$INSTALL_DIR"
  archive="$INSTALL_DIR/actionlint.tar.gz"

  curl --fail --silent --show-error --location \
    --retry 3 --retry-all-errors \
    --output "$archive" \
    "$ACTIONLINT_URL"

  actual_hash="$(sha256sum "$archive" | awk '{print $1}')"
  if [[ "$actual_hash" != "$ACTIONLINT_SHA256" ]]; then
    rm -f "$archive"
    printf 'actionlint archive checksum mismatch\n' >&2
    exit 1
  fi

  # Note: deliberately NOT a `trap ... RETURN`. A RETURN trap set inside a
  # function is not scoped to it — it survives and fires again when the *next*
  # function returns, at which point `archive` is out of scope and `set -u`
  # aborts. That only reproduces on a cold cache, so it passes locally whenever
  # a previous run already populated INSTALL_DIR.
  tar -xzf "$archive" -C "$INSTALL_DIR" actionlint
  rm -f "$archive"
  chmod 0755 "$ACTIONLINT_BIN"
  "$ACTIONLINT_BIN" -version

  if [[ -n "${GITHUB_PATH:-}" ]]; then
    printf '%s\n' "$INSTALL_DIR" >>"$GITHUB_PATH"
  fi
}

run_actionlint() {
  local workflows
  bootstrap

  shopt -s nullglob
  workflows=(
    "$REPO_ROOT"/.github/workflows/*.yml
    "$REPO_ROOT"/.github/workflows/*.yaml
  )
  shopt -u nullglob

  "$ACTIONLINT_BIN" -color "${workflows[@]}"
}

case "${1:---bootstrap}" in
  --bootstrap)
    bootstrap
    ;;
  --run)
    run_actionlint
    ;;
  *)
    printf 'usage: %s [--bootstrap|--run]\n' "$0" >&2
    exit 2
    ;;
esac
