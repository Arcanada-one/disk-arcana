#!/usr/bin/env bash
# Install only pinned security tools; cache contains binaries, never advisory data.
set -euo pipefail
TOOLS_ROOT="${CI_SECURITY_TOOLS_ROOT:?CI_SECURITY_TOOLS_ROOT must be set}"
AUDIT_VERSION=0.22.2
DENY_VERSION=0.20.2
matches() {
  [[ -x "$TOOLS_ROOT/bin/$1" ]] && [[ "$("$TOOLS_ROOT/bin/$1" --version)" == "$1 $2" ]]
}
if ! matches cargo-audit "$AUDIT_VERSION" || ! matches cargo-deny "$DENY_VERSION"; then
  source scripts/ci-ensure-cc.sh
  if ! matches cargo-audit "$AUDIT_VERSION"; then
    cargo install cargo-audit --version "=$AUDIT_VERSION" --locked --force --root "$TOOLS_ROOT"
  fi
  if ! matches cargo-deny "$DENY_VERSION"; then
    cargo install cargo-deny --version "=$DENY_VERSION" --locked --force --root "$TOOLS_ROOT"
  fi
fi
matches cargo-audit "$AUDIT_VERSION"
matches cargo-deny "$DENY_VERSION"
"$TOOLS_ROOT/bin/cargo-audit" --version
"$TOOLS_ROOT/bin/cargo-deny" --version
printf '%s\n' "$TOOLS_ROOT/bin" >> "${GITHUB_PATH:?GITHUB_PATH must be set}"
