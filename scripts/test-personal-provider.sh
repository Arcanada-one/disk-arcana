#!/usr/bin/env bash
set -euo pipefail
# Explicit task tools; no rustup or global installation here.
: "${PERSONAL_CARGO_BIN:?set the absolute task Cargo binary}"
: "${PERSONAL_RUSTC_BIN:?set the absolute task rustc binary}"
: "${CARGO_TARGET_DIR:?set a task-owned build directory}"
[[ "$PERSONAL_CARGO_BIN" = /* && -x "$PERSONAL_CARGO_BIN" ]]
[[ "$PERSONAL_RUSTC_BIN" = /* && -x "$PERSONAL_RUSTC_BIN" ]]
[[ "$CARGO_TARGET_DIR" = /* ]]
[[ "$("$PERSONAL_RUSTC_BIN" --version)" == 'rustc 1.97.1 '* ]]
[[ "$("$PERSONAL_CARGO_BIN" --version)" == 'cargo 1.97.1 '* ]]
export RUSTC="$PERSONAL_RUSTC_BIN"
"$PERSONAL_CARGO_BIN" tree -p disk-personal --features synthetic-fixtures -e features --locked
"$PERSONAL_CARGO_BIN" fmt -p disk-personal -- --check
"$PERSONAL_CARGO_BIN" clippy -p disk-personal --all-targets --all-features --locked -- -D warnings
"$PERSONAL_CARGO_BIN" test -p disk-personal --features synthetic-fixtures --locked
"$PERSONAL_CARGO_BIN" test -p disk-personal --no-default-features --test production_denial --locked
