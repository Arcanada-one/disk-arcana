#!/usr/bin/env bash
# DISK-0012 load-test smoke — 1000-file scanner walk (ignored unit test).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
cargo test -p disk-core --test load_scan load_scan_1000_markdown_files -- --ignored --nocapture
