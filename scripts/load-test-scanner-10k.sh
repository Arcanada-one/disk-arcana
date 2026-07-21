#!/usr/bin/env bash
# DISK-0012 / G3 — 10K-file scanner load harness (local/CI, no staging server).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
cargo test -p disk-core --test load_scan load_scan_10000_markdown_files -- --ignored --nocapture
