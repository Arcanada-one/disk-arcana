#!/usr/bin/env bash
# DISK-0012 / G3 — local 3-node gRPC sync harness (no staging server).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
cargo test -p disk-server --test load_sync_round_trip load_sync_three_nodes_round_trip -- --ignored --nocapture
