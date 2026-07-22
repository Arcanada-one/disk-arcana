#!/usr/bin/env bash
# DISK-0001 orchestrator live smoke on DEVS — enrollment probe, IT suites.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> cargo test — billing / Stripe (DISK-0018)"
cargo test -p disk-core billing::stripe -- --nocapture
cargo test -p disk-server billing::webhook -- --nocapture

echo "==> cargo test — two-node sync"
cargo test -p disk-server --test two_node_round_trip -- --nocapture

echo "==> cargo test — enrollment"
cargo test -p disk-server enrollment -- --nocapture
cargo test -p disk-cli enrollment -- --nocapture

echo "==> cargo test — agent webhooks (DISK-0028)"
cargo test -p disk-server agents::dispatch -- --nocapture

echo "==> cargo test — E2EE escrow (DISK-0015 slice 6)"
cargo test -p disk-core e2ee::escrow -- --nocapture

echo "==> prod enrollment :9445 TLS probe (operator gate RB-011)"
if timeout 5 bash -c 'echo | openssl s_client -connect disk.arcanada.ai:9445 -servername disk.arcanada.ai 2>/dev/null | openssl x509 -noout -subject' ; then
  echo "9445: TLS handshake OK"
else
  echo "9445: WARN — unreachable from this host (firewall / DISK_CA_MODE=offline — operator gate)"
fi

echo "==> live smoke PASS"
