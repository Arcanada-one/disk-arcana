# Load test harness (DISK-0012 / G3 / OWASP T6.2)

**Status:** Scaffold on DEVS/CI — no live staging server required.  
**Parent:** DISK-0001 §Phase 11; closes the **local** half of OWASP T6.2 / gap G3.

## Scope

| Tier | Scale | What it exercises | Where |
|------|-------|-------------------|-------|
| **smoke** | 1,000 files | `disk_core::scanner::scan_root` walk + filter | Every PR |
| **scale** | 10,000 files | Same scanner path at PRD file count | Every PR |
| **sync** | 3 nodes | Register → auth → `delta_download` over loopback TLS | Every PR |

Scanner tiers are **ignored** in default `cargo test`; the sync tier is a separate ignored integration test.

## Out of scope (deferred — staging operator gate)

- Production binary + real mTLS fleet certs on a staging host
- Wall-clock soak (hours) and ops-bot telemetry
- `ExchangeState` streaming at 10K+ files (DISK-0046)

## Run locally

```bash
bash scripts/load-test-harness.sh smoke   # scanner 1K
bash scripts/load-test-harness.sh scale   # scanner 10K
bash scripts/load-test-harness.sh sync    # 3-node gRPC round-trip
bash scripts/load-test-harness.sh all     # all tiers
```

Direct filters:

```bash
cargo test -p disk-core --test load_scan load_scan_10000_markdown_files -- --ignored --nocapture
cargo test -p disk-server --test load_sync_round_trip load_sync_three_nodes_round_trip -- --ignored --nocapture
```

## CI

- `.github/workflows/ci.yml` → `Test (linux)` runs `scripts/load-test-harness.sh all` after unit tests

## Evidence

| Artifact | Path |
|----------|------|
| Scanner harness | `crates/disk-core/tests/load_scan.rs` |
| Sync harness | `crates/disk-server/tests/load_sync_round_trip.rs` |
| Entry script | `scripts/load-test-harness.sh` |
| OWASP row | `docs/security/OWASP-gRPC-audit.md` T6.2 (partial) |

## References

- Baseline two-node IT: `crates/disk-server/tests/two_node_round_trip.rs`
- DISK-0012 plan: `datarim/plans/DISK-0012-plan.md`
- OWASP walkthrough: `docs/runbooks/DISK-RB-010-owasp-grpc-audit.md` §6
