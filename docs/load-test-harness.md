# Load test harness (DISK-0012 / G3 / OWASP T6.2)

**Status:** Scaffold on DEVS/CI — no live staging server required.  
**Parent:** DISK-0001 §Phase 11; closes the **local** half of OWASP T6.2 / gap G3.

## Scope

| Tier | Files | What it exercises | Where |
|------|-------|-------------------|-------|
| **smoke** | 1,000 | `disk_core::scanner::scan_root` walk + filter | Every PR (`load-harness-smoke` CI job) |
| **scale** | 10,000 | Same path at PRD-scale file count | Every PR (`load-harness-scale` CI job) |

Both tiers are **ignored** in default `cargo test` and run only via scripts.

## Out of scope (deferred — staging operator gate)

- Multi-node gRPC round-trip soak (2–3 nodes syncing against a real server)
- Production-like vault size + delta upload/download pressure
- Wall-clock soak (hours) and ops-bot telemetry

Track those under G3 tail / DISK-0046 streaming when a staging host is scheduled.

## Run locally

```bash
# Fast sanity (≈15s on DEVS)
bash scripts/load-test-harness.sh smoke

# 10K scale (≈2–5 min on DEVS)
bash scripts/load-test-harness.sh scale

# Both
bash scripts/load-test-harness.sh all
```

Direct test filters:

```bash
cargo test -p disk-core --test load_scan load_scan_1000_markdown_files -- --ignored --nocapture
cargo test -p disk-core --test load_scan load_scan_10000_markdown_files -- --ignored --nocapture
```

## CI

- `.github/workflows/ci.yml` → `load-harness-smoke` (1K)
- `.github/workflows/ci.yml` → `load-harness-scale` (10K)

## Evidence

| Artifact | Path |
|----------|------|
| Harness tests | `crates/disk-core/tests/load_scan.rs` |
| Entry script | `scripts/load-test-harness.sh` |
| OWASP row | `docs/security/OWASP-gRPC-audit.md` T6.2 (partial) |

## References

- DISK-0012 plan: `datarim/plans/DISK-0012-plan.md`
- OWASP walkthrough: `docs/runbooks/DISK-RB-010-owasp-grpc-audit.md` §6
