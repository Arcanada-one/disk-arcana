---
taskId: DISK-0012
title: Hardening (fuzz, benches, load test)
status: done
created: 2026-07-20
merged: 2026-07-20
merge_commit: 40c3cd0
pr: 40
complexity: L2
prefix: DISK
parent: DISK-0001
phase: implementation
branch: DISK-0012-hardening
---

# DISK-0012 — Hardening Implementation Plan (tail)

**Parent:** DISK-0001 §Phase 11. **Merged:** PR #40 → `40c3cd0` on `main`.

Prior work on `main`: `apply_plan` fuzz (#28), `cargo audit` + `gitleaks` in CI,
coverage gate (DISK-0032), cross-compile build job, fuzz-smoke 60s.

This branch completes the **tail** deliverables solvable on DEVS without operator.

---

## Phase map

| Item (DISK-0001 §11) | Status | Notes |
|------------------------|--------|-------|
| Cross-compile CI | **Done** (main) | `ci.yml` build matrix |
| Release workflow | **Done** (main) | `release-deploy.yml` |
| Fuzz: `apply_plan` | **Done** (main) | #28 |
| Fuzz: `path_validate` | **Done** | This branch |
| Fuzz: `proto_decode` | **Done** | This branch |
| Fuzz: `reconcile` | **Done** | This branch |
| `cargo audit` + gitleaks | **Done** (main) | lint job |
| Security audit (OWASP) | **Done** | PR DISK-0012-owasp-audit — checklist v1.0 + RB-010 + CI evidence gate |
| Load test 10K / 3 nodes | **Done** | PR #54–#55 — `load-test-harness.sh` tiers smoke/scale/sync |
| Auth / Enroll rate-limit (G1) | **Done** | PR #50, #53 |
| `RegisterNode` production gate (T2.10) | **Done** | PR #56 — `DISK_REGISTER_NODE_MODE` |
| Criterion benchmarks | **Done** | `benches/hardening.rs` |
| Scheduled deep fuzz | **Done** | `fuzz-deep.yml` weekly |

---

## Deliverables (this branch)

1. **Fuzz targets** under `fuzz/fuzz_targets/`:
   - `path_validate` — `disk_core::path_guard::validate`
   - `proto_decode` — prost decode for wire messages
   - `reconcile` — `ReconciliationEngine::reconcile`
2. **CI fuzz-smoke** — all four targets × 20s on every PR.
3. **Scheduled deep fuzz** — `.github/workflows/fuzz-deep.yml` (10 min/target, weekly).
4. **Criterion benches** — `crates/disk-core/benches/hardening.rs`.
5. **Load smoke** — `tests/load_scan.rs` + `scripts/load-test-scanner-smoke.sh` (1000 files).
6. **Bench smoke script** — `scripts/bench-hardening-smoke.sh`.

---

## Verification

```bash
# Fuzz (nightly toolchain)
cd fuzz && cargo +nightly fuzz run path_validate -- -max_total_time=10

# Benches
bash scripts/bench-hardening-smoke.sh

# Load
bash scripts/load-test-scanner-smoke.sh

# Unit + integration
cargo test --workspace --all-features
```

---

## Deferred (operator / future)

- OWASP operator walkthrough rows (T1.5, T1.6, T5.3, T6.3) — `DISK-RB-010`
- G3 staging soak / prod binary load — operator gate
- G4 external pentest before SaaS
- macOS/aarch64 release matrix expansion
- DISK-0015+ commercial MVP (E2EE wire integration, auth, billing)

---

## References

- Parent: `datarim/plans/DISK-0001-plan.md` §Phase 11
- Prior fuzz PR: #28
