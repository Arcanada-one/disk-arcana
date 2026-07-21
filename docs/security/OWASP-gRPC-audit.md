# OWASP-style gRPC security audit (DISK-0012 completion)

**Version:** 1.0 (agent-complete on DEVS)  
**Status:** Actionable checklist — not a formal penetration test.  
**Scope:** `disk-server` + `disk-client` gRPC/mTLS; loopback REST `:9444`.  
**Parent:** DISK-0001 §Phase 11 item 6; closes DISK-0012 deferred OWASP tail.

## How to use this document

| Column | Meaning |
|--------|---------|
| **ID** | Stable reference for tickets / PRs |
| **Evidence** | Test or source file proving the control |
| **Status** | `verified` = CI-covered; `operator` = staging walkthrough; `gap` = tracked backlog; `defer` = out of OSS v1 scope |

Run `bash scripts/validate-owasp-evidence.sh` in CI to ensure every `verified` row still has on-disk evidence.

Operator walkthrough: `docs/runbooks/DISK-RB-010-owasp-grpc-audit.md`.

---

## Threat model

| Asset | Port | Exposure | AuthN | AuthZ |
|-------|------|----------|-------|-------|
| Sync gRPC | `:9443` | Internet (mTLS) | Client cert | ACL per share |
| Enrollment gRPC | `:9445` (design) / shared listener (today) | Internet (TLS) | Opaque token + admin bearer | EnrollmentService scope |
| REST daemon | `:9444` | **Loopback only** | None (by design) | N/A |
| Admin enrollment RPCs | Same as enrollment | Internet | `DISK_ADMIN_TOKEN` bearer | Admin-only methods |

See also `SECURITY.md` § Phase 3 threat model (V-7 … V-14).

---

## Checklist

### T1 — Transport (TLS / mTLS)

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| T1.1 | TLS **1.3 only** (stricter than TLS 1.2+ minimum) | verified | `crates/disk-server/src/tls.rs` (`tls13_server_config`); `crates/disk-server/tests/tls_downgrade.rs` |
| T1.2 | mTLS client cert required in production | verified | `build_mtls_from_files`; `crates/disk-server/tests/mtls_cert_required.rs` |
| T1.3 | ALPN `h2` for gRPC | verified | `tls.rs` unit tests |
| T1.4 | Client SNI when server address is IP | verified | `crates/disk-client/tests/it_tls_domain.rs` |
| T1.5 | Cipher suite org policy review | operator | Document org baseline vs rustls 0.23 defaults on staging |
| T1.6 | Certificate rotation runbook | operator | `documentation/runbooks/disk-arcana/DISK-RB-001-enroll.md` (KB) |

### T2 — Authentication

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| T2.1 | `SyncService` requires bearer session token | verified | `crates/disk-server/tests/auth_required.rs` |
| T2.2 | Session token TTL (24h) + expiry eviction | verified | `auth/storage.rs` `SESSION_TTL`; `validate_expired_session_returns_none_and_evicts` |
| T2.3 | Invalid API key → `Unauthenticated` (no oracle) | verified | `auth/storage.rs` `wrong_key_unauthenticated` |
| T2.4 | Revoked node certs rejected | verified | `crates/disk-server/tests/node_revocation.rs` |
| T2.5 | API key brute-force rate limiting | verified | `auth/rate_limit.rs`; `auth/storage.rs`; `tests/auth_rate_limit.rs`; default 5 failures / 60s per `node_id` → `ResourceExhausted` |
| T2.6 | Enrollment token TTL enforced | verified | `crates/disk-server/tests/enrollment_expired_token.rs` |
| T2.7 | Enrollment token single-use (replay blocked) | verified | `crates/disk-server/tests/enrollment_token_replay.rs` |
| T2.8 | Cold-boot enroll without cert (DISK-0044) | gap | Operator-issued internal CA today; design options in backlog `DISK-0044` |

### T3 — Authorization (ACL)

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| T3.1 | Per-cert share direction in `disk-acl.yaml` | verified | `crates/disk-server/tests/acl_role_mismatch.rs` |
| T3.2 | ACL hot reload | verified | `crates/disk-server/tests/acl_reload_concurrent.rs` |
| T3.3 | ACL unhealthy → default **deny** | verified | `crates/disk-server/tests/acl_unhealthy_default_deny.rs` |
| T3.4 | Publisher upload signature verification | verified | `publisher_signature_success.rs`, `publisher_signature_failure.rs` |
| T3.5 | GPG ACL verifier path | verified | `crates/disk-server/tests/acl_gpg_verifier.rs` |

### T4 — Input validation & protocol abuse

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| T4.1 | Path traversal guard on vault paths | verified | `disk_core::path_guard`; fuzz `fuzz/fuzz_targets/path_validate.rs` |
| T4.2 | Decompression bomb caps (4/16/256 MiB) | verified | `crates/disk-server/tests/decompression_bomb.rs`; `middleware/bomb_guard.rs` |
| T4.3 | Stream replay / sequence monotonicity | verified | `crates/disk-server/tests/replay_protection.rs` |
| T4.4 | Protobuf decode never panics | verified | fuzz `fuzz/fuzz_targets/proto_decode.rs` |
| T4.5 | Delta apply never panics on adversarial input | verified | fuzz `fuzz/fuzz_targets/apply_plan.rs` |
| T4.6 | Reconcile engine fuzz smoke | verified | fuzz `fuzz/fuzz_targets/reconcile.rs`; CI fuzz-smoke job |

### T5 — Logging & secrets

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| T5.1 | `ApiKey` / `SessionToken` masked in Display/Debug | verified | `crates/disk-server/tests/log_redaction.rs`; `auth/api_key.rs` |
| T5.2 | gitleaks on every push | verified | `.github/workflows/ci.yml` lint job |
| T5.3 | Production crash dump redaction | operator | Verify journald/core dump policy on prod host |

### T6 — Availability & load

| ID | Control | Status | Evidence |
|----|---------|--------|----------|
| T6.1 | Documented message/size limits | verified | `SECURITY.md` V-13; `bomb_guard` constants |
| T6.2 | 10K-file / multi-node load harness | **defer** | Requires staging server — see `datarim/plans/DISK-0012-plan.md` |
| T6.3 | Connection rate limiting at edge | operator | Cloudflare / firewall policy outside repo |

---

## RPC inventory (review each)

Source of truth: `proto/disk.proto`.

### `AuthService`

| RPC | AuthN | AuthZ notes | Test hook |
|-----|-------|--------------|-----------|
| `RegisterNode` | None (bootstrap) | Should be disabled on prod or admin-gated | `auth.rs` unit tests |
| `Authenticate` | API key | Issues 24h session | `auth/storage.rs` |

### `SyncService` (all require bearer + mTLS + ACL)

| RPC | Streaming | Notes |
|-----|-----------|-------|
| `ExchangeState` | Unary | State reconcile; auth required |
| `UploadDelta` | Unary | Path guard + bomb guard |
| `SyncState` | Bidi | Replay guard on sequences |
| `DeltaUpload` | Client stream | Bomb guard per chunk |
| `DeltaDownload` | Server stream | Auth + path guard |

### `EnrollmentService`

| RPC | AuthN | Notes |
|-----|-------|-------|
| `IssuePendingToken` | Admin bearer | TTL clamp 3600 default / 86400 max |
| `Enroll` | Opaque token | Single-use; CSR validation |
| `RevokePending` | Admin bearer | Revokes unconsumed token |

---

## Open gaps (honest backlog)

| ID | Item | Tracking |
|----|------|----------|
| G2 | DISK-0044 cert-less bootstrap | `datarim/backlog.md` DISK-0044 |
| G3 | 10K load / soak | Staging operator gate |
| G4 | External pentest before SaaS | DISK-0017+ |

---

## Sign-off template (operator)

```text
Audit walkthrough DISK-RB-010 completed on: ________
Environment: staging / prod-readonly
Reviewer:
Remaining operator rows (T1.5, T1.6, T5.3, T6.3): ticked / waived with rationale
```

## References

- `SECURITY.md` — disclosure + V-7…V-14 table
- `docs/runbooks/DISK-RB-010-owasp-grpc-audit.md`
- Fuzz: `fuzz/fuzz_targets/{apply_plan,path_validate,proto_decode,reconcile}.rs`
- DISK-0012 plan: `datarim/plans/DISK-0012-plan.md`
