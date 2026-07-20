# OWASP-style gRPC security review (DISK-0012 / DISK-0013)

**Status:** Living checklist stub — not a formal penetration test.  
**Scope:** Disk Arcana server (`disk-server`) and client (`disk-client`) gRPC/mTLS surface.  
**Parent:** DISK-0001 §Phase 11 item 6.

## Threat model summary

| Asset | Exposure | Auth |
|-------|----------|------|
| Sync gRPC `:9443` | Internet (mTLS) | Client certificate + ACL |
| Enrollment `:9445` | Internet (TLS) | Opaque enrollment token |
| REST status `:9444` | Loopback only | None (by design) |
| Admin enrollment RPC | Same listener as sync | Bearer `DISK_ADMIN_TOKEN` |

## Checklist (STRIDE-oriented)

### Transport (TLS / mTLS)

- [x] Production sync listener requires client certificates (`ServerTlsConfig` + client CA).
- [x] Plaintext gRPC rejected in production mode (integration tests: `tls_downgrade.rs`).
- [x] Client sets SNI via `tls_domain` when server address is IP (`DISK-0060`).
- [ ] **Review:** TLS 1.2+ only, cipher suite hardening per org policy.
- [ ] **Review:** Certificate rotation runbook (DISK-RB-001).

### Authentication / session

- [x] API key rate limiting on auth attempts (security test suite).
- [x] Session token expiry enforced.
- [x] Revoked nodes rejected post-revoke.
- [ ] **Review:** Enrollment token TTL and single-use semantics on prod.
- [ ] **Gap (DISK-0044):** Cold-boot enroll without pre-issued cert — document operator path.

### Authorization (ACL)

- [x] Per-host directional policy in `disk-acl.yaml` with hot reload.
- [x] `acl_mismatch` sticky state (no silent downgrade).
- [x] Publisher signature verification on uploads.
- [ ] **Review:** ACL unhealthy → default deny (`acl_unhealthy_default_deny.rs`).

### Input validation

- [x] Path traversal guard (`path_guard`, fuzz target `path_validate`).
- [x] Oversized gRPC message rejection (`bomb_guard` middleware).
- [x] Protobuf decode graceful errors (fuzz `proto_decode`).
- [x] Delta apply never panics on adversarial input (fuzz `apply_plan`).

### Logging / secrets

- [x] gitleaks in CI.
- [x] Security test: no `api_key` / `session_token` in logs.
- [ ] **Review:** Production log redaction on crash dumps.

### Availability

- [x] Connection rate / message size limits documented in `SECURITY.md`.
- [ ] **Load:** 10K-file harness deferred (needs staging).

## RPC inventory (review each endpoint)

| Service | RPC | AuthZ notes |
|---------|-----|-------------|
| `AuthService` | `Authenticate` | API key → session token |
| `EnrollmentService` | `Enroll` | Token-gated; :9445 listener |
| `SyncService` | `PushState`, `PullDelta`, … | mTLS + ACL share scope |
| Admin | `PendingToken`, … | Bearer token |

## Recommended next steps

1. Operator walkthrough against staging with this checklist (tick remaining boxes).
2. External pentest before SaaS (DISK-0017) — out of scope for self-hosted OSS v1.
3. Track DISK-0044 enrollment bootstrap in a dedicated design task.

## References

- `SECURITY.md` — disclosure + Phase 3 threat model
- `documentation/runbooks/disk-arcana/DISK-RB-001-enroll.md`
- Fuzz targets: `fuzz/fuzz_targets/{apply_plan,path_validate,proto_decode,reconcile}.rs`
