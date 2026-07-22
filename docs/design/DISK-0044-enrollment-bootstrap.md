# DISK-0044 — Enrollment bootstrap (cold-boot without client cert)

**Status:** Implemented (DISK-0037 code path); audit closeout (DISK-0044).  
**Decision:** Option **(a)** — separate TLS-only public enrollment listener on `:9445`.

## Problem

The production mTLS listener (`DISK_BIND_ADDR`, default `:9443`) sets
`ServerTlsConfig::client_ca_root`, so the TLS handshake **requires** a fleet
client certificate. A brand-new node has no cert yet and cannot call
`EnrollmentService/Enroll` on that listener — classic chicken-and-egg.

## Consilium options (settled 2026-07)

| ID | Approach | Verdict |
|----|----------|---------|
| (a) | Dual listener: mTLS `:9443` + TLS-only `:9445` for `Enroll` only | **Chosen** — shipped DISK-0037 |
| (b) | Per-service optional client auth on one listener | Rejected — tonic/rustls wiring complexity, larger blast radius |
| (c) | Operator-issued internal CA only; `disk enroll` deferred | **Fallback** — `DISK_CA_MODE=offline` (DISK-0058 Approach A-a) |

## Implemented architecture

```
Cold-boot node                    disk-arcana-server
─────────────                     ──────────────────
disk enroll --server :9445  ──►  DISK_ENROLLMENT_BIND_ADDR (TLS, NO client_ca_root)
  opaque token + CSR                 └─ EnrollmentService.Enroll only

Enrolled node                     disk-arcana-server
─────────────                     ──────────────────
disk daemon / sync          ──►  DISK_BIND_ADDR (mTLS + ACL)
                                   └─ AuthService + SyncService (+ admin enroll RPCs)
```

### Security controls on `:9445`

- **No mTLS** — absence of client cert is intentional (see `network-exposure.md`).
- **`Enroll`** — gated by single-use opaque token (32 B), hostname-bound, TTL ≤ 86400 s.
- **Admin RPCs** (`IssuePendingToken`, `RevokePending`) — `x-disk-admin-token` metadata bearer; reachable on both listeners but external callers lack the bearer → `PermissionDenied`.
- **Audit** — every enroll attempt logged via `AuditEmitter`.

### Code map

| Component | Path |
|-----------|------|
| Dual listener boot | `crates/disk-server/src/main.rs` (`build_tls_public_only`, `srv_public`) |
| Config | `DISK_ENROLLMENT_BIND_ADDR` (default `0.0.0.0:9445`) — `config.rs` |
| Enrollment service | `crates/disk-server/src/enrollment/` |
| Client (no client cert) | `crates/disk-client/src/enrollment.rs` |
| CLI defaults | `disk enroll --server https://disk.arcanada.ai:9445` |
| IP-endpoint TLS name (DISK-0061) | `--tls-domain` / bootstrap `tls_domain` → `EnrollmentClient::connect` |
| Real-binary E2E | `crates/disk-server/tests/it_enrollment_real_binary.rs` |
| Boot wiring E2E | `crates/disk-server/tests/it_main_boot_wiring.rs` |
| Enrollment TLS domain E2E | `crates/disk-client/tests/it_enrollment_tls_domain.rs` |

### Offline / pre-provisioned mode

When `DISK_CA_MODE=offline` (DISK-0058), the public enrollment listener is
**not bound** and `OfflineCaClient` returns `EnrollmentDisabled`. Use operator-
issued leaf certs (current prod cutover path per DISK-0040).

## Remaining gates (honest)

| Gate | Owner | Notes |
|------|-------|-------|
| Prod `:9445` reachable from enrolling hosts | Operator / INFRA | Firewall + DNS; see `DISK-RB-001` § Firewall |
| Live Auth Arcana CA (`AUTH-0085`) | Operator | Tests use wiremock signer; prod needs `AUTH_ARCANA_CA_TOKEN` |
| Enrollment abuse rate limit on `:9445` | Backlog | Token semantics mitigate; edge rate-limit tracked separately (`network-exposure.md`) |
| `disk admin pending-token` over mTLS `:9443` | AUTH-0085 follow-up | RB-001 documents `:9445` + admin bearer as current default |
| Prod walkthrough sign-off | Operator | `docs/runbooks/DISK-RB-011-cold-boot-enroll.md` checklist |

## References

- `docs/network-exposure.md` — Tier 3 binding for `:9445`
- `documentation/runbooks/disk-arcana/DISK-RB-001-enroll.md` (KB) — full procedure
- OWASP checklist row T2.8 — cold-boot enroll without cert
