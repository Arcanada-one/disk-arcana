---
title: Disk Arcana — Network Exposure Baseline
status: live
last_review: 2026-05-24
next_review: 2026-08-22
schema: network-exposure-baseline-v1
---

# Disk Arcana — Network Exposure Baseline

This document declares every public-network bind exposed by
`disk-arcana-server` and `disk-cli`'s daemon. Each Tier 3 entry carries
`x-exposure-justification` and `x-exposure-expires` per the ecosystem-wide
`skills/network-exposure-baseline.md`. Drift between declared binds and
runtime configuration is a release-blocker.

Schema: each binding is a fenced YAML block parsed by future iterations of
`dev-tools/network-exposure-check.sh` once Rust runtime support lands. Until
then this file is the human-auditable single source of truth.

## Active bindings

### `disk-arcana-server` — mTLS gRPC listener

```yaml
service: disk-arcana-server
component: tonic mTLS gRPC (Auth + Sync + admin EnrollmentService)
env_var: DISK_BIND_ADDR
default: 0.0.0.0:9443
tier: 3
x-exposure-justification: "Cross-host mTLS sync — peer-cert authorisation enforced by ServerTlsConfig::client_ca_root; ACL fail-closed on cold boot"
x-exposure-expires: "2026-08-22"
mitigations:
  - mTLS client-cert handshake (rejects non-fleet clients at TLS layer)
  - Application-layer ACL enforcer (default-deny on cold boot, signed YAML reload)
  - Operator firewall MUST restrict to fleet IP set; mTLS is not a DoS gate
review_owner: Pavel Valentov
related_task: DISK-0037, DISK-0044
```

### `disk-arcana-server` — TLS-only public enrollment listener

```yaml
service: disk-arcana-server
component: tonic TLS gRPC (EnrollmentService.Enroll only — public RPC)
env_var: DISK_ENROLLMENT_BIND_ADDR
default: 0.0.0.0:9445
tier: 3
x-exposure-justification: "Enrollment public RPC — cold-boot nodes without a client cert exchange a single-use, hostname-bound, TTL-clamped opaque token for an mTLS client cert"
x-exposure-expires: "2026-08-22"
mitigations:
  - Opaque-token bearer auth (32-byte random, single-use, hostname-bound, TTL ≤ 86400 s)
  - admin RPCs gated by `x-disk-admin-token` metadata bearer (Unauthenticated on missing)
  - Audit emit on every Enroll attempt (success/fail) via AuditEmitter
  - Operator firewall MAY remain open for `:9445` (acceptable risk); rate-limit ticket tracked separately
  - No `ServerTlsConfig::client_ca_root` — client-cert absence is the contract, not a gap
review_owner: Pavel Valentov
related_task: DISK-0037, DISK-0044
```

### `disk-cli daemon` — local status HTTP

```yaml
service: disk-cli daemon
component: REST status endpoint
bind: 127.0.0.1:9444
tier: 1
justification_required: false
related_task: DISK-0006 R5
```

## Out of scope

- macOS / Linux installers' filesystem permissions — see DISK-RB-001.
- AUTH-0085 (`/v1/internal-ca/issue` upstream) — separate exposure ticket
  on Auth Arcana side.
- Rate limiting / abuse mitigation on `:9445` — separate backlog ticket;
  acceptable risk for the current round given token semantics.

## Review

Next quarterly review: **2026-08-22** (90-day TTL anchor from
`x-exposure-expires`). On the review date, re-validate each Tier 3 entry:
mitigations still hold, justification still applies, expiry pushed to
`review_date + 90d` only after explicit operator sign-off.
