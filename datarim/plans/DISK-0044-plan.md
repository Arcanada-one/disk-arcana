# DISK-0044 — Enrollment bootstrap (plan)

**Status:** done (audit closeout; implementation = DISK-0037 dual listener; DISK-0061 enrollment tls_domain)  
**Branch:** merged via PR #52 + post-closeout doc touchups

## Goal

Close the chicken-and-egg gap: cert-less nodes must reach `Enroll` on `:9445`.

## Delivered (this PR)

- [x] Design ADR `docs/design/DISK-0044-enrollment-bootstrap.md` (option a chosen)
- [x] Operator verify runbook `docs/runbooks/DISK-RB-011-cold-boot-enroll.md`
- [x] OWASP T2.8 → verified; evidence script extended
- [x] Stale client module doc corrected (`enrollment.rs`)

## Pre-existing (DISK-0037 — no code change required)

- Dual listener in `main.rs`
- `it_enrollment_real_binary.rs` E2E
- CLI `disk enroll --server :9445`

## Deferred gates (documented in ADR)

- Prod operator walkthrough (RB-011 sign-off)
- Live AUTH-0085 CA (tests use wiremock)
- `:9445` edge rate limiting
- `DISK_CA_MODE=offline` prod path (pre-provisioned certs)
