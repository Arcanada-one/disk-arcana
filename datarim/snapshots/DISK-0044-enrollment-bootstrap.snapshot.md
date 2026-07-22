# DISK-0044 snapshot — enrollment bootstrap closeout

**Date:** 2026-07-22  
**PRs:** #52 (audit/docs closeout), #109 DISK-0061 (enrollment `tls_domain`)  
**Decision:** Option (a) — TLS-only `:9445` public enrollment listener (implemented DISK-0037).

## Shipped

- Design ADR `docs/design/DISK-0044-enrollment-bootstrap.md`
- Operator verify runbook `docs/runbooks/DISK-RB-011-cold-boot-enroll.md`
- OWASP T2.8 verified; evidence gate extended
- DISK-0061 complement: `--tls-domain` on `disk enroll` / bootstrap TOML for IP endpoints

## CI evidence (15 tests, all green 2026-07-22)

- `it_enrollment_real_binary.rs` (3)
- `it_main_boot_wiring.rs` (boot markers)
- `enrollment_expired_token.rs` / `enrollment_token_replay.rs` / `enrollment_rate_limit.rs`
- `it_enrollment_tls_domain.rs` (2) / `it_enrollment_e2e.rs`

## Operator gates (not code blockers)

- RB-011 staging/prod walkthrough sign-off
- Prod firewall: `:9445` must be reachable when `DISK_CA_MODE!=offline` (probe 2026-07-22: `:9446` OK, `:9445` timeout from DEVS)
- `DISK_CA_MODE=offline` suppresses public listener (DISK-0058) — use pre-provisioned certs
- AUTH-0085 live CA token on prod server
