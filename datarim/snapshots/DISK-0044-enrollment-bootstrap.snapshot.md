# DISK-0044 snapshot — enrollment bootstrap closeout

**Date:** 2026-07-21  
**PR:** (pending)  
**Decision:** Option (a) — TLS-only `:9445` public enrollment listener (implemented DISK-0037).

## Shipped in this slice

- Design + operator verify docs
- OWASP T2.8 verified; G2 removed from open gaps
- `validate-owasp-evidence.sh` +28 paths

## CI evidence

- `it_enrollment_real_binary.rs`
- `it_main_boot_wiring.rs`
- `enrollment_expired_token.rs` / `enrollment_token_replay.rs`

## Operator gates (not blockers for merge)

- RB-011 staging/prod walkthrough
- Firewall `:9445` on prod fleet
- AUTH-0085 live CA token on prod server
