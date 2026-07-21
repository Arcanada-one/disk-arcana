#!/usr/bin/env bash
# Validate that OWASP checklist "verified" evidence files exist (DISK-0012).
# Fails closed if a referenced path is missing — prevents checklist drift.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$REPO_ROOT"

missing=0
check() {
    local path="$1"
    if [ ! -e "$path" ]; then
        printf 'MISSING evidence: %s\n' "$path" >&2
        missing=1
    fi
}

# T1 Transport
check crates/disk-server/src/tls.rs
check crates/disk-server/tests/tls_downgrade.rs
check crates/disk-server/tests/mtls_cert_required.rs
check crates/disk-client/tests/it_tls_domain.rs

# T2 Auth
check crates/disk-server/tests/auth_required.rs
check crates/disk-server/src/auth/storage.rs
check crates/disk-server/tests/node_revocation.rs
check crates/disk-server/src/auth/rate_limit.rs
check crates/disk-server/tests/auth_rate_limit.rs
check crates/disk-server/tests/enrollment_expired_token.rs
check crates/disk-server/tests/enrollment_token_replay.rs
check crates/disk-server/tests/enrollment_rate_limit.rs
check crates/disk-server/tests/it_enrollment_real_binary.rs
check crates/disk-server/tests/it_main_boot_wiring.rs
check docs/design/DISK-0044-enrollment-bootstrap.md
check docs/runbooks/DISK-RB-011-cold-boot-enroll.md

# T3 ACL
check crates/disk-server/tests/acl_role_mismatch.rs
check crates/disk-server/tests/acl_reload_concurrent.rs
check crates/disk-server/tests/acl_unhealthy_default_deny.rs
check crates/disk-server/tests/publisher_signature_success.rs
check crates/disk-server/tests/publisher_signature_failure.rs
check crates/disk-server/tests/acl_gpg_verifier.rs

# T4 Input
check crates/disk-core/src/path_guard.rs
check fuzz/fuzz_targets/path_validate.rs
check crates/disk-server/tests/decompression_bomb.rs
check crates/disk-server/tests/replay_protection.rs
check fuzz/fuzz_targets/proto_decode.rs
check fuzz/fuzz_targets/apply_plan.rs
check fuzz/fuzz_targets/reconcile.rs

# T5 Logging
check crates/disk-server/tests/log_redaction.rs

# T6 Load (partial scaffold)
check crates/disk-core/tests/load_scan.rs
check scripts/load-test-harness.sh
check scripts/load-test-scanner-smoke.sh
check scripts/load-test-scanner-10k.sh
check scripts/load-test-sync-smoke.sh
check crates/disk-server/tests/load_sync_round_trip.rs
check docs/load-test-harness.md

# Meta
check docs/security/OWASP-gRPC-audit.md
check docs/runbooks/DISK-RB-010-owasp-grpc-audit.md

if [ "$missing" -ne 0 ]; then
    printf 'OWASP evidence validation FAILED (%s missing)\n' "$missing" >&2
    exit 1
fi

printf 'OWASP evidence validation OK (%s paths)\n' 37
