//! DISK-0005 v1.1 — R-DIR-5 mitigation test (PRD-DISK-0001 §7 + creative §F).
//!
//! Asserts the default-deny contract: an enforcer that has never successfully
//! loaded an ACL must refuse every resolve() — no permissive default, no
//! «look at this cert and decide». This is the integration counterpart to the
//! unit tests in `acl::tests`; here we exercise the public re-exports from
//! the crate root to confirm the contract surface that downstream services
//! (`services::sync`) will actually consume.

use disk_server::{AclEnforcer, AclError, AclState, EnforcedRole, EnforcementTable, UnhealthyReason};

const CERT_A: [u8; 32] = [0xA1; 32];
const CERT_B: [u8; 32] = [0xB2; 32];

#[tokio::test]
async fn cold_boot_denies_every_resolution_regardless_of_share() {
    let enforcer = AclEnforcer::new_unhealthy();

    // Two different cert / share combinations: both must fail identically with
    // Unavailable(NeverLoaded). The point is that no input from the client
    // can flip the outcome — there is no carve-out path before the first
    // successful ACL load.
    for share in ["hermes-artefacts", "wiki", "anything-else"] {
        for fp in [&CERT_A, &CERT_B] {
            let err = enforcer.resolve(fp, share).await.unwrap_err();
            assert_eq!(
                err,
                AclError::Unavailable(UnhealthyReason::NeverLoaded),
                "default-deny breached for share={share}"
            );
        }
    }
}

#[tokio::test]
async fn unhealthy_state_after_signature_failure_keeps_denying() {
    // Simulate the "loaded once, then reload failed signature verify" path
    // (creative F3). Per the reload contract this should refuse-and-keep
    // previous, but if a caller explicitly demotes (e.g. cold-boot path),
    // every subsequent resolve() must fail with the recorded reason.
    let enforcer = AclEnforcer::new_unhealthy();
    enforcer
        .try_swap(AclState::Unhealthy(UnhealthyReason::SignatureFailed(
            "gpg verify failed (test fixture)".into(),
        )))
        .await;

    let err = enforcer.resolve(&CERT_A, "wiki").await.unwrap_err();
    assert_eq!(
        err,
        AclError::Unavailable(UnhealthyReason::SignatureFailed(
            "gpg verify failed (test fixture)".into()
        ))
    );
}

#[tokio::test]
async fn loaded_state_distinguishes_share_unknown_from_unhealthy() {
    // Once Loaded, a missing entry must surface as ShareUnknown — distinct
    // from Unavailable — so the client can apply R-DIR-7 backoff retry
    // instead of treating the failure as a hard ACL-down condition.
    let mut table = EnforcementTable::new(1);
    table.insert(CERT_A, "wiki", EnforcedRole::Bidirectional);
    let enforcer = AclEnforcer::new_loaded(table);

    // Known entry: Ok.
    let role = enforcer.resolve(&CERT_A, "wiki").await.expect("known");
    assert_eq!(role, EnforcedRole::Bidirectional);

    // Missing share on a known cert: ShareUnknown, not Unavailable.
    let err = enforcer.resolve(&CERT_A, "hermes-artefacts").await.unwrap_err();
    assert!(
        matches!(err, AclError::ShareUnknown { .. }),
        "Loaded state with missing entry MUST return ShareUnknown, got {err:?}"
    );

    // Unknown cert on a known share: also ShareUnknown — the enforcer does
    // not leak whether the cert is enrolled (anti-enumeration; PRD §10 v1.1).
    let err = enforcer.resolve(&CERT_B, "wiki").await.unwrap_err();
    assert!(
        matches!(err, AclError::ShareUnknown { .. }),
        "unknown cert MUST also return ShareUnknown, got {err:?}"
    );
}
