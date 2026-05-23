//! DISK-0005 v1.1 — ACL load-path integration tests.
//!
//! Exercises the loader (`acl::loader::load_from_yaml`) end-to-end against a
//! real migrated SQLite database + the [`AuditEmitter`] writing structured
//! events for each outcome. Covers PRD §6 V2 (ACL integrity) and the F1-F8
//! failure rows in creative-DISK-0005-architecture-acl-reload.md.

use disk_core::MetaDb;
use disk_server::{
    load_from_yaml, AclState, AclEnforcer, AlwaysFailVerifier, AuditEmitter, AuditEvent, AuditKind,
    EnforcedRole, NoopVerifier, RevokedSignerVerifier, UnhealthyReason,
};
use std::io::Write;
use tempfile::tempdir;

const VALID_YAML_V7: &str = r#"
version: 7
updated_at: "2026-05-24T12:00:00Z"
signed_by: pavel.valentov@arcanada.one
nodes:
  - cert_fingerprint: sha256:0101010101010101010101010101010101010101010101010101010101010101
    node_id_hint: arcana-ai
    shares:
      hermes-artefacts: publisher
"#;

const VALID_YAML_V5: &str = r#"
version: 5
updated_at: "2026-05-20T00:00:00Z"
signed_by: pavel.valentov@arcanada.one
nodes:
  - cert_fingerprint: sha256:0101010101010101010101010101010101010101010101010101010101010101
    shares:
      hermes-artefacts: receive_only
"#;

fn write_yaml(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("disk-acl.yaml");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    (dir, path)
}

async fn fresh_db() -> (tempfile::TempDir, MetaDb) {
    let dir = tempdir().unwrap();
    let path = dir.path().join("meta.sqlite");
    let db = MetaDb::open(&path).await.expect("open");
    (dir, db)
}

/// Walk the loader output through to the enforcer + an audit row.
/// Returns the resulting Loaded state for the caller to inspect.
async fn promote(
    enforcer: &AclEnforcer,
    audit: &AuditEmitter,
    yaml_path: &std::path::Path,
    stored_version: u64,
) {
    match load_from_yaml(yaml_path, stored_version, &NoopVerifier) {
        Ok(outcome) => {
            enforcer.try_swap(AclState::Loaded(outcome.table)).await;
            audit
                .emit(
                    AuditEvent::new(AuditKind::AclLoadOk).with_payload(&serde_json::json!({
                        "new_version": outcome.new_version,
                        "signed_by": outcome.signed_by,
                    })),
                )
                .await
                .expect("audit emit");
        }
        Err(e) => {
            let reason = e.into_unhealthy_reason();
            let kind = match &reason {
                UnhealthyReason::VersionRegress { .. } => AuditKind::AclVersionRegress,
                UnhealthyReason::FileMissing => AuditKind::AclFileMissing,
                _ => AuditKind::AclLoadFailure,
            };
            enforcer.try_swap(AclState::Unhealthy(reason.clone())).await;
            audit
                .emit(AuditEvent::new(kind).with_payload(
                    &serde_json::json!({ "reason": format!("{reason:?}") }),
                ))
                .await
                .expect("audit emit");
        }
    }
}

#[tokio::test]
async fn cold_boot_load_ok_promotes_enforcer_and_writes_audit_row() {
    let (_db_dir, db) = fresh_db().await;
    let (_yaml_dir, yaml_path) = write_yaml(VALID_YAML_V7);

    let enforcer = AclEnforcer::new_unhealthy();
    let audit = AuditEmitter::new(db.pool().clone());

    promote(&enforcer, &audit, &yaml_path, 0).await;

    // Enforcer is now Loaded with version 7.
    assert_eq!(enforcer.current_version().await, Some(7));

    // Resolve a real entry.
    let role = enforcer
        .resolve(&[0x01; 32], "hermes-artefacts")
        .await
        .expect("entry present");
    assert_eq!(role, EnforcedRole::Publisher);

    // Audit row written.
    assert_eq!(audit.count_by_kind(AuditKind::AclLoadOk).await.unwrap(), 1);
    assert_eq!(
        audit.count_by_kind(AuditKind::AclLoadFailure).await.unwrap(),
        0
    );

    // Payload contains expected metadata.
    let (_ts, payload_json) = audit.latest(AuditKind::AclLoadOk).await.unwrap().unwrap();
    assert!(payload_json.contains("new_version"));
    assert!(payload_json.contains("\"new_version\":7"));
}

#[tokio::test]
async fn version_regress_keeps_previous_and_emits_distinct_audit_kind() {
    let (_db_dir, db) = fresh_db().await;
    let (_yaml_dir7, yaml_path7) = write_yaml(VALID_YAML_V7);

    let enforcer = AclEnforcer::new_unhealthy();
    let audit = AuditEmitter::new(db.pool().clone());

    // First load: v7 succeeds.
    promote(&enforcer, &audit, &yaml_path7, 0).await;
    assert_eq!(enforcer.current_version().await, Some(7));

    // Operator-error: write a regressed file (v5) and reload, telling the
    // pipeline that the stored monotonic counter is now 7.
    let (_yaml_dir5, yaml_path5) = write_yaml(VALID_YAML_V5);
    promote(&enforcer, &audit, &yaml_path5, 7).await;

    // Enforcer is now Unhealthy(VersionRegress) — default-deny.
    assert_eq!(enforcer.current_version().await, None);
    let reason = enforcer.unhealthy_reason().await.expect("unhealthy");
    assert_eq!(
        reason,
        UnhealthyReason::VersionRegress {
            stored: 7,
            attempted: 5,
        }
    );

    // Distinct audit kind so dashboards can alarm separately on regress vs
    // generic load_failure.
    assert_eq!(
        audit.count_by_kind(AuditKind::AclVersionRegress).await.unwrap(),
        1
    );
    assert_eq!(
        audit.count_by_kind(AuditKind::AclLoadFailure).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn file_missing_emits_acl_file_missing_audit_kind() {
    let (_db_dir, db) = fresh_db().await;
    let dir = tempdir().unwrap();
    let missing_path = dir.path().join("does-not-exist.yaml");

    let enforcer = AclEnforcer::new_unhealthy();
    let audit = AuditEmitter::new(db.pool().clone());

    promote(&enforcer, &audit, &missing_path, 0).await;

    let reason = enforcer.unhealthy_reason().await.expect("unhealthy");
    assert_eq!(reason, UnhealthyReason::FileMissing);

    // Per creative-DISK-0005-architecture-acl-reload §F7, file-missing has
    // its own audit kind separate from generic load_failure.
    assert_eq!(
        audit.count_by_kind(AuditKind::AclFileMissing).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn signature_failed_emits_generic_load_failure_audit_kind() {
    let (_db_dir, db) = fresh_db().await;
    let (_yaml_dir, yaml_path) = write_yaml(VALID_YAML_V7);

    let enforcer = AclEnforcer::new_unhealthy();
    let audit = AuditEmitter::new(db.pool().clone());

    // Use AlwaysFailVerifier explicitly — promote() helper always uses Noop,
    // so we inline the failure path here for the negative case.
    let err = load_from_yaml(
        &yaml_path,
        0,
        &AlwaysFailVerifier("gpg verify exit=1"),
    )
    .unwrap_err();
    let reason = err.into_unhealthy_reason();
    assert_eq!(
        reason,
        UnhealthyReason::SignatureFailed("gpg verify exit=1".into())
    );

    enforcer.try_swap(AclState::Unhealthy(reason.clone())).await;
    audit
        .emit(AuditEvent::new(AuditKind::AclLoadFailure).with_payload(
            &serde_json::json!({ "reason": format!("{reason:?}") }),
        ))
        .await
        .expect("audit emit");

    assert_eq!(
        audit.count_by_kind(AuditKind::AclLoadFailure).await.unwrap(),
        1
    );
    // No load_ok was issued.
    assert_eq!(audit.count_by_kind(AuditKind::AclLoadOk).await.unwrap(), 0);
}

#[tokio::test]
async fn revoked_signer_distinct_unhealthy_reason() {
    let (_db_dir, db) = fresh_db().await;
    let (_yaml_dir, yaml_path) = write_yaml(VALID_YAML_V7);

    let enforcer = AclEnforcer::new_unhealthy();
    let audit = AuditEmitter::new(db.pool().clone());

    let err = load_from_yaml(&yaml_path, 0, &RevokedSignerVerifier("revoked 0xDEAD")).unwrap_err();
    let reason = err.into_unhealthy_reason();
    // F8: distinct enum variant so operator can grep for SignerRevoked
    // separately from generic signature failure.
    assert_eq!(reason, UnhealthyReason::SignerRevoked);

    enforcer.try_swap(AclState::Unhealthy(reason)).await;
    audit
        .emit(AuditEvent::new(AuditKind::AclLoadFailure))
        .await
        .expect("audit emit");

    // resolve() still default-denies.
    let err = enforcer
        .resolve(&[0x01; 32], "hermes-artefacts")
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        disk_server::AclError::Unavailable(UnhealthyReason::SignerRevoked)
    ));
}

#[tokio::test]
async fn second_successful_load_invalidates_old_role_for_changed_share() {
    // creative-acl-reload §6 state diagram: Loaded → Reloading → Loaded with
    // SessionInvalidate broadcast. This test exercises the data-level swap;
    // the broadcast itself is a P4a step 8 deliverable (deferred to round 3).
    let (_db_dir, db) = fresh_db().await;
    let enforcer = AclEnforcer::new_unhealthy();
    let audit = AuditEmitter::new(db.pool().clone());

    // First load: publisher on share.
    let (_yaml_dir7, yaml_path7) = write_yaml(VALID_YAML_V7);
    promote(&enforcer, &audit, &yaml_path7, 0).await;
    assert_eq!(
        enforcer
            .resolve(&[0x01; 32], "hermes-artefacts")
            .await
            .unwrap(),
        EnforcedRole::Publisher
    );

    // Second load: same cert, same share, role flipped to receive_only at v8.
    let v8 = r#"
version: 8
updated_at: "2026-05-25T00:00:00Z"
signed_by: pavel.valentov@arcanada.one
nodes:
  - cert_fingerprint: sha256:0101010101010101010101010101010101010101010101010101010101010101
    shares:
      hermes-artefacts: receive_only
"#;
    let (_yaml_dir8, yaml_path8) = write_yaml(v8);
    promote(&enforcer, &audit, &yaml_path8, 7).await;

    // Role flipped.
    assert_eq!(
        enforcer
            .resolve(&[0x01; 32], "hermes-artefacts")
            .await
            .unwrap(),
        EnforcedRole::ReceiveOnly
    );
    assert_eq!(enforcer.current_version().await, Some(8));
    // Two acl.load_ok events recorded.
    assert_eq!(audit.count_by_kind(AuditKind::AclLoadOk).await.unwrap(), 2);
}
