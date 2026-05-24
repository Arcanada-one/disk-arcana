//! DISK-0006 R6 — gRPC transport adapter for [`SyncLoop`].
//!
//! The R5 state machine is transport-agnostic: `begin_sync` / `finish_sync`
//! accept arbitrary `Result<(), LoopError>` outcomes. R6 closes the loop by
//! mapping real `SyncService` responses onto those outcomes.
//!
//! Wire mapping (server is `disk-arcana-server::services::sync.rs`):
//!
//! | Server `Status`                                          | `LoopError`           |
//! |----------------------------------------------------------|-----------------------|
//! | `PermissionDenied` + `AclMismatchDetails` in `details()` | `AclRoleMismatch`     |
//! | `PermissionDenied` + message `share unknown:`            | `ShareUnknown`        |
//! | `PermissionDenied` + message `ACL role mismatch:`        | `AclRoleMismatch`     |
//! | `Unavailable` / `DeadlineExceeded`                       | `TransportUnavailable`|
//! | any other status / `tonic::transport::Error`             | `TransportUnavailable`|
//!
//! `AclMismatchDetails` is the authoritative signal — message-text matching
//! is the fallback for stubs that do not encode the proto payload (and for
//! older server builds before the details encoder landed).

use std::collections::HashMap;

use disk_proto::disk::AclMismatchDetails;
use prost::Message;
use tonic::{Code, Status};

use super::LoopError;
use crate::connection::{ClientError, DiskClient};

/// Map a `tonic::Status` returned by `SyncService` to a [`LoopError`].
pub fn classify_tonic_status(status: &Status) -> LoopError {
    let details = status.details();
    if !details.is_empty() && AclMismatchDetails::decode(details).is_ok() {
        return LoopError::AclRoleMismatch;
    }
    match status.code() {
        Code::PermissionDenied => {
            let msg = status.message();
            if msg.contains("share unknown") {
                LoopError::ShareUnknown
            } else if msg.contains("ACL role mismatch") {
                LoopError::AclRoleMismatch
            } else {
                // Unknown PermissionDenied — treat as sticky ACL mismatch so the
                // client surfaces it to the operator instead of hammering the
                // server in an infinite backoff loop.
                LoopError::AclRoleMismatch
            }
        }
        Code::Unavailable | Code::DeadlineExceeded => LoopError::TransportUnavailable,
        _ => LoopError::TransportUnavailable,
    }
}

/// Project a [`ClientError`] (which subsumes both `tonic::Status` and
/// `tonic::transport::Error`) onto a [`LoopError`].
pub fn classify_client_error(err: &ClientError) -> LoopError {
    match err {
        ClientError::Status(s) => classify_tonic_status(s),
        ClientError::Transport(_)
        | ClientError::NotAuthenticated
        | ClientError::MetadataError(_) => LoopError::TransportUnavailable,
    }
}

/// Async transport the loop calls per iteration. Returning `Ok(())` drives
/// the state machine to `Idle`; an `Err` is mapped per `LoopError` semantics.
#[tonic::async_trait]
pub trait SyncTransport: Send {
    async fn execute(&mut self) -> Result<(), LoopError>;
}

/// Production transport: invokes `SyncService::ExchangeState` against the
/// configured share. R6 ships an empty exchange (no local files, empty
/// node clock) — sufficient for ACL admission probing. Real Scan/Hash
/// payloads land in R8 + R9 once the streaming `SyncState` RPC is wired.
pub struct RemoteSync<'a> {
    client: &'a DiskClient,
    share: String,
}

impl<'a> RemoteSync<'a> {
    pub fn new(client: &'a DiskClient, share: impl Into<String>) -> Self {
        Self {
            client,
            share: share.into(),
        }
    }

    pub fn share(&self) -> &str {
        &self.share
    }
}

#[tonic::async_trait]
impl<'a> SyncTransport for RemoteSync<'a> {
    async fn execute(&mut self) -> Result<(), LoopError> {
        match self
            .client
            .exchange_state(&self.share, Vec::new(), HashMap::new())
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(classify_client_error(&e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use disk_proto::disk::AclMismatchDetails;
    use prost::Message;
    use tonic::{Code, Status};

    #[test]
    fn permission_denied_with_acl_details_maps_to_acl_role_mismatch() {
        let details = AclMismatchDetails {
            claimed_role: "send_only".into(),
            enforced_role: "receive_only".into(),
            share: "vault".into(),
            cert_fingerprint: vec![1, 2, 3],
            ts_ms: 42,
        };
        let mut buf = Vec::new();
        details.encode(&mut buf).unwrap();
        let status = Status::with_details(Code::PermissionDenied, "ACL role mismatch", buf.into());
        assert_eq!(classify_tonic_status(&status), LoopError::AclRoleMismatch);
    }

    #[test]
    fn permission_denied_share_unknown_message_maps_to_share_unknown() {
        let status =
            Status::permission_denied("share unknown: vault; retry after ACL provisioning");
        assert_eq!(classify_tonic_status(&status), LoopError::ShareUnknown);
    }

    #[test]
    fn permission_denied_role_mismatch_message_maps_to_acl_role_mismatch() {
        let status = Status::permission_denied("ACL role mismatch: enforced=ro claimed=so");
        assert_eq!(classify_tonic_status(&status), LoopError::AclRoleMismatch);
    }

    #[test]
    fn unavailable_maps_to_transport_unavailable() {
        let status = Status::unavailable("ACL enforcer unhealthy");
        assert_eq!(
            classify_tonic_status(&status),
            LoopError::TransportUnavailable
        );
    }

    #[test]
    fn deadline_exceeded_maps_to_transport_unavailable() {
        let status = Status::deadline_exceeded("timeout");
        assert_eq!(
            classify_tonic_status(&status),
            LoopError::TransportUnavailable
        );
    }

    #[test]
    fn unknown_status_maps_to_transport_unavailable() {
        let status = Status::internal("boom");
        assert_eq!(
            classify_tonic_status(&status),
            LoopError::TransportUnavailable
        );
    }

    #[test]
    fn permission_denied_unknown_message_maps_to_acl_role_mismatch_sticky() {
        let status = Status::permission_denied("unrecognised reason");
        assert_eq!(classify_tonic_status(&status), LoopError::AclRoleMismatch);
    }

    #[test]
    fn client_error_not_authenticated_maps_to_transport_unavailable() {
        let err = ClientError::NotAuthenticated;
        assert_eq!(classify_client_error(&err), LoopError::TransportUnavailable);
    }

    #[test]
    fn client_error_metadata_maps_to_transport_unavailable() {
        let err = ClientError::MetadataError("bad header".into());
        assert_eq!(classify_client_error(&err), LoopError::TransportUnavailable);
    }
}
