//! mTLS peer-certificate propagation interceptor.
//!
//! tonic terminates mTLS at the transport layer (`ServerTlsConfig::client_ca_root`),
//! but the verified peer certificate is exposed only via the connection-level
//! `TlsConnectInfo` extension — it is NOT visible to a gRPC handler that calls
//! [`crate::auth::CertIdentity::from_request`], which looks for a
//! `CertificateDer` extension on the request.
//!
//! Without bridging the two, [`CertIdentity::from_request`] always returns
//! `None`, the ACL enforcer's `check_acl_by_cert` short-circuits to `Ok(())`,
//! and every mTLS-valid client is admitted to every share regardless of its
//! ACL role. This interceptor closes that gap: it reads the leaf peer cert from
//! the connection info and inserts it as a `CertificateDer` request extension so
//! the ACL check resolves a real fingerprint.
//!
//! Wired in `main.rs` via `InterceptedService` around every gRPC service.

use rustls::pki_types::CertificateDer;
use tonic::{Request, Status};

/// Copy the leaf mTLS peer certificate from the connection info into the
/// request extensions as a `CertificateDer<'static>`.
///
/// No-op when the connection presented no client certificate (one-way TLS or a
/// non-TLS transport in tests) — in that case the downstream ACL check falls
/// through to the legacy session-token path, exactly as before.
#[allow(clippy::result_large_err)] // tonic Interceptor bound requires Result<_, Status>
pub fn propagate_peer_cert(mut req: Request<()>) -> Result<Request<()>, Status> {
    if let Some(certs) = req.peer_certs() {
        if let Some(leaf) = certs.first() {
            let owned: CertificateDer<'static> = leaf.clone().into_owned();
            req.extensions_mut().insert(owned);
        }
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::CertIdentity;

    #[test]
    fn no_peer_cert_is_noop_and_identity_absent() {
        let req = Request::new(());
        let out = propagate_peer_cert(req).expect("interceptor never fails");
        assert!(
            CertIdentity::from_request(&out).is_none(),
            "without a peer cert no CertIdentity extension must be injected"
        );
    }

    #[test]
    fn injected_cert_extension_is_resolvable_by_cert_identity() {
        // Simulate what the interceptor produces: a CertificateDer extension on
        // the request. (peer_certs() reads TlsConnectInfo which cannot be
        // synthesised in a unit test, so we assert the post-injection contract
        // that from_request depends on.)
        let der: Vec<u8> = vec![0x30, 0x82, 0x01, 0x0a, 0xDE, 0xAD, 0xBE, 0xEF];
        let cert = CertificateDer::from(der.clone());
        let mut req = Request::new(());
        req.extensions_mut().insert(cert);

        let id = CertIdentity::from_request(&req)
            .expect("a CertificateDer extension must resolve to a CertIdentity");
        assert_eq!(id.fingerprint, CertIdentity::from_der(&der).fingerprint);
    }
}
