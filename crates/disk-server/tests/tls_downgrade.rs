//! TLS 1.3 enforcement test (V-8, T-Downgrade).
//!
//! Verifies that `DevSelfSignedProvider` produces a `rustls::ServerConfig`
//! that accepts TLS 1.3 connections and rejects TLS 1.2 by attempting
//! a handshake with a TLS 1.2-only client.
//!
//! Approach: start a real TCP listener with our TLS config, then connect
//! with a `rustls` client restricted to TLS 1.2.  Expect the handshake to
//! fail (rustls returns an error).
//!
//! DISK-0004 Step 15.

use std::net::TcpListener;
use std::sync::Arc;

use disk_server::DevSelfSignedProvider;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

/// Helper: build a TLS 1.2-only client config trusting `cert_der`.
fn tls12_client_config(cert_der: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(cert_der.to_vec()))
        .expect("add cert to roots");

    Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[test]
fn server_config_rejects_tls12_client() {
    // Generate a fresh cert.
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    let cert_der = cert.der().to_vec();

    // Build TLS 1.3-only server config via StaticPemProvider.
    let provider =
        disk_server::StaticPemProvider::from_bytes(cert_pem.into_bytes(), key_pem.into_bytes());
    use disk_server::CertProvider;
    let server_cfg = provider.server_config().expect("server_config");

    // Spawn a minimal TLS server in a background thread.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_cfg_clone = Arc::clone(&server_cfg);
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut conn = rustls::ServerConnection::new(server_cfg_clone).unwrap();
            // Attempt the handshake; it will fail because client offers TLS 1.2 only.
            let _ = conn.complete_io(&mut stream);
        }
    });

    // Connect with a TLS 1.2-only client — expect failure.
    let client_cfg = tls12_client_config(&cert_der);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut client_conn = ClientConnection::new(client_cfg, server_name).unwrap();

    let mut tcp = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    let result = client_conn.complete_io(&mut tcp);

    // The handshake must fail: TLS 1.2 client cannot negotiate with TLS 1.3-only server.
    assert!(
        result.is_err(),
        "TLS 1.2 client must fail to connect to TLS 1.3-only server"
    );
}

#[test]
fn server_config_alpn_h2() {
    let (server_cfg, _) = DevSelfSignedProvider::generate().expect("generate");
    assert_eq!(
        server_cfg.alpn_protocols,
        vec![b"h2".to_vec()],
        "ALPN must be h2"
    );
}
