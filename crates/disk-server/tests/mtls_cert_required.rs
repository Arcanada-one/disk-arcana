//! mTLS enforcement test (P4a Step 5 + Step 11).
//!
//! Verifies that a server configured with `tls13_mtls_server_config` rejects
//! clients that present no client certificate.
//!
//! Approach: start a raw TCP + rustls server requiring mTLS, then attempt a
//! handshake with a plain one-way TLS client (no client cert). Expect the
//! handshake to fail.

use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

use disk_server::tls13_mtls_server_config;

/// Build a TLS 1.3 client config that trusts `server_cert_der` but sends
/// NO client certificate.
fn tls13_no_client_cert_config(server_cert_der: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            server_cert_der.to_vec(),
        ))
        .expect("add server cert");

    Arc::new(
        ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

#[test]
fn mtls_server_rejects_client_without_cert() {
    // --- Generate server cert ---
    let CertifiedKey {
        cert: srv_cert,
        signing_key: srv_key,
    } = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let srv_cert_der = srv_cert.der().to_vec();
    let srv_key_der = srv_key.serialize_der();

    // --- Generate a CA cert (also self-signed, used as the mTLS client verifier root) ---
    // We use the server cert itself as the "CA" root — the important thing is
    // that the client sends no cert, so the CA contents don't matter.
    let ca_pem = srv_cert.pem().into_bytes();

    let server_chain = vec![rustls::pki_types::CertificateDer::from(
        srv_cert_der.clone(),
    )];
    let server_key = rustls::pki_types::PrivateKeyDer::Pkcs8(srv_key_der.into());

    let server_cfg = tls13_mtls_server_config(server_chain, server_key, &ca_pem)
        .expect("build mTLS server config");

    // --- Spawn a background TLS server ---
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server_cfg_clone = Arc::clone(&server_cfg);

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut conn = rustls::ServerConnection::new(server_cfg_clone).unwrap();
            // Drive the handshake; we don't care about the result here.
            let _ = conn.complete_io(&mut stream);
        }
    });

    // --- Connect with a client that presents NO client cert ---
    let client_cfg = tls13_no_client_cert_config(&srv_cert_der);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut client_conn = ClientConnection::new(client_cfg, server_name).unwrap();
    let mut tcp = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();

    // Drive the full handshake AND attempt to read/write application data.
    // The server's CertificateRequired alert may arrive after the initial
    // ClientHello exchange, so we must drain all pending I/O until we see
    // an error. We cap at 10 iterations to avoid an infinite loop.
    let mut got_err = false;
    for _ in 0..10 {
        match client_conn.complete_io(&mut tcp) {
            Err(_) => {
                got_err = true;
                break;
            }
            Ok(_) => {
                // Try to read application data to force the server's alert.
                let mut buf = vec![0u8; 256];
                match client_conn.reader().read(&mut buf) {
                    Err(_) => {
                        got_err = true;
                        break;
                    }
                    Ok(0) => {
                        got_err = true;
                        break;
                    }
                    Ok(_) => {}
                }
            }
        }
    }

    // The server requires a client cert; the client sends none → the session
    // must eventually fail (either during handshake or on first read).
    assert!(
        got_err,
        "mTLS server must reject client without a client certificate"
    );
}

#[test]
fn mtls_server_config_alpn_is_h2() {
    let CertifiedKey { cert, signing_key: key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.der().to_vec();
    let ca_pem = cert.pem().into_bytes();
    let chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    let cfg = tls13_mtls_server_config(chain, key, &ca_pem).expect("build config");
    assert_eq!(
        cfg.alpn_protocols,
        vec![b"h2".to_vec()],
        "ALPN must be h2 for gRPC"
    );
}
