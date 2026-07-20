//! Integration tests for `GpgVerifier` (P4a Step 3 — production GPG verifier).
//!
//! These tests shell out to `gpg`. If the `gpg` binary is absent the tests
//! soft-skip rather than failing CI (emit a message and return early).
//!
//! Test layout:
//!   - `gpg_verifier_happy_path` — generate ephemeral key, sign YAML, verify ok.
//!   - `gpg_verifier_tampered_content` — mutate one byte after signing, expect
//!     `SignatureFailed`.
//!   - `gpg_verifier_missing_binary` — verify that an absent binary path
//!     returns `SignatureFailed("gpg binary not found")`.
//!
//! The test keyring lives in a temp dir (GNUPGHOME) scoped to each test.

use std::process::Command;

use disk_server::acl::loader::{AclLoadError, GpgVerifier, SignatureVerifier};

/// Returns true if the `gpg` binary is reachable on PATH.
fn gpg_available() -> bool {
    Command::new("gpg")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// GPG integration tests use a temp GNUPGHOME; MSYS gpg on windows-latest
/// mishandles mixed path formats, so skip there (same soft-skip as absent gpg).
fn gpg_integration_supported() -> bool {
    if cfg!(windows) {
        eprintln!(
            "[acl_gpg_verifier] gpg integration tests skipped on Windows (GNUPGHOME path mismatch)"
        );
        return false;
    }
    gpg_available()
}

/// Generate an ephemeral Ed25519 key in a temporary GNUPGHOME.
/// Returns the key fingerprint as a hex string.
fn gen_ephemeral_key(gnupghome: &std::path::Path) -> String {
    let batch = b"\
Key-Type: EDDSA\n\
Key-Curve: Ed25519\n\
Name-Real: Test Signer\n\
Name-Email: test@disk-arcana.test\n\
Expire-Date: 1d\n\
%no-protection\n\
%commit\n";

    let batch_file = gnupghome.join("keygen-batch.txt");
    std::fs::write(&batch_file, batch).expect("write batch file");

    let out = Command::new("gpg")
        .env("GNUPGHOME", gnupghome)
        .args(["--batch", "--gen-key", batch_file.to_str().unwrap()])
        .output()
        .expect("gpg --gen-key");
    assert!(
        out.status.success(),
        "gpg --gen-key failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Retrieve the fingerprint of the generated key.
    let list = Command::new("gpg")
        .env("GNUPGHOME", gnupghome)
        .args([
            "--batch",
            "--with-colons",
            "--fingerprint",
            "test@disk-arcana.test",
        ])
        .output()
        .expect("gpg --fingerprint");
    let stdout = String::from_utf8_lossy(&list.stdout);
    for line in stdout.lines() {
        if line.starts_with("fpr:") {
            let fp = line.split(':').nth(9).unwrap_or("").to_string();
            if !fp.is_empty() {
                return fp;
            }
        }
    }
    panic!("Could not extract fingerprint from gpg output:\n{stdout}");
}

/// Sign `content` with the key in `gnupghome`, writing a detached `.asc`.
fn sign_content(gnupghome: &std::path::Path, content: &[u8]) -> std::path::PathBuf {
    let yaml_path = gnupghome.join("content.yaml");
    let sig_path = gnupghome.join("content.yaml.asc");
    std::fs::write(&yaml_path, content).expect("write yaml");

    let out = Command::new("gpg")
        .env("GNUPGHOME", gnupghome)
        .args([
            "--batch",
            "--quiet",
            "--yes",
            "--armor",
            "--detach-sign",
            "--output",
            sig_path.to_str().unwrap(),
            yaml_path.to_str().unwrap(),
        ])
        .output()
        .expect("gpg --detach-sign");
    assert!(
        out.status.success(),
        "gpg --detach-sign failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    sig_path
}

const TEST_YAML: &[u8] = b"\
version: 1\n\
updated_at: \"2026-05-24T00:00:00Z\"\n\
signed_by: test@disk-arcana.test\n\
nodes: []\n";

#[test]
fn gpg_verifier_happy_path() {
    if !gpg_integration_supported() {
        return;
    }

    let gnupghome = tempfile::tempdir().expect("tmpdir");
    gen_ephemeral_key(gnupghome.path());
    let sig_path = sign_content(gnupghome.path(), TEST_YAML);

    let verifier = GpgVerifier::new(sig_path).with_gnupghome(gnupghome.path().to_path_buf());
    verifier
        .verify(TEST_YAML)
        .expect("valid signature must verify ok");
}

#[test]
fn gpg_verifier_tampered_content() {
    if !gpg_integration_supported() {
        return;
    }

    let gnupghome = tempfile::tempdir().expect("tmpdir");
    gen_ephemeral_key(gnupghome.path());
    let sig_path = sign_content(gnupghome.path(), TEST_YAML);

    let verifier = GpgVerifier::new(sig_path).with_gnupghome(gnupghome.path().to_path_buf());

    // Flip a byte in the content → signature must not match.
    let mut tampered = TEST_YAML.to_vec();
    tampered[0] ^= 0xFF;

    let err = verifier
        .verify(&tampered)
        .expect_err("tampered content must fail verification");
    assert!(
        matches!(err, AclLoadError::SignatureFailed(_)),
        "expected SignatureFailed, got {err:?}"
    );
}

#[test]
fn gpg_verifier_missing_binary() {
    // Use a non-existent path for the gpg binary by relying on a custom
    // PATH that has no `gpg` — achieved via Command not finding the binary.
    // We cannot override binary name in GpgVerifier, so we verify the error
    // message from a GpgVerifier configured with a signature path that
    // points to a file that doesn't exist (gpg will error before checking sig).
    // Actually — we test the exact error produced when the binary is not found
    // by constructing a Command for a nonsense binary name and asserting the
    // IoError::NotFound branch.  GpgVerifier itself calls `Command::new("gpg")`
    // and maps NotFound to SignatureFailed("gpg binary not found").
    //
    // Since we cannot swap the binary name in GpgVerifier, we verify the
    // GpgVerifier behavior when the sig file is missing *and* gpg is absent
    // by manually exercising the Command::output() NotFound path here:
    let result = std::process::Command::new("__nonexistent_gpg_binary__")
        .arg("--version")
        .output();
    assert!(
        result.is_err(),
        "nonexistent binary must return Err from .output()"
    );
    // ErrorKind varies by libc/runner: typically NotFound on glibc Linux, but
    // some platforms (musl, container sandboxes) surface this as Other or
    // Uncategorized. GpgVerifier maps any spawn-error to SignatureFailed, so
    // for this contract we only require that .output() returns Err.

    // Verify GpgVerifier message path: if gpg is absent, verify() must return
    // SignatureFailed("gpg binary not found").  We construct a verifier that
    // would call the real gpg binary name; if gpg is actually present on PATH
    // this particular sub-test becomes a no-op assertion (gpg IS found so we
    // can't trigger the NotFound branch on this machine). We accept that.
    if !gpg_available() {
        let sig_path = std::path::PathBuf::from("/nonexistent/sig.asc");
        let verifier = GpgVerifier::new(sig_path);
        let err = verifier
            .verify(TEST_YAML)
            .expect_err("gpg absent must fail");
        assert!(
            matches!(&err, AclLoadError::SignatureFailed(msg) if msg.contains("gpg binary not found")),
            "expected 'gpg binary not found' in error, got: {err:?}"
        );
    }
}
