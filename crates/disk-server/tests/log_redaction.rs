//! Log redaction test (V-14, T-Secret-Leak).
//!
//! Verifies that `ApiKey` and `SessionToken` Display/Debug implementations
//! never expose the raw key/token value — they must only print the masked form.
//!
//! DISK-0004 Step 18 (security logging contracts).

use disk_server::{ApiKey, SessionToken};

#[test]
fn api_key_display_masked() {
    let k = ApiKey::generate();
    let raw = k.as_str().to_owned();
    let displayed = format!("{k}");
    assert_eq!(displayed, "arc_disk_***");
    // Raw key must not appear in the masked string.
    assert!(!displayed.contains(&raw[9..]), "raw key leaked in Display");
}

#[test]
fn api_key_debug_masked() {
    let k = ApiKey::generate();
    let raw = k.as_str().to_owned();
    let debug = format!("{k:?}");
    assert_eq!(debug, "ApiKey(arc_disk_***)");
    assert!(!debug.contains(&raw[9..]), "raw key leaked in Debug");
}

#[test]
fn session_token_display_masked() {
    let t = SessionToken::generate();
    let raw = t.as_str().to_owned();
    let displayed = format!("{t}");
    assert_eq!(displayed, "arc_disk_sess_***");
    assert!(
        !displayed.contains(&raw[14..]),
        "raw token leaked in Display"
    );
}

#[test]
fn session_token_debug_masked() {
    let t = SessionToken::generate();
    let raw = t.as_str().to_owned();
    let debug = format!("{t:?}");
    assert_eq!(debug, "SessionToken(arc_disk_sess_***)");
    assert!(!debug.contains(&raw[14..]), "raw token leaked in Debug");
}

/// Verify that even a vec of api keys doesn't leak when debug-printed.
#[test]
fn vec_of_api_keys_debug_masked() {
    let keys: Vec<ApiKey> = (0..3).map(|_| ApiKey::generate()).collect();
    let debug = format!("{keys:?}");
    assert!(!debug.contains("arc_disk_A"), "raw key prefix leaked");
    // Just ensure the masked form appears.
    assert!(debug.contains("arc_disk_***"));
}
