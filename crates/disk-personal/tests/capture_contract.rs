use disk_personal::capture_binding::CaptureDescriptor;
use serde_json::{json, Value};
fn vector() -> Value {
    serde_json::from_str(include_str!("fixtures/capture-canonical.json")).unwrap()
}
fn parse(v: &Value) -> bool {
    CaptureDescriptor::parse(&serde_json::to_vec(v).unwrap()).is_ok()
}
#[test]
fn canonical_independent_vector_and_numeric_spelling() {
    let v = vector();
    let bytes = serde_json::to_vec(&v["descriptor"]).unwrap();
    let d = CaptureDescriptor::parse(&bytes).unwrap();
    assert_eq!(d.fingerprint_input(), v["fingerprintInput"]);
    let s = String::from_utf8(bytes).unwrap();
    assert!(CaptureDescriptor::parse(
        s.replace(
            "\"cancellationGeneration\":0",
            "\"cancellationGeneration\":-0"
        )
        .as_bytes()
    )
    .is_ok());
    assert!(
        CaptureDescriptor::parse(s.replace("\"sizeBytes\":3", "\"sizeBytes\":3e0").as_bytes())
            .is_ok()
    );
}
#[test]
fn reject_unknown_version_fields_fraction_overflow_and_substitution() {
    for (key, value) in [
        ("schemaVersion", json!("personal-capture/v2")),
        ("operation", json!("grant")),
        ("cancellationGeneration", json!(9007199254740991_u64)),
        ("cancellationGeneration", json!(-1)),
        ("expectedConversationRevision", json!(0.5)),
        ("requestFingerprint", json!("0".repeat(64))),
        ("realmId", json!("10000000-0000-4000-8000-000000000002")),
        ("extra", json!(true)),
    ] {
        let mut d = vector()["descriptor"].clone();
        d[key] = value;
        assert!(!parse(&d), "{key}");
    }
    for key in ["sizeBytes", "sha256", "objectId", "unknown"] {
        let mut d = vector()["descriptor"].clone();
        d["parts"][0][key] = json!(null);
        assert!(!parse(&d));
    }
}
#[test]
fn full_identity_detects_ids_intentionally_absent_from_fingerprint() {
    let a = vector()["descriptor"].clone();
    let mut b = a.clone();
    b["messageId"] = json!("00000000-0000-0000-0000-000000000000");
    let a = CaptureDescriptor::parse(&serde_json::to_vec(&a).unwrap()).unwrap();
    let b = CaptureDescriptor::parse(&serde_json::to_vec(&b).unwrap()).unwrap();
    assert_eq!(a.fingerprint_input(), b.fingerprint_input());
    assert_ne!(a.descriptor_identity(), b.descriptor_identity());
}
