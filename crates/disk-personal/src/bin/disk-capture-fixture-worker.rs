//! Owned synthetic process/restart and syscall-observation fixture only.
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    use disk_personal::{
        capture_binding::CaptureDescriptor,
        fixture_support::{Binding, CaptureFixture, Kind, Request},
    };
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 3);
    let path = std::path::Path::new(&args[2]);
    let binding = Binding {
        realm_id: "10000000-0000-4000-8000-000000000001".into(),
        deployment_id: "20000000-0000-4000-8000-000000000001".into(),
    };
    if args[1] == "denied" {
        assert!(CaptureFixture::open_without_trusted_startup(path, &binding)
            .await
            .is_err());
        println!("STARTUP_UNAVAILABLE");
        return;
    }
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/capture-canonical.json")).unwrap();
    let d = CaptureDescriptor::parse(&serde_json::to_vec(&v["descriptor"]).unwrap()).unwrap();
    let request = Request {
        operation_id: "30000000-0000-4000-8000-000000000001".into(),
        attempt_id: "40000000-0000-4000-8000-000000000001".into(),
        object_id: "50000000-0000-4000-8000-000000000001".into(),
        revision_id: "60000000-0000-4000-8000-000000000001".into(),
        kind: Kind::Note,
        expected_len: 3,
        sha256: disk_personal::fixture_support::digest(b"abc"),
    };
    let part = "0000000b-0000-4000-8000-000000000001";
    if args[1] == "seed" {
        CaptureFixture::initialize(path, &binding).await.unwrap();
    } else {
        assert_eq!(args[1], "read");
    }
    let mut fixture = CaptureFixture::open(path, &binding).await.unwrap();
    let receipt = fixture.stage(&d, part, &request, b"abc").await.unwrap();
    assert_eq!(fixture.read(&d, part, &request).await.unwrap(), b"abc");
    fixture.close().await.unwrap();
    println!("{}", serde_json::to_string(&receipt).unwrap());
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(78);
}
