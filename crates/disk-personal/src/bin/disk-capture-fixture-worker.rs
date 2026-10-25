//! Owned synthetic process/restart fixture. Explicit identities, no runtime authority.
#[cfg(target_os = "linux")]
mod linux {
    use disk_personal::{
        capture_binding::CaptureDescriptor,
        fixture_support::{Binding, CaptureFixture, Kind, Request},
    };
    use serde_json::Value;
    use std::path::Path;

    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    const PART: &str = "0000000b-0000-4000-8000-000000000001";

    fn canonical_id(value: &str) -> Result<String> {
        let id = uuid::Uuid::parse_str(value)?;
        if id.is_nil() || id.to_string() != value {
            return Err("canonical non-nil synthetic UUID required".into());
        }
        Ok(value.into())
    }

    fn descriptor(realm: &str, payload: &[u8]) -> Result<CaptureDescriptor> {
        let mut fixture: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/capture-canonical.json"))?;
        let sha = disk_personal::fixture_support::digest(payload);
        // Regenerate the supplied canonical fixture input, then verify against
        // the actual existing CaptureDescriptor parser/fingerprint implementation.
        let mut input: Value = serde_json::from_str(
            fixture["fingerprintInput"]
                .as_str()
                .ok_or("fixture input")?,
        )?;
        input[1] = realm.into();
        input[5][0][1] = sha.clone().into();
        input[5][0][2] = payload.len().into();
        fixture["descriptor"]["realmId"] = realm.into();
        fixture["descriptor"]["parts"][0]["sha256"] = sha.into();
        fixture["descriptor"]["parts"][0]["sizeBytes"] = payload.len().into();
        fixture["descriptor"]["requestFingerprint"] =
            disk_personal::fixture_support::digest(input.to_string().as_bytes()).into();
        Ok(CaptureDescriptor::parse(&serde_json::to_vec(
            &fixture["descriptor"],
        )?)?)
    }

    pub async fn run(args: &[String]) -> Result<()> {
        if args.len() != 6 || !matches!(args[1].as_str(), "seed" | "read" | "denied") {
            return Err("expected mode root realm deployment a|b".into());
        }
        let path = Path::new(&args[2]);
        let binding = Binding {
            realm_id: canonical_id(&args[3])?,
            deployment_id: canonical_id(&args[4])?,
        };
        let payload: &[u8] = match args[5].as_str() {
            "a" => b"abc",
            "b" => b"xyz",
            _ => return Err("closed synthetic payload selector required".into()),
        };
        let d = descriptor(&binding.realm_id, payload)?;
        let request = Request {
            operation_id: "30000000-0000-4000-8000-000000000001".into(),
            attempt_id: "40000000-0000-4000-8000-000000000001".into(),
            object_id: "50000000-0000-4000-8000-000000000001".into(),
            revision_id: "60000000-0000-4000-8000-000000000001".into(),
            kind: Kind::Note,
            expected_len: payload.len() as u64,
            sha256: disk_personal::fixture_support::digest(payload),
        };
        if args[1] == "denied" {
            if CaptureFixture::open_without_trusted_startup(path, &binding)
                .await
                .is_ok()
            {
                return Err("unavailable startup unexpectedly opened".into());
            }
            println!("STARTUP_UNAVAILABLE");
            return Ok(());
        }
        if args[1] == "seed" {
            CaptureFixture::initialize(path, &binding).await?;
        }
        let mut fixture = CaptureFixture::open(path, &binding).await?;
        if args[1] == "read" {
            // A reopen must prove existing bytes before any idempotent stage call.
            if fixture.read(&d, PART, &request).await? != payload {
                return Err("existing synthetic payload mismatch".into());
            }
        }
        let receipt = fixture.stage(&d, PART, &request, payload).await?;
        if fixture.read(&d, PART, &request).await? != payload {
            return Err("synthetic readback mismatch".into());
        }
        fixture.close().await?;
        println!("{}", serde_json::to_string(&receipt)?);
        Ok(())
    }
}
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if linux::run(&std::env::args().collect::<Vec<_>>())
        .await
        .is_err()
    {
        eprintln!("FIXTURE_REFUSED");
        std::process::exit(78);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(78);
}
