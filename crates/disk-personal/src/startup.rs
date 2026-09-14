//! No trusted deployment, encrypted-mount and Auth startup verifier is installed.
//! This boundary deliberately performs no storage inspection or hydration.
#[derive(Debug, thiserror::Error)]
#[error("personal startup verification unavailable")]
pub struct StartupUnavailable;

/// Cannot be constructed by callers or deserialized from a claimed receipt.
pub struct AdmittedStartup {
    _sealed: (),
}

pub fn verify_startup() -> Result<AdmittedStartup, StartupUnavailable> {
    Err(StartupUnavailable)
}

#[cfg(all(target_os = "linux", feature = "synthetic-fixtures"))]
pub(crate) fn synthetic_startup() -> AdmittedStartup {
    AdmittedStartup { _sealed: () }
}
