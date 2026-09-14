//! Explicit test harness, unavailable in default builds. No private-data use.
pub use crate::provider::types::{
    digest, Binding, Error, Inspection, Kind, LocalCommit, Request, Result,
};
use crate::provider::Provider;
use std::path::Path;

pub struct Fixture {
    provider: Provider,
}

fn guard(path: &Path) -> Result<()> {
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or(Error::UnsafePath)?;
    if !path.is_absolute() || !leaf.starts_with("disk-personal-fixture-") || leaf.len() > 100 {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

impl Fixture {
    pub async fn initialize(path: &Path, binding: &Binding) -> Result<()> {
        guard(path)?;
        Provider::initialize(path, binding).await
    }

    pub async fn open(path: &Path, binding: &Binding) -> Result<Self> {
        guard(path)?;
        Ok(Self {
            provider: Provider::open(path, binding).await?,
        })
    }

    pub async fn stage(&mut self, request: &Request, bytes: &[u8]) -> Result<LocalCommit> {
        self.provider.stage(request, bytes, &mut |_| Ok(())).await
    }

    /// A local deterministic IO-failure/crash checkpoint, never a permit.
    pub async fn stage_with_checkpoint(
        &mut self,
        request: &Request,
        bytes: &[u8],
        checkpoint: &mut dyn FnMut(&'static str) -> Result<()>,
    ) -> Result<LocalCommit> {
        self.provider.stage(request, bytes, checkpoint).await
    }

    pub async fn read(&mut self, request: &Request) -> Result<Vec<u8>> {
        self.provider.read(request).await
    }

    pub async fn inspect(&mut self) -> Result<Inspection> {
        self.provider.inspect().await
    }

    pub async fn close(self) -> Result<()> {
        self.provider.close().await
    }

    /// Pins the actual SQLite VM in a test callback. Dropping the sender resumes
    /// it with interruption. Call only in a disposable child process.
    pub async fn pause_sql_worker(&mut self) -> Result<std::sync::mpsc::Sender<()>> {
        self.provider.pause_sql_worker().await
    }

    /// Inject one marker-creation failure. This is not an observed OS failure.
    pub fn fail_poison_persistence(&mut self) {
        self.provider.fail_poison_persistence();
    }
}

/// Explicit v2 synthetic fixture. Its startup token is not trusted admission.
/// Legacy v1 roots cannot be opened or migrated through this API.
pub struct CaptureFixture {
    provider: Provider,
}
impl CaptureFixture {
    pub async fn initialize(path: &Path, binding: &Binding) -> Result<()> {
        let admission = crate::startup::synthetic_startup();
        Self::initialize_after_startup(path, binding, admission).await
    }
    async fn initialize_after_startup(
        path: &Path,
        binding: &Binding,
        _admission: crate::startup::AdmittedStartup,
    ) -> Result<()> {
        guard(path)?;
        Provider::initialize_profile(path, binding, true).await
    }
    pub async fn open(path: &Path, binding: &Binding) -> Result<Self> {
        let admission = crate::startup::synthetic_startup();
        Self::open_after_startup(path, binding, admission).await
    }
    async fn open_after_startup(
        path: &Path,
        binding: &Binding,
        _admission: crate::startup::AdmittedStartup,
    ) -> Result<Self> {
        guard(path)?;
        Ok(Self {
            provider: Provider::open_profile(path, binding, true).await?,
        })
    }
    /// Exercise the real unavailable startup boundary before touching any path.
    pub async fn open_without_trusted_startup(path: &Path, binding: &Binding) -> Result<Self> {
        let admission = crate::startup::verify_startup().map_err(|_| Error::InvalidInput)?;
        Self::open_after_startup(path, binding, admission).await
    }
    pub async fn stage(
        &mut self,
        d: &crate::capture_binding::CaptureDescriptor,
        part: &str,
        request: &Request,
        bytes: &[u8],
    ) -> Result<LocalCommit> {
        self.provider
            .stage_capture(d, part, request, bytes, &mut |_| Ok(()))
            .await
    }
    pub async fn stage_with_checkpoint(
        &mut self,
        d: &crate::capture_binding::CaptureDescriptor,
        part: &str,
        request: &Request,
        bytes: &[u8],
        checkpoint: &mut dyn FnMut(&'static str) -> Result<()>,
    ) -> Result<LocalCommit> {
        self.provider
            .stage_capture(d, part, request, bytes, checkpoint)
            .await
    }
    pub async fn read(
        &mut self,
        d: &crate::capture_binding::CaptureDescriptor,
        part: &str,
        request: &Request,
    ) -> Result<Vec<u8>> {
        self.provider.read_capture(d, part, request).await
    }
    pub async fn close(self) -> Result<()> {
        self.provider.close().await
    }
}
