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
