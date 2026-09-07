pub(crate) mod fs;
mod inventory;
pub(crate) mod types;

use fs::Root;
use sqlx::{Connection, SqliteConnection};
use std::io::Write;
use std::path::Path;
use types::{Binding, Error, Inspection, LocalCommit, Request, Result};

/// Synchronous fixture checkpoints; never a production callback or admission gate.
pub(crate) type Checkpoint<'a> = &'a mut dyn FnMut(&'static str) -> Result<()>;

pub(crate) struct Provider {
    db: SqliteConnection,
    root: Root,
    poisoned: bool,
}

impl Provider {
    pub async fn initialize(path: &Path, binding: &Binding) -> Result<()> {
        let mut root = Root::initialize(path, binding)?;
        root.starting_worker();
        let mut db = inventory::connect(&root).await?;
        let result = inventory::initialize(&mut db, binding).await;
        db.close().await?;
        root.acknowledge_shutdown();
        result
    }

    pub async fn open(path: &Path, binding: &Binding) -> Result<Self> {
        let mut root = Root::open(path, binding)?;
        root.validate()?;
        root.starting_worker();
        let mut db = inventory::connect(&root).await?;
        if let Err(error) = inventory::verify_binding(&mut db, binding).await {
            db.close().await?;
            root.acknowledge_shutdown();
            return Err(error);
        }
        let mut provider = Self {
            db,
            root,
            poisoned: false,
        };
        if let Err(error) = provider.consistency().await {
            provider.close().await?;
            return Err(error);
        }
        Ok(provider)
    }

    pub async fn close(self) -> Result<()> {
        // Retain the process lock through SQLite worker shutdown/housekeeping.
        let Self { db, mut root, .. } = self;
        db.close().await?;
        root.acknowledge_shutdown();
        drop(root);
        Ok(())
    }

    fn available(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        self.root.validate()
    }

    fn poison<T>(&mut self) -> Result<T> {
        self.poisoned = true;
        match self.root.poison() {
            Err(e) => Err(e),
            Ok(()) => Err(Error::PoisonUncertain),
        }
    }

    fn durable_bytes(&self, request: &Request) -> Result<Vec<u8>> {
        let dir = self.root.object_dir(request, false)?;
        let file = self
            .root
            .existing(&dir, &request.object_name())?
            .ok_or(Error::NotFound)?;
        self.root.verified_bytes(file, request)
    }

    async fn consistency(&mut self) -> Result<()> {
        self.available()?;
        let records = match inventory::records(&mut self.db).await {
            Ok(records) => records,
            Err(_) => return self.poison(),
        };
        for record in records {
            if record.committed.is_some() && self.durable_bytes(&record.request).is_err() {
                return self.poison();
            }
        }
        Ok(())
    }

    pub async fn stage(
        &mut self,
        request: &Request,
        bytes: &[u8],
        checkpoint: Checkpoint<'_>,
    ) -> Result<LocalCommit> {
        self.available()?;
        request.validate()?;
        if !request.verifies(bytes) {
            return Err(Error::InvalidInput);
        }
        self.consistency().await?;
        let prior = inventory::records(&mut self.db).await?;
        if !prior
            .iter()
            .any(|r| r.request.operation_id == request.operation_id)
        {
            self.reject_unattributed_files(request)?;
        }
        checkpoint("before_prepare")?;
        let (was_reserved, commit) = inventory::reserve(&mut self.db, request).await?;
        if let Some(commit) = commit {
            return Ok(commit);
        }
        checkpoint("after_prepare")?;
        let destination = self.root.object_dir(request, true)?;
        if let Some(file) = self.root.existing(&destination, &request.object_name())? {
            if !was_reserved {
                return Err(Error::Conflict);
            }
            self.root.verified_bytes(file.try_clone()?, request)?;
            checkpoint("before_file_sync")?;
            file.sync_all()?;
        } else {
            self.prepare_file(request, bytes, was_reserved, checkpoint)?;
            checkpoint("before_rename")?;
            self.root.publish(request, &destination)?;
            checkpoint("after_rename")?;
        }
        checkpoint("before_directory_sync")?;
        self.root.sync_publish_dirs(&destination, checkpoint)?;
        checkpoint("after_directory_sync")?;
        self.available()?;
        // These are observable boundaries outside the SQLite COMMIT call.
        checkpoint("before_commit")?;
        let commit = inventory::commit(&mut self.db, request).await?;
        checkpoint("after_commit")?;
        Ok(commit)
    }

    fn reject_unattributed_files(&self, request: &Request) -> Result<()> {
        if self
            .root
            .existing(&self.root.staging, &request.staging_name())?
            .is_some()
        {
            return Err(Error::Conflict);
        }
        match self.root.object_dir(request, false) {
            Ok(dir) => {
                if self.root.existing(&dir, &request.object_name())?.is_some() {
                    return Err(Error::Conflict);
                }
            }
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        Ok(())
    }

    fn prepare_file(
        &self,
        request: &Request,
        bytes: &[u8],
        was_reserved: bool,
        checkpoint: Checkpoint<'_>,
    ) -> Result<()> {
        if let Some(file) = self
            .root
            .existing(&self.root.staging, &request.staging_name())?
        {
            if !was_reserved {
                return Err(Error::Conflict);
            }
            // A partial or different retained attempt remains unresolved forever.
            // This operation never truncates, unlinks or guesses a resume offset.
            self.root.verified_bytes(file.try_clone()?, request)?;
            checkpoint("before_file_sync")?;
            file.sync_all()?;
            checkpoint("after_file_sync")?;
            return Ok(());
        }
        let mut file = self.root.create_stage(request)?;
        checkpoint("after_create")?;
        checkpoint("before_write")?;
        let split = bytes.len().min(4096);
        file.write_all(&bytes[..split])?;
        checkpoint("after_partial_write")?;
        for chunk in bytes[split..].chunks(65_536) {
            file.write_all(chunk)?;
        }
        checkpoint("after_write")?;
        checkpoint("before_file_sync")?;
        file.sync_all()?;
        checkpoint("after_file_sync")?;
        Ok(())
    }

    pub async fn read(&mut self, request: &Request) -> Result<Vec<u8>> {
        self.available()?;
        request.validate()?;
        self.consistency().await?;
        let records = inventory::records(&mut self.db).await?;
        let record = records
            .into_iter()
            .find(|r| r.request.operation_id == request.operation_id)
            .ok_or(Error::NotFound)?;
        if record.request != *request {
            return Err(Error::Conflict);
        }
        if record.committed.is_none() {
            return Err(Error::UnresolvedPrepared);
        }
        match self.durable_bytes(request) {
            Ok(bytes) => Ok(bytes),
            Err(_) => self.poison(),
        }
    }

    pub async fn inspect(&mut self) -> Result<Inspection> {
        self.consistency().await?;
        let records = inventory::records(&mut self.db).await?;
        Ok(Inspection {
            prepared: records.iter().filter(|r| r.committed.is_none()).count(),
            durable: records.into_iter().filter_map(|r| r.committed).collect(),
            sqlite_policy: inventory::verify_policy(&mut self.db).await?,
        })
    }

    pub async fn pause_sql_worker(&mut self) -> Result<std::sync::mpsc::Sender<()>> {
        self.available()?;
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        {
            let mut handle = self.db.lock_handle().await?;
            let mut entered = Some(entered);
            handle.set_progress_handler(1, move || {
                if let Some(entered) = entered.take() {
                    let _ = entered.send(());
                    let _ = wait.recv();
                }
                false
            });
        }
        let query = sqlx::query("SELECT COUNT(*) FROM attempts").execute(&mut self.db);
        tokio::pin!(query);
        tokio::select! {
            result = &mut query => { result?; Err(Error::InvalidInput) },
            signal = observed => { signal.map_err(|_| Error::InvalidInput)?; Ok(release) },
        }
        // Returning drops the query future while the actual SQLite VM is paused.
    }

    pub fn fail_poison_persistence(&mut self) {
        self.root.fail_poison_before_create = true;
    }
}
