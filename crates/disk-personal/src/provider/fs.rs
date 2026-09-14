//! Path hygiene for an exclusively owned synthetic root, not a production VFS.
use super::types::{Binding, Error, Request, Result, MAX_BLOB};
use rustix::fs::{FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags};
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

static ABANDONED_WORKER: AtomicBool = AtomicBool::new(false);

pub(crate) struct Root {
    pub path: PathBuf,
    dir: File,
    lock: Option<File>,
    shutdown_acknowledged: bool,
    worker_started: bool,
    pub fail_poison_before_create: bool,
    pub staging: File,
    objects: File,
    device: u64,
    inode: u64,
}

fn checked(meta: &Metadata, device: u64, directory: bool) -> Result<()> {
    let expected_mode = if directory { 0o700 } else { 0o600 };
    if meta.dev() != device
        || meta.uid() != rustix::process::geteuid().as_raw()
        || meta.mode() & 0o7777 != expected_mode
        || (directory && !meta.is_dir())
        || (!directory && (!meta.is_file() || meta.nlink() != 1))
    {
        return Err(Error::UnsafePath);
    }
    Ok(())
}

fn open_relative(dir: &File, name: &str, flags: OFlags, mode: Mode) -> Result<File> {
    let fd = rustix::fs::openat2(
        dir,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        mode,
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
    )
    .map_err(std::io::Error::from)?;
    Ok(File::from(fd))
}

impl Root {
    pub fn initialize(path: &Path, binding: &Binding) -> Result<Self> {
        if ABANDONED_WORKER.load(Ordering::SeqCst) {
            return Err(Error::LifecycleAbandoned);
        }
        binding.validate()?;
        let parent = path.parent().ok_or(Error::UnsafePath)?;
        if !path.is_absolute() || parent.canonicalize()? != parent {
            return Err(Error::UnsafePath);
        }
        // No recursive creation and no reuse of an existing directory.
        std::fs::DirBuilder::new().mode(0o700).create(path)?;
        for name in ["staging", "objects"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(path.join(name))?;
        }
        for name in ["inventory.sqlite", "writer.lock", "fixture.json"] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(name))?;
            if name == "fixture.json" {
                file.write_all(&serde_json::to_vec(binding)?)?;
            }
            file.sync_all()?;
        }
        File::open(path)?.sync_all()?;
        File::open(parent)?.sync_all()?;
        Self::open(path, binding)
    }

    pub fn open(path: &Path, binding: &Binding) -> Result<Self> {
        if ABANDONED_WORKER.load(Ordering::SeqCst) {
            return Err(Error::LifecycleAbandoned);
        }
        binding.validate()?;
        if !path.is_absolute() || path.canonicalize()? != path {
            return Err(Error::UnsafePath);
        }
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        let dir = File::from(fd);
        let meta = dir.metadata()?;
        checked(&meta, meta.dev(), true)?;
        Self::check_entries(path, meta.dev())?;
        let marker = open_relative(&dir, "fixture.json", OFlags::RDONLY, Mode::empty())?;
        let mut bytes = Vec::new();
        marker.take(1025).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 || serde_json::from_slice::<Binding>(&bytes)? != *binding {
            return Err(Error::UnsafePath);
        }
        let lock = open_relative(&dir, "writer.lock", OFlags::RDWR, Mode::empty())?;
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| Error::WriterBusy)?;
        let staging = open_relative(
            &dir,
            "staging",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )?;
        let objects = open_relative(
            &dir,
            "objects",
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )?;
        Ok(Self {
            path: path.to_owned(),
            dir,
            lock: Some(lock),
            shutdown_acknowledged: false,
            worker_started: false,
            fail_poison_before_create: false,
            staging,
            objects,
            device: meta.dev(),
            inode: meta.ino(),
        })
    }

    fn check_entries(path: &Path, device: u64) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error::UnsafePath)?;
            let directory = matches!(name, "staging" | "objects");
            if !directory
                && !matches!(
                    name,
                    "inventory.sqlite"
                        | "inventory.sqlite-wal"
                        | "inventory.sqlite-shm"
                        | "inventory.sqlite-journal"
                        | "writer.lock"
                        | "fixture.json"
                        | "POISON"
                )
            {
                return Err(Error::UnsafePath);
            }
            checked(&std::fs::symlink_metadata(entry.path())?, device, directory)?;
        }
        for name in [
            "inventory.sqlite",
            "writer.lock",
            "fixture.json",
            "staging",
            "objects",
        ] {
            checked(
                &std::fs::symlink_metadata(path.join(name))?,
                device,
                matches!(name, "staging" | "objects"),
            )?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if ABANDONED_WORKER.load(Ordering::SeqCst) {
            return Err(Error::LifecycleAbandoned);
        }
        let meta = std::fs::symlink_metadata(&self.path)?;
        checked(&meta, self.device, true)?;
        if meta.ino() != self.inode {
            return Err(Error::UnsafePath);
        }
        Self::check_entries(&self.path, self.device)?;
        for (name, handle) in [
            ("staging", &self.staging),
            ("objects", &self.objects),
            ("writer.lock", self.lock.as_ref().ok_or(Error::UnsafePath)?),
        ] {
            let current = std::fs::symlink_metadata(self.path.join(name))?;
            if current.ino() != handle.metadata()?.ino() {
                return Err(Error::UnsafePath);
            }
        }
        if self.path.join("POISON").try_exists()? {
            return Err(Error::Poisoned);
        }
        Ok(())
    }

    pub fn poison(&mut self) -> Result<()> {
        if std::mem::take(&mut self.fail_poison_before_create) {
            return Err(Error::PoisonUncertain);
        }
        let result = (|| -> Result<()> {
            let mut file = open_relative(
                &self.dir,
                "POISON",
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o600),
            )?;
            file.write_all(b"synthetic provider integrity failure\n")?;
            file.sync_all()?;
            self.dir.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            Err(Error::PoisonUncertain)
        } else {
            Err(Error::Poisoned)
        }
    }

    pub fn object_dir(&self, request: &Request, create: bool) -> Result<File> {
        if create {
            match rustix::fs::mkdirat(
                &self.objects,
                &request.object_id,
                Mode::from_raw_mode(0o700),
            ) {
                Ok(()) => self.objects.sync_all()?,
                Err(rustix::io::Errno::EXIST) => (),
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
        let dir = open_relative(
            &self.objects,
            &request.object_id,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
        )?;
        checked(&dir.metadata()?, self.device, true)?;
        Ok(dir)
    }

    pub fn existing(&self, dir: &File, name: &str) -> Result<Option<File>> {
        match open_relative(dir, name, OFlags::RDONLY, Mode::empty()) {
            Ok(file) => {
                checked(&file.metadata()?, self.device, false)?;
                Ok(Some(file))
            }
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn verified_bytes(&self, file: File, request: &Request) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        file.take(MAX_BLOB as u64 + 1).read_to_end(&mut bytes)?;
        if !request.verifies(&bytes) {
            return Err(Error::UnresolvedPrepared);
        }
        Ok(bytes)
    }

    pub fn create_stage(&self, request: &Request) -> Result<File> {
        open_relative(
            &self.staging,
            &request.staging_name(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
            Mode::from_raw_mode(0o600),
        )
    }

    pub fn publish(&self, request: &Request, destination: &File) -> Result<()> {
        rustix::fs::renameat_with(
            &self.staging,
            request.staging_name(),
            destination,
            request.object_name(),
            RenameFlags::NOREPLACE,
        )
        .map_err(std::io::Error::from)?;
        Ok(())
    }

    pub fn sync_publish_dirs(
        &self,
        destination: &File,
        checkpoint: &mut dyn FnMut(&'static str) -> Result<()>,
    ) -> Result<()> {
        checkpoint("before_staging_directory_sync")?;
        self.staging.sync_all()?;
        checkpoint("before_destination_directory_sync")?;
        destination.sync_all()?;
        checkpoint("before_objects_directory_sync")?;
        self.objects.sync_all()?;
        checkpoint("before_root_directory_sync")?;
        self.dir.sync_all()?;
        Ok(())
    }

    pub fn acknowledge_shutdown(&mut self) {
        self.shutdown_acknowledged = true;
    }

    pub fn starting_worker(&mut self) {
        self.worker_started = true;
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        if self.worker_started && !self.shutdown_acknowledged {
            // SQLx Drop may leave its worker finishing an operation. Fail closed:
            // the OS releases this retained lock only when this process exits.
            // Never confuse an abandoned future with acknowledged shutdown.
            if let Some(lock) = self.lock.take() {
                std::mem::forget(lock);
            }
            ABANDONED_WORKER.store(true, Ordering::SeqCst);
        }
    }
}
