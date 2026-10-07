//! Synchronous descriptor-relative file layer for a future SQLite VFS adapter.
//! No SQLite ABI registration, WAL/shared-memory support, mount admission, or
//! runtime composition is provided. Only an already admitted directory is used.
use crate::parent_journal::{DirectoryIdentity, JournalError};
use crate::parent_native::ObjectKey;
use rustix::fs::{FlockOperation, Mode, OFlags, ResolveFlags};
use std::cell::Cell;
use std::fs::File;
use std::os::unix::fs::{FileExt, MetadataExt};

type Result<T> = std::result::Result<T, JournalError>;
const MAX_FILE: u64 = 16 * 1024 * 1024;
/// Closed names only; callers cannot inject paths or select another namespace.
pub enum Entry<'a> {
    Inventory,
    RollbackJournal,
    Object(&'a ObjectKey),
}
impl Entry<'_> {
    fn name(&self) -> String {
        match self {
            Self::Inventory => "inventory.sqlite".into(),
            Self::RollbackJournal => "inventory.sqlite-journal".into(),
            Self::Object(k) => format!(
                "{}-{}-{}.blob",
                k.part_id(),
                k.object_id(),
                k.object_revision()
            ),
        }
    }
}
pub struct Directory {
    file: File,
    identity: DirectoryIdentity,
    poisoned: Cell<bool>,
}
pub struct Locked<'a> {
    directory: &'a Directory,
    lock: File,
}
pub struct PageFile<'a> {
    file: File,
    guard: &'a Locked<'a>,
    writable: bool,
}
fn directory_identity(f: &File, i: DirectoryIdentity) -> Result<()> {
    let m = f.metadata()?;
    if !m.is_dir()
        || m.dev() != i.device
        || m.ino() != i.inode
        || m.uid() != i.uid
        || i.uid != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != 0o700
    {
        return Err(JournalError::UnsafeDirectory);
    }
    Ok(())
}
impl Directory {
    pub fn from_admitted_handle(file: File, identity: DirectoryIdentity) -> Result<Self> {
        directory_identity(&file, identity)?;
        Ok(Self {
            file,
            identity,
            poisoned: Cell::new(false),
        })
    }
    fn open(&self, name: &str, flags: OFlags) -> Result<File> {
        directory_identity(&self.file, self.identity)?;
        let mode = if flags.contains(OFlags::CREATE) {
            Mode::from_raw_mode(0o600)
        } else {
            Mode::empty()
        };
        let f = File::from(rustix::fs::openat2(
            &self.file,
            name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            mode,
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?);
        self.check(&f)?;
        Ok(f)
    }
    fn check(&self, f: &File) -> Result<()> {
        let m = f.metadata()?;
        if !m.is_file()
            || m.dev() != self.identity.device
            || m.uid() != self.identity.uid
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
        {
            return Err(JournalError::UnsafeEntry);
        }
        if m.len() > MAX_FILE {
            return Err(JournalError::Capacity);
        }
        Ok(())
    }
    /// Lock is retained for every opened file, through all synchronous IO.
    /// Existing provisioner-created writer.lock is required; never created here.
    pub fn with_exclusive<T>(&self, action: impl FnOnce(&Locked<'_>) -> Result<T>) -> Result<T> {
        if self.poisoned.get() {
            return Err(JournalError::Pending);
        }
        let lock = self.open("writer.lock", OFlags::RDWR)?;
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == rustix::io::Errno::WOULDBLOCK {
                JournalError::Pending
            } else {
                e.into()
            }
        })?;
        let guard = Locked {
            directory: self,
            lock,
        };
        let result = action(&guard);
        if result.is_ok() && guard.directory.poisoned.get() {
            return Err(JournalError::Pending);
        }
        result
    }
}
impl Drop for Locked<'_> {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.lock, FlockOperation::Unlock);
    }
}
impl<'a> Locked<'a> {
    fn ready(&self) -> Result<()> {
        if self.directory.poisoned.get() {
            Err(JournalError::Pending)
        } else {
            directory_identity(&self.directory.file, self.directory.identity)
        }
    }
    pub fn open_read(&'a self, entry: &Entry<'_>) -> Result<PageFile<'a>> {
        self.ready()?;
        Ok(PageFile {
            file: self.directory.open(&entry.name(), OFlags::RDONLY)?,
            guard: self,
            writable: false,
        })
    }
    /// Existing mutable files are only the closed inventory/rollback names.
    /// Object bytes are immutable and can only be created exclusively.
    pub fn open_inventory_write(&'a self, rollback: bool) -> Result<PageFile<'a>> {
        self.ready()?;
        let entry = if rollback {
            Entry::RollbackJournal
        } else {
            Entry::Inventory
        };
        Ok(PageFile {
            file: self.directory.open(&entry.name(), OFlags::RDWR)?,
            guard: self,
            writable: true,
        })
    }
    pub fn create_new(&'a self, entry: &Entry<'_>) -> Result<PageFile<'a>> {
        self.ready()?;
        // Once creation starts, errors are uncertain until external recovery.
        let result = self
            .directory
            .open(&entry.name(), OFlags::RDWR | OFlags::CREATE | OFlags::EXCL);
        if result.is_err() {
            self.directory.poisoned.set(true);
        }
        Ok(PageFile {
            file: result?,
            guard: self,
            writable: true,
        })
    }
    pub fn sync_directory(&self) -> Result<()> {
        self.ready()?;
        if let Err(e) = self.directory.file.sync_all() {
            self.directory.poisoned.set(true);
            return Err(e.into());
        }
        Ok(())
    }
}
fn range(offset: u64, len: usize) -> Result<()> {
    if offset
        .checked_add(len as u64)
        .is_none_or(|end| end > MAX_FILE)
    {
        return Err(JournalError::Capacity);
    }
    Ok(())
}
impl PageFile<'_> {
    /// SQLite-style short-read behavior: zero fill, report actual bytes read.
    /// This is not a successful full page read; the ABI adapter must map short IO.
    pub fn read_at(&self, offset: u64, bytes: &mut [u8]) -> Result<usize> {
        self.guard.ready()?;
        self.guard.directory.check(&self.file)?;
        range(offset, bytes.len())?;
        bytes.fill(0);
        let mut count = 0;
        while count < bytes.len() {
            match self
                .file
                .read_at(&mut bytes[count..], offset + count as u64)
            {
                Ok(0) => break,
                Ok(n) => count += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(count)
    }
    pub fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<()> {
        self.guard.ready()?;
        if !self.writable {
            return Err(JournalError::UnsafeEntry);
        }
        self.guard.directory.check(&self.file)?;
        range(offset, bytes.len())?;
        if let Err(e) = self.file.write_all_at(bytes, offset) {
            self.guard.directory.poisoned.set(true);
            return Err(e.into());
        }
        Ok(())
    }
    pub fn sync(&self) -> Result<()> {
        self.guard.ready()?;
        if let Err(e) = self.file.sync_all() {
            self.guard.directory.poisoned.set(true);
            return Err(e.into());
        }
        Ok(())
    }
    pub fn len(&self) -> Result<u64> {
        self.guard.ready()?;
        self.guard.directory.check(&self.file)?;
        Ok(self.file.metadata()?.len())
    }
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn range_overflow_and_cap_refuse() {
        assert!(range(u64::MAX, 1).is_err());
        assert!(range(MAX_FILE, 1).is_err());
        assert!(range(MAX_FILE, 0).is_ok());
    }
    #[test]
    fn closed_database_names() {
        assert_eq!(Entry::Inventory.name(), "inventory.sqlite");
        assert_eq!(Entry::RollbackJournal.name(), "inventory.sqlite-journal");
    }

    #[test]
    fn actual_pages_sync_reopen_and_short_read_zero_fill() {
        use std::fs::{self, OpenOptions};
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        let path =
            std::env::temp_dir().join(format!("disk-vfs-source-fixture-{}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(path.clone());
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path.join("writer.lock"))
            .unwrap();
        let root = File::open(&path).unwrap();
        let m = root.metadata().unwrap();
        let identity = DirectoryIdentity {
            device: m.dev(),
            inode: m.ino(),
            uid: m.uid(),
        };
        let directory = Directory::from_admitted_handle(root, identity).unwrap();
        directory
            .with_exclusive(|guard| {
                let file = guard.create_new(&Entry::Inventory)?;
                file.write_at(0, b"abc")?;
                file.sync()?;
                guard.sync_directory()
            })
            .unwrap();
        drop(directory);
        let directory =
            Directory::from_admitted_handle(File::open(&path).unwrap(), identity).unwrap();
        directory
            .with_exclusive(|guard| {
                let file = guard.open_read(&Entry::Inventory)?;
                let mut bytes = [9; 5];
                assert_eq!(file.read_at(0, &mut bytes)?, 3);
                assert_eq!(bytes, [97, 98, 99, 0, 0]);
                assert!(matches!(
                    file.write_at(0, b"bad"),
                    Err(JournalError::UnsafeEntry)
                ));
                assert_eq!(file.len()?, 3);
                Ok(())
            })
            .unwrap();
    }
}
