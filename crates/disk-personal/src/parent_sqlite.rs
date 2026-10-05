//! Concrete descriptor-relative rollback SQLite VFS. Admission is supplied by
//! the caller; no pathname constructor or default registration is available.
use crate::parent_journal::DirectoryIdentity;
use disk_personal_sqlite::{File as SqlFile, Vfs};
use rustix::fs::{AtFlags, FlockOperation, Mode, OFlags, ResolveFlags};
use std::fs::File;
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
const MAX_FILE: u64 = 16 * 1024 * 1024;
struct Root {
    dir: File,
    identity: DirectoryIdentity,
    lock: File,
    poisoned: AtomicBool,
}
impl Drop for Root {
    fn drop(&mut self) {
        let _ = rustix::fs::flock(&self.lock, FlockOperation::Unlock);
    }
}
impl Root {
    fn ready(&self) -> io::Result<()> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(io::Error::other("uncertain SQLite IO; recovery required"));
        }
        check_directory(&self.dir, self.identity)
    }
    fn checked(&self, f: &File) -> io::Result<()> {
        let m = f.metadata()?;
        if !m.is_file()
            || m.dev() != self.identity.device
            || m.uid() != self.identity.uid
            || m.nlink() != 1
            || m.mode() & 0o7777 != 0o600
        {
            return Err(io::Error::other("unsafe SQLite entry"));
        }
        if m.len() > MAX_FILE {
            return Err(io::Error::other("SQLite file capacity"));
        }
        Ok(())
    }
    fn open(&self, name: &str, create: bool, exclusive: bool) -> io::Result<File> {
        self.ready()?;
        if !matches!(
            name,
            "inventory.sqlite"
                | "inventory.sqlite-journal"
                | "inventory.sqlite-wal"
                | "inventory.sqlite-shm"
        ) {
            return Err(io::Error::other("SQLite namespace denied"));
        }
        let mut flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if create {
            flags |= OFlags::CREATE;
        }
        if exclusive {
            flags |= OFlags::EXCL;
        }
        let fd = rustix::fs::openat2(
            &self.dir,
            name,
            flags,
            if create {
                Mode::from_raw_mode(0o600)
            } else {
                Mode::empty()
            },
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?;
        let file = File::from(fd);
        self.checked(&file)?;
        // Directory synchronization covers both newly created database/journal
        // names before SQLite writes depend on their recovery visibility.
        if create {
            self.mutation(self.dir.sync_all())?;
        }
        Ok(file)
    }
    fn mutation<T>(&self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }
}
fn check_directory(dir: &File, i: DirectoryIdentity) -> io::Result<()> {
    let m = dir.metadata()?;
    if !m.is_dir()
        || m.dev() != i.device
        || m.ino() != i.inode
        || m.uid() != i.uid
        || i.uid != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != 0o700
    {
        return Err(io::Error::other("unsafe SQLite directory"));
    }
    Ok(())
}
pub struct DescriptorVfs {
    root: Arc<Root>,
}
impl DescriptorVfs {
    /// Existing admitted handle and provisioner-created writer.lock only.
    /// Exclusive flock is retained through all SQLite callbacks and connection
    /// close; another process/connection receives WouldBlock before db access.
    pub fn from_admitted_handle(dir: File, identity: DirectoryIdentity) -> io::Result<Self> {
        check_directory(&dir, identity)?;
        let fd = rustix::fs::openat2(
            &dir,
            "writer.lock",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?;
        let lock = File::from(fd);
        let m = lock.metadata()?;
        if !m.is_file()
            || m.dev() != identity.device
            || m.uid() != identity.uid
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
        {
            return Err(io::Error::other("unsafe SQLite writer lock"));
        }
        rustix::fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
        Ok(Self {
            root: Arc::new(Root {
                dir,
                identity,
                lock,
                poisoned: AtomicBool::new(false),
            }),
        })
    }
}
struct DescriptorFile {
    file: File,
    root: Arc<Root>,
}
fn range(offset: u64, len: usize) -> io::Result<()> {
    if offset
        .checked_add(len as u64)
        .is_none_or(|end| end > MAX_FILE)
    {
        return Err(io::Error::other("SQLite IO range"));
    }
    Ok(())
}
impl SqlFile for DescriptorFile {
    fn read(&mut self, offset: u64, bytes: &mut [u8]) -> io::Result<usize> {
        self.root.ready()?;
        self.root.checked(&self.file)?;
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
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(count)
    }
    fn write(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.root.ready()?;
        self.root.checked(&self.file)?;
        range(offset, bytes.len())?;
        self.root.mutation(self.file.write_all_at(bytes, offset))
    }
    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.root.ready()?;
        self.root.checked(&self.file)?;
        range(len, 0)?;
        self.root.mutation(self.file.set_len(len))
    }
    fn sync(&mut self) -> io::Result<()> {
        self.root.ready()?;
        self.root.mutation(self.file.sync_all())
    }
    fn size(&mut self) -> io::Result<u64> {
        self.root.ready()?;
        self.root.checked(&self.file)?;
        Ok(self.file.metadata()?.len())
    }
}
impl Vfs for DescriptorVfs {
    fn open(&self, name: &str, create: bool, exclusive: bool) -> io::Result<Box<dyn SqlFile>> {
        if !matches!(name, "inventory.sqlite" | "inventory.sqlite-journal") {
            return Err(io::Error::other("WAL/shared-memory open denied"));
        }
        Ok(Box::new(DescriptorFile {
            file: self.root.open(name, create, exclusive)?,
            root: self.root.clone(),
        }))
    }
    fn exists(&self, name: &str) -> io::Result<bool> {
        match self.root.open(name, false, false) {
            Ok(_) => Ok(true),
            Err(e) if e.raw_os_error() == Some(2) => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn delete(&self, name: &str, _sync_directory: bool) -> io::Result<()> {
        if name != "inventory.sqlite-journal" {
            return Err(io::Error::other("SQLite deletion denied"));
        }
        // No directory traversal/symlink follows; only the closed rollback name.
        // Ignore missing only, and always fsync the directory after unlink.
        match self.root.open(name, false, false) {
            Ok(_) => (),
            Err(e) if e.raw_os_error() == Some(2) => return Ok(()),
            Err(e) => return Err(e),
        }
        self.root.mutation(
            rustix::fs::unlinkat(&self.root.dir, name, AtFlags::empty()).map_err(Into::into),
        )?;
        self.root.mutation(self.root.dir.sync_all())
    }
}
