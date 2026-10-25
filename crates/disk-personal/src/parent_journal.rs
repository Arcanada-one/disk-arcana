//! Descriptor-relative durable native owner-outcome journal primitive (Linux).
//! No pathname mount discovery, root creation, private-data admission or SQLite
//! VFS is provided. The caller must already hold admitted startup/effect leases.
use crate::parent_native::{Id, OriginalEffect, Outcome};
use rustix::fs::{FlockOperation, Mode, OFlags, RenameFlags, ResolveFlags};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

const MAX_RECORD: usize = 16_384;
const MAX_RECORDS: usize = 128;
const SCHEMA: &str = "disk-local-owner-journal/1-source";
#[derive(Debug)]
pub enum JournalError {
    UnsafeDirectory,
    UnsafeEntry,
    Corrupt,
    Conflict,
    Capacity,
    Pending,
    /// Includes ENOSYS unchanged: absence of openat2 never enables openat fallback.
    Io(std::io::Error),
}
impl From<std::io::Error> for JournalError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<rustix::io::Errno> for JournalError {
    fn from(e: rustix::io::Errno) -> Self {
        Self::Io(e.into())
    }
}
type Result<T> = std::result::Result<T, JournalError>;

/// Structural identity of the ALREADY authenticated/admitted directory FD.
/// Matching these numbers is confinement, never encrypted-mount/key proof.
#[derive(Clone, Copy)]
pub struct DirectoryIdentity {
    pub device: u64,
    pub inode: u64,
    pub uid: u32,
}
pub struct Journal {
    dir: File,
    identity: DirectoryIdentity,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecord {
    schema_version: String,
    effect_lease_id: Id,
    outcome: Outcome,
}
impl LocalRecord {
    pub fn effect_lease_id(&self) -> &Id {
        &self.effect_lease_id
    }
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }
}
/// Neither variant is an authenticated wire receipt or permission to release.
/// Existing only observes retained bytes; it does not promote an old UNKNOWN.
pub enum RecordResult {
    Recorded,
    Existing,
}

fn same_dir(file: &File, expected: DirectoryIdentity) -> Result<()> {
    let m = file.metadata()?;
    if !m.is_dir()
        || m.dev() != expected.device
        || m.ino() != expected.inode
        || m.uid() != expected.uid
        || m.uid() != rustix::process::geteuid().as_raw()
        || m.mode() & 0o7777 != 0o700
    {
        return Err(JournalError::UnsafeDirectory);
    }
    Ok(())
}
fn checked_file(file: &File, expected: DirectoryIdentity) -> Result<std::fs::Metadata> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.dev() != expected.device
        || m.uid() != expected.uid
        || m.mode() & 0o7777 != 0o600
        || m.nlink() != 1
    {
        return Err(JournalError::UnsafeEntry);
    }
    Ok(m)
}
type ScannedRecord = (String, Vec<u8>, LocalRecord);
struct Writer(File);
impl Drop for Writer {
    fn drop(&mut self) {
        // Synchronous IO has completed before return; explicitly unlock the
        // shared open-file description even if a fork retained another copy.
        let _ = rustix::fs::flock(&self.0, FlockOperation::Unlock);
    }
}
impl Journal {
    /// Does not create directories, lock files, or missing mounts. Provisioner
    /// supplies an existing0700 directory and existing0600 writer.lock.
    pub fn from_admitted_handle(dir: File, identity: DirectoryIdentity) -> Result<Self> {
        same_dir(&dir, identity)?;
        Ok(Self { dir, identity })
    }
    fn open(&self, name: &str, flags: OFlags) -> Result<File> {
        same_dir(&self.dir, self.identity)?;
        let fd = rustix::fs::openat2(
            &self.dir,
            name,
            flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            if flags.contains(OFlags::CREATE) {
                Mode::from_raw_mode(0o600)
            } else {
                Mode::empty()
            },
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?;
        let file = File::from(fd);
        checked_file(&file, self.identity)?;
        Ok(file)
    }
    fn lock(&self) -> Result<Writer> {
        let file = self.open("writer.lock", OFlags::RDWR)?;
        rustix::fs::flock(&file, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == rustix::io::Errno::WOULDBLOCK {
                JournalError::Pending
            } else {
                JournalError::from(e)
            }
        })?;
        Ok(Writer(file))
    }
    fn read(&self, name: &str) -> Result<Vec<u8>> {
        let file = self.open(name, OFlags::RDONLY)?;
        let before = checked_file(&file, self.identity)?;
        if before.len() > MAX_RECORD as u64 {
            return Err(JournalError::Capacity);
        }
        let mut bytes = Vec::new();
        (&file)
            .take((MAX_RECORD + 1) as u64)
            .read_to_end(&mut bytes)?;
        let after = checked_file(&file, self.identity)?;
        if bytes.len() > MAX_RECORD
            || before.len() != after.len()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.mtime() != after.mtime()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || bytes.len() as u64 != after.len()
        {
            return Err(JournalError::Corrupt);
        }
        Ok(bytes)
    }
    fn scan(&self) -> Result<Vec<ScannedRecord>> {
        same_dir(&self.dir, self.identity)?;
        // New directory description: never share/reuse a cursor across calls.
        let dir = rustix::fs::openat2(
            &self.dir,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_XDEV,
        )?;
        let entries = rustix::fs::Dir::read_from(&dir)?;
        let mut records = Vec::new();
        let mut seen_receipts = std::collections::BTreeSet::new();
        let mut seen_seq = std::collections::BTreeSet::new();
        for entry in entries {
            let entry = entry?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| JournalError::UnsafeEntry)?;
            if [".", "..", "writer.lock"].contains(&name) {
                continue;
            }
            // A partial append is retained, never guessed complete or removed.
            if name.ends_with(".pending") {
                return Err(JournalError::Pending);
            }
            let id = name
                .strip_suffix(".json")
                .ok_or(JournalError::UnsafeEntry)?;
            let parsed: Id = serde_json::from_value(serde_json::Value::String(id.into()))
                .map_err(|_| JournalError::UnsafeEntry)?;
            if records.len() >= MAX_RECORDS {
                return Err(JournalError::Capacity);
            }
            let bytes = self.read(name)?;
            let record: LocalRecord =
                serde_json::from_slice(&bytes).map_err(|_| JournalError::Corrupt)?;
            if record.schema_version != SCHEMA
                || record.effect_lease_id != parsed
                || !seen_receipts.insert(record.outcome.owner_receipt_id().to_owned())
                || !seen_seq.insert(record.outcome.local_sequence())
            {
                return Err(JournalError::Corrupt);
            }
            records.push((name.into(), bytes, record));
        }
        records.sort_by_key(|(_, _, r)| r.outcome.local_sequence());
        Ok(records)
    }
    /// Protected local inspection only. Missing records never prove no-commit.
    /// Calls require current access/recovery admission from the parent caller.
    pub fn inspect(&self) -> Result<Vec<LocalRecord>> {
        let _writer = self.lock()?;
        Ok(self.scan()?.into_iter().map(|(_, _, r)| r).collect())
    }
    /// Append the ORIGINAL native outcome under the original effect lease.
    /// It is the caller's duty to authenticate expected via Auth readback and
    /// retain exclusive admitted directory ownership/lease through this call.
    /// This primitive does not atomically commit object bytes or SQLite state.
    pub fn record(
        &self,
        lease: &Id,
        outcome: &Outcome,
        expected: &OriginalEffect,
    ) -> Result<RecordResult> {
        if !outcome.matches_original_effect(expected) {
            return Err(JournalError::Conflict);
        }
        let record = LocalRecord {
            schema_version: SCHEMA.into(),
            effect_lease_id: lease.clone(),
            outcome: outcome.clone(),
        };
        let bytes = serde_json::to_vec(&record).map_err(|_| JournalError::Corrupt)?;
        if bytes.len() > MAX_RECORD {
            return Err(JournalError::Capacity);
        }
        let _writer = self.lock()?;
        let records = self.scan()?;
        for (_, old, record) in &records {
            if record.effect_lease_id == *lease {
                return if old == &bytes {
                    Ok(RecordResult::Existing)
                } else {
                    Err(JournalError::Conflict)
                };
            }
            if record.outcome.owner_receipt_id() == outcome.owner_receipt_id()
                || record.outcome.local_sequence() == outcome.local_sequence()
            {
                return Err(JournalError::Conflict);
            }
        }
        if records.len() >= MAX_RECORDS {
            return Err(JournalError::Capacity);
        }
        let stem = lease.as_str();
        let pending = format!("{stem}.pending");
        let final_name = format!("{stem}.json");
        let mut file = self.open(&pending, OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL)?;
        // Any error retains the partial file; never truncate/unlink/retry it.
        file.write_all(&bytes)?;
        file.sync_all()?;
        checked_file(&file, self.identity)?;
        rustix::fs::renameat_with(
            &self.dir,
            &pending,
            &self.dir,
            &final_name,
            RenameFlags::NOREPLACE,
        )?;
        self.dir.sync_all()?;
        Ok(RecordResult::Recorded)
    }
}

#[cfg(test)]
#[path = "parent_journal_tests.rs"]
mod tests;
