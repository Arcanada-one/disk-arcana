//! Controlled storage leaf for real SQLite ABI/transaction tests only.
use disk_personal_sqlite::{File, Vfs};
use std::{
    collections::BTreeMap,
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
#[derive(Default)]
struct State {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
    fail_sync: AtomicBool,
}
#[derive(Clone, Default)]
pub struct MemoryVfs(Arc<State>);
impl MemoryVfs {
    pub fn fail_next_sync(&self) {
        self.0.fail_sync.store(true, Ordering::Release);
    }
}
struct Handle {
    state: Arc<State>,
    name: String,
}
impl File for Handle {
    fn read(&mut self, o: u64, b: &mut [u8]) -> io::Result<usize> {
        let files = self.state.files.lock().unwrap();
        let f = files
            .get(&self.name)
            .ok_or_else(|| io::Error::from_raw_os_error(2))?;
        let o = usize::try_from(o).map_err(|_| io::Error::other("range"))?;
        let n = b.len().min(f.len().saturating_sub(o));
        if n != 0 {
            b[..n].copy_from_slice(&f[o..o + n]);
        }
        Ok(n)
    }
    fn write(&mut self, o: u64, b: &[u8]) -> io::Result<()> {
        let mut files = self.state.files.lock().unwrap();
        let f = files
            .get_mut(&self.name)
            .ok_or_else(|| io::Error::from_raw_os_error(2))?;
        let o = usize::try_from(o).map_err(|_| io::Error::other("range"))?;
        let end = o
            .checked_add(b.len())
            .filter(|n| *n <= 16 * 1024 * 1024)
            .ok_or_else(|| io::Error::other("range"))?;
        if f.len() < end {
            f.resize(end, 0);
        }
        f[o..end].copy_from_slice(b);
        Ok(())
    }
    fn truncate(&mut self, n: u64) -> io::Result<()> {
        if n > 16 * 1024 * 1024 {
            return Err(io::Error::other("range"));
        }
        self.state
            .files
            .lock()
            .unwrap()
            .get_mut(&self.name)
            .ok_or_else(|| io::Error::from_raw_os_error(2))?
            .resize(n as usize, 0);
        Ok(())
    }
    fn sync(&mut self) -> io::Result<()> {
        if self.state.fail_sync.swap(false, Ordering::AcqRel) {
            Err(io::Error::from_raw_os_error(5))
        } else {
            Ok(())
        }
    }
    fn size(&mut self) -> io::Result<u64> {
        Ok(self
            .state
            .files
            .lock()
            .unwrap()
            .get(&self.name)
            .ok_or_else(|| io::Error::from_raw_os_error(2))?
            .len() as u64)
    }
}
impl Vfs for MemoryVfs {
    fn open(&self, n: &str, create: bool, exclusive: bool) -> io::Result<Box<dyn File>> {
        let mut files = self.0.files.lock().unwrap();
        if files.contains_key(n) {
            if exclusive {
                return Err(io::Error::from_raw_os_error(17));
            }
        } else if create {
            files.insert(n.into(), Vec::new());
        } else {
            return Err(io::Error::from_raw_os_error(2));
        }
        Ok(Box::new(Handle {
            state: self.0.clone(),
            name: n.into(),
        }))
    }
    fn exists(&self, n: &str) -> io::Result<bool> {
        Ok(self.0.files.lock().unwrap().contains_key(n))
    }
    fn delete(&self, n: &str, _: bool) -> io::Result<()> {
        self.0.files.lock().unwrap().remove(n);
        Ok(())
    }
}
