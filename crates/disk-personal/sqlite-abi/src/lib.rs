//! Private SQLite C ABI boundary. Callbacks own their file handles; a connection
//! owns registration, descriptor provider and all statements until close. No
//! default VFS registration, pathname fallback, WAL, mmap or shared memory.
mod registration;
use libsqlite3_sys as sql;
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io;
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::rc::Rc;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};

pub trait File: Send {
    fn read(&mut self, offset: u64, bytes: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()>;
    fn truncate(&mut self, len: u64) -> io::Result<()>;
    fn sync(&mut self) -> io::Result<()>;
    fn size(&mut self) -> io::Result<u64>;
}
pub trait Vfs: Send + Sync + 'static {
    fn open(
        &self,
        name: &str,
        create: bool,
        exclusive: bool,
        read_only: bool,
    ) -> io::Result<Box<dyn File>>;
    fn exists(&self, name: &str) -> io::Result<bool>;
    fn delete(&self, name: &str, sync_directory: bool) -> io::Result<()>;
}
#[derive(Debug)]
pub struct Error {
    pub code: i32,
    pub io: Option<String>,
}
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Integer(i64),
    Text(String),
    Blob(Vec<u8>),
}
type Result<T> = std::result::Result<T, Error>;
struct Context {
    vfs: Mutex<Option<Arc<dyn Vfs>>>,
    last_io: Mutex<Option<String>>,
    default: *mut sql::sqlite3_vfs,
    main_open: AtomicBool,
}
#[repr(C)]
struct Handle {
    base: sql::sqlite3_file,
    file: *mut Box<dyn File>,
    level: c_int,
    context: *mut Context,
    provider: *mut Arc<dyn Vfs>,
    is_main: bool,
    writable: bool,
}
struct Registration {
    vfs: Box<sql::sqlite3_vfs>,
    context: Box<Context>,
    name: CString,
}
/// Thread-affine NOMUTEX connection; borrowed statements cannot escape methods.
pub struct Connection {
    db: *mut sql::sqlite3,
    registration: Registration,
    _thread: PhantomData<Rc<()>>,
}
static NEXT: AtomicU64 = AtomicU64::new(0);

fn code(e: io::Error, ctx: &Context) -> c_int {
    let busy = e.kind() == io::ErrorKind::WouldBlock;
    *ctx.last_io.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.to_string());
    if busy {
        sql::SQLITE_BUSY
    } else {
        sql::SQLITE_IOERR
    }
}
fn provider(ctx: &Context) -> io::Result<Arc<dyn Vfs>> {
    ctx.vfs
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .ok_or_else(|| io::Error::other("retired VFS"))
}
fn guarded(ctx: &Context, f: impl FnOnce() -> io::Result<c_int>) -> c_int {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => code(e, ctx),
        Err(_) => sql::SQLITE_IOERR,
    }
}
// SAFETY for all callbacks: SQLite calls only while Connection retains the boxed
// registration/context. xOpen initializes Handle before publishing pMethods;
// xClose consumes its unique Box once. NOMUTEX connection is thread-affine.
unsafe fn context<'a>(v: *mut sql::sqlite3_vfs) -> &'a Context {
    &*((*v).pAppData.cast::<Context>())
}
unsafe fn handle<'a>(f: *mut sql::sqlite3_file) -> &'a mut Handle {
    &mut *f.cast::<Handle>()
}
unsafe fn filename<'a>(n: *const c_char) -> io::Result<&'a str> {
    if n.is_null() {
        return Err(io::Error::other("temporary files disabled"));
    }
    CStr::from_ptr(n)
        .to_str()
        .map_err(|_| io::Error::other("invalid filename"))
}
fn valid_name(n: &str) -> bool {
    matches!(n, "inventory.sqlite" | "inventory.sqlite-journal")
}
unsafe extern "C" fn open(
    v: *mut sql::sqlite3_vfs,
    n: *const c_char,
    f: *mut sql::sqlite3_file,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    (*f).pMethods = ptr::null();
    let ctx = context(v);
    guarded(ctx, || {
        let name = filename(n)?;
        if !valid_name(name)
            || flags
                & (sql::SQLITE_OPEN_DELETEONCLOSE | sql::SQLITE_OPEN_MEMORY | sql::SQLITE_OPEN_WAL)
                != 0
            || flags & (sql::SQLITE_OPEN_READWRITE | sql::SQLITE_OPEN_READONLY) == 0
            || (flags & sql::SQLITE_OPEN_READONLY != 0
                && (name == "inventory.sqlite"
                    || flags & (sql::SQLITE_OPEN_CREATE | sql::SQLITE_OPEN_READWRITE) != 0))
        {
            return Err(io::Error::other(format!(
                "unsupported SQLite open name={name} flags={flags}"
            )));
        }
        let provider = provider(ctx)?;
        let is_main = name == "inventory.sqlite";
        if is_main
            && ctx
                .main_open
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        struct Reservation<'a> {
            context: &'a Context,
            active: bool,
        }
        impl Drop for Reservation<'_> {
            fn drop(&mut self) {
                if self.active {
                    self.context.main_open.store(false, Ordering::Release);
                }
            }
        }
        let mut reservation = Reservation {
            context: ctx,
            active: is_main,
        };
        let file = provider.open(
            name,
            flags & sql::SQLITE_OPEN_CREATE != 0,
            flags & sql::SQLITE_OPEN_EXCLUSIVE != 0,
            flags & sql::SQLITE_OPEN_READONLY != 0,
        )?;
        ptr::write(
            f.cast::<Handle>(),
            Handle {
                base: sql::sqlite3_file { pMethods: &METHODS },
                file: Box::into_raw(Box::new(file)),
                level: sql::SQLITE_LOCK_NONE,
                context: (*v).pAppData.cast(),
                provider: Box::into_raw(Box::new(provider)),
                is_main,
                writable: flags & sql::SQLITE_OPEN_READWRITE != 0,
            },
        );
        reservation.active = false;
        if !out.is_null() {
            *out = flags;
        }
        Ok(sql::SQLITE_OK)
    })
}
unsafe extern "C" fn close(f: *mut sql::sqlite3_file) -> c_int {
    let h = handle(f);
    let ctx = &*h.context;
    guarded(ctx, || {
        drop(Box::from_raw(h.file));
        drop(Box::from_raw(h.provider));
        h.provider = ptr::null_mut();
        h.file = ptr::null_mut();
        h.base.pMethods = ptr::null();
        if h.is_main {
            ctx.main_open.store(false, Ordering::Release);
        }
        Ok(sql::SQLITE_OK)
    })
}
unsafe extern "C" fn read(
    f: *mut sql::sqlite3_file,
    p: *mut c_void,
    n: c_int,
    offset: i64,
) -> c_int {
    let h = handle(f);
    let ctx = &*h.context;
    guarded(ctx, || {
        if n < 0 || offset < 0 || n > 16 * 1024 * 1024 {
            return Err(io::Error::other("invalid read range"));
        }
        let bytes = std::slice::from_raw_parts_mut(p.cast::<u8>(), n as usize);
        bytes.fill(0);
        let got = (**h.file).read(offset as u64, bytes)?;
        if got > bytes.len() {
            return Err(io::Error::other("invalid read count"));
        }
        bytes[got..].fill(0);
        Ok(if got == bytes.len() {
            sql::SQLITE_OK
        } else {
            sql::SQLITE_IOERR_SHORT_READ
        })
    })
}
unsafe extern "C" fn write(
    f: *mut sql::sqlite3_file,
    p: *const c_void,
    n: c_int,
    offset: i64,
) -> c_int {
    let h = handle(f);
    let ctx = &*h.context;
    guarded(ctx, || {
        if !h.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only SQLite handle",
            ));
        }
        if n < 0 || offset < 0 || n > 16 * 1024 * 1024 {
            return Err(io::Error::other("invalid write range"));
        }
        (**h.file).write(
            offset as u64,
            std::slice::from_raw_parts(p.cast::<u8>(), n as usize),
        )?;
        Ok(sql::SQLITE_OK)
    })
}
unsafe extern "C" fn truncate(f: *mut sql::sqlite3_file, len: i64) -> c_int {
    let h = handle(f);
    guarded(&*h.context, || {
        if !h.writable {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only SQLite handle",
            ));
        }
        if len < 0 {
            return Err(io::Error::other("negative truncate"));
        }
        (**h.file).truncate(len as u64)?;
        Ok(sql::SQLITE_OK)
    })
}
unsafe extern "C" fn sync(f: *mut sql::sqlite3_file, _flags: c_int) -> c_int {
    let h = handle(f);
    guarded(&*h.context, || {
        (**h.file).sync()?;
        Ok(sql::SQLITE_OK)
    })
}
unsafe extern "C" fn size(f: *mut sql::sqlite3_file, out: *mut i64) -> c_int {
    let h = handle(f);
    guarded(&*h.context, || {
        *out = i64::try_from((**h.file).size()?).map_err(|_| io::Error::other("file too large"))?;
        Ok(sql::SQLITE_OK)
    })
}
// External writer.lock is already held EXCLUSIVE for the whole connection by
// the descriptor provider. SQLite lock transitions are tracked locally; locks
// never release the external lease on SHARED/NONE or during rollback recovery.
unsafe extern "C" fn lock(f: *mut sql::sqlite3_file, level: c_int) -> c_int {
    let h = handle(f);
    if !(sql::SQLITE_LOCK_SHARED..=sql::SQLITE_LOCK_EXCLUSIVE).contains(&level) {
        return sql::SQLITE_MISUSE;
    }
    h.level = h.level.max(level);
    sql::SQLITE_OK
}
unsafe extern "C" fn unlock(f: *mut sql::sqlite3_file, level: c_int) -> c_int {
    if ![sql::SQLITE_LOCK_NONE, sql::SQLITE_LOCK_SHARED].contains(&level) {
        return sql::SQLITE_MISUSE;
    }
    let h = handle(f);
    h.level = h.level.min(level);
    sql::SQLITE_OK
}
unsafe extern "C" fn reserved(f: *mut sql::sqlite3_file, out: *mut c_int) -> c_int {
    *out = c_int::from(handle(f).level >= sql::SQLITE_LOCK_RESERVED);
    sql::SQLITE_OK
}
unsafe extern "C" fn control(_: *mut sql::sqlite3_file, _: c_int, _: *mut c_void) -> c_int {
    sql::SQLITE_NOTFOUND
}
unsafe extern "C" fn sector(_: *mut sql::sqlite3_file) -> c_int {
    4096
}
unsafe extern "C" fn device(_: *mut sql::sqlite3_file) -> c_int {
    0
}
static METHODS: sql::sqlite3_io_methods = sql::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: Some(write),
    xTruncate: Some(truncate),
    xSync: Some(sync),
    xFileSize: Some(size),
    xLock: Some(lock),
    xUnlock: Some(unlock),
    xCheckReservedLock: Some(reserved),
    xFileControl: Some(control),
    xSectorSize: Some(sector),
    xDeviceCharacteristics: Some(device),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};
unsafe extern "C" fn delete(v: *mut sql::sqlite3_vfs, n: *const c_char, s: c_int) -> c_int {
    let ctx = context(v);
    guarded(ctx, || {
        let n = filename(n)?;
        if n != "inventory.sqlite-journal" {
            return Err(io::Error::other("delete denied"));
        }
        provider(ctx)?.delete(n, s != 0)?;
        Ok(sql::SQLITE_OK)
    })
}
unsafe extern "C" fn access(
    v: *mut sql::sqlite3_vfs,
    n: *const c_char,
    flags: c_int,
    out: *mut c_int,
) -> c_int {
    let ctx = context(v);
    guarded(ctx, || {
        let n = filename(n)?;
        if !(valid_name(n) || matches!(n, "inventory.sqlite-wal" | "inventory.sqlite-shm"))
            || ![
                sql::SQLITE_ACCESS_EXISTS,
                sql::SQLITE_ACCESS_READ,
                sql::SQLITE_ACCESS_READWRITE,
            ]
            .contains(&flags)
        {
            return Err(io::Error::other(format!(
                "access denied name={n} flags={flags}"
            )));
        }
        let exists = provider(ctx)?.exists(n)?;
        if exists && !valid_name(n) {
            return Err(io::Error::other(
                "existing WAL/shared memory requires unsupported recovery",
            ));
        }
        *out = c_int::from(exists);
        Ok(sql::SQLITE_OK)
    })
}
unsafe extern "C" fn fullpath(
    v: *mut sql::sqlite3_vfs,
    n: *const c_char,
    len: c_int,
    out: *mut c_char,
) -> c_int {
    let ctx = context(v);
    guarded(ctx, || {
        let n = filename(n)?;
        if !valid_name(n) || len <= n.len() as c_int {
            return Err(io::Error::other("path denied"));
        }
        ptr::copy_nonoverlapping(n.as_ptr(), out.cast::<u8>(), n.len());
        *out.add(n.len()) = 0;
        Ok(sql::SQLITE_OK)
    })
}
unsafe extern "C" fn random(v: *mut sql::sqlite3_vfs, n: c_int, out: *mut c_char) -> c_int {
    let d = context(v).default;
    (*d).xRandomness.map_or(0, |f| f(d, n, out))
}
unsafe extern "C" fn sleep(_: *mut sql::sqlite3_vfs, n: c_int) -> c_int {
    let n = n.clamp(0, 1_000_000);
    std::thread::sleep(std::time::Duration::from_micros(n as u64));
    n
}
unsafe extern "C" fn time(v: *mut sql::sqlite3_vfs, out: *mut f64) -> c_int {
    let d = context(v).default;
    (*d).xCurrentTime.map_or(sql::SQLITE_IOERR, |f| f(d, out))
}
impl Connection {
    pub fn open(provider: impl Vfs, create: bool) -> Result<Self> {
        // SAFETY: initialized SQLite owns its default VFS; all callback pointers
        // and boxed data below remain stable until unregister after db close.
        unsafe {
            let registration_id = registration::reserve(&NEXT).ok_or_else(|| Error {
                code: sql::SQLITE_FULL,
                io: Some("VFS registration capacity".into()),
            })?;
            let rc = sql::sqlite3_initialize();
            if rc != sql::SQLITE_OK {
                return Err(Error { code: rc, io: None });
            }
            let default = sql::sqlite3_vfs_find(ptr::null());
            if default.is_null() {
                return Err(Error {
                    code: sql::SQLITE_CANTOPEN,
                    io: None,
                });
            }
            let name = CString::new(format!(
                "disk-personal-fd-{}-{}",
                std::process::id(),
                registration_id
            ))
            .unwrap();
            let mut context = Box::new(Context {
                vfs: Mutex::new(Some(Arc::new(provider))),
                last_io: Mutex::new(None),
                default,
                main_open: AtomicBool::new(false),
            });
            let mut vfs: Box<sql::sqlite3_vfs> = Box::new(std::mem::zeroed());
            vfs.iVersion = 1;
            vfs.szOsFile = std::mem::size_of::<Handle>() as c_int;
            vfs.mxPathname = 64;
            vfs.zName = name.as_ptr();
            vfs.pAppData = (&mut *context as *mut Context).cast();
            vfs.xOpen = Some(open);
            vfs.xDelete = Some(delete);
            vfs.xAccess = Some(access);
            vfs.xFullPathname = Some(fullpath);
            vfs.xRandomness = Some(random);
            vfs.xSleep = Some(sleep);
            vfs.xCurrentTime = Some(time);
            let rc = sql::sqlite3_vfs_register(&mut *vfs, 0);
            if rc != sql::SQLITE_OK {
                return Err(Error { code: rc, io: None });
            }
            let registration = Registration { vfs, context, name };
            let mut db = ptr::null_mut();
            let flags = sql::SQLITE_OPEN_READWRITE
                | sql::SQLITE_OPEN_NOMUTEX
                | if create { sql::SQLITE_OPEN_CREATE } else { 0 };
            let rc = sql::sqlite3_open_v2(
                c"inventory.sqlite".as_ptr(),
                &mut db,
                flags,
                registration.name.as_ptr(),
            );
            if rc != sql::SQLITE_OK {
                let error = Error {
                    code: rc,
                    io: registration
                        .context
                        .last_io
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .take(),
                };
                if !db.is_null() {
                    sql::sqlite3_close(db);
                }
                drop(registration);
                return Err(error);
            }
            let mut connection = Self {
                db,
                registration,
                _thread: PhantomData,
            };
            connection.batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY; PRAGMA locking_mode=EXCLUSIVE; PRAGMA mmap_size=0; PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA max_page_count=4096;")?;
            Ok(connection)
        }
    }
    fn error(&self, code: i32) -> Error {
        Error {
            code,
            io: self
                .registration
                .context
                .last_io
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take(),
        }
    }
    /// Trusted source SQL only; parameters belong in query(), never interpolation.
    pub fn batch(&mut self, text: &str) -> Result<()> {
        let text = CString::new(text).map_err(|_| self.error(sql::SQLITE_MISUSE))?;
        // SAFETY: live db, nul terminated SQL; no user callback/error allocation.
        let rc = unsafe {
            sql::sqlite3_exec(
                self.db,
                text.as_ptr(),
                None,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc != sql::SQLITE_OK {
            Err(self.error(rc))
        } else {
            Ok(())
        }
    }
    pub fn query(&mut self, text: &str, params: &[Value]) -> Result<Vec<Vec<Value>>> {
        let text = CString::new(text).map_err(|_| self.error(sql::SQLITE_MISUSE))?;
        // SAFETY: statement finalized by guard on every exit, bound values copied
        // SQLITE_TRANSIENT, result bytes copied before the next step/finalize.
        unsafe {
            let mut stmt = ptr::null_mut();
            let mut tail = ptr::null();
            let rc = sql::sqlite3_prepare_v2(self.db, text.as_ptr(), -1, &mut stmt, &mut tail);
            struct Statement(*mut sql::sqlite3_stmt);
            impl Drop for Statement {
                fn drop(&mut self) {
                    unsafe {
                        sql::sqlite3_finalize(self.0);
                    }
                }
            }
            let _statement = Statement(stmt);
            if rc != sql::SQLITE_OK {
                return Err(self.error(rc));
            }
            if stmt.is_null()
                || !CStr::from_ptr(tail)
                    .to_bytes()
                    .iter()
                    .all(u8::is_ascii_whitespace)
                || sql::sqlite3_bind_parameter_count(stmt) != params.len() as c_int
            {
                return Err(self.error(sql::SQLITE_MISUSE));
            }
            for (i, p) in params.iter().enumerate() {
                let i = (i + 1) as c_int;
                let rc = match p {
                    Value::Null => sql::sqlite3_bind_null(stmt, i),
                    Value::Integer(n) => sql::sqlite3_bind_int64(stmt, i, *n),
                    Value::Text(s) => {
                        if s.len() > 16 * 1024 * 1024 {
                            return Err(self.error(sql::SQLITE_TOOBIG));
                        }
                        sql::sqlite3_bind_text(
                            stmt,
                            i,
                            s.as_ptr().cast(),
                            s.len() as c_int,
                            sql::SQLITE_TRANSIENT(),
                        )
                    }
                    Value::Blob(b) => {
                        if b.len() > 16 * 1024 * 1024 {
                            return Err(self.error(sql::SQLITE_TOOBIG));
                        }
                        sql::sqlite3_bind_blob(
                            stmt,
                            i,
                            b.as_ptr().cast(),
                            b.len() as c_int,
                            sql::SQLITE_TRANSIENT(),
                        )
                    }
                };
                if rc != sql::SQLITE_OK {
                    return Err(self.error(rc));
                }
            }
            let mut rows = Vec::new();
            let mut total = 0usize;
            loop {
                let rc = sql::sqlite3_step(stmt);
                if rc == sql::SQLITE_DONE {
                    return Ok(rows);
                }
                if rc != sql::SQLITE_ROW {
                    return Err(self.error(rc));
                }
                if rows.len() >= 1024 {
                    return Err(self.error(sql::SQLITE_TOOBIG));
                }
                let columns = sql::sqlite3_column_count(stmt);
                if columns > 32 {
                    return Err(self.error(sql::SQLITE_TOOBIG));
                }
                let mut row = Vec::new();
                for i in 0..columns {
                    let value = match sql::sqlite3_column_type(stmt, i) {
                        sql::SQLITE_NULL => Value::Null,
                        sql::SQLITE_INTEGER => Value::Integer(sql::sqlite3_column_int64(stmt, i)),
                        kind @ (sql::SQLITE_TEXT | sql::SQLITE_BLOB) => {
                            let n = sql::sqlite3_column_bytes(stmt, i) as usize;
                            total = total
                                .checked_add(n)
                                .ok_or_else(|| self.error(sql::SQLITE_TOOBIG))?;
                            if total > 16 * 1024 * 1024 {
                                return Err(self.error(sql::SQLITE_TOOBIG));
                            }
                            let p = if kind == sql::SQLITE_TEXT {
                                sql::sqlite3_column_text(stmt, i).cast::<u8>()
                            } else {
                                sql::sqlite3_column_blob(stmt, i).cast::<u8>()
                            };
                            let bytes = if n == 0 {
                                Vec::new()
                            } else {
                                if p.is_null() {
                                    return Err(self.error(sql::SQLITE_NOMEM));
                                }
                                std::slice::from_raw_parts(p, n).to_vec()
                            };
                            if kind == sql::SQLITE_TEXT {
                                Value::Text(
                                    String::from_utf8(bytes)
                                        .map_err(|_| self.error(sql::SQLITE_CORRUPT))?,
                                )
                            } else {
                                Value::Blob(bytes)
                            }
                        }
                        _ => return Err(self.error(sql::SQLITE_MISMATCH)),
                    };
                    row.push(value);
                }
                rows.push(row);
            }
        }
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        unsafe {
            sql::sqlite3_close(self.db);
        }
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        unsafe {
            sql::sqlite3_vfs_unregister(&mut *self.vfs);
        }
        // SQLite exposes process-global VFS pointers. Another in-process SQLite
        // consumer may retain one even after unregister. Retire small callback
        // metadata permanently; release provider/FDs when the last opened file
        // closes. New operations through a retired pointer safely refuse. This
        // is bounded to128 registrations, not unbounded leaked mount ownership.
        self.context
            .vfs
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        let vfs = std::mem::replace(&mut self.vfs, Box::new(unsafe { std::mem::zeroed() }));
        let context = std::mem::replace(
            &mut self.context,
            Box::new(Context {
                vfs: Mutex::new(None),
                last_io: Mutex::new(None),
                default: ptr::null_mut(),
                main_open: AtomicBool::new(false),
            }),
        );
        let name = std::mem::replace(&mut self.name, CString::new("").unwrap());
        Box::leak(vfs);
        Box::leak(context);
        let _ = name.into_raw();
    }
}

#[cfg(test)]
extern crate self as disk_personal_sqlite;
#[cfg(test)]
mod test_vfs;
#[cfg(test)]
mod tests {
    use super::*;
    use test_vfs::MemoryVfs;
    #[test]
    fn actual_engine_commit_rollback_reopen_and_bound_parameters() {
        let vfs = MemoryVfs::default();
        let mut db = Connection::open(vfs.clone(), true).unwrap();
        db.batch("CREATE TABLE records(k TEXT PRIMARY KEY,v BLOB) STRICT;")
            .unwrap();
        db.query("BEGIN IMMEDIATE", &[]).unwrap();
        db.query(
            "INSERT INTO records VALUES(?1,?2)",
            &[
                Value::Text("literal'; --".into()),
                Value::Blob(vec![0, 1, 2]),
            ],
        )
        .unwrap();
        db.query("ROLLBACK", &[]).unwrap();
        assert!(db.query("SELECT * FROM records", &[]).unwrap().is_empty());
        db.query(
            "INSERT INTO records VALUES(?1,?2)",
            &[Value::Text("original".into()), Value::Blob(vec![0, 1, 2])],
        )
        .unwrap();
        drop(db);
        let mut db = Connection::open(vfs, false).unwrap();
        assert_eq!(
            db.query(
                "SELECT v FROM records WHERE k=?1",
                &[Value::Text("original".into())]
            )
            .unwrap(),
            vec![vec![Value::Blob(vec![0, 1, 2])]]
        );
        assert!(db.query("SELECT 1; SELECT 2", &[]).is_err());
    }
    #[test]
    fn sync_error_and_unknown_namespace_never_succeed() {
        let vfs = MemoryVfs::default();
        let mut db = Connection::open(vfs.clone(), true).unwrap();
        db.batch("CREATE TABLE records(k TEXT);").unwrap();
        vfs.fail_next_sync();
        let e = db
            .query(
                "INSERT INTO records VALUES(?1)",
                &[Value::Text("no-proof".into())],
            )
            .unwrap_err();
        assert_ne!(e.code, sql::SQLITE_OK);
        assert!(e.io.is_some());
        assert!(db
            .batch("ATTACH DATABASE '../foreign.sqlite' AS foreign_db;")
            .is_err());
    }
    #[test]
    fn abi_short_read_zero_fill_and_lock_levels() {
        let mut provider = Box::new(Context {
            vfs: Mutex::new(Some(Arc::new(MemoryVfs::default()))),
            last_io: Mutex::new(None),
            default: ptr::null_mut(),
            main_open: AtomicBool::new(false),
        });
        let memory = provider.vfs.lock().unwrap().as_ref().unwrap().clone();
        let mut file = memory.open("inventory.sqlite", true, true, false).unwrap();
        file.write(0, b"abc").unwrap();
        let mut h = Handle {
            base: sql::sqlite3_file { pMethods: &METHODS },
            file: Box::into_raw(Box::new(file)),
            level: sql::SQLITE_LOCK_NONE,
            context: &mut *provider,
            provider: Box::into_raw(Box::new(memory)),
            is_main: false,
            writable: true,
        };
        let f = (&mut h as *mut Handle).cast::<sql::sqlite3_file>();
        let mut b = [9u8; 5];
        let mut reserved_lock = 0;
        unsafe {
            assert_eq!(
                read(f, b.as_mut_ptr().cast(), 5, 0),
                sql::SQLITE_IOERR_SHORT_READ
            );
            assert_eq!(b, [97, 98, 99, 0, 0]);
            assert_eq!(lock(f, sql::SQLITE_LOCK_EXCLUSIVE), sql::SQLITE_OK);
            assert_eq!(reserved(f, &mut reserved_lock), sql::SQLITE_OK);
            assert_eq!(reserved_lock, 1);
            assert_eq!(unlock(f, sql::SQLITE_LOCK_NONE), sql::SQLITE_OK);
            assert_eq!(reserved(f, &mut reserved_lock), sql::SQLITE_OK);
            assert_eq!(reserved_lock, 0);
            assert_eq!(close(f), sql::SQLITE_OK);
        }
    }
    #[test]
    fn single_main_connection_and_retired_registration_refuse_safely() {
        let db = Connection::open(MemoryVfs::default(), true).unwrap();
        let vfs = (&*db.registration.vfs) as *const sql::sqlite3_vfs as *mut sql::sqlite3_vfs;
        let name = db.registration.name.clone();
        let mut other = ptr::null_mut();
        unsafe {
            let rc = sql::sqlite3_open_v2(
                c"inventory.sqlite".as_ptr(),
                &mut other,
                sql::SQLITE_OPEN_READWRITE,
                name.as_ptr(),
            );
            assert_ne!(rc, sql::SQLITE_OK);
            sql::sqlite3_close(other);
        }
        drop(db);
        let mut exists = 1;
        unsafe {
            assert_ne!(
                access(
                    vfs,
                    c"inventory.sqlite".as_ptr(),
                    sql::SQLITE_ACCESS_EXISTS,
                    &mut exists
                ),
                sql::SQLITE_OK
            );
        }
    }
}
