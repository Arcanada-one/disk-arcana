//! Concrete native SQLite backend: immutable bytes, inventory disposition and
//! original owner journal commit together. Auth remains a separate reconciliation
//! step under Parent's live fence. Supplied handles never admit themselves.
use crate::parent_adapter::{Observation, Refusal, Result};
use crate::parent_authority::Effect;
use crate::parent_journal::DirectoryIdentity;
use crate::parent_native::{
    CancelledResource, Id, NativeBackend, ObjectKey, OriginalEffect, Outcome, Request,
};
use crate::parent_sqlite::DescriptorVfs;
use disk_personal_sqlite::{Connection, Value};
use std::cell::{Cell, RefCell};
use std::fs::File;

const CAPTURES: &str =
    "CREATE TABLE captures (id TEXT PRIMARY KEY, descriptor TEXT NOT NULL, cancelled TEXT) STRICT";
const ATTEMPTS:&str="CREATE TABLE attempts (resource TEXT PRIMARY KEY, lease TEXT NOT NULL UNIQUE, proposal TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('prepared','committed'))) STRICT";
const OBJECTS:&str="CREATE TABLE objects (resource TEXT PRIMARY KEY, capture TEXT NOT NULL REFERENCES captures(id), receipt TEXT NOT NULL, body BLOB, outcome TEXT NOT NULL) STRICT";
const JOURNAL:&str="CREATE TABLE owner_journal (owner_receipt TEXT PRIMARY KEY, lease TEXT NOT NULL UNIQUE, sequence TEXT NOT NULL UNIQUE, resource TEXT NOT NULL, outcome TEXT NOT NULL) STRICT";
const SCHEMA: [(&str, &str); 4] = [
    ("attempts", ATTEMPTS),
    ("captures", CAPTURES),
    ("objects", OBJECTS),
    ("owner_journal", JOURNAL),
];
/// Internal authenticated lookup disposition supplied by real Control. It is not
/// a wire grant, a caller request field, or a default permission. Unknown refuses
/// fresh staging; only Control's fenced original no-commit lookup selects New.
pub enum OriginalDisposition {
    FencedNoCommit,
    ExistingOrUnknown,
}
/// Trusted server composition only. Parsing/constructing this does not authenticate
/// it. Real Control must derive it under the same live effect/revocation fence.
pub struct NativeCommitContext {
    lease: Id,
    proposal: Outcome,
    original: OriginalEffect,
    resource: String,
    descriptor: String,
    disposition: OriginalDisposition,
}
impl NativeCommitContext {
    pub fn from_control_readback(
        lease: Id,
        proposal: Outcome,
        original: OriginalEffect,
        request: &Request,
        disposition: OriginalDisposition,
    ) -> Result<Self> {
        if !proposal.matches_original_effect(&original) {
            return Err(Refusal::Conflict);
        }
        Ok(Self {
            lease,
            proposal,
            original,
            resource: request.resource_identity(),
            descriptor: request.descriptor_identity(),
            disposition,
        })
    }
    fn matches(&self, r: &Request) -> Result<()> {
        if self.resource != r.resource_identity()
            || self.descriptor != r.descriptor_identity()
            || !self.proposal.matches_original_effect(&self.original)
        {
            Err(Refusal::NotAvailable)
        } else {
            Ok(())
        }
    }
}
pub struct SqliteBackend {
    db: RefCell<Connection>,
    uncertain: Cell<bool>,
    last_error: RefCell<Option<String>>,
}
fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}
fn string(v: &Value) -> Result<&str> {
    if let Value::Text(s) = v {
        Ok(s)
    } else {
        Err(Refusal::Unavailable)
    }
}
impl SqliteBackend {
    /// Caller has already admitted startup and supplied the exact directory FD.
    /// `create` initializes ONLY a blank dedicated database; existing schema is
    /// checked exactly, never silently migrated or read via default SQLite VFS.
    pub fn from_admitted_handle(
        dir: File,
        identity: DirectoryIdentity,
        create: bool,
    ) -> std::result::Result<Self, String> {
        let provider =
            DescriptorVfs::from_admitted_handle(dir, identity).map_err(|e| e.to_string())?;
        let db = Connection::open(provider, create)
            .map_err(|e| format!("SQLite {} {:?}", e.code, e.io))?;
        Self::initialize(db, create)
    }
    fn initialize(mut db: Connection, create: bool) -> std::result::Result<Self, String> {
        let definitions=db.query("SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",&[]).map_err(|e|format!("SQLite {} {:?}",e.code,e.io))?;
        if definitions.is_empty() && create {
            db.batch(&format!("BEGIN IMMEDIATE; {CAPTURES}; {ATTEMPTS}; {OBJECTS}; {JOURNAL}; PRAGMA user_version=1; COMMIT;")).map_err(|e|format!("SQLite {} {:?}",e.code,e.io))?;
        }
        let definitions = db
            .query(
                "SELECT name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name",
                &[],
            )
            .map_err(|e| format!("SQLite {} {:?}", e.code, e.io))?;
        if definitions.len() != SCHEMA.len()
            || definitions
                .iter()
                .zip(SCHEMA)
                .any(|(row, (name, definition))| row != &[text(name), text(definition)])
        {
            return Err("native inventory schema mismatch".into());
        }
        if db
            .query("PRAGMA user_version", &[])
            .map_err(|e| format!("SQLite {}", e.code))?
            != vec![vec![Value::Integer(1)]]
        {
            return Err("native inventory version mismatch".into());
        }
        db.batch("PRAGMA secure_delete=ON;")
            .map_err(|e| format!("SQLite {} {:?}", e.code, e.io))?;
        Ok(Self {
            db: RefCell::new(db),
            uncertain: Cell::new(false),
            last_error: RefCell::new(None),
        })
    }
    /// Content-free IO diagnostic: never includes SQL rows/private bytes.
    pub fn last_io_error(&self) -> Option<String> {
        self.last_error.borrow().clone()
    }
    fn ready(&self) -> Result<()> {
        if self.uncertain.get() {
            Err(Refusal::Pending)
        } else {
            Ok(())
        }
    }
    fn query(&self, sql: &str, params: &[Value]) -> Result<Vec<Vec<Value>>> {
        self.ready()?;
        self.db.borrow_mut().query(sql, params).map_err(|e| {
            self.uncertain.set(true);
            *self.last_error.borrow_mut() = Some(format!("SQLite {} {:?}", e.code, e.io));
            Refusal::Unavailable
        })
    }
    fn transaction<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        self.ready()?;
        self.query("BEGIN IMMEDIATE", &[])?;
        struct ActiveTransaction<'a> {
            backend: &'a SqliteBackend,
            active: bool,
        }
        impl Drop for ActiveTransaction<'_> {
            fn drop(&mut self) {
                if self.active {
                    self.backend.uncertain.set(true);
                    if let Ok(mut db) = self.backend.db.try_borrow_mut() {
                        let _ = db.query("ROLLBACK", &[]);
                    }
                }
            }
        }
        let mut transaction = ActiveTransaction {
            backend: self,
            active: true,
        };
        match action() {
            Ok(value) => {
                if self.query("COMMIT", &[]).is_err() {
                    self.uncertain.set(true);
                    return Err(Refusal::Pending);
                }
                transaction.active = false;
                Ok(value)
            }
            Err(e) => {
                // Attempt rollback even after IO error, but never clear poison or
                // reinterpret rollback success as proof that a failed commit did not happen.
                if let Err(error) = self.db.borrow_mut().query("ROLLBACK", &[]) {
                    self.uncertain.set(true);
                    *self.last_error.borrow_mut() =
                        Some(format!("SQLite {} {:?}", error.code, error.io));
                }
                transaction.active = false;
                Err(e)
            }
        }
    }
    fn capture(&self, r: &Request) -> Result<Option<Value>> {
        let rows = self.query(
            "SELECT descriptor,cancelled FROM captures WHERE id=?1",
            &[text(r.capture_id())],
        )?;
        if rows.is_empty() {
            return Ok(None);
        }
        if rows.len() != 1 || rows[0].len() != 2 || string(&rows[0][0])? != r.descriptor_identity()
        {
            return Err(Refusal::Conflict);
        }
        Ok(Some(rows[0][1].clone()))
    }
    fn observe_context(
        &self,
        e: &NativeCommitContext,
        r: &Request,
    ) -> Result<Observation<(), Outcome>> {
        e.matches(r)?;
        self.ready()?;
        if let Some(cancelled) = self.capture(r)? {
            if cancelled != Value::Null {
                let rows = self.query(
                    "SELECT outcome FROM owner_journal WHERE resource=?1",
                    &[text(r.resource_identity())],
                )?;
                for row in rows {
                    let outcome = Outcome::parse(string(&row[0])?.as_bytes())?;
                    if matches!(outcome, Outcome::Cleaned(_)) {
                        return Ok(Observation::CancelledCleaned { outcome });
                    }
                }
                return Ok(Observation::CleanupPending);
            }
        }
        let attempts = self.query(
            "SELECT state FROM attempts WHERE resource=?1",
            &[text(r.resource_identity())],
        )?;
        if !attempts.is_empty() && attempts[0][0] != text("committed") {
            return Ok(Observation::Prepared);
        }
        let rows = self.query(
            "SELECT outcome FROM objects WHERE resource=?1",
            &[text(r.resource_identity())],
        )?;
        if rows.len() == 1 {
            if attempts.len() != 1 {
                return Ok(Observation::Corrupt);
            }
            let outcome = Outcome::parse(string(&rows[0][0])?.as_bytes())?;
            outcome.receipt(r)?;
            let journal = self.query(
                "SELECT outcome,owner_receipt,sequence FROM owner_journal WHERE resource=?1",
                &[text(r.resource_identity())],
            )?;
            let proposal = self.query(
                "SELECT proposal FROM attempts WHERE resource=?1",
                &[text(r.resource_identity())],
            )?;
            if journal
                != vec![vec![
                    rows[0][0].clone(),
                    text(outcome.owner_receipt_id()),
                    text(outcome.local_sequence().to_string()),
                ]]
                || proposal != vec![vec![rows[0][0].clone()]]
            {
                return Ok(Observation::Corrupt);
            }
            return Ok(Observation::Durable {
                receipt: (),
                outcome,
            });
        }
        if !rows.is_empty() || !attempts.is_empty() {
            return Ok(Observation::Corrupt);
        }
        Ok(match e.disposition {
            OriginalDisposition::FencedNoCommit => Observation::Unseen,
            OriginalDisposition::ExistingOrUnknown => Observation::Unknown,
        })
    }
    fn journal(&self, e: &NativeCommitContext, r: &Request) -> Result<()> {
        let total = self.query("SELECT count(*) FROM owner_journal", &[])?;
        if total != vec![vec![Value::Integer(0)]]
            && total
                .first()
                .and_then(|r| r.first())
                .is_none_or(|v| !matches!(v,Value::Integer(n) if *n<128))
        {
            return Err(Refusal::Backpressure);
        }
        let json =
            String::from_utf8(e.proposal.registration_json()?).map_err(|_| Refusal::Unavailable)?;
        self.query("INSERT INTO owner_journal(owner_receipt,lease,sequence,resource,outcome) VALUES(?1,?2,?3,?4,?5)",&[text(e.proposal.owner_receipt_id()),text(e.lease.as_str()),text(e.proposal.local_sequence().to_string()),text(r.resource_identity()),text(json)])?;
        Ok(())
    }
    fn stage_context(
        &self,
        e: &NativeCommitContext,
        r: &Request,
        bytes: &[u8],
    ) -> Result<Option<Outcome>> {
        e.matches(r)?;
        r.verify_body(bytes)?;
        e.proposal.receipt(r)?;
        if !e
            .proposal
            .matches_operation(crate::parent_adapter::Operation::Stage)
        {
            return Err(Refusal::Conflict);
        }
        match self.observe_context(e, r)? {
            Observation::Durable { outcome, .. } => {
                self.read_context(e, r, r.selected_size()?)?;
                return Ok(Some(outcome));
            }
            Observation::Unseen => (),
            Observation::Prepared | Observation::Unknown => return Err(Refusal::Pending),
            _ => return Err(Refusal::Conflict),
        }
        // Durable PREPARED establishes attempted work before bytes are committed.
        // Crash/reopen at this boundary cannot infer freshness or replay writes.
        let proposal =
            String::from_utf8(e.proposal.registration_json()?).map_err(|_| Refusal::Unavailable)?;
        self.transaction(|| {
            self.query("INSERT INTO captures(id,descriptor,cancelled) VALUES(?1,?2,NULL) ON CONFLICT(id) DO NOTHING",&[text(r.capture_id()),text(r.descriptor_identity())])?;
            if self.capture(r)?!=Some(Value::Null){return Err(Refusal::Conflict);}
            self.query("INSERT INTO attempts(resource,lease,proposal,state) VALUES(?1,?2,?3,'prepared')",&[text(r.resource_identity()),text(e.lease.as_str()),text(&proposal)])?;Ok(())
        })?;
        let receipt = r.selected_receipt_json()?;
        let result=self.transaction(|| {
            if self.capture(r)?!=Some(Value::Null){return Err(Refusal::Conflict);}
            self.query("INSERT INTO objects(resource,capture,receipt,body,outcome) VALUES(?1,?2,?3,?4,?5)",&[text(r.resource_identity()),text(r.capture_id()),text(receipt),Value::Blob(bytes.to_vec()),text(proposal)])?;
            self.journal(e,r)?;
            self.query("UPDATE attempts SET state='committed' WHERE resource=?1 AND lease=?2 AND state='prepared'",&[text(r.resource_identity()),text(e.lease.as_str())])?;Ok(())
        });
        match result {
            Ok(()) => Ok(Some(e.proposal.clone())),
            Err(Refusal::Pending | Refusal::Unavailable) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn read_context(&self, e: &NativeCommitContext, r: &Request, max: usize) -> Result<Vec<u8>> {
        e.matches(r)?;
        if !matches!(self.observe_context(e, r)?, Observation::Durable { .. }) {
            return Err(Refusal::NotAvailable);
        }
        let expected = r.selected_size()?;
        if max != expected {
            return Err(Refusal::NotAvailable);
        }
        if self.capture(r)? != Some(Value::Null) {
            return Err(Refusal::NotAvailable);
        }
        let rows=self.query("SELECT o.receipt,o.body,o.outcome,a.state FROM objects o JOIN attempts a ON a.resource=o.resource WHERE o.resource=?1 AND length(o.body)=?2",&[text(r.resource_identity()),Value::Integer(max as i64)])?;
        if rows.len() != 1
            || rows[0].len() != 4
            || rows[0][0] != text(r.selected_receipt_json()?)
            || rows[0][3] != text("committed")
        {
            return Err(Refusal::NotAvailable);
        }
        let outcome = Outcome::parse(string(&rows[0][2])?.as_bytes())?;
        outcome.receipt(r)?;
        let bytes = match &rows[0][1] {
            Value::Blob(b) if b.len() == expected => b.clone(),
            _ => return Err(Refusal::NotAvailable),
        };
        r.verify_body(&bytes)?;
        Ok(bytes)
    }
    fn tombstone_context(
        &self,
        e: &NativeCommitContext,
        r: &Request,
        objects: &[ObjectKey],
        c: &CancelledResource,
    ) -> Result<()> {
        e.matches(r)?;
        if c.objects(r)? != objects {
            return Err(Refusal::NotAvailable);
        }
        c.verify_cleaned(r, &e.proposal)?;
        let cancelled = serde_json::to_string(c).map_err(|_| Refusal::Unavailable)?;
        self.transaction(|| {
            let pending=self.query("SELECT count(*) FROM attempts WHERE state='prepared' AND resource IN (SELECT resource FROM objects WHERE capture=?1)",&[text(r.capture_id())])?;
            if pending!=vec![vec![Value::Integer(0)]]{return Err(Refusal::Pending);}
            // Prepared attempts may have no object row: full descriptor resource
            // keys below prevent cleanup from overlooking that crash boundary.
            for key in r.part_resource_identities(){
                let rows=self.query("SELECT state FROM attempts WHERE resource=?1",&[text(key)])?;
                if rows.iter().any(|r|r[0]!=text("committed")){return Err(Refusal::Pending);}
            }
            self.query("INSERT INTO captures(id,descriptor,cancelled) VALUES(?1,?2,?3) ON CONFLICT(id) DO NOTHING",&[text(r.capture_id()),text(r.descriptor_identity()),text(&cancelled)])?;
            match self.capture(r)? {Some(Value::Null)=>{self.query("UPDATE captures SET cancelled=?1 WHERE id=?2 AND cancelled IS NULL",&[text(&cancelled),text(r.capture_id())])?;},Some(value) if value==text(&cancelled)=>(),_=>return Err(Refusal::Conflict)}Ok(())
        })
    }
    fn cleanup_context(
        &self,
        e: &NativeCommitContext,
        r: &Request,
        objects: &[ObjectKey],
        c: &CancelledResource,
    ) -> Result<Option<Outcome>> {
        e.matches(r)?;
        if c.objects(r)? != objects {
            return Err(Refusal::NotAvailable);
        }
        c.verify_cleaned(r, &e.proposal)?;
        let cancelled = serde_json::to_string(c).map_err(|_| Refusal::Unavailable)?;
        if self.capture(r)? != Some(text(cancelled)) {
            return Err(Refusal::NotAvailable);
        }
        let existing = self.query(
            "SELECT outcome FROM owner_journal WHERE resource=?1",
            &[text(r.resource_identity())],
        )?;
        if existing.len() > 1 {
            return Err(Refusal::Unavailable);
        }
        if existing.len() == 1 {
            let outcome = Outcome::parse(string(&existing[0][0])?.as_bytes())?;
            c.verify_cleaned(r, &outcome)?;
            if !outcome.matches_original_effect(&e.original) {
                return Err(Refusal::Conflict);
            }
            return Ok(Some(outcome));
        }
        let result = self.transaction(|| {
            // Keys derive solely from the complete authenticated cancellation
            // descriptor, never from a path/prefix supplied by an HTTP caller.
            for resource in r.part_resource_identities() {
                self.query(
                    "UPDATE objects SET body=NULL WHERE resource=?1 AND capture=?2",
                    &[text(resource), text(r.capture_id())],
                )?;
            }
            let left = self.query(
                "SELECT count(*) FROM objects WHERE capture=?1 AND body IS NOT NULL",
                &[text(r.capture_id())],
            )?;
            if left != vec![vec![Value::Integer(0)]] {
                return Err(Refusal::Conflict);
            }
            self.journal(e, r)?;
            Ok(())
        });
        match result {
            Ok(()) => Ok(Some(e.proposal.clone())),
            Err(Refusal::Pending | Refusal::Unavailable) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
impl NativeBackend<Effect<NativeCommitContext>> for SqliteBackend {
    fn observe(
        &self,
        e: &Effect<NativeCommitContext>,
        r: &Request,
    ) -> Result<Observation<(), Outcome>> {
        self.observe_context(e.native_lease(), r)
    }
    fn stage(
        &self,
        e: &Effect<NativeCommitContext>,
        r: &Request,
        b: &[u8],
    ) -> Result<Option<Outcome>> {
        {
            e.require_backend_operation(r, crate::parent_adapter::Operation::Stage)?;
            self.stage_context(e.native_lease(), r, b)
        }
    }
    fn read_exact(
        &self,
        e: &Effect<NativeCommitContext>,
        r: &Request,
        max: usize,
    ) -> Result<Vec<u8>> {
        self.read_context(e.native_lease(), r, max)
    }
    fn tombstone_exact(
        &self,
        e: &Effect<NativeCommitContext>,
        r: &Request,
        k: &[ObjectKey],
        c: &CancelledResource,
    ) -> Result<()> {
        {
            e.require_backend_operation(r, crate::parent_adapter::Operation::CleanupCancelled)?;
            self.tombstone_context(e.native_lease(), r, k, c)
        }
    }
    fn cleanup_exact(
        &self,
        e: &Effect<NativeCommitContext>,
        r: &Request,
        k: &[ObjectKey],
        c: &CancelledResource,
    ) -> Result<Option<Outcome>> {
        {
            e.require_backend_operation(r, crate::parent_adapter::Operation::CleanupCancelled)?;
            self.cleanup_context(e.native_lease(), r, k, c)
        }
    }
}

#[cfg(test)]
#[path = "parent_backend_tests.rs"]
mod tests;
