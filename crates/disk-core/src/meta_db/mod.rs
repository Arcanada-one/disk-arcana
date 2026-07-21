//! SQLite metadata index.
//!
//! Phase 1 (DISK-0002) shipped `MetaDb::open` with WAL + migrations. Phase 2
//! (DISK-0003) layers CRUD methods for the `files`, `tombstones`, and
//! `conflicts` tables and wires up `BEGIN ... COMMIT` batch transactions.

pub mod conflicts;
mod billing;
mod files;
mod node_baseline;
mod tombstones;

use std::path::Path;

use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};

use crate::error::MetaDbError;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Handle to the on-disk SQLite metadata index. Cheap to clone (wraps a pool).
#[derive(Debug, Clone)]
pub struct MetaDb {
    pool: SqlitePool,
}

impl MetaDb {
    /// Open (or create) a SQLite database file and run pending migrations.
    pub async fn open(path: &Path) -> Result<Self, MetaDbError> {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool })
    }

    /// Read-only handle for code that needs to issue raw queries.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}
