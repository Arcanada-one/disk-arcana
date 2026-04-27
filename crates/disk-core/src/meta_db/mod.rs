//! SQLite metadata index. Phase 1 supplies open + migrations only.
//! CRUD methods land in DISK-0003.

use std::path::Path;

use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};

use crate::error::MetaDbError;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

#[derive(Debug, Clone)]
pub struct MetaDb {
    pool: SqlitePool,
}

impl MetaDb {
    /// Open (or create) a SQLite database file and run migrations.
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

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}
