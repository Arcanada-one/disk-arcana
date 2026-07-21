//! AI agent webhooks and optimistic write revisions (DISK-0028 slice 1).

use sqlx::Row;

use super::MetaDb;
use crate::error::MetaDbError;

/// Registered outbound webhook for agent/sync events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWebhookRow {
    pub id: String,
    pub tenant_id: Option<String>,
    pub vault_id: String,
    pub url: String,
    pub events: Vec<String>,
    pub label: Option<String>,
    pub enabled: bool,
    pub created_at: i64,
}

/// Input for registering a webhook.
#[derive(Debug, Clone)]
pub struct NewAgentWebhook<'a> {
    pub id: &'a str,
    pub tenant_id: Option<&'a str>,
    pub vault_id: &'a str,
    pub url: &'a str,
    pub secret_hash: &'a [u8; 32],
    pub signing_secret: &'a str,
    pub events: &'a [String],
    pub label: Option<&'a str>,
}

/// Target for outbound webhook delivery (includes signing key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWebhookDeliveryTarget {
    pub id: String,
    pub url: String,
    pub signing_secret: String,
}

/// Agent-facing revision counter for optimistic writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentWriteRevision {
    pub revision: u64,
    pub content_hash: Option<[u8; 32]>,
    pub updated_at: i64,
    pub updated_by: Option<String>,
}

/// Result of a conditional revision bump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevisionBumpOutcome {
    Applied { new_revision: u64 },
    Conflict { current_revision: u64 },
}

impl MetaDb {
    pub async fn insert_agent_webhook(
        &self,
        webhook: NewAgentWebhook<'_>,
    ) -> Result<(), MetaDbError> {
        let now = unix_now_secs();
        let events_json = serde_json::to_string(webhook.events)
            .map_err(|e| MetaDbError::Invalid(format!("events json: {e}")))?;
        sqlx::query(
            r#"
            INSERT INTO agent_webhooks (
                id, tenant_id, vault_id, url, secret_hash, signing_secret,
                events_json, label, enabled, created_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9)
            "#,
        )
        .bind(webhook.id)
        .bind(webhook.tenant_id)
        .bind(webhook.vault_id)
        .bind(webhook.url)
        .bind(webhook.secret_hash.as_slice())
        .bind(webhook.signing_secret)
        .bind(events_json)
        .bind(webhook.label)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_agent_webhooks(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
    ) -> Result<Vec<AgentWebhookRow>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT id, tenant_id, vault_id, url, events_json, label, enabled, created_at
            FROM agent_webhooks
            WHERE tenant_id IS ?1 AND vault_id = ?2
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let events_json: String = row.try_get("events_json")?;
            let events: Vec<String> = serde_json::from_str(&events_json)
                .map_err(|e| MetaDbError::Invalid(format!("events json: {e}")))?;
            let enabled: i64 = row.try_get("enabled")?;
            out.push(AgentWebhookRow {
                id: row.try_get("id")?,
                tenant_id: row.try_get("tenant_id")?,
                vault_id: row.try_get("vault_id")?,
                url: row.try_get("url")?,
                events,
                label: row.try_get("label")?,
                enabled: enabled != 0,
                created_at: row.try_get("created_at")?,
            });
        }
        Ok(out)
    }

    pub async fn delete_agent_webhook(
        &self,
        tenant_id: Option<&str>,
        webhook_id: &str,
    ) -> Result<bool, MetaDbError> {
        let result = sqlx::query(
            r#"
            DELETE FROM agent_webhooks
            WHERE tenant_id IS ?1 AND id = ?2
            "#,
        )
        .bind(tenant_id)
        .bind(webhook_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Enabled webhooks for a tenant/vault that subscribe to `event`.
    pub async fn list_agent_webhooks_for_event(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        event: &str,
    ) -> Result<Vec<AgentWebhookDeliveryTarget>, MetaDbError> {
        let rows = sqlx::query(
            r#"
            SELECT id, url, signing_secret, events_json
            FROM agent_webhooks
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND enabled = 1
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::new();
        for row in rows {
            let events_json: String = row.try_get("events_json")?;
            let events: Vec<String> = serde_json::from_str(&events_json)
                .map_err(|e| MetaDbError::Invalid(format!("events json: {e}")))?;
            if !events.iter().any(|e| e == event) {
                continue;
            }
            let signing_secret: Option<String> = row.try_get("signing_secret")?;
            let Some(signing_secret) = signing_secret.filter(|s| !s.is_empty()) else {
                continue;
            };
            out.push(AgentWebhookDeliveryTarget {
                id: row.try_get("id")?,
                url: row.try_get("url")?,
                signing_secret,
            });
        }
        Ok(out)
    }

    pub async fn get_agent_write_revision(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
    ) -> Result<AgentWriteRevision, MetaDbError> {
        let row = sqlx::query(
            r#"
            SELECT revision, content_hash, updated_at, updated_by
            FROM agent_write_revisions
            WHERE tenant_id IS ?1 AND vault_id = ?2 AND path = ?3
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .fetch_optional(&self.pool)
        .await?;

        Ok(match row {
            Some(row) => {
                let revision: i64 = row.try_get("revision")?;
                let hash_bytes: Option<Vec<u8>> = row.try_get("content_hash")?;
                AgentWriteRevision {
                    revision: revision as u64,
                    content_hash: hash_bytes.and_then(|b| b.try_into().ok()),
                    updated_at: row.try_get("updated_at")?,
                    updated_by: row.try_get("updated_by")?,
                }
            }
            None => AgentWriteRevision {
                revision: 0,
                content_hash: None,
                updated_at: 0,
                updated_by: None,
            },
        })
    }

    /// Bump revision when `expected_revision` matches the stored value (or both are 0 for create).
    pub async fn bump_agent_write_revision(
        &self,
        tenant_id: Option<&str>,
        vault_id: &str,
        path: &str,
        expected_revision: u64,
        content_hash: [u8; 32],
        updated_by: &str,
    ) -> Result<RevisionBumpOutcome, MetaDbError> {
        let current = self
            .get_agent_write_revision(tenant_id, vault_id, path)
            .await?;
        if current.revision != expected_revision {
            return Ok(RevisionBumpOutcome::Conflict {
                current_revision: current.revision,
            });
        }

        let now = unix_now_secs();
        let new_revision = expected_revision + 1;
        sqlx::query(
            r#"
            INSERT INTO agent_write_revisions (
                tenant_id, vault_id, path, revision, content_hash, updated_at, updated_by
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(tenant_id, vault_id, path) DO UPDATE SET
                revision = excluded.revision,
                content_hash = excluded.content_hash,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            WHERE agent_write_revisions.revision = ?8
            "#,
        )
        .bind(tenant_id)
        .bind(vault_id)
        .bind(path)
        .bind(new_revision as i64)
        .bind(content_hash.as_slice())
        .bind(now)
        .bind(updated_by)
        .bind(expected_revision as i64)
        .execute(&self.pool)
        .await?;

        let after = self
            .get_agent_write_revision(tenant_id, vault_id, path)
            .await?;
        if after.revision == new_revision {
            Ok(RevisionBumpOutcome::Applied {
                new_revision: after.revision,
            })
        } else {
            Ok(RevisionBumpOutcome::Conflict {
                current_revision: after.revision,
            })
        }
    }
}

fn unix_now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn webhook_crud_round_trip() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("agents.sqlite"))
            .await
            .unwrap();

        let secret_hash = blake3::hash(b"whsec-test").into();
        db.insert_agent_webhook(NewAgentWebhook {
            id: "wh1",
            tenant_id: Some("corp"),
            vault_id: "default",
            url: "https://agent.example/hook",
            secret_hash: &secret_hash,
            signing_secret: "whsec_test",
            events: &["agent.write_ok".into()],
            label: Some("dreamer"),
        })
        .await
        .unwrap();

        let listed = db
            .list_agent_webhooks(Some("corp"), "default")
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].url, "https://agent.example/hook");
        assert!(listed[0].enabled);

        assert!(db.delete_agent_webhook(Some("corp"), "wh1").await.unwrap());
        assert!(!db.delete_agent_webhook(Some("corp"), "wh1").await.unwrap());
    }

    #[tokio::test]
    async fn revision_optimistic_bump() {
        let dir = tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("agents-rev.sqlite"))
            .await
            .unwrap();

        let hash1 = blake3::hash(b"v1").into();
        let applied = db
            .bump_agent_write_revision(Some("t1"), "default", "a.md", 0, hash1, "agent-a")
            .await
            .unwrap();
        assert_eq!(applied, RevisionBumpOutcome::Applied { new_revision: 1 });

        let conflict = db
            .bump_agent_write_revision(Some("t1"), "default", "a.md", 0, hash1, "agent-b")
            .await
            .unwrap();
        assert_eq!(
            conflict,
            RevisionBumpOutcome::Conflict {
                current_revision: 1
            }
        );

        let hash2 = blake3::hash(b"v2").into();
        let applied2 = db
            .bump_agent_write_revision(Some("t1"), "default", "a.md", 1, hash2, "agent-b")
            .await
            .unwrap();
        assert_eq!(applied2, RevisionBumpOutcome::Applied { new_revision: 2 });
    }
}
