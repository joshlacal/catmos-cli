use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::path::Path;
use std::str::FromStr;

use crate::error::{CatmosError, Result};
use crate::recovery::{PersistedRecoveryFlags, ResetPendingPayload};
use crate::types::{Conversation, Member, Message, MessageContent};

/// SQLCipher-encrypted database for per-account storage.
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Open (or create) a SQLCipher database at `path` with the given encryption key.
    pub async fn open(path: &Path, encryption_key: &str) -> Result<Self> {
        let url = format!("sqlite:{}", path.display());
        let options = SqliteConnectOptions::from_str(&url)
            .map_err(|e| CatmosError::Storage(format!("Invalid DB path: {e}")))?
            .create_if_missing(true)
            .pragma("key", format!("'{encryption_key}'"))
            .pragma("cipher_page_size", "4096".to_string())
            .pragma("journal_mode", "WAL".to_string());

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        // Verify the key works by reading from the DB
        sqlx::query("SELECT count(*) FROM sqlite_master")
            .fetch_one(&pool)
            .await
            .map_err(|_| {
                CatmosError::Storage("Database key incorrect or database corrupted".into())
            })?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    /// Open an unencrypted database (for development/testing).
    pub async fn open_unencrypted(path: &Path) -> Result<Self> {
        let url = format!("sqlite:{}", path.display());
        let options = SqliteConnectOptions::from_str(&url)
            .map_err(|e| CatmosError::Storage(format!("Invalid DB path: {e}")))?
            .create_if_missing(true)
            .pragma("journal_mode", "WAL".to_string());

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        let db = Self { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        let statements = [
            (
                "conversations",
                "CREATE TABLE IF NOT EXISTS conversations (
                conversation_id TEXT PRIMARY KEY,
                group_id      TEXT NOT NULL,
                name          TEXT,
                description   TEXT,
                creator       TEXT NOT NULL,
                epoch         INTEGER NOT NULL DEFAULT 0,
                cipher_suite  TEXT NOT NULL DEFAULT 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
                created_at    TEXT NOT NULL,
                last_message_at TEXT,
                unread_count  INTEGER NOT NULL DEFAULT 0,
                alias         TEXT
            )",
            ),
            (
                "members",
                "CREATE TABLE IF NOT EXISTS members (
                did           TEXT NOT NULL,
                group_id      TEXT NOT NULL,
                user_did      TEXT NOT NULL,
                device_id     TEXT,
                device_name   TEXT,
                is_admin      INTEGER NOT NULL DEFAULT 0,
                is_moderator  INTEGER NOT NULL DEFAULT 0,
                joined_at     TEXT NOT NULL,
                PRIMARY KEY (did, group_id),
                FOREIGN KEY (group_id) REFERENCES conversations(conversation_id)
            )",
            ),
            (
                "messages",
                "CREATE TABLE IF NOT EXISTS messages (
                id            TEXT PRIMARY KEY,
                convo_id      TEXT NOT NULL,
                sender_did    TEXT,
                content_type  TEXT NOT NULL DEFAULT 'text',
                content_json  TEXT NOT NULL,
                epoch         INTEGER NOT NULL DEFAULT 0,
                seq           INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL,
                FOREIGN KEY (convo_id) REFERENCES conversations(conversation_id)
            )",
            ),
            (
                "idx_messages",
                "CREATE INDEX IF NOT EXISTS idx_messages_convo_seq ON messages(convo_id, seq)",
            ),
            (
                "session",
                "CREATE TABLE IF NOT EXISTS session (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )",
            ),
        ];

        for (name, sql) in &statements {
            sqlx::query(sql)
                .execute(&self.pool)
                .await
                .map_err(|e| CatmosError::Storage(format!("Migration '{name}' failed: {e}")))?;
        }

        // ── Additive migrations: recovery state machine columns (spec §8) ──
        //
        // SQLite has no `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, so we
        // probe `pragma_table_info` for the column name and only add it if
        // missing. Any other error is fatal (a real schema problem). This
        // keeps `migrate()` idempotent across restarts.
        let recovery_columns: &[(&str, &str)] = &[
            ("needs_rejoin", "INTEGER NOT NULL DEFAULT 0"),
            ("reset_new_group_id", "TEXT NULL"),
            ("reset_generation", "INTEGER NULL"),
            ("reset_notified_at_ms", "INTEGER NULL"),
            ("recovery_attempt_count", "INTEGER NOT NULL DEFAULT 0"),
            ("last_rejoin_attempt_ms", "INTEGER NULL"),
            ("unrecoverable_local", "INTEGER NOT NULL DEFAULT 0"),
        ];
        for (col, decl) in recovery_columns {
            let existing: Option<(String,)> = sqlx::query_as(
                "SELECT name FROM pragma_table_info('conversations') WHERE name = ?1",
            )
            .bind(col)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                CatmosError::Storage(format!("Probe column '{col}' failed: {e}"))
            })?;
            if existing.is_some() {
                continue;
            }
            let stmt = format!("ALTER TABLE conversations ADD COLUMN {col} {decl}");
            sqlx::query(&stmt).execute(&self.pool).await.map_err(|e| {
                CatmosError::Storage(format!("Add column '{col}' failed: {e}"))
            })?;
        }

        Ok(())
    }

    // ── Session key-value store ──────────────────────────────────────────

    pub async fn store_session_value(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query("INSERT OR REPLACE INTO session (key, value) VALUES (?1, ?2)")
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn get_session_value(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM session WHERE key = ?1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| r.get("value")))
    }

    // ── Conversations ────────────────────────────────────────────────────

    pub async fn store_conversation(&self, convo: &Conversation) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO conversations
             (conversation_id, group_id, name, description, creator, epoch, cipher_suite, created_at, last_message_at, unread_count, alias)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .bind(&convo.conversation_id)
        .bind(&convo.group_id)
        .bind(&convo.name)
        .bind(&convo.description)
        .bind(&convo.creator)
        .bind(convo.epoch as i64)
        .bind(&convo.cipher_suite)
        .bind(convo.created_at.to_rfc3339())
        .bind(convo.last_message_at.map(|t| t.to_rfc3339()))
        .bind(convo.unread_count as i32)
        .bind(&convo.alias)
        .execute(&self.pool)
        .await?;

        // Upsert members
        for member in &convo.members {
            sqlx::query(
                "INSERT OR REPLACE INTO members
                 (did, group_id, user_did, device_id, device_name, is_admin, is_moderator, joined_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )
            .bind(&member.did)
            .bind(&convo.group_id)
            .bind(&member.user_did)
            .bind(&member.device_id)
            .bind(&member.device_name)
            .bind(member.is_admin as i32)
            .bind(member.is_moderator as i32)
            .bind(member.joined_at.to_rfc3339())
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    pub async fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let rows = sqlx::query(
            "SELECT conversation_id, group_id, name, description, creator, epoch, cipher_suite,
                    created_at, last_message_at, unread_count, alias
             FROM conversations ORDER BY last_message_at DESC NULLS LAST",
        )
        .fetch_all(&self.pool)
        .await?;

        let convos = rows
            .iter()
            .map(|row| {
                let created_str: String = row.get("created_at");
                let last_msg_str: Option<String> = row.get("last_message_at");
                Conversation {
                    conversation_id: row.get("conversation_id"),
                    group_id: row.get("group_id"),
                    name: row.get("name"),
                    description: row.get("description"),
                    creator: row.get("creator"),
                    epoch: row.get::<i64, _>("epoch") as u64,
                    cipher_suite: row.get("cipher_suite"),
                    members: vec![], // loaded separately
                    created_at: DateTime::parse_from_rfc3339(&created_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    last_message_at: last_msg_str.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    }),
                    unread_count: row.get::<i32, _>("unread_count") as u32,
                    alias: row.get("alias"),
                }
            })
            .collect();

        Ok(convos)
    }

    // ── Messages ─────────────────────────────────────────────────────────

    pub async fn store_message(&self, msg: &Message) -> Result<()> {
        let (content_type, content_json) = serialize_content(&msg.content);
        sqlx::query(
            "INSERT OR REPLACE INTO messages
             (id, convo_id, sender_did, content_type, content_json, epoch, seq, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(&msg.id)
        .bind(&msg.convo_id)
        .bind(&msg.sender_did)
        .bind(&content_type)
        .bind(&content_json)
        .bind(msg.epoch as i64)
        .bind(msg.seq as i64)
        .bind(msg.created_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_messages(
        &self,
        convo_id: &str,
        limit: u32,
        before_seq: Option<u64>,
    ) -> Result<Vec<Message>> {
        let rows = if let Some(seq) = before_seq {
            sqlx::query(
                "SELECT id, convo_id, sender_did, content_type, content_json, epoch, seq, created_at
                 FROM messages WHERE convo_id = ?1 AND seq < ?2
                 ORDER BY seq DESC LIMIT ?3",
            )
            .bind(convo_id)
            .bind(seq as i64)
            .bind(limit as i32)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, convo_id, sender_did, content_type, content_json, epoch, seq, created_at
                 FROM messages WHERE convo_id = ?1
                 ORDER BY seq DESC LIMIT ?2",
            )
            .bind(convo_id)
            .bind(limit as i32)
            .fetch_all(&self.pool)
            .await?
        };

        let mut messages: Vec<Message> = rows.iter().map(map_message_row).collect();
        messages.reverse(); // return in chronological order
        Ok(messages)
    }

    /// Get the highest seq number stored locally for a conversation.
    /// Used to request only newer messages from the server via `sinceSeq`.
    pub async fn get_max_seq(&self, convo_id: &str) -> Result<Option<i64>> {
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT MAX(seq) FROM messages WHERE convo_id = ?1 AND seq > 0",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(seq,)| seq))
    }

    // ── Members ──────────────────────────────────────────────────────────

    // ── Recovery state machine (spec §8) ─────────────────────────────────

    /// Load the persisted recovery flags for `convo_id`. Returns default
    /// (HEALTHY, no payload) when the row is missing.
    pub async fn get_recovery_flags(&self, convo_id: &str) -> Result<PersistedRecoveryFlags> {
        let row = sqlx::query(
            "SELECT needs_rejoin, reset_new_group_id, reset_generation,
                    reset_notified_at_ms, recovery_attempt_count,
                    last_rejoin_attempt_ms, unrecoverable_local
             FROM conversations WHERE conversation_id = ?1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Ok(PersistedRecoveryFlags::default());
        };

        let needs_rejoin: i64 = row.get("needs_rejoin");
        let unrecoverable_local: i64 = row.get("unrecoverable_local");
        let reset_new_group_id: Option<String> = row.get("reset_new_group_id");
        let reset_generation: Option<i64> = row.get("reset_generation");
        let reset_notified_at_ms: Option<i64> = row.get("reset_notified_at_ms");
        let recovery_attempt_count: i64 = row.get("recovery_attempt_count");
        let last_rejoin_attempt_ms: Option<i64> = row.get("last_rejoin_attempt_ms");

        let reset = match (reset_new_group_id, reset_generation, reset_notified_at_ms) {
            (Some(gid), Some(gen), Some(ts)) => Some(ResetPendingPayload {
                new_group_id: gid,
                reset_generation: gen,
                notified_at_ms: ts,
            }),
            _ => None,
        };

        Ok(PersistedRecoveryFlags {
            needs_rejoin: needs_rejoin != 0,
            unrecoverable_local: unrecoverable_local != 0,
            reset,
            recovery_attempt_count: recovery_attempt_count.max(0) as u32,
            last_rejoin_attempt_ms,
        })
    }

    /// Mark a conversation as needing a deferred External Commit rejoin
    /// (§8.2). Idempotent.
    pub async fn mark_needs_rejoin(&self, convo_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE conversations SET needs_rejoin = 1 WHERE conversation_id = ?1",
        )
        .bind(convo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Clear the `NEEDS_REJOIN` flag (called on successful rejoin).
    pub async fn clear_needs_rejoin(&self, convo_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE conversations
             SET needs_rejoin = 0,
                 recovery_attempt_count = 0,
                 last_rejoin_attempt_ms = NULL
             WHERE conversation_id = ?1",
        )
        .bind(convo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Persist an attempt counter bump and timestamp after a failed rejoin.
    pub async fn record_rejoin_attempt(
        &self,
        convo_id: &str,
        attempt_count: u32,
        attempt_ms: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE conversations
             SET recovery_attempt_count = ?1,
                 last_rejoin_attempt_ms = ?2
             WHERE conversation_id = ?3",
        )
        .bind(attempt_count as i64)
        .bind(attempt_ms)
        .bind(convo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark a conversation as locally unrecoverable (max attempts hit, §8.2).
    pub async fn mark_unrecoverable_local(&self, convo_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE conversations
             SET unrecoverable_local = 1, needs_rejoin = 0
             WHERE conversation_id = ?1",
        )
        .bind(convo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Clear the `UNRECOVERABLE_LOCAL` flag (e.g. after server reset
    /// `GroupResetEvent` rescues us).
    pub async fn clear_unrecoverable_local(&self, convo_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE conversations SET unrecoverable_local = 0 WHERE conversation_id = ?1",
        )
        .bind(convo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Persist a `RESET_PENDING` payload received via `GroupResetEvent`
    /// (§8.2 / §8.6). The triple is required.
    pub async fn mark_reset_pending(
        &self,
        convo_id: &str,
        new_group_id: &str,
        reset_generation: i64,
        notified_at_ms: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE conversations
             SET reset_new_group_id = ?1,
                 reset_generation = ?2,
                 reset_notified_at_ms = ?3
             WHERE conversation_id = ?4",
        )
        .bind(new_group_id)
        .bind(reset_generation)
        .bind(notified_at_ms)
        .bind(convo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Clear the persisted `RESET_PENDING` payload (after Phase 1 deferred
    /// recovery succeeds in adopting the new group).
    pub async fn clear_reset_pending(&self, convo_id: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        // Swap group_id from the persisted reset_new_group_id, then clear all reset columns.
        sqlx::query(
            "UPDATE conversations
             SET group_id = COALESCE(reset_new_group_id, group_id),
                 reset_new_group_id = NULL,
                 reset_generation = NULL,
                 reset_notified_at_ms = NULL
             WHERE conversation_id = ?1",
        )
        .bind(convo_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn get_members(&self, group_id: &str) -> Result<Vec<Member>> {
        let rows = sqlx::query(
            "SELECT did, user_did, device_id, device_name, is_admin, is_moderator, joined_at
             FROM members WHERE group_id = ?1",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;

        let members = rows
            .iter()
            .map(|row| {
                let joined_str: String = row.get("joined_at");
                Member {
                    did: row.get("did"),
                    user_did: row.get("user_did"),
                    device_id: row.get("device_id"),
                    device_name: row.get("device_name"),
                    is_admin: row.get::<i32, _>("is_admin") != 0,
                    is_moderator: row.get::<i32, _>("is_moderator") != 0,
                    joined_at: DateTime::parse_from_rfc3339(&joined_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                }
            })
            .collect();

        Ok(members)
    }
}

#[cfg(test)]
mod reset_pending_tests {
    use super::*;
    use crate::types::Conversation;

    fn fixture_convo(convo_id: &str, group_id: &str) -> Conversation {
        Conversation {
            conversation_id: convo_id.to_string(),
            group_id: group_id.to_string(),
            name: None,
            description: None,
            creator: String::new(),
            epoch: 0,
            cipher_suite: String::new(),
            members: vec![],
            created_at: Utc::now(),
            last_message_at: None,
            unread_count: 0,
            alias: None,
        }
    }

    async fn read_group_id(db: &Database, convo_id: &str) -> String {
        db.list_conversations()
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.conversation_id == convo_id)
            .expect("conversation must exist")
            .group_id
    }

    #[tokio::test]
    async fn clear_reset_pending_swaps_group_id() {
        let path = std::env::temp_dir()
            .join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
        let db = Database::open_unencrypted(&path).await.unwrap();

        let convo_id = "convo-1";
        let old_group_id = "old-group-hex";
        let new_group_id = "new-group-hex";

        db.store_conversation(&fixture_convo(convo_id, old_group_id))
            .await
            .unwrap();
        db.mark_reset_pending(convo_id, new_group_id, 1, 0)
            .await
            .unwrap();

        let pre = read_group_id(&db, convo_id).await;
        assert_eq!(pre, old_group_id);

        db.clear_reset_pending(convo_id).await.unwrap();

        let post = read_group_id(&db, convo_id).await;
        assert_eq!(
            post, new_group_id,
            "clear_reset_pending must swap group_id from reset_new_group_id"
        );
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn serialize_content(content: &MessageContent) -> (String, String) {
    match content {
        MessageContent::Text(text) => ("text".into(), text.clone()),
        MessageContent::Reaction {
            target_message_id,
            emoji,
            action,
        } => (
            "reaction".into(),
            serde_json::json!({
                "target_message_id": target_message_id,
                "emoji": emoji,
                "action": action,
            })
            .to_string(),
        ),
        MessageContent::System(text) => ("system".into(), text.clone()),
        MessageContent::Unknown => ("unknown".into(), String::new()),
    }
}

fn deserialize_content(content_type: &str, content_json: &str) -> MessageContent {
    match content_type {
        "text" => MessageContent::Text(content_json.to_string()),
        "reaction" => {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(content_json) {
                MessageContent::Reaction {
                    target_message_id: v["target_message_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                    emoji: v["emoji"].as_str().unwrap_or_default().to_string(),
                    action: serde_json::from_value(v["action"].clone())
                        .unwrap_or(crate::types::ReactionAction::Add),
                }
            } else {
                MessageContent::Unknown
            }
        }
        "system" => MessageContent::System(content_json.to_string()),
        _ => MessageContent::Unknown,
    }
}

fn map_message_row(row: &sqlx::sqlite::SqliteRow) -> Message {
    let content_type: String = row.get("content_type");
    let content_json: String = row.get("content_json");
    let created_str: String = row.get("created_at");

    Message {
        id: row.get("id"),
        convo_id: row.get("convo_id"),
        sender_did: row.get("sender_did"),
        content: deserialize_content(&content_type, &content_json),
        epoch: row.get::<i64, _>("epoch") as u64,
        seq: row.get::<i64, _>("seq") as u64,
        created_at: DateTime::parse_from_rfc3339(&created_str)
            .unwrap_or_default()
            .with_timezone(&Utc),
    }
}
