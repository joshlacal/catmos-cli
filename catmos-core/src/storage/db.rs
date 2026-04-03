use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::path::Path;
use std::str::FromStr;

use crate::error::{CatmosError, Result};
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
            .pragma("key", encryption_key.to_string())
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
            ("conversations", "CREATE TABLE IF NOT EXISTS conversations (
                group_id      TEXT PRIMARY KEY,
                name          TEXT,
                description   TEXT,
                creator       TEXT NOT NULL,
                epoch         INTEGER NOT NULL DEFAULT 0,
                cipher_suite  TEXT NOT NULL DEFAULT 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
                created_at    TEXT NOT NULL,
                last_message_at TEXT,
                unread_count  INTEGER NOT NULL DEFAULT 0,
                alias         TEXT
            )"),
            ("members", "CREATE TABLE IF NOT EXISTS members (
                did           TEXT NOT NULL,
                group_id      TEXT NOT NULL,
                user_did      TEXT NOT NULL,
                device_id     TEXT,
                device_name   TEXT,
                is_admin      INTEGER NOT NULL DEFAULT 0,
                is_moderator  INTEGER NOT NULL DEFAULT 0,
                joined_at     TEXT NOT NULL,
                PRIMARY KEY (did, group_id),
                FOREIGN KEY (group_id) REFERENCES conversations(group_id)
            )"),
            ("messages", "CREATE TABLE IF NOT EXISTS messages (
                id            TEXT PRIMARY KEY,
                convo_id      TEXT NOT NULL,
                sender_did    TEXT,
                content_type  TEXT NOT NULL DEFAULT 'text',
                content_json  TEXT NOT NULL,
                epoch         INTEGER NOT NULL DEFAULT 0,
                seq           INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL,
                FOREIGN KEY (convo_id) REFERENCES conversations(group_id)
            )"),
            ("idx_messages", "CREATE INDEX IF NOT EXISTS idx_messages_convo_seq ON messages(convo_id, seq)"),
            ("session", "CREATE TABLE IF NOT EXISTS session (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )"),
        ];

        for (name, sql) in &statements {
            sqlx::query(sql).execute(&self.pool).await.map_err(|e| {
                CatmosError::Storage(format!("Migration '{name}' failed: {e}"))
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
             (group_id, name, description, creator, epoch, cipher_suite, created_at, last_message_at, unread_count, alias)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
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
            "SELECT group_id, name, description, creator, epoch, cipher_suite,
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

    // ── Members ──────────────────────────────────────────────────────────

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
