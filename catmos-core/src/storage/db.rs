use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;

use crate::error::{CatmosError, Result};
use crate::types::{Conversation, Member, Message, MessageContent};

/// SQLCipher-encrypted database for per-account storage.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open (or create) a SQLCipher database at `path` with the given encryption key.
    pub fn open(path: &Path, encryption_key: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Configure SQLCipher
        conn.pragma_update(None, "key", encryption_key)?;
        conn.pragma_update(None, "cipher_page_size", 4096)?;
        conn.pragma_update(None, "kdf_iter", 256000)?;
        conn.pragma_update(None, "cipher_plaintext_header_size", 32)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;

        // Verify the key works by reading from the DB
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .map_err(|_| {
                CatmosError::Storage("Database key incorrect or database corrupted".into())
            })?;

        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Open an unencrypted database (for development/testing).
    pub fn open_unencrypted(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS conversations (
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
            );

            CREATE TABLE IF NOT EXISTS members (
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
            );

            CREATE TABLE IF NOT EXISTS messages (
                id            TEXT PRIMARY KEY,
                convo_id      TEXT NOT NULL,
                sender_did    TEXT,
                content_type  TEXT NOT NULL DEFAULT 'text',
                content_json  TEXT NOT NULL,
                epoch         INTEGER NOT NULL DEFAULT 0,
                seq           INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL,
                FOREIGN KEY (convo_id) REFERENCES conversations(group_id)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_convo_seq
                ON messages(convo_id, seq);

            CREATE TABLE IF NOT EXISTS session (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    // ── Session key-value store ──────────────────────────────────────────

    pub fn store_session_value(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO session (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn get_session_value(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM session WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get(0)?)),
            None => Ok(None),
        }
    }

    // ── Conversations ────────────────────────────────────────────────────

    pub fn store_conversation(&self, convo: &Conversation) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO conversations
             (group_id, name, description, creator, epoch, cipher_suite, created_at, last_message_at, unread_count, alias)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                convo.group_id,
                convo.name,
                convo.description,
                convo.creator,
                convo.epoch as i64,
                convo.cipher_suite,
                convo.created_at.to_rfc3339(),
                convo.last_message_at.map(|t| t.to_rfc3339()),
                convo.unread_count,
                convo.alias,
            ],
        )?;

        // Upsert members
        for member in &convo.members {
            self.conn.execute(
                "INSERT OR REPLACE INTO members
                 (did, group_id, user_did, device_id, device_name, is_admin, is_moderator, joined_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    member.did,
                    convo.group_id,
                    member.user_did,
                    member.device_id,
                    member.device_name,
                    member.is_admin as i32,
                    member.is_moderator as i32,
                    member.joined_at.to_rfc3339(),
                ],
            )?;
        }

        Ok(())
    }

    pub fn list_conversations(&self) -> Result<Vec<Conversation>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, name, description, creator, epoch, cipher_suite,
                    created_at, last_message_at, unread_count, alias
             FROM conversations ORDER BY last_message_at DESC NULLS LAST",
        )?;

        let convos = stmt
            .query_map([], |row| {
                let created_str: String = row.get(6)?;
                let last_msg_str: Option<String> = row.get(7)?;
                Ok(Conversation {
                    group_id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    creator: row.get(3)?,
                    epoch: row.get::<_, i64>(4)? as u64,
                    cipher_suite: row.get(5)?,
                    members: vec![], // loaded separately
                    created_at: DateTime::parse_from_rfc3339(&created_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                    last_message_at: last_msg_str.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    }),
                    unread_count: row.get(8)?,
                    alias: row.get(9)?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(convos)
    }

    // ── Messages ─────────────────────────────────────────────────────────

    pub fn store_message(&self, msg: &Message) -> Result<()> {
        let (content_type, content_json) = serialize_content(&msg.content);
        self.conn.execute(
            "INSERT OR REPLACE INTO messages
             (id, convo_id, sender_did, content_type, content_json, epoch, seq, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                msg.id,
                msg.convo_id,
                msg.sender_did,
                content_type,
                content_json,
                msg.epoch as i64,
                msg.seq as i64,
                msg.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_messages(&self, convo_id: &str, limit: u32, before_seq: Option<u64>) -> Result<Vec<Message>> {
        let mut messages = if let Some(seq) = before_seq {
            let mut stmt = self.conn.prepare(
                "SELECT id, convo_id, sender_did, content_type, content_json, epoch, seq, created_at
                 FROM messages WHERE convo_id = ?1 AND seq < ?2
                 ORDER BY seq DESC LIMIT ?3",
            )?;
            let rows = stmt.query_map(params![convo_id, seq as i64, limit], map_message_row)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id, convo_id, sender_did, content_type, content_json, epoch, seq, created_at
                 FROM messages WHERE convo_id = ?1
                 ORDER BY seq DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![convo_id, limit], map_message_row)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };

        messages.reverse(); // return in chronological order
        Ok(messages)
    }

    // ── Members ──────────────────────────────────────────────────────────

    pub fn get_members(&self, group_id: &str) -> Result<Vec<Member>> {
        let mut stmt = self.conn.prepare(
            "SELECT did, user_did, device_id, device_name, is_admin, is_moderator, joined_at
             FROM members WHERE group_id = ?1",
        )?;

        let members = stmt
            .query_map(params![group_id], |row| {
                let joined_str: String = row.get(6)?;
                Ok(Member {
                    did: row.get(0)?,
                    user_did: row.get(1)?,
                    device_id: row.get(2)?,
                    device_name: row.get(3)?,
                    is_admin: row.get::<_, i32>(4)? != 0,
                    is_moderator: row.get::<_, i32>(5)? != 0,
                    joined_at: DateTime::parse_from_rfc3339(&joined_str)
                        .unwrap_or_default()
                        .with_timezone(&Utc),
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

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

fn map_message_row(row: &rusqlite::Row) -> rusqlite::Result<Message> {
    let content_type: String = row.get(3)?;
    let content_json: String = row.get(4)?;
    let created_str: String = row.get(7)?;

    Ok(Message {
        id: row.get(0)?,
        convo_id: row.get(1)?,
        sender_did: row.get(2)?,
        content: deserialize_content(&content_type, &content_json),
        epoch: row.get::<_, i64>(5)? as u64,
        seq: row.get::<_, i64>(6)? as u64,
        created_at: DateTime::parse_from_rfc3339(&created_str)
            .unwrap_or_default()
            .with_timezone(&Utc),
    })
}
