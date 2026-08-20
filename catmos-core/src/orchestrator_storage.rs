use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension};
use std::sync::{Arc, Mutex, RwLock};

use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::storage::MLSStorageBackend;
use catbird_mls::orchestrator::types::*;
use catbird_mls::MLSContext;

/// Locally cached encrypted-metadata snapshot for a conversation. Mirrors
/// what `bootstrap_group_metadata` writes after a successful blob fetch +
/// decrypt: the JSON-serialized `GroupMetadataV1` payload, the bound
/// `metadata_version`, and the locator pointing at the server-stored
/// ciphertext. Used by the bootstrap path to detect "blob already in sync at
/// this version" and skip a redundant fetch.
pub struct LocalMetadataSnapshot {
    pub metadata_json: Option<String>,
    pub metadata_version: Option<i64>,
    pub metadata_blob_locator: Option<String>,
}

/// JSON-shaped canonical plaintext that gets sealed by the field-level
/// encryption layer before persistence. Storing the rich payload (rather
/// than the bare `text` column) means that encrypted rows retain enough
/// fidelity to rebuild the in-memory `Message` after a round-trip, while
/// the `text NOT NULL` constraint is satisfied by writing an empty string
/// to the legacy column when the encrypted payload is the source of truth.
#[derive(serde::Serialize, serde::Deserialize)]
struct CanonicalMessageBody<'a> {
    text: &'a str,
    payload_json: Option<&'a str>,
}

#[derive(serde::Deserialize)]
struct CanonicalMessageBodyOwned {
    text: String,
    payload_json: Option<String>,
}

/// Version tag stamped into `payload_key_version` on every encrypted row.
const PAYLOAD_KEY_VERSION_V1: i64 = 1;

/// SQLite-backed storage for Catmos desktop.
pub struct SqliteStorage {
    conn: Mutex<Connection>,
    /// Shared MLS context used for the field-level (envelope) encryption layer.
    /// Set via [`SqliteStorage::set_mls_context`] after the context is built
    /// in `lib.rs`. When unset — or when the per-DID content root key is not
    /// yet installed — the write/read paths fall back to plaintext columns so
    /// the orchestrator can keep functioning during the bootstrap window
    /// (initial sync may run before login completes).
    mls_context: RwLock<Option<Arc<MLSContext>>>,
}

impl SqliteStorage {
    pub fn new(db_path: &str, encryption_key: &str) -> std::result::Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_path)?;
        // Set SQLCipher key (required even for unencrypted use with bundled-sqlcipher)
        conn.execute_batch(&format!("PRAGMA key = '{}';", encryption_key))?;
        #[cfg(target_os = "android")]
        {
            let version: String =
                conn.pragma_query_value(None, "cipher_version", |row| row.get(0))?;
            if version.is_empty() {
                tracing::error!("Android SQLCipher probe returned empty cipher_version");
                return Err(rusqlite::Error::InvalidQuery);
            }
            tracing::info!("Android SQLCipher enabled (cipher_version={version})");
        }
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;")?;
        let storage = Self {
            conn: Mutex::new(conn),
            mls_context: RwLock::new(None),
        };
        storage.create_tables()?;
        Ok(storage)
    }

    /// Bind the per-process MLS context for the field-level encryption layer.
    /// Called once from `lib.rs::run()` right after the context is constructed.
    /// Idempotent; later calls replace the binding.
    pub fn set_mls_context(&self, ctx: Arc<MLSContext>) {
        if let Ok(mut guard) = self.mls_context.write() {
            *guard = Some(ctx);
        }
    }

    fn mls_context_snapshot(&self) -> Option<Arc<MLSContext>> {
        self.mls_context
            .read()
            .ok()
            .and_then(|g| g.as_ref().cloned())
    }

    /// Read the most recent (highest sequence_number) `entry_hmac` for a
    /// conversation so the next encrypted row can extend the HMAC chain.
    /// Returns `None` for the first row in a conversation (chain seed = 32
    /// zero bytes is supplied by the Rust core when `prev_hmac=None`) or
    /// when prior rows are legacy-plaintext (no chain).
    fn last_entry_hmac(&self, conversation_id: &str) -> Option<Vec<u8>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT entry_hmac FROM messages
             WHERE conversation_id = ?1 AND entry_hmac IS NOT NULL
             ORDER BY sequence_number DESC LIMIT 1",
            rusqlite::params![conversation_id],
            |r| r.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()
        .ok()
        .flatten()
        .flatten()
    }

    /// Seal a `Message` for storage via the field-level encryption layer.
    /// Returns `None` if the MLS context is unbound or its content root key
    /// has not been installed yet — callers fall back to legacy plaintext
    /// columns and log a warning so the orchestrator can continue functioning
    /// during the bootstrap window (initial sync may run before login
    /// finishes installing the content root key).
    fn try_encrypt_message_body(&self, message: &Message) -> Option<(Vec<u8>, Vec<u8>)> {
        let ctx = self.mls_context_snapshot()?;
        let body = CanonicalMessageBody {
            text: &message.text,
            payload_json: message.payload_json.as_deref(),
        };
        let plaintext = match serde_json::to_vec(&body) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    message_id = %message.id,
                    error = %err,
                    "try_encrypt_message_body: canonical body serialization failed; falling back to plaintext"
                );
                return None;
            }
        };
        let encrypted = match ctx
            .encrypt_message_payload(message.conversation_id.clone(), plaintext)
        {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!(
                    message_id = %message.id,
                    error = ?err,
                    "try_encrypt_message_body: encrypt_message_payload failed (content root key may be unset); falling back to plaintext"
                );
                return None;
            }
        };
        let prev_hmac = self.last_entry_hmac(&message.conversation_id);
        let entry_hmac = match ctx.compute_message_hmac(
            message.conversation_id.clone(),
            prev_hmac,
            message.id.clone(),
            encrypted.clone(),
        ) {
            Ok(tag) => tag,
            Err(err) => {
                tracing::warn!(
                    message_id = %message.id,
                    error = ?err,
                    "try_encrypt_message_body: compute_message_hmac failed; falling back to plaintext"
                );
                return None;
            }
        };
        Some((encrypted, entry_hmac))
    }

    fn create_tables(&self) -> std::result::Result<(), rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS conversations (
                conversation_id TEXT NOT NULL,
                user_did TEXT NOT NULL,
                group_id TEXT NOT NULL,
                epoch INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'Active',
                join_method TEXT,
                join_epoch INTEGER,
                needs_rejoin INTEGER NOT NULL DEFAULT 0,
                members_json TEXT NOT NULL DEFAULT '[]',
                metadata_json TEXT,
                metadata_version INTEGER,
                metadata_blob_locator TEXT,
                avatar_blob_locator TEXT,
                avatar_bytes BLOB,
                avatar_content_type TEXT,
                created_at TEXT,
                updated_at TEXT,
                sequencer_did TEXT,
                reset_new_group_id TEXT,
                reset_generation INTEGER,
                reset_notified_at_ms INTEGER,
                quarantine_reason_tag TEXT,
                quarantine_since_ms INTEGER,
                PRIMARY KEY (conversation_id, user_did)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_did TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                is_own INTEGER NOT NULL DEFAULT 0,
                delivery_status_json TEXT,
                payload_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_messages_convo_seq
                ON messages(conversation_id, sequence_number);

            CREATE TABLE IF NOT EXISTS sync_cursors (
                user_did TEXT PRIMARY KEY,
                conversations_cursor TEXT,
                messages_cursor TEXT
            );

            CREATE TABLE IF NOT EXISTS group_states (
                group_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                epoch INTEGER NOT NULL,
                members_json TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS ws_cursors (
                conversation_id TEXT PRIMARY KEY,
                cursor TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_messages (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recovery_backoffs (
                conversation_id TEXT PRIMARY KEY,
                failed_rejoin_count INTEGER NOT NULL,
                last_attempt_at_ms INTEGER NOT NULL,
                quarantined_until_ms INTEGER
            );

            CREATE TABLE IF NOT EXISTS recovery_globals (
                key TEXT PRIMARY KEY,
                val_int INTEGER
            );
            ",
        )?;
        Self::ensure_messages_delivery_status_column(&conn)?;
        Self::ensure_conversations_reset_pending_columns(&conn)?;
        Self::ensure_conversations_metadata_columns(&conn)?;
        Self::ensure_conversations_sequencer_column(&conn)?;
        Self::ensure_conversations_quarantine_columns(&conn)?;
        Self::ensure_message_field_columns(&conn)?;
        Self::ensure_message_field_migration_v1(&conn)?;
        Ok(())
    }

    /// Add the field-level-encryption columns to the `messages` table on
    /// pre-cutover installs. New installs already get these columns from the
    /// `CREATE TABLE` above implicitly via the migration path; this helper
    /// is the only place that adds them so the column list stays in one place.
    /// `text` stays `NOT NULL` because making it nullable would require a full
    /// table rebuild on SQLite; encrypted rows write an empty string into it
    /// and put the real payload in `payload_encrypted`.
    fn ensure_message_field_columns(conn: &Connection) -> std::result::Result<(), rusqlite::Error> {
        let existing: std::collections::HashSet<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(1))?;
            rows.filter_map(|r| r.ok()).collect()
        };
        if !existing.contains("payload_encrypted") {
            conn.execute("ALTER TABLE messages ADD COLUMN payload_encrypted BLOB", [])?;
        }
        if !existing.contains("entry_hmac") {
            conn.execute("ALTER TABLE messages ADD COLUMN entry_hmac BLOB", [])?;
        }
        if !existing.contains("payload_key_version") {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN payload_key_version INTEGER",
                [],
            )?;
        }
        // Tombstone parity with iOS/Android: catmos desktop does not currently
        // expose user-initiated message delete, but the columns are added now
        // so that when a delete path lands later it can soft-delete without
        // another schema migration breaking the HMAC chain.
        if !existing.contains("is_tombstone") {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN is_tombstone INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if !existing.contains("deleted_at") {
            conn.execute("ALTER TABLE messages ADD COLUMN deleted_at INTEGER", [])?;
        }
        Ok(())
    }

    /// First-run drop of any pre-field-encryption message rows. Matches the
    /// `MLSPlaintextHeaderMigration` precedent on iOS / Android: existing
    /// transcripts cannot satisfy the encrypted-row invariants (no HMAC chain
    /// seed, no per-conversation content key derivation history), so we drop
    /// them once and record the migration in a `migration_status` table so
    /// it is never re-run.
    fn ensure_message_field_migration_v1(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS migration_status (
                name TEXT PRIMARY KEY,
                applied_at INTEGER NOT NULL
            )",
            [],
        )?;
        let already: i64 = conn.query_row(
            "SELECT COUNT(*) FROM migration_status WHERE name = ?1",
            ["MLSMessageFieldMigrationV1"],
            |r| r.get(0),
        )?;
        if already > 0 {
            return Ok(());
        }
        conn.execute("DELETE FROM messages", [])?;
        conn.execute(
            "INSERT INTO migration_status (name, applied_at) VALUES (?1, strftime('%s','now'))",
            ["MLSMessageFieldMigrationV1"],
        )?;
        Ok(())
    }

    /// Layer 3 quarantine: add `quarantine_reason_tag` + `quarantine_since_ms`
    /// columns to existing installs. New schemas already have them via the
    /// `CREATE TABLE` above; this idempotent migration covers upgrades.
    /// Mirrors the `ensure_conversations_reset_pending_columns` pattern.
    fn ensure_conversations_quarantine_columns(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(conversations)")?;
        let mut has_quarantine_reason_tag = false;
        let mut has_quarantine_since_ms = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            match column_name?.as_str() {
                "quarantine_reason_tag" => has_quarantine_reason_tag = true,
                "quarantine_since_ms" => has_quarantine_since_ms = true,
                _ => {}
            }
        }

        if !has_quarantine_reason_tag {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN quarantine_reason_tag TEXT",
                [],
            )?;
        }
        if !has_quarantine_since_ms {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN quarantine_since_ms INTEGER",
                [],
            )?;
        }
        Ok(())
    }

    /// Add the encrypted-metadata bookkeeping columns to `conversations` for
    /// pre-cutover databases. New schemas already include these columns from
    /// `CREATE TABLE`, but existing installs need an in-place migration.
    /// Each ALTER is guarded by a PRAGMA inspection so re-running is a no-op.
    fn ensure_conversations_metadata_columns(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(conversations)")?;
        let mut has_metadata_version = false;
        let mut has_metadata_blob_locator = false;
        let mut has_avatar_blob_locator = false;
        let mut has_avatar_bytes = false;
        let mut has_avatar_content_type = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            match column_name?.as_str() {
                "metadata_version" => has_metadata_version = true,
                "metadata_blob_locator" => has_metadata_blob_locator = true,
                "avatar_blob_locator" => has_avatar_blob_locator = true,
                "avatar_bytes" => has_avatar_bytes = true,
                "avatar_content_type" => has_avatar_content_type = true,
                _ => {}
            }
        }

        if !has_metadata_version {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN metadata_version INTEGER",
                [],
            )?;
        }
        if !has_metadata_blob_locator {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN metadata_blob_locator TEXT",
                [],
            )?;
        }
        if !has_avatar_blob_locator {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN avatar_blob_locator TEXT",
                [],
            )?;
        }
        if !has_avatar_bytes {
            conn.execute("ALTER TABLE conversations ADD COLUMN avatar_bytes BLOB", [])?;
        }
        if !has_avatar_content_type {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN avatar_content_type TEXT",
                [],
            )?;
        }
        Ok(())
    }

    fn ensure_conversations_sequencer_column(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(conversations)")?;
        let mut has_sequencer_did = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            if column_name? == "sequencer_did" {
                has_sequencer_did = true;
            }
        }

        if !has_sequencer_did {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN sequencer_did TEXT",
                [],
            )?;
        }
        Ok(())
    }

    fn ensure_conversations_reset_pending_columns(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(conversations)")?;
        let mut has_reset_new_group_id = false;
        let mut has_reset_generation = false;
        let mut has_reset_notified_at_ms = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            match column_name?.as_str() {
                "reset_new_group_id" => has_reset_new_group_id = true,
                "reset_generation" => has_reset_generation = true,
                "reset_notified_at_ms" => has_reset_notified_at_ms = true,
                _ => {}
            }
        }

        if !has_reset_new_group_id {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN reset_new_group_id TEXT",
                [],
            )?;
        }
        if !has_reset_generation {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN reset_generation INTEGER",
                [],
            )?;
        }
        if !has_reset_notified_at_ms {
            conn.execute(
                "ALTER TABLE conversations ADD COLUMN reset_notified_at_ms INTEGER",
                [],
            )?;
        }
        Ok(())
    }

    fn ensure_messages_delivery_status_column(
        conn: &Connection,
    ) -> std::result::Result<(), rusqlite::Error> {
        let mut stmt = conn.prepare("PRAGMA table_info(messages)")?;
        let mut has_delivery_status_json = false;
        let mut has_payload_json = false;
        let column_names = stmt.query_map([], |row| row.get::<_, String>(1))?;

        for column_name in column_names {
            match column_name?.as_str() {
                "delivery_status_json" => has_delivery_status_json = true,
                "payload_json" => has_payload_json = true,
                _ => {}
            }
        }

        if !has_delivery_status_json {
            conn.execute(
                "ALTER TABLE messages ADD COLUMN delivery_status_json TEXT",
                [],
            )?;
        }

        if !has_payload_json {
            conn.execute("ALTER TABLE messages ADD COLUMN payload_json TEXT", [])?;
        }

        Ok(())
    }

    /// Adopt a new MLS group id for a conversation after a server-initiated
    /// group reset (spec §8.5). catmos stays in the deferred-recovery
    /// architecture: the websocket handler flags `needs_rejoin` and sets
    /// `ConversationState::NeedsRejoin`; this method additionally rewrites
    /// `conversations.group_id` so the subsequent External Commit in the sync
    /// loop targets the new group instead of re-deriving the old one.
    pub fn update_conversation_group_id(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET group_id = ?1 WHERE conversation_id = ?2",
            rusqlite::params![new_group_id_hex, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Rehydrate a `ConversationState::ResetPending` payload from the
    /// persisted columns (spec §8.5). Returns `Some(ResetPending { .. })`
    /// only when all three reset columns are non-NULL — partial rows are
    /// treated as "no payload" and yield `None`. Callers that need to
    /// repopulate the orchestrator's in-memory `conversation_states` map
    /// after restart should consult this helper.
    pub fn get_reset_pending(&self, conversation_id: &str) -> Option<ConversationState> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT reset_new_group_id, reset_generation, reset_notified_at_ms
             FROM conversations WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
            |row| {
                let new_group_id: Option<String> = row.get(0)?;
                let reset_generation: Option<i64> = row.get(1)?;
                let notified_at_ms: Option<i64> = row.get(2)?;
                Ok((new_group_id, reset_generation, notified_at_ms))
            },
        )
        .ok()
        .and_then(|(new_group_id, reset_generation, notified_at_ms)| {
            match (new_group_id, reset_generation, notified_at_ms) {
                (Some(new_group_id), Some(reset_generation), Some(notified_at_ms)) => {
                    Some(ConversationState::ResetPending {
                        new_group_id,
                        reset_generation: reset_generation as i32,
                        notified_at_ms,
                    })
                }
                _ => None,
            }
        })
    }

    /// Persist the decrypted `GroupMetadataV1` payload (as JSON) along with
    /// the version and blob locator that produced it. Avatars are persisted
    /// separately via [`update_avatar_bytes`] so a metadata-only update does
    /// not invalidate cached avatar bytes.
    pub fn update_metadata_json(
        &self,
        conversation_id: &str,
        metadata_json: &str,
        metadata_version: u64,
        metadata_blob_locator: &str,
        avatar_blob_locator: Option<&str>,
        avatar_content_type: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET metadata_json = ?1,
                 metadata_version = ?2,
                 metadata_blob_locator = ?3,
                 avatar_blob_locator = ?4,
                 avatar_content_type = COALESCE(?5, avatar_content_type)
             WHERE conversation_id = ?6",
            rusqlite::params![
                metadata_json,
                metadata_version as i64,
                metadata_blob_locator,
                avatar_blob_locator,
                avatar_content_type,
                conversation_id,
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Persist decrypted avatar bytes alongside their MIME type so the
    /// SvelteKit frontend can render them as a `data:` URL without a second
    /// IPC round-trip per render.
    pub fn update_avatar_bytes(
        &self,
        conversation_id: &str,
        avatar_bytes: &[u8],
        content_type: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET avatar_bytes = ?1,
                 avatar_content_type = COALESCE(?2, avatar_content_type)
             WHERE conversation_id = ?3",
            rusqlite::params![avatar_bytes, content_type, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Read the cached metadata snapshot for a conversation (decrypted JSON +
    /// version + locator). Returns `None` only when the conversation row is
    /// missing; otherwise an all-`None`-fields snapshot indicates "no
    /// bootstrap has run yet for this conversation".
    pub fn get_metadata_snapshot(&self, conversation_id: &str) -> Option<LocalMetadataSnapshot> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT metadata_json, metadata_version, metadata_blob_locator
             FROM conversations WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
            |row| {
                Ok(LocalMetadataSnapshot {
                    metadata_json: row.get(0)?,
                    metadata_version: row.get(1)?,
                    metadata_blob_locator: row.get(2)?,
                })
            },
        )
        .ok()
    }

    /// Read raw avatar bytes + MIME type for a conversation. Returns `None`
    /// when no avatar has been bootstrapped (or has been cleared).
    pub fn get_avatar(&self, conversation_id: &str) -> Option<(Vec<u8>, Option<String>)> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT avatar_bytes, avatar_content_type
             FROM conversations WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
            |row| {
                let bytes: Option<Vec<u8>> = row.get(0)?;
                let ct: Option<String> = row.get(1)?;
                Ok(bytes.map(|b| (b, ct)))
            },
        )
        .ok()
        .flatten()
    }

    /// Persist a per-conversation WebSocket cursor (spec §7.1).
    pub fn set_ws_cursor(&self, conversation_id: &str, cursor: &str) {
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "INSERT OR REPLACE INTO ws_cursors (conversation_id, cursor) VALUES (?1, ?2)",
            rusqlite::params![conversation_id, cursor],
        );
    }

    /// Load a persisted WebSocket cursor for a conversation.
    pub fn get_ws_cursor(&self, conversation_id: &str) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT cursor FROM ws_cursors WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
            |row| row.get(0),
        )
        .ok()
    }
}

#[async_trait]
impl MLSStorageBackend for SqliteStorage {
    async fn ensure_conversation_exists(
        &self,
        user_did: &str,
        conversation_id: &str,
        group_id: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO conversations (conversation_id, user_did, group_id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![conversation_id, user_did, group_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn update_join_info(
        &self,
        conversation_id: &str,
        user_did: &str,
        join_method: JoinMethod,
        join_epoch: u64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let method_str = serde_json::to_string(&join_method)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        conn.execute(
            "UPDATE conversations SET join_method = ?1, join_epoch = ?2
             WHERE conversation_id = ?3 AND user_did = ?4",
            rusqlite::params![method_str, join_epoch, conversation_id, user_did],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_conversation(
        &self,
        user_did: &str,
        conversation_id: &str,
    ) -> Result<Option<ConversationView>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at, sequencer_did
                 FROM conversations WHERE conversation_id = ?1 AND user_did = ?2",
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        let result = stmt
            .query_row(rusqlite::params![conversation_id, user_did], |row| {
                let conversation_id: String = row.get(0)?;
                let group_id: String = row.get(1)?;
                let epoch: u64 = row.get(2)?;
                let members_json: String = row.get(3)?;
                let metadata_json: Option<String> = row.get(4)?;
                let created_at: Option<String> = row.get(5)?;
                let updated_at: Option<String> = row.get(6)?;
                let sequencer_did: Option<String> = row.get(7)?;

                let members: Vec<MemberView> =
                    serde_json::from_str(&members_json).unwrap_or_default();
                let metadata: Option<ConversationMetadata> =
                    metadata_json.and_then(|j| serde_json::from_str(&j).ok());
                let created = created_at.and_then(|s| s.parse().ok());
                let updated = updated_at.and_then(|s| s.parse().ok());

                Ok(ConversationView {
                    group_id,
                    conversation_id,
                    epoch,
                    members,
                    metadata,
                    created_at: created,
                    updated_at: updated,
                    sequencer_did,
                })
            })
            .ok();

        Ok(result)
    }

    async fn list_conversations(&self, user_did: &str) -> Result<Vec<ConversationView>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, group_id, epoch, members_json, metadata_json, created_at, updated_at, sequencer_did
                 FROM conversations WHERE user_did = ?1",
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        let rows = stmt
            .query_map(rusqlite::params![user_did], |row| {
                let conversation_id: String = row.get(0)?;
                let group_id: String = row.get(1)?;
                let epoch: u64 = row.get(2)?;
                let members_json: String = row.get(3)?;
                let metadata_json: Option<String> = row.get(4)?;
                let created_at: Option<String> = row.get(5)?;
                let updated_at: Option<String> = row.get(6)?;
                let sequencer_did: Option<String> = row.get(7)?;

                let members: Vec<MemberView> =
                    serde_json::from_str(&members_json).unwrap_or_default();
                let metadata = metadata_json.and_then(|j| serde_json::from_str(&j).ok());
                let created = created_at.and_then(|s| s.parse().ok());
                let updated = updated_at.and_then(|s| s.parse().ok());

                Ok(ConversationView {
                    group_id,
                    conversation_id,
                    epoch,
                    members,
                    metadata,
                    created_at: created,
                    updated_at: updated,
                    sequencer_did,
                })
            })
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
        }
        Ok(result)
    }

    async fn delete_conversations(&self, user_did: &str, ids: &[&str]) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        for id in ids {
            conn.execute(
                "DELETE FROM conversations WHERE conversation_id = ?1 AND user_did = ?2",
                rusqlite::params![id, user_did],
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    async fn set_conversation_state(
        &self,
        conversation_id: &str,
        state: ConversationState,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let state_str =
            serde_json::to_string(&state).map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        conn.execute(
            "UPDATE conversations SET state = ?1 WHERE conversation_id = ?2",
            rusqlite::params![state_str, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Read the persisted conversation state (spec §8.2). The `state` column
    /// stores a JSON-serialized `ConversationState`, so we round-trip through
    /// serde and the full payload (including `ResetPending {..}`) survives.
    /// Returns `Ok(None)` when the row is missing or the column is NULL/empty.
    async fn get_conversation_state(
        &self,
        conversation_id: &str,
    ) -> Result<Option<ConversationState>> {
        let conn = self.conn.lock().unwrap();
        let state_str: Option<String> = conn
            .query_row(
                "SELECT state FROM conversations WHERE conversation_id = ?1",
                rusqlite::params![conversation_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten();
        let Some(s) = state_str else {
            return Ok(None);
        };
        if s.is_empty() {
            return Ok(None);
        }
        // Fresh installs historically used the SQL default `Active` before
        // state persistence was JSON-backed. Treat that legacy value as the
        // canonical enum so callers can still apply lifecycle freshness gates
        // without accepting an unparseable state as proof of currency.
        if s == "Active" {
            return Ok(Some(ConversationState::Active));
        }
        serde_json::from_str::<ConversationState>(&s)
            .map(Some)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))
    }

    async fn mark_needs_rejoin(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET needs_rejoin = 1 WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn needs_rejoin(&self, conversation_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let val: i32 = conn
            .query_row(
                "SELECT needs_rejoin FROM conversations WHERE conversation_id = ?1",
                rusqlite::params![conversation_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(val != 0)
    }

    async fn clear_rejoin_flag(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET needs_rejoin = 0 WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Persist the RESET_PENDING payload (spec §8.5) so a `groupReset`
    /// observed before a restart survives the restart and the deferred
    /// recovery loop can resume Phase 1 against the new group id.
    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET reset_new_group_id = ?1,
                 reset_generation = ?2,
                 reset_notified_at_ms = ?3
             WHERE conversation_id = ?4",
            rusqlite::params![
                new_group_id_hex,
                reset_generation as i64,
                notified_at_ms,
                conversation_id,
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn clear_reset_pending_for_delete(
        &self,
        conversation_id: &str,
        expected_generation: i32,
    ) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET reset_new_group_id = NULL,
                 reset_generation = NULL,
                 reset_notified_at_ms = NULL
             WHERE conversation_id = ?1 AND reset_generation = ?2",
            rusqlite::params![conversation_id, expected_generation],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(true)
    }

    async fn set_conversation_sequencer(
        &self,
        conversation_id: &str,
        sequencer_did: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations SET sequencer_did = ?1 WHERE conversation_id = ?2",
            rusqlite::params![sequencer_did, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Layer 3 quarantine persistence (spec MLS robustness Layer 3). Mirrors
    /// `mark_reset_pending`: the orchestrator's `enter_quarantine` writes the
    /// JSON-serialized `ConversationState::Quarantined` into `state` (via
    /// `set_conversation_state`) AND calls this hook for the dedicated
    /// columns, so reads (incl. `get_conversation_state`) round-trip through
    /// the existing JSON path while the columns are available for direct UI
    /// queries via `get_quarantine_state` without re-parsing JSON.
    async fn mark_quarantined(
        &self,
        conversation_id: &str,
        reason_tag: &str,
        since_ms: i64,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET quarantine_reason_tag = ?1,
                 quarantine_since_ms = ?2
             WHERE conversation_id = ?3",
            rusqlite::params![reason_tag, since_ms, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn clear_quarantine(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE conversations
             SET quarantine_reason_tag = NULL,
                 quarantine_since_ms = NULL
             WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn store_message(&self, message: &Message) -> Result<()> {
        let delivery_status_json = message
            .delivery_status
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        // Attempt field-level encryption. Falls back to legacy plaintext when
        // the context isn't bound yet OR when the content root key hasn't
        // been installed (initial sync may run before login completes).
        let sealed = self.try_encrypt_message_body(message);

        let conn = self.conn.lock().unwrap();
        match sealed {
            Some((encrypted, entry_hmac)) => {
                conn.execute(
                    "INSERT OR REPLACE INTO messages (id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json, payload_encrypted, entry_hmac, payload_key_version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    rusqlite::params![
                        message.id,
                        message.conversation_id,
                        message.sender_did,
                        // text/payload_json kept blank when the sealed payload
                        // is the source of truth — `text NOT NULL` schema
                        // constraint forces an empty string here, not NULL.
                        "",
                        message.timestamp.to_rfc3339(),
                        message.epoch,
                        message.sequence_number,
                        message.is_own as i32,
                        delivery_status_json,
                        Option::<String>::None,
                        encrypted,
                        entry_hmac,
                        PAYLOAD_KEY_VERSION_V1,
                    ],
                )
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
            }
            None => {
                tracing::warn!(
                    message_id = %message.id,
                    conversation_id = %message.conversation_id,
                    "store_message: field-encryption unavailable; falling back to legacy plaintext columns"
                );
                conn.execute(
                    "INSERT OR REPLACE INTO messages (id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json, payload_encrypted, entry_hmac, payload_key_version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL, NULL)",
                    rusqlite::params![
                        message.id,
                        message.conversation_id,
                        message.sender_did,
                        message.text,
                        message.timestamp.to_rfc3339(),
                        message.epoch,
                        message.sequence_number,
                        message.is_own as i32,
                        delivery_status_json,
                        message.payload_json,
                    ],
                )
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
            }
        }
        Ok(())
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> Result<Vec<Message>> {
        let mls_ctx = self.mls_context_snapshot();
        let conn = self.conn.lock().unwrap();
        let mut result = Vec::new();

        if let Some(before) = before_sequence {
            let mut stmt = conn
                .prepare(
                    "SELECT id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json, payload_encrypted
                     FROM messages WHERE conversation_id = ?1 AND sequence_number < ?2 AND COALESCE(is_tombstone, 0) = 0
                     ORDER BY sequence_number DESC LIMIT ?3",
                )
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            let rows = stmt
                .query_map(rusqlite::params![conversation_id, before, limit], |row| {
                    row_to_message(row, mls_ctx.as_deref())
                })
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            for row in rows {
                result.push(row.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
            }
        } else {
            let mut stmt = conn
                .prepare(
                    "SELECT id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json, payload_encrypted
                     FROM messages WHERE conversation_id = ?1 AND COALESCE(is_tombstone, 0) = 0
                     ORDER BY sequence_number DESC LIMIT ?2",
                )
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            let rows = stmt
                .query_map(rusqlite::params![conversation_id, limit], |row| {
                    row_to_message(row, mls_ctx.as_deref())
                })
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

            for row in rows {
                result.push(row.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
            }
        }

        result.reverse();
        Ok(result)
    }

    async fn message_exists(&self, message_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i32 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE id = ?1",
                rusqlite::params![message_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(count > 0)
    }

    async fn get_sync_cursor(&self, user_did: &str) -> Result<SyncCursor> {
        let conn = self.conn.lock().unwrap();
        let cursor = conn
            .query_row(
                "SELECT conversations_cursor, messages_cursor FROM sync_cursors WHERE user_did = ?1",
                rusqlite::params![user_did],
                |row| {
                    Ok(SyncCursor {
                        conversations_cursor: row.get(0)?,
                        messages_cursor: row.get(1)?,
                    })
                },
            )
            .unwrap_or_default();
        Ok(cursor)
    }

    async fn set_sync_cursor(&self, user_did: &str, cursor: &SyncCursor) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO sync_cursors (user_did, conversations_cursor, messages_cursor)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                user_did,
                cursor.conversations_cursor,
                cursor.messages_cursor,
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn set_group_state(&self, state: &GroupState) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let members_json = serde_json::to_string(&state.members)
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO group_states (group_id, conversation_id, epoch, members_json)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                state.group_id,
                state.conversation_id,
                state.epoch,
                members_json
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn get_group_state(&self, group_id: &str) -> Result<Option<GroupState>> {
        let conn = self.conn.lock().unwrap();
        let result = conn
            .query_row(
                "SELECT group_id, conversation_id, epoch, members_json FROM group_states WHERE group_id = ?1",
                rusqlite::params![group_id],
                |row| {
                    let group_id: String = row.get(0)?;
                    let conversation_id: String = row.get(1)?;
                    let epoch: u64 = row.get(2)?;
                    let members_json: String = row.get(3)?;
                    let members: Vec<String> =
                        serde_json::from_str(&members_json).unwrap_or_default();
                    Ok(GroupState {
                        group_id,
                        conversation_id,
                        epoch,
                        members,
                    })
                },
            )
            .ok();
        Ok(result)
    }

    async fn delete_group_state(&self, group_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM group_states WHERE group_id = ?1",
            rusqlite::params![group_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    // -- Pending Messages (self-echo dedup across restarts, spec §5) --

    async fn store_pending_message(&self, conversation_id: &str, message_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        conn.execute(
            "INSERT OR IGNORE INTO pending_messages (message_id, conversation_id, created_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![message_id, conversation_id, now],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn remove_pending_message(&self, message_id: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn
            .execute(
                "DELETE FROM pending_messages WHERE message_id = ?1",
                rusqlite::params![message_id],
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(rows > 0)
    }

    async fn get_recovery_state(&self) -> Result<PersistedRecoveryState> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT conversation_id, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms
                 FROM recovery_backoffs",
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(PersistedRecoveryBackoff {
                    conversation_id: row.get(0)?,
                    failed_rejoin_count: row.get(1)?,
                    last_attempt_at_ms: row.get(2)?,
                    quarantined_until_ms: row.get(3)?,
                })
            })
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        let mut entries = Vec::new();
        for r in rows {
            entries.push(r.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
        }

        let last_global_rejoin_attempt_at_ms = conn
            .query_row(
                "SELECT val_int FROM recovery_globals WHERE key = 'last_global_rejoin_attempt_at_ms'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;

        Ok(PersistedRecoveryState {
            entries,
            last_global_rejoin_attempt_at_ms,
        })
    }

    async fn set_recovery_backoff(&self, entry: &PersistedRecoveryBackoff) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO recovery_backoffs
             (conversation_id, failed_rejoin_count, last_attempt_at_ms, quarantined_until_ms)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                entry.conversation_id,
                entry.failed_rejoin_count,
                entry.last_attempt_at_ms,
                entry.quarantined_until_ms,
            ],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn clear_recovery_backoff(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM recovery_backoffs WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn set_last_global_rejoin_attempt_at(&self, at_ms: i64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO recovery_globals (key, val_int)
             VALUES ('last_global_rejoin_attempt_at_ms', ?1)",
            rusqlite::params![at_ms],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "get_conversation_state",
            "mark_reset_pending",
            "clear_reset_pending_for_delete",
            "set_conversation_sequencer",
            "mark_quarantined",
            "clear_quarantine",
            "store_pending_message",
            "remove_pending_message",
            "get_recovery_state",
            "set_recovery_backoff",
            "clear_recovery_backoff",
            "set_last_global_rejoin_attempt_at",
        ]
    }
}

fn row_to_message(row: &rusqlite::Row, mls_ctx: Option<&MLSContext>) -> rusqlite::Result<Message> {
    let id: String = row.get(0)?;
    let conversation_id: String = row.get(1)?;
    let sender_did: String = row.get(2)?;
    let legacy_text: String = row.get(3)?;
    let timestamp_str: String = row.get(4)?;
    let epoch: u64 = row.get(5)?;
    let sequence_number: u64 = row.get(6)?;
    let is_own: i32 = row.get(7)?;
    let delivery_status_json: Option<String> = row.get(8)?;
    let legacy_payload_json: Option<String> = row.get(9)?;
    let payload_encrypted: Option<Vec<u8>> = row.get(10)?;

    let timestamp = timestamp_str
        .parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap_or_else(|_| chrono::Utc::now());
    let delivery_status =
        delivery_status_json.and_then(|json| match serde_json::from_str::<DeliveryStatus>(&json) {
            Ok(status) => Some(status),
            Err(err) => {
                tracing::warn!(
                    message_id = %id,
                    error = %err,
                    "Failed to deserialize delivery_status_json; defaulting to None"
                );
                None
            }
        });

    // Prefer the encrypted column when present and the MLS context is bound;
    // fall back to the legacy plaintext columns for rows written during a
    // bootstrap-race window or before the field-encryption migration ran.
    let (text, payload_json) = match (payload_encrypted, mls_ctx) {
        (Some(ref wire), Some(ctx)) if !wire.is_empty() => {
            match ctx.decrypt_message_payload(conversation_id.clone(), wire.clone()) {
                Ok(plaintext) => {
                    match serde_json::from_slice::<CanonicalMessageBodyOwned>(&plaintext) {
                        Ok(body) => (body.text, body.payload_json),
                        Err(err) => {
                            tracing::warn!(
                                message_id = %id,
                                error = %err,
                                "row_to_message: canonical body deserialize failed; row will surface empty text"
                            );
                            (legacy_text, legacy_payload_json)
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!(
                        message_id = %id,
                        error = ?err,
                        "row_to_message: decrypt_message_payload failed; falling back to legacy columns"
                    );
                    (legacy_text, legacy_payload_json)
                }
            }
        }
        // Sealed row read without an MLS context: log loudly. In production
        // the orchestrator owns the context for its lifetime, so this branch
        // should only fire during the bootstrap window before login installs
        // the context. The legacy `text` column will be an empty string here
        // (because the write path put the real payload in `payload_encrypted`),
        // so the UI will surface a blank body — preferable to a panic.
        (Some(_), None) => {
            tracing::error!(
                message_id = %id,
                "row_to_message: sealed row read with no MLS context bound; \
                 payload will surface empty until the context is installed"
            );
            (legacy_text, legacy_payload_json)
        }
        _ => (legacy_text, legacy_payload_json),
    };

    Ok(Message {
        id,
        conversation_id,
        sender_did,
        text,
        timestamp,
        epoch,
        sequence_number,
        is_own: is_own != 0,
        delivery_status,
        payload_json,
    })
}

#[cfg(test)]
mod field_encryption_tests {
    use super::*;
    use catbird_mls::KeychainAccess;
    use catbird_mls::MLSError;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// Minimal in-memory `KeychainAccess` impl used in tests so we don't have
    /// to depend on the OS keychain (which would taint the developer's real
    /// `keyring` store and break parallel test runs).
    struct InMemoryKeychain {
        inner: StdMutex<HashMap<String, Vec<u8>>>,
    }

    impl InMemoryKeychain {
        fn new() -> Self {
            Self {
                inner: StdMutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl KeychainAccess for InMemoryKeychain {
        async fn read(&self, key: String) -> std::result::Result<Option<Vec<u8>>, MLSError> {
            Ok(self.inner.lock().unwrap().get(&key).cloned())
        }
        async fn write(&self, key: String, value: Vec<u8>) -> std::result::Result<(), MLSError> {
            self.inner.lock().unwrap().insert(key, value);
            Ok(())
        }
        async fn delete(&self, key: String) -> std::result::Result<(), MLSError> {
            self.inner.lock().unwrap().remove(&key);
            Ok(())
        }
    }

    /// 32-byte hex key suitable for SQLCipher's `PRAGMA key`.
    const TEST_DB_KEY: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    fn new_temp_storage() -> (tempfile::TempDir, SqliteStorage) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let db_path = tmp.path().join("catmos-test.db");
        let storage =
            SqliteStorage::new(db_path.to_str().unwrap(), TEST_DB_KEY).expect("open SqliteStorage");
        (tmp, storage)
    }

    /// Smoke-test the schema migration: after `SqliteStorage::new` the new
    /// columns must exist on `messages` and the `MLSMessageFieldMigrationV1`
    /// migration row must be present. This is the catmos-desktop equivalent
    /// of the iOS `MLSPlaintextHeaderMigration` migration-status check.
    #[test]
    fn message_field_columns_and_migration_row_exist() {
        let (_tmp, storage) = new_temp_storage();
        let conn = storage.conn.lock().unwrap();

        let mut stmt = conn.prepare("PRAGMA table_info(messages)").unwrap();
        let cols: std::collections::HashSet<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        for required in &[
            "payload_encrypted",
            "entry_hmac",
            "payload_key_version",
            "is_tombstone",
            "deleted_at",
        ] {
            assert!(
                cols.contains(*required),
                "missing required column on messages: {}",
                required
            );
        }

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM migration_status WHERE name = 'MLSMessageFieldMigrationV1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "MLSMessageFieldMigrationV1 row should be present");
    }

    /// Without an MLS context bound, `store_message` must fall back to legacy
    /// plaintext columns rather than panicking — this is the bootstrap-race
    /// path (initial sync may run before login installs the content root key).
    #[tokio::test]
    async fn store_message_falls_back_to_plaintext_without_mls_context() {
        let (_tmp, storage) = new_temp_storage();
        let now = Utc::now();
        let msg = Message {
            id: "msg-1".into(),
            conversation_id: "conv-1".into(),
            sender_did: "did:plc:sender".into(),
            text: "hello bootstrap".into(),
            timestamp: now,
            epoch: 0,
            sequence_number: 1,
            is_own: true,
            delivery_status: None,
            payload_json: None,
        };
        storage.store_message(&msg).await.expect("store");

        let got = storage
            .get_messages("conv-1", 10, None)
            .await
            .expect("read");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "hello bootstrap");
        // Encrypted column should be NULL on the legacy fallback row.
        let conn = storage.conn.lock().unwrap();
        let payload_encrypted: Option<Vec<u8>> = conn
            .query_row(
                "SELECT payload_encrypted FROM messages WHERE id = 'msg-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            payload_encrypted.is_none(),
            "fallback row must leave payload_encrypted NULL"
        );
    }

    #[tokio::test]
    async fn conversation_sequencer_did_round_trips() {
        let (_tmp, storage) = new_temp_storage();
        let user_did = "did:plc:alice";
        let conversation_id = "conv-sequencer";
        let group_id = "group-sequencer";
        let sequencer_did = "did:web:ds-b.example";

        storage
            .ensure_conversation_exists(user_did, conversation_id, group_id)
            .await
            .expect("create conversation");
        storage
            .set_conversation_sequencer(conversation_id, sequencer_did)
            .await
            .expect("persist sequencer");
        assert!(
            storage
                .implemented_optional_methods()
                .contains(&"set_conversation_sequencer"),
            "storage capabilities should report sequencer persistence"
        );

        let got = storage
            .get_conversation(user_did, conversation_id)
            .await
            .expect("load conversation")
            .expect("conversation exists");
        assert_eq!(got.sequencer_did.as_deref(), Some(sequencer_did));

        let listed = storage
            .list_conversations(user_did)
            .await
            .expect("list conversations");
        let listed = listed
            .into_iter()
            .find(|c| c.conversation_id == conversation_id)
            .expect("listed conversation");
        assert_eq!(listed.sequencer_did.as_deref(), Some(sequencer_did));
    }

    /// Full roundtrip: install a content-root key on an ephemeral
    /// `MLSContext`, write a message via `store_message` (encrypts + chains
    /// HMAC), read it back via `get_messages` (decrypts), and verify the
    /// payload survives. Also verifies that the encrypted column and the
    /// HMAC tag are persisted (not just the legacy plaintext fallback).
    #[tokio::test]
    async fn message_round_trip_with_field_encryption() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let storage_db = tmp.path().join("catmos-test.db");
        let mls_db = tmp.path().join("mls-test.db");

        let storage = SqliteStorage::new(storage_db.to_str().unwrap(), TEST_DB_KEY)
            .expect("open SqliteStorage");

        let keychain: Box<dyn KeychainAccess> = Box::new(InMemoryKeychain::new());
        let mls_ctx = catbird_mls::MLSContext::new(
            mls_db.to_string_lossy().to_string(),
            TEST_DB_KEY.to_string(),
            keychain,
        )
        .expect("construct MLSContext");
        mls_ctx
            .set_content_root_key(vec![0x42u8; 32])
            .expect("set content root key");
        storage.set_mls_context(mls_ctx.clone());

        let now = Utc::now();
        let msg = Message {
            id: "msg-rt".into(),
            conversation_id: "conv-rt".into(),
            sender_did: "did:plc:sender".into(),
            text: "round-trip body".into(),
            timestamp: now,
            epoch: 0,
            sequence_number: 1,
            is_own: true,
            delivery_status: None,
            payload_json: Some(
                r#"{"version":1,"messageType":"text","text":"round-trip body"}"#.into(),
            ),
        };
        storage.store_message(&msg).await.expect("store");

        // The encrypted column and HMAC tag must be persisted; the legacy
        // text column should hold an empty string (NOT NULL constraint).
        {
            let conn = storage.conn.lock().unwrap();
            let (payload_encrypted, entry_hmac, text, payload_key_version): (
                Option<Vec<u8>>,
                Option<Vec<u8>>,
                String,
                Option<i64>,
            ) = conn
                .query_row(
                    "SELECT payload_encrypted, entry_hmac, text, payload_key_version FROM messages WHERE id = 'msg-rt'",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert!(
                payload_encrypted
                    .as_ref()
                    .map(|b| !b.is_empty())
                    .unwrap_or(false),
                "payload_encrypted must be populated"
            );
            assert!(
                entry_hmac.as_ref().map(|b| !b.is_empty()).unwrap_or(false),
                "entry_hmac must be populated"
            );
            assert_eq!(
                text, "",
                "legacy text column should be empty for sealed rows"
            );
            assert_eq!(payload_key_version, Some(1));
        }

        // Read back through the public API — should decrypt and restore the
        // original text + payload_json.
        let got = storage
            .get_messages("conv-rt", 10, None)
            .await
            .expect("read");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].text, "round-trip body");
        assert_eq!(
            got[0].payload_json.as_deref(),
            Some(r#"{"version":1,"messageType":"text","text":"round-trip body"}"#)
        );
    }

    /// HMAC chain: two messages on the same conversation should chain — the
    /// second row's HMAC must be a function of the first row's HMAC, so
    /// rewriting the second row's prev-hmac input (via tampering or replay)
    /// is detectable. We just assert the tags are different and non-empty
    /// here; full chain verification is the Rust core's responsibility.
    #[tokio::test]
    async fn hmac_chain_advances_per_row() {
        let tmp = tempfile::tempdir().unwrap();
        let storage_db = tmp.path().join("catmos-test.db");
        let mls_db = tmp.path().join("mls-test.db");
        let storage = SqliteStorage::new(storage_db.to_str().unwrap(), TEST_DB_KEY).unwrap();
        let keychain: Box<dyn KeychainAccess> = Box::new(InMemoryKeychain::new());
        let mls_ctx = catbird_mls::MLSContext::new(
            mls_db.to_string_lossy().to_string(),
            TEST_DB_KEY.to_string(),
            keychain,
        )
        .unwrap();
        mls_ctx.set_content_root_key(vec![0x11u8; 32]).unwrap();
        storage.set_mls_context(mls_ctx);

        let now = Utc::now();
        for (id, seq) in [("m1", 1u64), ("m2", 2u64)] {
            let msg = Message {
                id: id.into(),
                conversation_id: "conv-chain".into(),
                sender_did: "did:plc:s".into(),
                text: format!("body-{}", id),
                timestamp: now,
                epoch: 0,
                sequence_number: seq,
                is_own: false,
                delivery_status: None,
                payload_json: None,
            };
            storage.store_message(&msg).await.unwrap();
        }
        let conn = storage.conn.lock().unwrap();
        let h1: Vec<u8> = conn
            .query_row("SELECT entry_hmac FROM messages WHERE id = 'm1'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let h2: Vec<u8> = conn
            .query_row("SELECT entry_hmac FROM messages WHERE id = 'm2'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(h1.len(), 32);
        assert_eq!(h2.len(), 32);
        assert_ne!(h1, h2, "chained HMACs should differ");
    }

    /// Tombstone visibility filter: rows flagged `is_tombstone = 1` must be
    /// excluded from `get_messages`. catmos desktop doesn't currently expose
    /// user-initiated delete, but the schema parity contract requires the
    /// read path to honor the flag for when iOS/Android replicate a delete.
    #[tokio::test]
    async fn tombstoned_rows_are_excluded_from_get_messages() {
        let (_tmp, storage) = new_temp_storage();
        let now = Utc::now();
        for (id, seq) in [("msg-a", 1u64), ("msg-b", 2u64), ("msg-c", 3u64)] {
            let msg = Message {
                id: id.into(),
                conversation_id: "conv-x".into(),
                sender_did: "did:plc:sender".into(),
                text: format!("body-{}", id),
                timestamp: now,
                epoch: 0,
                sequence_number: seq,
                is_own: false,
                delivery_status: None,
                payload_json: None,
            };
            storage.store_message(&msg).await.unwrap();
        }
        // Tombstone msg-b out of band.
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute(
                "UPDATE messages SET is_tombstone = 1, deleted_at = strftime('%s','now') WHERE id = 'msg-b'",
                [],
            )
            .unwrap();
        }
        let got = storage.get_messages("conv-x", 10, None).await.unwrap();
        let ids: Vec<&str> = got.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["msg-a", "msg-c"]);
    }
}
