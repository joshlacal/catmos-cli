use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension};
use std::collections::{HashMap, HashSet};
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

    /// Seal new message content. Existing authenticated rows retain their
    /// original ciphertext and tag when mutable delivery metadata changes.
    fn encrypt_message_body(
        message: &Message,
        ctx: Option<&MLSContext>,
    ) -> Result<Option<Vec<u8>>> {
        let Some(ctx) = ctx else { return Ok(None) };
        let plaintext = serde_json::to_vec(&CanonicalMessageBody {
            text: &message.text,
            payload_json: message.payload_json.as_deref(),
        })
        .map_err(storage_error)?;
        match ctx.encrypt_message_payload(message.conversation_id.clone(), plaintext) {
            Ok(payload) => Ok(Some(payload)),
            // Preserve the existing bootstrap window until its content root
            // is available; other cryptographic failures must remain errors.
            Err(catbird_mls::MLSError::InvalidState(_)) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
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

            CREATE TABLE IF NOT EXISTS conversation_group_aliases (
                conversation_id TEXT NOT NULL,
                user_did TEXT NOT NULL,
                group_id TEXT NOT NULL,
                first_seen_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                PRIMARY KEY (conversation_id, user_did, group_id)
            );

            CREATE INDEX IF NOT EXISTS idx_conversation_group_aliases_group
                ON conversation_group_aliases(group_id);

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

            CREATE TABLE IF NOT EXISTS pending_local_deletes (
                conversation_id TEXT PRIMARY KEY,
                group_id_hex TEXT
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
        // NULL identifies pre-fix rows. Reads authenticate their original
        // append order; the first append records an order only after every
        // existing tag verifies. No ciphertext or HMAC is rewritten.
        if !existing.contains("hmac_sequence") {
            conn.execute("ALTER TABLE messages ADD COLUMN hmac_sequence INTEGER", [])?;
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
            "INSERT OR IGNORE INTO conversation_group_aliases
             (conversation_id, user_did, group_id)
             SELECT conversation_id, user_did, group_id
             FROM conversations WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        conn.execute(
            "UPDATE conversations SET group_id = ?1 WHERE conversation_id = ?2",
            rusqlite::params![new_group_id_hex, conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        conn.execute(
            "INSERT OR IGNORE INTO conversation_group_aliases
             (conversation_id, user_did, group_id)
             SELECT conversation_id, user_did, group_id
             FROM conversations WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Return every group source historically owned by a stable conversation.
    /// Each source remains available for independent field decryption/HMAC
    /// verification; callers may normalize only after those checks succeed.
    pub fn list_conversation_group_ids(&self, conversation_id: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT group_id FROM conversations WHERE conversation_id = ?1
                 UNION
                 SELECT group_id FROM conversation_group_aliases WHERE conversation_id = ?1",
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params![conversation_id], |row| row.get(0))
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        let group_ids: Vec<String> = rows
            .map(|row| row.map_err(|e| OrchestratorError::Storage(e.to_string())))
            .collect::<Result<Vec<_>>>()?;
        for group_id in &group_ids {
            let owners = historical_group_owners(&conn, group_id)?;
            if owners.len() > 1
                || owners
                    .iter()
                    .next()
                    .is_some_and(|owner| owner != conversation_id)
            {
                return Err(OrchestratorError::Storage(format!(
                    "historical MLS group {group_id} has ambiguous ownership"
                )));
            }
        }
        Ok(group_ids)
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

impl SqliteStorage {
    /// Return all source IDs that may contain history for a stable
    /// conversation. Historical rows are intentionally left under their
    /// original IDs because both encryption and HMAC bind that exact value.
    fn message_source_ids(&self, conversation_id: &str) -> Result<(String, Vec<String>)> {
        let conn = self.conn.lock().unwrap();
        let mut source_ids = HashSet::from([conversation_id.to_string()]);

        // Exact stable IDs win over any legacy group spelling collision.
        let has_stable_row: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM conversations WHERE conversation_id = ?1)",
                rusqlite::params![conversation_id],
                |row| row.get(0),
            )
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        let stable_id = if has_stable_row {
            conversation_id.to_string()
        } else {
            let owners = historical_group_owners(&conn, conversation_id)?;
            if owners.len() > 1 {
                return Err(OrchestratorError::Storage(format!(
                    "ambiguous historical group mapping for {conversation_id}"
                )));
            }
            if let Some(owner) = owners.into_iter().next() {
                let mut owner_stmt = conn
                    .prepare(
                        "SELECT group_id FROM conversations WHERE conversation_id = ?1
                         UNION
                         SELECT group_id FROM conversation_group_aliases WHERE conversation_id = ?1",
                    )
                    .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
                let owner_rows = owner_stmt
                    .query_map(rusqlite::params![owner], |row| row.get::<_, String>(0))
                    .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
                for group_id in owner_rows {
                    source_ids
                        .insert(group_id.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
                }
                owner
            } else {
                conversation_id.to_string()
            }
        };

        if has_stable_row {
            let mut exact_stmt = conn
                .prepare(
                    "SELECT group_id FROM conversations WHERE conversation_id = ?1
                     UNION
                     SELECT group_id FROM conversation_group_aliases WHERE conversation_id = ?1",
                )
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
            let exact_rows = exact_stmt
                .query_map(rusqlite::params![conversation_id], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
            for group_id in exact_rows {
                source_ids.insert(group_id.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
            }
        }

        for source_id in &source_ids {
            let owners = historical_group_owners(&conn, source_id)?;
            if owners.len() > 1 || owners.iter().any(|owner| owner != &stable_id) {
                return Err(OrchestratorError::Storage(format!(
                    "historical MLS group {source_id} has ambiguous ownership"
                )));
            }
        }
        Ok((stable_id, source_ids.into_iter().collect()))
    }
}

/// Return the canonical stable owners for a group source. A legacy row whose
/// conversation ID equals the group spelling is ignored when a stable owner
/// also claims the source, so it cannot create a false second owner.
fn historical_group_owners(conn: &Connection, group_id: &str) -> Result<HashSet<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT conversation_id FROM conversations WHERE group_id = ?1
             UNION
             SELECT conversation_id FROM conversation_group_aliases WHERE group_id = ?1",
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
    let rows = stmt
        .query_map(rusqlite::params![group_id], |row| row.get::<_, String>(0))
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
    let all: HashSet<String> = rows
        .map(|row| row.map_err(|e| OrchestratorError::Storage(e.to_string())))
        .collect::<std::result::Result<_, _>>()?;
    let canonical: HashSet<String> = all
        .iter()
        .filter(|owner| owner.as_str() != group_id)
        .cloned()
        .collect();
    Ok(if canonical.is_empty() { all } else { canonical })
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
        conn.execute(
            "INSERT OR IGNORE INTO conversation_group_aliases
             (conversation_id, user_did, group_id) VALUES (?1, ?2, ?3)",
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
                    canonical_state: None,
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
                    canonical_state: None,
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

    /// Publish full reset authority before native code may retire a predecessor.
    async fn mark_reset_pending(
        &self,
        conversation_id: &str,
        new_group_id_hex: &str,
        reset_generation: i32,
        notified_at_ms: i64,
    ) -> Result<()> {
        if conversation_id.is_empty() || !valid_reset_target(new_group_id_hex) || reset_generation < 0 {
            return Err(storage_error("invalid reset authority shape"));
        }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(storage_error)?;
        let row = read_reset_projection(&tx, conversation_id)?
            .ok_or_else(|| storage_error("reset authority has no unique conversation owner"))?;
        let state = row.valid_state().ok_or_else(|| storage_error("inconsistent persisted reset authority"))?;
        if state == ConversationState::Closed {
            return Err(storage_error("closed conversation cannot be reset"));
        }
        let replay = match state {
            ConversationState::ResetPending { .. } => {
                let (target, generation, notified) = row.pending_tuple(false)
                    .ok_or_else(|| storage_error("incomplete persisted reset authority"))?;
                if reset_generation < generation
                    || (reset_generation == generation && (target != new_group_id_hex || notified != notified_at_ms))
                {
                    return Err(storage_error("stale or conflicting reset authority"));
                }
                reset_generation == generation
            }
            _ => {
                if row.target.is_some() || row.notified.is_some()
                    || row.generation.is_some_and(|generation| i64::from(reset_generation) <= generation)
                {
                    return Err(storage_error("stale or incomplete reset authority"));
                }
                false
            }
        };
        let reset_state = serde_json::to_string(&ConversationState::ResetPending {
            new_group_id: new_group_id_hex.into(), reset_generation, notified_at_ms,
        }).map_err(storage_error)?;
        // Exact replay is a no-op unless a later route/quarantine writer needs
        // reconciliation. All quarantine representations clear in this commit.
        if !replay || row.needs_rejoin != 1 || row.quarantine_reason.is_some() || row.quarantine_since.is_some() {
            let changed = tx.execute(
                "UPDATE conversations SET state=?1, reset_new_group_id=?2, reset_generation=?3,
                    reset_notified_at_ms=?4, needs_rejoin=1,
                    quarantine_reason_tag=NULL, quarantine_since_ms=NULL
                 WHERE conversation_id=?5 AND user_did=?6",
                rusqlite::params![reset_state,new_group_id_hex,reset_generation,notified_at_ms,conversation_id,row.user_did],
            ).map_err(storage_error)?;
            if changed != 1 { return Err(storage_error("reset publication did not update its owner")); }
        }
        tx.execute("DELETE FROM recovery_backoffs WHERE conversation_id=?1", [conversation_id]).map_err(storage_error)?;
        tx.commit().map_err(storage_error)?;
        Ok(())
    }

    /// Change only the pending target after native verifies the winning Welcome.
    async fn adopt_reset_pending_target(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> Result<bool> {
        if conversation_id.is_empty() || expected_generation < 0
            || !valid_reset_target(expected_old_target) || !valid_reset_target(authoritative_new_target)
        { return Ok(false); }
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(storage_error)?;
        let Some(row) = read_reset_projection(&tx, conversation_id)? else { return Ok(false) };
        let Some((target,generation,notified)) = row.pending_tuple(true) else { return Ok(false) };
        if target != expected_old_target || generation != expected_generation
            || persisted_reset_quarantine(&tx, conversation_id)?
        { return Ok(false); }
        if target == authoritative_new_target { return Ok(true); }
        let state = serde_json::to_string(&ConversationState::ResetPending {
            new_group_id: authoritative_new_target.into(), reset_generation: generation, notified_at_ms: notified,
        }).map_err(storage_error)?;
        let changed = tx.execute(
            "UPDATE conversations SET state=?1, reset_new_group_id=?2, needs_rejoin=1
             WHERE conversation_id=?3 AND user_did=?4",
            rusqlite::params![state,authoritative_new_target,conversation_id,row.user_did],
        ).map_err(storage_error)?;
        if changed != 1 { return Ok(false); }
        tx.commit().map_err(storage_error)?;
        Ok(true)
    }

    /// Complete only the exact pending authority. History retains its original
    /// group/AAD, while the durable generation high-water survives completion.
    async fn complete_reset_pending(
        &self,
        conversation_id: &str,
        expected_generation: i32,
        expected_new_group_id_hex: &str,
        landed_epoch: u64,
    ) -> Result<bool> {
        if conversation_id.is_empty() || expected_generation < 0 || !valid_reset_target(expected_new_group_id_hex) {
            return Ok(false);
        }
        let landed_epoch = i64::try_from(landed_epoch).map_err(storage_error)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(storage_error)?;
        let Some(row) = read_reset_projection(&tx, conversation_id)? else { return Ok(false) };
        // Exact post-commit retry reads the durable completion without changing
        // aliases, timestamps or any message/crypto row.
        if row.valid_state() == Some(ConversationState::Active)
            && row.target.is_none() && row.notified.is_none()
            && row.generation == Some(i64::from(expected_generation))
            && row.group_id == expected_new_group_id_hex
            && row.epoch == landed_epoch && row.join_epoch == Some(landed_epoch)
            && row.needs_rejoin == 0 && row.quarantine_reason.is_none() && row.quarantine_since.is_none()
            && !persisted_reset_quarantine(&tx, conversation_id)?
        { return Ok(true); }
        let Some((target,generation,_)) = row.pending_tuple(true) else { return Ok(false) };
        if target != expected_new_group_id_hex || generation != expected_generation
            || (row.group_id == expected_new_group_id_hex && row.epoch > landed_epoch)
            || persisted_reset_quarantine(&tx, conversation_id)?
        { return Ok(false); }
        for group_id in [row.group_id.as_str(), expected_new_group_id_hex] {
            tx.execute(
                "INSERT OR IGNORE INTO conversation_group_aliases (conversation_id,user_did,group_id) VALUES (?1,?2,?3)",
                rusqlite::params![conversation_id,row.user_did,group_id],
            ).map_err(storage_error)?;
        }
        let changed = tx.execute(
            "UPDATE conversations SET group_id=?1,epoch=?2,join_epoch=?2,state='Active',
                reset_new_group_id=NULL,reset_notified_at_ms=NULL,needs_rejoin=0
             WHERE conversation_id=?3 AND user_did=?4",
            rusqlite::params![expected_new_group_id_hex,landed_epoch,conversation_id,row.user_did],
        ).map_err(storage_error)?;
        if changed != 1 { return Ok(false); }
        tx.commit().map_err(storage_error)?;
        Ok(true)
    }

    /// Retire only the coordinates whose accepted terminal proof the native
    /// caller has archived. This never imports crypto or projects Active.
    async fn complete_account_exit(
        &self,
        conversation_id: &str,
        expected_group_id_hex: &str,
        expected_reset_generation: Option<i32>,
        terminal_epoch: u64,
        terminal_state: ConversationState,
    ) -> Result<bool> {
        let canonical_id = uuid::Uuid::parse_str(conversation_id).is_ok_and(|id|
            id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122
                && id.to_string() == conversation_id);
        if !canonical_id
            || expected_group_id_hex.len() != 64
            || !expected_group_id_hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || expected_reset_generation.is_some_and(|generation| generation <= 0)
            || !matches!(terminal_state, ConversationState::Closed | ConversationState::DeviceRemoved)
        {
            return Ok(false);
        }
        if terminal_epoch > 9_007_199_254_740_991 {
            return Err(storage_error("account exit epoch exceeds canonical integer range"));
        }
        let terminal_epoch = i64::try_from(terminal_epoch).map_err(storage_error)?;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(storage_error)?;
        let rows = {
            let mut statement = tx.prepare(
                "SELECT user_did, group_id, epoch, state, reset_new_group_id,
                        reset_generation, reset_notified_at_ms
                 FROM conversations WHERE conversation_id = ?1",
            ).map_err(storage_error)?;
            let rows = statement.query_map([conversation_id], |row| Ok((
                row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?, row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<i64>>(5)?, row.get::<_, Option<i64>>(6)?,
            ))).map_err(storage_error)?;
            rows.collect::<std::result::Result<Vec<_>, _>>().map_err(storage_error)?
        };
        // The callback has no user-DID parameter; an ambiguous shared bucket
        // must never update more than one account's projection.
        let [(user_did, group_id, epoch, state_json, target, generation, notified)] = rows.as_slice() else {
            return Ok(false);
        };
        let state = if state_json == "Active" { ConversationState::Active } else {
            match serde_json::from_str::<ConversationState>(state_json) {
                Ok(state) => state,
                Err(_) => return Ok(false),
            }
        };
        if *epoch < 0 || generation.is_some_and(|generation| generation < 0) {
            return Ok(false);
        }
        let pending = match (target.as_deref(), *generation, *notified) {
            (None, _, None) => None,
            (Some(target), Some(generation), Some(notified)) if !target.is_empty() => Some((target, generation, notified)),
            _ => return Ok(false),
        };
        if let ConversationState::ResetPending { new_group_id, reset_generation, notified_at_ms } = &state {
            if pending != Some((new_group_id.as_str(), i64::from(*reset_generation), *notified_at_ms)) {
                return Ok(false);
            }
        }
        let was_terminal = matches!(state, ConversationState::Closed | ConversationState::DeviceRemoved);
        let was_closed = state == ConversationState::Closed;
        if was_closed && (state != terminal_state || pending.is_some()) {
            return Ok(false);
        }
        let matches = match expected_reset_generation {
            Some(expected) => match pending {
                Some((target, generation, _)) => target == expected_group_id_hex
                    && generation == i64::from(expected)
                    && (group_id != expected_group_id_hex || *epoch <= terminal_epoch),
                None => was_terminal && group_id == expected_group_id_hex
                    && *generation == Some(i64::from(expected))
                    && state == terminal_state && *epoch == terminal_epoch,
            },
            None => pending.is_none() && !matches!(state, ConversationState::ResetPending { .. })
                && group_id == expected_group_id_hex
                && if was_closed { *epoch == terminal_epoch } else { *epoch <= terminal_epoch },
        };
        if !matches { return Ok(false); }
        for alias in [group_id.as_str(), expected_group_id_hex] {
            tx.execute(
                "INSERT OR IGNORE INTO conversation_group_aliases (conversation_id, user_did, group_id) VALUES (?1, ?2, ?3)",
                rusqlite::params![conversation_id, user_did, alias],
            ).map_err(storage_error)?;
        }
        let state_json = serde_json::to_string(&terminal_state).map_err(storage_error)?;
        let changed = tx.execute(
            "UPDATE conversations SET group_id = ?1, epoch = ?2, state = ?3,
                    reset_new_group_id = NULL, reset_notified_at_ms = NULL, needs_rejoin = 0
             WHERE conversation_id = ?4 AND user_did = ?5",
            rusqlite::params![expected_group_id_hex, terminal_epoch, state_json, conversation_id, user_did],
        ).map_err(storage_error)?;
        if changed != 1 { return Ok(false); }
        // reset_generation remains the high-water fence; all message rows,
        // native state, keys and historical aliases remain untouched.
        tx.commit().map_err(storage_error)?;
        Ok(true)
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
            .map_err(storage_error)?;
        let ctx = self.mls_context_snapshot();
        let mut conn = self.conn.lock().unwrap();
        // Predecessor lookup, optional authenticated legacy order adoption,
        // and insert must be one atomic operation even across processes.
        let transaction = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let existing: Option<(String, Option<Vec<u8>>, String, Option<String>)> = transaction.query_row(
            "SELECT conversation_id, payload_encrypted, text, payload_json FROM messages WHERE id=?1",
            rusqlite::params![message.id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(storage_error)?;
        if let Some((bucket, encrypted, legacy_text, legacy_payload)) = existing {
            if bucket != message.conversation_id {
                return Err(storage_error(
                    "a stored message ID cannot move to another conversation",
                ));
            }
            let (text, payload_json) = if let Some(encrypted) = encrypted {
                let ctx = ctx
                    .as_deref()
                    .ok_or_else(|| storage_error("message encryption key is unavailable"))?;
                verified_message_chain(&transaction, Some(ctx), &bucket)?
                    .ok_or_else(|| storage_error("message encryption key is unavailable"))?;
                let plaintext = ctx
                    .decrypt_message_payload(bucket.clone(), encrypted)
                    .map_err(storage_error)?;
                let body: CanonicalMessageBodyOwned =
                    serde_json::from_slice(&plaintext).map_err(storage_error)?;
                (body.text, body.payload_json)
            } else {
                (legacy_text, legacy_payload)
            };
            if text != message.text || payload_json != message.payload_json {
                return Err(storage_error(
                    "conflicting immutable content for an existing message ID",
                ));
            }
            // Delivery status is mutable. Resealing a row would invalidate
            // every subsequent chain link (and could chain a row to itself).
            transaction
                .execute(
                    "UPDATE messages SET delivery_status_json=?2 WHERE id=?1",
                    rusqlite::params![message.id, delivery_status_json],
                )
                .map_err(storage_error)?;
            transaction.commit().map_err(storage_error)?;
            return Ok(());
        }
        let encrypted = Self::encrypt_message_body(message, ctx.as_deref())?;
        let (hmac, hmac_sequence) = if let Some(encrypted) = &encrypted {
            let ctx = ctx.as_deref().unwrap();
            let chain = verified_message_chain(&transaction, Some(ctx), &message.conversation_id)?
                .ok_or_else(|| storage_error("message encryption key is unavailable"))?;
            // Authenticate the entire legacy chain before adopting ordering
            // metadata. Original message payloads and MACs remain byte exact.
            for (index, entry) in chain.iter().enumerate() {
                if entry.sequence.is_none() {
                    transaction.execute("UPDATE messages SET hmac_sequence=?2 WHERE id=?1 AND hmac_sequence IS NULL",
                        rusqlite::params![entry.id, index as i64 + 1]).map_err(storage_error)?;
                }
            }
            let previous = chain.last().map(|entry| entry.hmac.clone());
            let tag = ctx
                .compute_message_hmac(
                    message.conversation_id.clone(),
                    previous,
                    message.id.clone(),
                    encrypted.clone(),
                )
                .map_err(storage_error)?;
            (Some(tag), Some(chain.len() as i64 + 1))
        } else {
            (None, None)
        };
        transaction.execute(
            "INSERT INTO messages (id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json, payload_encrypted, entry_hmac, payload_key_version, hmac_sequence)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
            rusqlite::params![message.id,message.conversation_id,message.sender_did,
                if encrypted.is_some() { "" } else { message.text.as_str() },
                message.timestamp.to_rfc3339(),message.epoch,message.sequence_number,message.is_own as i32,
                delivery_status_json,if encrypted.is_some() { None } else { message.payload_json.as_deref() },
                encrypted,hmac,hmac_sequence.map(|_| PAYLOAD_KEY_VERSION_V1),hmac_sequence],
        ).map_err(storage_error)?;
        transaction.commit().map_err(storage_error)?;
        Ok(())
    }

    async fn get_messages(
        &self,
        conversation_id: &str,
        limit: u32,
        before_sequence: Option<u64>,
    ) -> Result<Vec<Message>> {
        let (stable_conversation_id, source_ids) = self.message_source_ids(conversation_id)?;
        let mls_ctx = self.mls_context_snapshot();
        let mut conn = self.conn.lock().unwrap();
        // Verify and project the same snapshot even if another process
        // appends or updates message rows while this page is being read.
        let transaction = conn.transaction().map_err(storage_error)?;
        let mut by_id = HashMap::new();
        for source_id in source_ids {
            // Sender generation and delivery order are not append order.
            // Authenticate the complete source bucket before selecting a page.
            verified_message_chain(&transaction, mls_ctx.as_deref(), &source_id)?;
            let mut stmt = transaction.prepare(
                "SELECT id, conversation_id, sender_did, text, timestamp, epoch, sequence_number, is_own, delivery_status_json, payload_json, payload_encrypted, entry_hmac, is_tombstone
                 FROM messages WHERE conversation_id=?1 ORDER BY sequence_number ASC",
            ).map_err(storage_error)?;
            let rows = stmt
                .query_map(rusqlite::params![source_id], |row| {
                    Ok((
                        row_to_message(row, mls_ctx.as_deref())?,
                        row.get::<_, i64>(12)? != 0,
                    ))
                })
                .map_err(storage_error)?;
            for row in rows {
                let (message, tombstone) =
                    row.map_err(|e| OrchestratorError::Storage(e.to_string()))?;
                if before_sequence.map_or(true, |before| message.sequence_number < before)
                    && !tombstone
                {
                    merge_or_reject_message(&mut by_id, message)?;
                }
            }
        }
        transaction.commit().map_err(storage_error)?;
        let mut result: Vec<Message> = by_id.into_values().collect();
        result.sort_by(|left, right| {
            // A local send timestamp can be later than the next server entry.
            crate::types::message_order_key(left.sequence_number, &left.timestamp, &left.id)
                .cmp(&crate::types::message_order_key(right.sequence_number, &right.timestamp, &right.id))
        });
        if result.len() > limit as usize {
            result.drain(..result.len() - limit as usize);
        }
        for message in &mut result {
            message.conversation_id = stable_conversation_id.clone();
        }
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

    async fn mark_pending_local_delete(
        &self,
        conversation_id: &str,
        group_id_hex: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO pending_local_deletes (conversation_id, group_id_hex)
             VALUES (?1, ?2)",
            rusqlite::params![conversation_id, group_id_hex],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn clear_pending_local_delete(&self, conversation_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM pending_local_deletes WHERE conversation_id = ?1",
            rusqlite::params![conversation_id],
        )
        .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn list_pending_local_deletes(&self) -> Result<Vec<PendingLocalDelete>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT conversation_id, group_id_hex FROM pending_local_deletes")
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(PendingLocalDelete {
                    conversation_id: row.get(0)?,
                    group_id_hex: row.get(1)?,
                })
            })
            .map_err(|e| OrchestratorError::Storage(e.to_string()))?;
        let mut list = Vec::new();
        for r in rows {
            list.push(r.map_err(|e| OrchestratorError::Storage(e.to_string()))?);
        }
        Ok(list)
    }

    fn implemented_optional_methods(&self) -> &'static [&'static str] {
        &[
            "get_conversation_state",
            "mark_reset_pending",
            "adopt_reset_pending_target",
            "complete_reset_pending",
            "complete_account_exit",
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
            "mark_pending_local_delete",
            "clear_pending_local_delete",
            "list_pending_local_deletes",
        ]
    }
}

/// Match native ValidatedResetTarget: legacy/reset candidates span 16–64
/// bytes and may use uppercase hex. Do not substitute account-exit bounds.
fn valid_reset_target(target: &str) -> bool {
    hex::decode(target).is_ok_and(|bytes| (16..=64).contains(&bytes.len()))
}

struct ResetProjectionRow {
    user_did: String,
    group_id: String,
    epoch: i64,
    join_epoch: Option<i64>,
    state: String,
    target: Option<String>,
    generation: Option<i64>,
    notified: Option<i64>,
    needs_rejoin: i64,
    quarantine_reason: Option<String>,
    quarantine_since: Option<i64>,
}

impl ResetProjectionRow {
    fn valid_state(&self) -> Option<ConversationState> {
        if self.epoch < 0 || self.join_epoch.is_some_and(|epoch| epoch < 0)
            || self.generation.is_some_and(|generation| !(0..=i64::from(i32::MAX)).contains(&generation))
            || !matches!(self.needs_rejoin, 0 | 1)
        { return None; }
        if self.state == "Active" { return Some(ConversationState::Active); }
        let value: serde_json::Value = serde_json::from_str(&self.state).ok()?;
        let state: ConversationState = serde_json::from_str(&self.state).ok()?;
        // Future/unknown payload fields cannot silently disappear on rewrite.
        (serde_json::to_value(&state).ok()? == value).then_some(state)
    }

    fn pending_tuple(&self, require_clean_route: bool) -> Option<(&str, i32, i64)> {
        let ConversationState::ResetPending { new_group_id, reset_generation, notified_at_ms } = self.valid_state()? else { return None };
        let target = self.target.as_deref()?;
        if !valid_reset_target(target) || reset_generation < 0
            || target != new_group_id || self.generation != Some(i64::from(reset_generation))
            || self.notified != Some(notified_at_ms)
            || (require_clean_route && (self.needs_rejoin != 1 || self.quarantine_reason.is_some() || self.quarantine_since.is_some()))
        { return None; }
        Some((target, reset_generation, notified_at_ms))
    }
}

fn read_reset_projection(tx: &rusqlite::Transaction<'_>, conversation_id: &str) -> Result<Option<ResetProjectionRow>> {
    let mut statement = tx.prepare(
        "SELECT user_did,group_id,epoch,join_epoch,state,reset_new_group_id,reset_generation,
                reset_notified_at_ms,needs_rejoin,quarantine_reason_tag,quarantine_since_ms
         FROM conversations WHERE conversation_id=?1",
    ).map_err(storage_error)?;
    let rows = statement.query_map([conversation_id], |row| Ok(ResetProjectionRow {
        user_did: row.get(0)?,group_id: row.get(1)?,epoch: row.get(2)?,join_epoch: row.get(3)?,
        state: row.get(4)?,target: row.get(5)?,generation: row.get(6)?,notified: row.get(7)?,
        needs_rejoin: row.get(8)?,quarantine_reason: row.get(9)?,quarantine_since: row.get(10)?,
    })).map_err(storage_error)?;
    let mut rows = rows.collect::<rusqlite::Result<Vec<_>>>().map_err(storage_error)?;
    // The callback has no DID argument; account ambiguity must not update
    // multiple projections even if all their pending tuples happen to match.
    Ok(if rows.len() == 1 { rows.pop() } else { None })
}

fn persisted_reset_quarantine(tx: &rusqlite::Transaction<'_>, conversation_id: &str) -> Result<bool> {
    tx.query_row("SELECT EXISTS(SELECT 1 FROM recovery_backoffs WHERE conversation_id=?1 AND quarantined_until_ms IS NOT NULL)", [conversation_id], |row| row.get(0)).map_err(storage_error)
}

fn storage_error(error: impl std::fmt::Display) -> OrchestratorError {
    OrchestratorError::Storage(error.to_string())
}

#[derive(Clone)]
struct ChainedMessage {
    id: String,
    payload: Vec<u8>,
    hmac: Vec<u8>,
    sequence: Option<i64>,
}

/// Verify immutable encrypted rows in their local append order, independently
/// of sender generation, timestamp and server delivery sequence. A legacy
/// order can only be recovered by existing authentic tags; never re-MAC data.
fn verified_message_chain(
    conn: &Connection,
    ctx: Option<&MLSContext>,
    bucket: &str,
) -> Result<Option<Vec<ChainedMessage>>> {
    let Some(ctx) = ctx else { return Ok(None) };
    let mut statement = conn.prepare("SELECT id,payload_encrypted,entry_hmac,hmac_sequence FROM messages WHERE conversation_id=?1 ORDER BY hmac_sequence ASC, rowid ASC").map_err(storage_error)?;
    let records = statement
        .query_map(rusqlite::params![bucket], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        })
        .map_err(storage_error)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    let mut entries = Vec::new();
    for (id, payload, hmac, sequence) in records {
        match (payload, hmac) {
            (Some(payload), Some(hmac)) if !payload.is_empty() => entries.push(ChainedMessage {
                id,
                payload,
                hmac,
                sequence,
            }),
            (None, None) if sequence.is_none() => {}
            _ => {
                return Err(storage_error(format!(
                    "incomplete authenticated message in bucket {bucket}"
                )))
            }
        }
    }
    // Assigned ordering is a complete contiguous local sequence. Accepting
    // gaps or mixed legacy rows could make len + 1 sort before the verified
    // tail on the next append, even when the current cryptographic path is
    // authentic. Do not normalize unverified ordering metadata implicitly.
    if entries.iter().any(|entry| entry.sequence.is_some())
        && entries
            .iter()
            .enumerate()
            .any(|(index, entry)| entry.sequence != Some(index as i64 + 1))
    {
        return Err(storage_error(format!(
            "invalid message HMAC ordering in bucket {bucket}; original rows preserved"
        )));
    }
    let verify = |entry: &ChainedMessage, previous: Option<Vec<u8>>| -> Result<Option<bool>> {
        match ctx.verify_message_hmac(
            bucket.into(),
            previous,
            entry.id.clone(),
            entry.payload.clone(),
            entry.hmac.clone(),
        ) {
            Ok(matches) => Ok(Some(matches)),
            Err(catbird_mls::MLSError::InvalidState(_)) => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    };
    let mut previous = None;
    let mut valid = true;
    for entry in &entries {
        match verify(entry, previous)? {
            Some(true) => previous = Some(entry.hmac.clone()),
            Some(false) => {
                valid = false;
                break;
            }
            None => return Ok(None),
        }
    }
    if valid {
        return Ok(Some(entries));
    }
    // Bounded forensic compatibility for old authenticated rows whose order
    // metadata was absent. Branches, missing links and corrupt rows fail; an
    // authentic unique path is returned without changing any row on reads.
    if entries.len() > 256 || entries.iter().any(|entry| entry.sequence.is_some()) {
        return Err(storage_error(format!(
            "message HMAC mismatch in bucket {bucket}; retained rows need integrity review"
        )));
    }
    let mut ordered = Vec::with_capacity(entries.len());
    let mut previous = None;
    while !entries.is_empty() {
        let mut candidate = None;
        for (index, entry) in entries.iter().enumerate() {
            if verify(entry, previous.clone())? == Some(true) {
                if candidate.replace(index).is_some() {
                    return Err(storage_error(format!("legacy message HMAC chain branches in bucket {bucket}; original rows preserved")));
                }
            }
        }
        let index = candidate.ok_or_else(|| {
            storage_error(format!(
                "message HMAC mismatch in bucket {bucket}; original rows preserved"
            ))
        })?;
        let entry = entries.remove(index);
        previous = Some(entry.hmac.clone());
        ordered.push(entry);
    }
    Ok(Some(ordered))
}

fn merge_or_reject_message(by_id: &mut HashMap<String, Message>, message: Message) -> Result<()> {
    if let Some(existing) = by_id.get(&message.id) {
        let same_payload = existing.sender_did == message.sender_did
            && existing.text == message.text
            && existing.timestamp == message.timestamp
            && existing.epoch == message.epoch
            && existing.sequence_number == message.sequence_number
            && existing.is_own == message.is_own
            && existing.delivery_status == message.delivery_status
            && existing.payload_json == message.payload_json;
        if !same_payload {
            return Err(OrchestratorError::Storage(format!(
                "conflicting duplicate message ID {} across conversation buckets",
                message.id
            )));
        }
        return Ok(());
    }
    by_id.insert(message.id.clone(), message);
    Ok(())
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

    #[tokio::test]
    async fn historical_group_aliases_survive_two_resets_and_reopen() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let db_path = tmp.path().join("catmos-aliases.db");
        let conversation_id = "conv-history";
        let user_did = "did:plc:alice";
        let groups = ["group-before-reset", "group-after-reset", "group-latest"];

        {
            let storage =
                SqliteStorage::new(db_path.to_str().unwrap(), TEST_DB_KEY).expect("open storage");
            storage
                .ensure_conversation_exists(user_did, conversation_id, groups[0])
                .await
                .expect("create conversation");
            storage
                .update_conversation_group_id(conversation_id, groups[1])
                .expect("first reset projection");
            storage
                .update_conversation_group_id(conversation_id, groups[2])
                .expect("second reset projection");

            let mut sources = storage
                .list_conversation_group_ids(conversation_id)
                .expect("list historical sources");
            sources.sort();
            let mut expected = groups
                .iter()
                .map(|group| group.to_string())
                .collect::<Vec<_>>();
            expected.sort();
            assert_eq!(sources, expected);
        }

        let reopened =
            SqliteStorage::new(db_path.to_str().unwrap(), TEST_DB_KEY).expect("reopen storage");
        let mut sources = reopened
            .list_conversation_group_ids(conversation_id)
            .expect("list aliases after reopen");
        sources.sort();
        let mut expected = groups
            .iter()
            .map(|group| group.to_string())
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(sources, expected);
    }

    #[tokio::test]
    async fn stable_reads_fail_when_a_historical_group_has_two_owners() {
        let (_tmp, storage) = new_temp_storage();
        storage
            .ensure_conversation_exists("did:plc:alice", "conv-owner-a", "group-a")
            .await
            .expect("create first conversation");
        storage
            .ensure_conversation_exists("did:plc:alice", "conv-owner-b", "group-b")
            .await
            .expect("create second conversation");
        {
            let conn = storage.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO conversation_group_aliases (conversation_id, user_did, group_id)
                 VALUES ('conv-owner-b', 'did:plc:alice', 'group-a')",
                [],
            )
            .expect("create conflicting historical owner");
        }

        assert!(
            storage.list_conversation_group_ids("conv-owner-a").is_err(),
            "stable reads must fail closed when a source has multiple owners"
        );
    }

    fn exit_table_snapshot(storage: &SqliteStorage, table: &str) -> Vec<Vec<rusqlite::types::Value>> {
        let conn = storage.conn.lock().unwrap();
        let mut statement = conn.prepare(&format!("SELECT * FROM {table} ORDER BY rowid")).unwrap();
        let columns = statement.column_count();
        statement.query_map([], |row| (0..columns).map(|column| row.get(column)).collect())
            .unwrap().collect::<std::result::Result<Vec<_>, _>>().unwrap()
    }

    #[tokio::test]
    async fn account_exit_pending_reset_preserves_authenticated_history_and_high_water() {
        let root = tempfile::tempdir().unwrap();
        let storage = hmac_fixture_storage(root.path(), "exit-crypto");
        let id = "8188478e-8d96-4a19-9239-3a2a831b40ea";
        let old_group = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let new_group = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        storage.ensure_conversation_exists("did:plc:alice", id, old_group).await.unwrap();
        storage.set_group_state(&GroupState { group_id: old_group.into(), conversation_id: id.into(), epoch: 9, members: vec![] }).await.unwrap();
        let mut message = hmac_fixture_message("retained-exit", 1);
        message.conversation_id = id.into();
        storage.store_message(&message).await.unwrap();
        storage.mark_reset_pending(id, new_group, 7, 123).await.unwrap();
        storage.set_conversation_state(id, ConversationState::ResetPending { new_group_id: new_group.into(), reset_generation: 7, notified_at_ms: 123 }).await.unwrap();
        storage.mark_needs_rejoin(id).await.unwrap();
        let messages = exit_table_snapshot(&storage, "messages");
        let native_projection = exit_table_snapshot(&storage, "group_states");
        assert!(storage.complete_account_exit(id, new_group, Some(7), 2, ConversationState::Closed).await.unwrap());
        assert_eq!(storage.get_conversation_state(id).await.unwrap(), Some(ConversationState::Closed));
        assert!(!storage.needs_rejoin(id).await.unwrap());
        assert!(storage.get_reset_pending(id).is_none());
        assert_eq!(storage.get_conversation("did:plc:alice", id).await.unwrap().unwrap().group_id, new_group);
        assert_eq!(storage.get_conversation("did:plc:alice", id).await.unwrap().unwrap().epoch, 2);
        assert_eq!(exit_table_snapshot(&storage, "messages"), messages);
        assert_eq!(exit_table_snapshot(&storage, "group_states"), native_projection);
        let generation: Option<i64> = storage.conn.lock().unwrap().query_row("SELECT reset_generation FROM conversations WHERE conversation_id = ?1", [id], |row| row.get(0)).unwrap();
        assert_eq!(generation, Some(7));
        let aliases = storage.list_conversation_group_ids(id).unwrap();
        assert!(aliases.contains(&old_group.to_owned()) && aliases.contains(&new_group.to_owned()));
        assert!(storage.complete_account_exit(id, new_group, Some(7), 2, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit(id, new_group, Some(6), 2, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit(id, new_group, Some(8), 2, ConversationState::Closed).await.unwrap());
        assert!(storage.complete_account_exit(id, new_group, None, 2, ConversationState::Closed).await.unwrap());
        drop(storage);
        let reopened = hmac_fixture_storage(root.path(), "exit-crypto-reloaded");
        assert_eq!(reopened.get_conversation_state(id).await.unwrap(), Some(ConversationState::Closed));
        assert_eq!(reopened.get_messages(id, 10, None).await.unwrap()[0].text, "fixture body retained-exit");
        assert_eq!(exit_table_snapshot(&reopened, "messages"), messages);
    }

    #[tokio::test]
    async fn account_exit_mismatch_and_partial_payload_are_read_only() {
        for case in ["wrong-group", "old-generation", "new-generation", "no-reset-expectation", "partial", "wrong-state-payload", "newer-epoch", "ambiguous-account", "invalid-terminal"] {
            let (_root, storage) = new_temp_storage();
            let id = "8188478e-8d96-4a19-9239-3a2a831b40ea";
            let old_group = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
            let target = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
            storage.ensure_conversation_exists("did:plc:alice", id, old_group).await.unwrap();
            storage.mark_reset_pending(id, target, 7, 123).await.unwrap();
            storage.set_conversation_state(id, ConversationState::ResetPending { new_group_id: target.into(), reset_generation: 7, notified_at_ms: 123 }).await.unwrap();
            let mut expected_group = target;
            let mut expected_generation = Some(7);
            let mut terminal = ConversationState::Closed;
            match case {
                "wrong-group" => expected_group = old_group,
                "old-generation" => expected_generation = Some(6),
                "new-generation" => expected_generation = Some(8),
                "no-reset-expectation" => expected_generation = None,
                "partial" => { storage.conn.lock().unwrap().execute("UPDATE conversations SET reset_notified_at_ms = NULL", []).unwrap(); },
                "wrong-state-payload" => storage.set_conversation_state(id, ConversationState::ResetPending { new_group_id: old_group.into(), reset_generation: 7, notified_at_ms: 123 }).await.unwrap(),
                "newer-epoch" => { storage.conn.lock().unwrap().execute("UPDATE conversations SET group_id = ?1, epoch = 99", [target]).unwrap(); },
                "ambiguous-account" => storage.ensure_conversation_exists("did:plc:bob", id, old_group).await.unwrap(),
                "invalid-terminal" => terminal = ConversationState::Active,
                _ => unreachable!(),
            }
            let before: Vec<_> = ["conversations", "conversation_group_aliases", "messages", "group_states"].iter().map(|table| exit_table_snapshot(&storage, table)).collect();
            assert!(!storage.complete_account_exit(id, expected_group, expected_generation, 2, terminal).await.unwrap(), "{case}");
            let after: Vec<_> = ["conversations", "conversation_group_aliases", "messages", "group_states"].iter().map(|table| exit_table_snapshot(&storage, table)).collect();
            assert_eq!(before, after, "CAS miss wrote state for {case}");
        }
    }

    #[tokio::test]
    async fn account_exit_device_removed_accepts_only_exact_new_exit_coordinates() {
        let id = "8188478e-8d96-4a19-9239-3a2a831b40ea";
        let old_group = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let target = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
        for terminal in [ConversationState::Closed, ConversationState::DeviceRemoved] {
            let (_root, storage) = new_temp_storage();
            storage.ensure_conversation_exists("did:plc:alice", id, old_group).await.unwrap();
            storage.set_conversation_state(id, ConversationState::DeviceRemoved).await.unwrap();
            storage.conn.lock().unwrap().execute("UPDATE conversations SET epoch = 9", []).unwrap();
            storage.mark_reset_pending(id, target, 7, 123).await.unwrap();
            let before = exit_table_snapshot(&storage, "conversations");
            assert!(!storage.complete_account_exit(id, target, Some(8), 2, terminal.clone()).await.unwrap());
            assert!(!storage.complete_account_exit(id, old_group, Some(7), 2, terminal.clone()).await.unwrap());
            assert!(!storage.complete_account_exit(id, target, None, 2, terminal.clone()).await.unwrap());
            assert_eq!(exit_table_snapshot(&storage, "conversations"), before);
            assert!(storage.complete_account_exit(id, target, Some(7), 2, terminal.clone()).await.unwrap());
            assert_eq!(storage.get_conversation_state(id).await.unwrap(), Some(terminal));
            assert_eq!(storage.get_conversation("did:plc:alice", id).await.unwrap().unwrap().epoch, 2);
            assert!(!storage.needs_rejoin(id).await.unwrap());
            assert!(storage.list_conversation_group_ids(id).unwrap().contains(&old_group.to_owned()));
        }
    }

    #[tokio::test]
    async fn account_exit_invalid_canonical_shapes_do_not_write() {
        let canonical_id = "8188478e-8d96-4a19-9239-3a2a831b40ea";
        let canonical_group = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        for (case, id, group, generation) in [
            ("legacy-id", "exit-legacy".to_owned(), canonical_group.to_owned(), None),
            ("uppercase-id", canonical_id.to_uppercase(), canonical_group.to_owned(), None),
            ("compact-id", canonical_id.replace('-', ""), canonical_group.to_owned(), None),
            ("uuid-v1", "8188478e-8d96-1a19-9239-3a2a831b40ea".into(), canonical_group.to_owned(), None),
            ("uuid-wrong-variant", "8188478e-8d96-4a19-7239-3a2a831b40ea".into(), canonical_group.to_owned(), None),
            ("empty-group", canonical_id.to_owned(), String::new(), None),
            ("short-group", canonical_id.to_owned(), "aa".repeat(16), None),
            ("long-group", canonical_id.to_owned(), "aa".repeat(33), None),
            ("uppercase-group", canonical_id.to_owned(), canonical_group.to_uppercase(), None),
            ("nonhex-group", canonical_id.to_owned(), "gg".repeat(32), None),
            ("zero-generation", canonical_id.to_owned(), canonical_group.to_owned(), Some(0)),
            ("negative-generation", canonical_id.to_owned(), canonical_group.to_owned(), Some(-1)),
        ] {
            let (_root, storage) = new_temp_storage();
            storage.ensure_conversation_exists("did:plc:alice", &id, &group).await.unwrap();
            if let Some(generation) = generation {
                // Deliberately corrupt stored authority; the validated reset
                // publication callback now correctly rejects these inputs.
                storage.conn.lock().unwrap().execute(
                    "UPDATE conversations SET reset_new_group_id=?1, reset_generation=?2, reset_notified_at_ms=123, needs_rejoin=1 WHERE conversation_id=?3",
                    rusqlite::params![group,generation,id],
                ).unwrap();
                storage.set_conversation_state(&id, ConversationState::ResetPending {
                    new_group_id: group.clone(), reset_generation: generation, notified_at_ms: 123,
                }).await.unwrap();
            }
            let before: Vec<_> = ["conversations", "conversation_group_aliases", "messages", "group_states"]
                .iter().map(|table| exit_table_snapshot(&storage, table)).collect();
            assert!(!storage.complete_account_exit(&id, &group, generation, 2, ConversationState::Closed).await.unwrap(), "{case}");
            let after: Vec<_> = ["conversations", "conversation_group_aliases", "messages", "group_states"]
                .iter().map(|table| exit_table_snapshot(&storage, table)).collect();
            assert_eq!(before, after, "invalid canonical shape wrote state for {case}");
        }
    }

    #[tokio::test]
    async fn account_exit_no_reset_is_exact_idempotent_and_transactional() {
        let (_root, storage) = new_temp_storage();
        let id = "8188478e-8d96-4a19-9239-3a2a831b40ea";
        let group = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        storage.ensure_conversation_exists("did:plc:alice", id, group).await.unwrap();
        storage.conn.lock().unwrap().execute("UPDATE conversations SET reset_generation = 7, epoch = 3, needs_rejoin = 1", []).unwrap();
        storage.conn.lock().unwrap().execute_batch("CREATE TRIGGER reject_exit BEFORE UPDATE OF state ON conversations BEGIN SELECT RAISE(ABORT, 'fixture interruption'); END;").unwrap();
        let before = exit_table_snapshot(&storage, "conversations");
        let aliases = exit_table_snapshot(&storage, "conversation_group_aliases");
        assert!(storage.complete_account_exit(id, group, None, 4, ConversationState::DeviceRemoved).await.is_err());
        assert_eq!(exit_table_snapshot(&storage, "conversations"), before);
        assert_eq!(exit_table_snapshot(&storage, "conversation_group_aliases"), aliases, "alias writes must roll back with the terminal projection");
        storage.conn.lock().unwrap().execute_batch("DROP TRIGGER reject_exit;").unwrap();
        assert!(!storage.complete_account_exit(id, group, None, 2, ConversationState::DeviceRemoved).await.unwrap());
        assert!(storage.complete_account_exit(id, group, None, 4, ConversationState::DeviceRemoved).await.unwrap());
        assert!(storage.complete_account_exit(id, group, None, 4, ConversationState::DeviceRemoved).await.unwrap());
        assert!(!storage.complete_account_exit(id, group, None, 3, ConversationState::DeviceRemoved).await.unwrap());
        assert!(!storage.complete_account_exit(id, group, Some(8), 5, ConversationState::DeviceRemoved).await.unwrap());
        let before_forward_retry = exit_table_snapshot(&storage, "conversations");
        assert!(!storage.complete_account_exit(id, group, Some(7), 5, ConversationState::DeviceRemoved).await.unwrap());
        assert!(!storage.complete_account_exit(id, group, Some(7), 4, ConversationState::Closed).await.unwrap());
        assert_eq!(exit_table_snapshot(&storage, "conversations"), before_forward_retry, "a cleared reset generation cannot authorize a new terminal tuple");
        assert!(storage.complete_account_exit(id, group, Some(7), 4, ConversationState::DeviceRemoved).await.unwrap());
        assert!(storage.complete_account_exit(id, group, None, 5, ConversationState::DeviceRemoved).await.unwrap());
        assert!(!storage.complete_account_exit(id, group, None, 4, ConversationState::Closed).await.unwrap());
        assert!(storage.complete_account_exit(id, group, None, 5, ConversationState::Closed).await.unwrap());
        assert!(storage.complete_account_exit(id, group, None, 5, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit(id, group, None, 6, ConversationState::Closed).await.unwrap());
        assert!(!storage.complete_account_exit(id, group, None, 5, ConversationState::DeviceRemoved).await.unwrap());
        assert_eq!(storage.get_conversation_state(id).await.unwrap(), Some(ConversationState::Closed));
        assert!(!storage.needs_rejoin(id).await.unwrap());
        assert_eq!(storage.conn.lock().unwrap().query_row("SELECT reset_generation FROM conversations", [], |row| row.get::<_, Option<i64>>(0)).unwrap(), Some(7));
    }

    #[tokio::test]
    async fn complete_reset_pending_projects_aliases_through_production_storage_trait() {
        let (_tmp, storage) = new_temp_storage();
        let conversation_id = "conv-production-reset";
        let old_group = "group-old";
        let new_group = "aabbccddeeff00112233445566778899aa";
        storage
            .ensure_conversation_exists("did:plc:alice", conversation_id, old_group)
            .await
            .expect("create conversation");
        storage
            .mark_reset_pending(conversation_id, new_group, 7, 123)
            .await
            .expect("mark pending reset");

        let mismatch =
            MLSStorageBackend::complete_reset_pending(&storage, conversation_id, 6, new_group, 41)
                .await
                .expect("mismatched reset completion should be a clean miss");
        assert!(!mismatch);
        assert_eq!(
            storage
                .get_conversation("did:plc:alice", conversation_id)
                .await
                .expect("read pending conversation")
                .expect("pending conversation exists")
                .group_id,
            old_group,
            "a CAS miss must not advance the current group"
        );

        let completed =
            MLSStorageBackend::complete_reset_pending(&storage, conversation_id, 7, new_group, 42)
                .await
                .expect("complete reset through storage interface");
        assert!(completed, "exact reset completion should commit");

        let conversation = storage
            .get_conversation("did:plc:alice", conversation_id)
            .await
            .expect("read completed conversation")
            .expect("conversation exists");
        assert_eq!(conversation.group_id, new_group);
        assert_eq!(conversation.epoch, 42);
        let mut sources = storage
            .list_conversation_group_ids(conversation_id)
            .expect("read reset aliases");
        sources.sort();
        let mut expected = vec![old_group.to_string(), new_group.to_string()];
        expected.sort();
        assert_eq!(sources, expected);
        assert!(storage
            .get_conversation_state(conversation_id)
            .await
            .expect("read reset state")
            .is_some_and(|state| matches!(state, ConversationState::Active)));
    }

    #[tokio::test]
    async fn get_messages_legacy_input_normalizes_route_to_stable_owner() {
        let (_tmp, storage) = new_temp_storage();
        let stable_id = "conv-stable-route";
        let old_group = "group-route-old";
        let current_group = "group-route-current";
        storage
            .ensure_conversation_exists("did:plc:alice", stable_id, old_group)
            .await
            .expect("create conversation");
        storage
            .update_conversation_group_id(stable_id, current_group)
            .expect("project current group");

        storage
            .store_message(&Message {
                id: "legacy-route-message".into(),
                conversation_id: old_group.into(),
                sender_did: "did:plc:alice".into(),
                text: "legacy history".into(),
                timestamp: Utc::now(),
                epoch: 0,
                sequence_number: 1,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .expect("store legacy history");

        let messages = storage
            .get_messages(old_group, 10, None)
            .await
            .expect("resolve legacy input");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].conversation_id, stable_id);
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

    #[tokio::test]
    async fn canonical_history_orders_confirmed_sequences_before_pending_after_reopen() {
        let root = tempfile::tempdir().unwrap();
        let storage = hmac_fixture_storage(root.path(), "order-crypto");
        let id = "e16c197e-c3b7-4d96-b9de-ee62400460b3";
        let group = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        storage.ensure_conversation_exists("did:plc:alice", id, group).await.unwrap();
        let base = chrono::DateTime::parse_from_rfc3339("2026-09-05T08:46:25Z").unwrap().with_timezone(&Utc);
        // Server acceptance orders own10 before peer11, but the local ACK
        // timestamp is later. Pending timestamps must never override that
        // confirmed order, including a retained local terminal system marker.
        for (name, sequence, millis, own) in [
            ("peer-12", 12, 1000, false),
            ("own-10", 10, 500, true),
            ("peer-11", 11, 409, false),
            ("pending-after", 0, 2000, true),
            ("pending-before", 0, 0, true),
            ("terminal-marker", 0, 3000, true),
            ("pending-between", 0, 450, true),
        ] {
            let mut message = hmac_fixture_message(name, sequence);
            message.conversation_id = id.into();
            message.timestamp = base + chrono::Duration::milliseconds(millis);
            message.is_own = own;
            if name == "terminal-marker" {
                message.payload_json = Some(serde_json::to_string(&catbird_mls::orchestrator::types::MLSMessagePayload::system("conversation.closed")).unwrap());
            }
            storage.store_message(&message).await.unwrap();
        }
        let stored = exit_table_snapshot(&storage, "messages");
        let expected = ["own-10", "peer-11", "peer-12", "pending-before", "pending-between", "pending-after", "terminal-marker"];
        let history = storage.get_messages(id, 50, None).await.unwrap();
        assert_eq!(history.iter().map(|message| message.id.as_str()).collect::<Vec<_>>(), expected);
        assert_eq!(exit_table_snapshot(&storage, "messages"), stored, "display ordering must not rewrite ciphertext, HMAC or append order");
        drop(storage);
        let reopened = hmac_fixture_storage(root.path(), "order-crypto-reopened");
        let reloaded = reopened.get_messages(id, 50, None).await.unwrap();
        assert_eq!(reloaded.iter().map(|message| message.id.as_str()).collect::<Vec<_>>(), expected);
        assert_eq!(reloaded.last().unwrap().payload().unwrap().text.as_deref(), Some("conversation.closed"));
        let pending_tail = reopened.get_messages(id, 3, None).await.unwrap();
        assert_eq!(pending_tail.iter().map(|message| message.id.as_str()).collect::<Vec<_>>(), ["pending-between", "pending-after", "terminal-marker"]);
        let before_peer = reopened.get_messages(id, 50, Some(11)).await.unwrap();
        assert_eq!(before_peer.iter().filter(|message| message.sequence_number > 0).map(|message| message.id.as_str()).collect::<Vec<_>>(), ["own-10"]);
        assert_eq!(exit_table_snapshot(&reopened, "messages"), stored);
    }

    #[tokio::test]
    async fn get_messages_merges_reset_buckets_before_limit_and_verifies_source_hmac() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let storage_db = tmp.path().join("catmos-history.db");
        let mls_db = tmp.path().join("mls-history.db");
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
            .set_content_root_key(vec![0x77u8; 32])
            .expect("set content root key");
        storage.set_mls_context(mls_ctx);

        let stable_id = "conv-history";
        let groups = ["group-before", "group-reset", "group-latest"];
        storage
            .ensure_conversation_exists("did:plc:alice", stable_id, groups[0])
            .await
            .expect("create conversation");
        storage
            .update_conversation_group_id(stable_id, groups[1])
            .expect("first reset");
        storage
            .update_conversation_group_id(stable_id, groups[2])
            .expect("second reset");

        let now = Utc::now();
        for (index, group_id) in groups.iter().enumerate() {
            storage
                .store_message(&Message {
                    id: format!("history-{}", index + 1),
                    conversation_id: (*group_id).to_string(),
                    sender_did: "did:plc:alice".into(),
                    text: format!("history-{}", index + 1),
                    timestamp: now + chrono::Duration::minutes(index as i64),
                    epoch: index as u64,
                    sequence_number: index as u64 + 1,
                    is_own: true,
                    delivery_status: None,
                    payload_json: None,
                })
                .await
                .expect("store source-keyed history");
        }
        storage
            .store_message(&Message {
                id: "history-4".into(),
                conversation_id: groups[2].into(),
                sender_did: "did:plc:alice".into(),
                text: "history-4".into(),
                timestamp: now + chrono::Duration::minutes(3),
                epoch: 3,
                sequence_number: 4,
                is_own: true,
                delivery_status: None,
                payload_json: None,
            })
            .await
            .expect("store second latest-bucket row");

        let history = storage
            .get_messages(stable_id, 3, None)
            .await
            .expect("merge source buckets");
        assert_eq!(
            history
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            vec!["history-2", "history-3", "history-4"]
        );
        assert!(history
            .iter()
            .all(|message| message.conversation_id == stable_id));

        let before_latest = storage
            .get_messages(stable_id, 10, Some(4))
            .await
            .expect("page before latest");
        assert_eq!(
            before_latest
                .iter()
                .map(|message| message.id.as_str())
                .collect::<Vec<_>>(),
            vec!["history-1", "history-2", "history-3"]
        );

        {
            let conn = storage.conn.lock().unwrap();
            conn.execute(
                "UPDATE messages SET entry_hmac = zeroblob(32) WHERE id = 'history-2'",
                [],
            )
            .expect("tamper history HMAC");
        }
        assert!(
            storage.get_messages(stable_id, 10, None).await.is_err(),
            "source HMAC tampering must fail the merged read"
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

    fn hmac_fixture_storage(root: &std::path::Path, crypto_name: &str) -> SqliteStorage {
        let storage =
            SqliteStorage::new(root.join("messages.db").to_str().unwrap(), TEST_DB_KEY).unwrap();
        let context = MLSContext::new(
            root.join(crypto_name).to_string_lossy().into(),
            TEST_DB_KEY.into(),
            Box::new(InMemoryKeychain::new()),
        )
        .unwrap();
        context.set_content_root_key(vec![0x5c; 32]).unwrap();
        storage.set_mls_context(context);
        storage
    }

    fn hmac_fixture_message(id: &str, sequence: u64) -> Message {
        Message {
            id: id.into(),
            conversation_id: "hmac-fixture".into(),
            sender_did: format!("did:plc:sender-{id}"),
            text: format!("fixture body {id}"),
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-09-05T02:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            epoch: 1,
            sequence_number: sequence,
            is_own: false,
            delivery_status: Some(DeliveryStatus::Pending),
            payload_json: Some(format!("{{\"text\":\"fixture body {id}\"}}")),
        }
    }

    fn hmac_fixture_bytes(storage: &SqliteStorage) -> Vec<(String, Vec<u8>, Vec<u8>)> {
        let connection = storage.conn.lock().unwrap();
        let mut query = connection
            .prepare("SELECT id,payload_encrypted,entry_hmac FROM messages ORDER BY id")
            .unwrap();
        query
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "called in a separate process by the HMAC reload regression"]
    async fn hmac_reload_child_process() {
        let root = std::path::PathBuf::from(
            std::env::var_os("CATMOS_HMAC_FIXTURE_ROOT").expect("fixture root"),
        );
        let storage = hmac_fixture_storage(&root, "child-crypto.db");
        let messages = storage
            .get_messages("hmac-fixture", 10, None)
            .await
            .unwrap();
        assert_eq!(messages.len(), 3);
        let mut update = messages
            .iter()
            .find(|message| message.id == "own")
            .unwrap()
            .clone();
        update.delivery_status = Some(DeliveryStatus::DeliveredToAll);
        storage.store_message(&update).await.unwrap();
        storage.store_message(&update).await.unwrap();
        update.text = "conflicting replacement".into();
        assert!(storage.store_message(&update).await.is_err());
        assert_eq!(
            storage
                .get_messages("hmac-fixture", 10, None)
                .await
                .unwrap()
                .len(),
            3
        );
    }

    #[tokio::test]
    async fn hmac_out_of_order_senders_survive_process_reload_and_duplicate_metadata_update() {
        let directory = tempfile::tempdir().unwrap();
        let storage = hmac_fixture_storage(directory.path(), "parent-crypto.db");
        for (id, sequence) in [("own", 17), ("peer", 0), ("sibling", 1)] {
            storage
                .store_message(&hmac_fixture_message(id, sequence))
                .await
                .unwrap();
            storage
                .get_messages("hmac-fixture", 10, None)
                .await
                .unwrap();
        }
        let original = hmac_fixture_bytes(&storage);
        drop(storage);
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "orchestrator_storage::field_encryption_tests::hmac_reload_child_process",
                "--ignored",
                "--test-threads=1",
            ])
            .env("CATMOS_HMAC_FIXTURE_ROOT", directory.path())
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&child.stdout)
        );
        let storage = hmac_fixture_storage(directory.path(), "verification-crypto.db");
        let messages = storage
            .get_messages("hmac-fixture", 10, None)
            .await
            .unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(
            messages
                .iter()
                .find(|m| m.id == "own")
                .unwrap()
                .delivery_status,
            Some(DeliveryStatus::DeliveredToAll)
        );
        assert_eq!(
            hmac_fixture_bytes(&storage),
            original,
            "metadata updates must preserve ciphertext and tags byte for byte"
        );
        storage
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE messages SET entry_hmac=zeroblob(32) WHERE id='peer'",
                [],
            )
            .unwrap();
        assert!(
            storage
                .get_messages("hmac-fixture", 10, None)
                .await
                .is_err(),
            "tampered authentication remains an error"
        );
    }

    #[tokio::test]
    async fn hmac_invalid_order_metadata_cannot_commit_a_broken_append() {
        for invalid in [
            [Some(10), Some(11), Some(12)],
            [Some(1), Some(2), Some(4)],
            [Some(1), Some(1), Some(3)],
            [Some(0), Some(1), Some(2)],
            [Some(-1), Some(1), Some(2)],
            [Some(1), None, Some(3)],
        ] {
            let directory = tempfile::tempdir().unwrap();
            let storage = hmac_fixture_storage(directory.path(), "crypto.db");
            for (id, sequence) in [("a", 17), ("b", 0), ("c", 1)] {
                storage
                    .store_message(&hmac_fixture_message(id, sequence))
                    .await
                    .unwrap();
            }
            let original = hmac_fixture_bytes(&storage);
            {
                let connection = storage.conn.lock().unwrap();
                for (id, value) in ["a", "b", "c"].into_iter().zip(invalid) {
                    connection
                        .execute(
                            "UPDATE messages SET hmac_sequence=?2 WHERE id=?1",
                            rusqlite::params![id, value],
                        )
                        .unwrap();
                }
            }
            assert!(storage.get_messages("hmac-fixture", 10, None).await.is_err());
            assert!(storage
                .store_message(&hmac_fixture_message("d", 0))
                .await
                .is_err());
            assert_eq!(hmac_fixture_bytes(&storage), original);
            let connection = storage.conn.lock().unwrap();
            for (id, value) in ["a", "b", "c"].into_iter().zip(invalid) {
                let preserved: Option<i64> = connection
                    .query_row(
                        "SELECT hmac_sequence FROM messages WHERE id=?1",
                        rusqlite::params![id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(preserved, value);
            }
        }
    }

    #[tokio::test]
    async fn hmac_legacy_order_is_proved_without_rewriting_ciphertext_or_tags() {
        let directory = tempfile::tempdir().unwrap();
        let storage = hmac_fixture_storage(directory.path(), "crypto.db");
        for (id, sequence) in [("a", 17), ("b", 0), ("c", 1)] {
            storage
                .store_message(&hmac_fixture_message(id, sequence))
                .await
                .unwrap();
        }
        {
            let connection = storage.conn.lock().unwrap();
            connection
                .execute("UPDATE messages SET hmac_sequence=NULL", [])
                .unwrap();
            // Model a legacy replacement/reordering that retained a valid
            // unique authenticated chain but changed physical row ordering.
            connection
                .execute("UPDATE messages SET rowid=100 WHERE id='a'", [])
                .unwrap();
        }
        let original = hmac_fixture_bytes(&storage);
        assert_eq!(
            storage
                .get_messages("hmac-fixture", 10, None)
                .await
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            storage
                .conn
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM messages WHERE hmac_sequence IS NULL",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            3,
            "read-only verification must not mutate legacy rows"
        );
        storage
            .store_message(&hmac_fixture_message("d", 0))
            .await
            .unwrap();
        let updated = hmac_fixture_bytes(&storage);
        assert_eq!(
            &updated[..3],
            original.as_slice(),
            "adopting verified order must not re-MAC rows"
        );
        let connection = storage.conn.lock().unwrap();
        for (id, expected) in [("a", 1), ("b", 2), ("c", 3), ("d", 4)] {
            assert_eq!(
                connection
                    .query_row(
                        "SELECT hmac_sequence FROM messages WHERE id=?1",
                        [id],
                        |r| r.get::<_, i64>(0)
                    )
                    .unwrap(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn hmac_legacy_branch_cannot_be_resealed_or_silently_repaired() {
        let directory = tempfile::tempdir().unwrap();
        let storage = hmac_fixture_storage(directory.path(), "crypto.db");
        for (id, sequence) in [("a", 17), ("b", 0), ("c", 1)] {
            storage
                .store_message(&hmac_fixture_message(id, sequence))
                .await
                .unwrap();
        }
        {
            let connection = storage.conn.lock().unwrap();
            let previous: Vec<u8> = connection
                .query_row("SELECT entry_hmac FROM messages WHERE id='a'", [], |r| {
                    r.get(0)
                })
                .unwrap();
            let payload: Vec<u8> = connection
                .query_row(
                    "SELECT payload_encrypted FROM messages WHERE id='c'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let tag = storage
                .mls_context_snapshot()
                .unwrap()
                .compute_message_hmac("hmac-fixture".into(), Some(previous), "c".into(), payload)
                .unwrap();
            connection
                .execute("UPDATE messages SET entry_hmac=?1 WHERE id='c'", [tag])
                .unwrap();
            connection
                .execute("UPDATE messages SET hmac_sequence=NULL", [])
                .unwrap();
        }
        let original = hmac_fixture_bytes(&storage);
        assert!(storage
            .get_messages("hmac-fixture", 10, None)
            .await
            .unwrap_err()
            .to_string()
            .contains("branches"));
        assert!(storage
            .store_message(&hmac_fixture_message("d", 2))
            .await
            .is_err());
        assert_eq!(
            hmac_fixture_bytes(&storage),
            original,
            "failed verification preserves all original rows"
        );
    }

    #[tokio::test]
    async fn hmac_independent_writers_extend_one_atomic_append_chain() {
        let directory = tempfile::tempdir().unwrap();
        let first = Arc::new(hmac_fixture_storage(directory.path(), "first-crypto.db"));
        let second = Arc::new(hmac_fixture_storage(directory.path(), "second-crypto.db"));
        let mut workers = Vec::new();
        for (index, storage) in [first.clone(), second].into_iter().enumerate() {
            workers.push(std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        for counter in 0..8 {
                            storage
                                .store_message(&hmac_fixture_message(
                                    &format!("{index}-{counter}"),
                                    0,
                                ))
                                .await
                                .unwrap();
                        }
                    });
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(
            first
                .get_messages("hmac-fixture", 100, None)
                .await
                .unwrap()
                .len(),
            16
        );
        assert_eq!(
            first
                .conn
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(DISTINCT hmac_sequence) FROM messages",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            16
        );
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

#[cfg(test)]
mod reset_target_tests;
