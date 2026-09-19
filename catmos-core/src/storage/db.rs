use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use sqlx::Row;
use std::path::Path;
use std::str::FromStr;
use std::sync::RwLock;

use crate::error::{CatmosError, Result};
use crate::recovery::{
    PersistedRecoveryFlags, QuarantinePayload, QuarantineReason, ResetPendingPayload,
};
use crate::types::{Conversation, Member, Message, MessageContent};

/// Version tag stamped into `payload_key_version` on every encrypted row.
/// Field-level encryption layer v1: AES-256-GCM payload + HMAC-SHA256 entry
/// chain, both keyed off the per-DID content root key (see
/// `crate::storage::keys`).
const PAYLOAD_KEY_VERSION_V1: i64 = 1;

/// JSON-shaped canonical plaintext that gets sealed by the field-level
/// encryption layer before persistence. Storing the rich payload (rather
/// than only the bare `content_json` column) means encrypted rows retain
/// enough fidelity to rebuild the in-memory `MessageContent` enum after a
/// round-trip, while the `content_type`/`content_json NOT NULL` schema
/// constraints are satisfied by writing placeholder values to those legacy
/// columns when the encrypted payload is the source of truth.
#[derive(serde::Serialize, serde::Deserialize)]
struct CanonicalMessageBody {
    content_type: String,
    content_json: String,
}

/// Map a persisted quarantine reason tag back into the enum. Unknown tags
/// fall back to `RepeatedFramingFailures` — the most generic reason — so a
/// future server-side or upstream-enum addition can't break rehydration.
fn quarantine_reason_from_tag(tag: &str) -> QuarantineReason {
    match tag {
        "peer_bad_commit" => QuarantineReason::PeerBadCommit,
        "multi_peer_bad_commits" => QuarantineReason::MultiPeerBadCommits,
        "repeated_framing_failures" => QuarantineReason::RepeatedFramingFailures,
        _ => QuarantineReason::RepeatedFramingFailures,
    }
}

/// SQLCipher-encrypted database for per-account storage.
pub struct Database {
    pool: SqlitePool,
    /// Per-DID content-root key for the field-level encryption layer
    /// (`catbird_mls::field_encryption`). Installed via
    /// [`Database::set_content_root_key`] from the session bootstrap path
    /// after `load_or_create_content_root_key` returns. When `None` — or
    /// before login completes — `store_message` falls back to the legacy
    /// plaintext columns so the orchestrator can keep functioning during
    /// the bootstrap window (initial sync may run before login installs
    /// the key).
    content_root_key: RwLock<Option<Vec<u8>>>,
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

        let db = Self {
            pool,
            content_root_key: RwLock::new(None),
        };
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

        let db = Self {
            pool,
            content_root_key: RwLock::new(None),
        };
        db.migrate().await?;
        Ok(db)
    }

    /// Install the per-DID content-root key for the field-level encryption
    /// layer. Called once from the session bootstrap path
    /// (`crate::runtime::Runtime::initialize`) after the key file is
    /// materialized via `crate::storage::keys::load_or_create_content_root_key`.
    /// Idempotent; later calls replace the binding. Sync (RwLock write, no
    /// await needed).
    pub fn set_content_root_key(&self, key: Vec<u8>) {
        if let Ok(mut guard) = self.content_root_key.write() {
            *guard = Some(key);
        }
    }

    /// Drop the in-memory content-root key. Called from logout. Existing
    /// encrypted rows remain readable on the next session bootstrap (the
    /// key file on disk is what makes that possible).
    #[allow(dead_code)]
    pub fn clear_content_root_key(&self) {
        if let Ok(mut guard) = self.content_root_key.write() {
            *guard = None;
        }
    }

    /// Snapshot the current content-root key, if installed. Returns `None`
    /// when the bootstrap path has not yet called
    /// [`set_content_root_key`] (e.g. the initial sync racing against
    /// login completion).
    fn content_root_key_snapshot(&self) -> Option<Vec<u8>> {
        self.content_root_key
            .read()
            .ok()
            .and_then(|g| g.as_ref().cloned())
    }

    /// Test-only accessor for the underlying `SqlitePool`. Integration
    /// tests in `tests/` need to issue raw `PRAGMA` / `SELECT` queries to
    /// inspect the schema and the encrypted/legacy column populations.
    /// Not part of the public API — `#[doc(hidden)]` keeps it out of
    /// rustdoc but still reachable from the integration test crate.
    #[doc(hidden)]
    pub fn pool_for_test(&self) -> &SqlitePool {
        &self.pool
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
                cipher_suite  TEXT NOT NULL DEFAULT 'MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519',
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
                "conversation_group_aliases",
                "CREATE TABLE IF NOT EXISTS conversation_group_aliases (
                conversation_id TEXT NOT NULL,
                group_id       TEXT NOT NULL,
                first_seen_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                PRIMARY KEY (conversation_id, group_id)
            )",
            ),
            (
                "idx_conversation_group_aliases_group",
                "CREATE INDEX IF NOT EXISTS idx_conversation_group_aliases_group
                 ON conversation_group_aliases(group_id)",
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
            sqlx::query(sqlx::AssertSqlSafe(*sql))
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
        //
        // The metadata columns (metadata_version, metadata_blob_locator,
        // avatar_*) hold encrypted-blob bookkeeping. After the MLS metadata
        // cutover the server stops returning plaintext titles/descriptions
        // entirely; these columns are populated via `bootstrap_group_metadata`
        // (catmos-core/src/chat/metadata.rs) after a Welcome / external-commit
        // join / metadata-update commit merge.
        let recovery_columns: &[(&str, &str)] = &[
            ("needs_rejoin", "INTEGER NOT NULL DEFAULT 0"),
            ("reset_new_group_id", "TEXT NULL"),
            ("reset_generation", "INTEGER NULL"),
            ("reset_notified_at_ms", "INTEGER NULL"),
            ("recovery_attempt_count", "INTEGER NOT NULL DEFAULT 0"),
            ("last_rejoin_attempt_ms", "INTEGER NULL"),
            ("unrecoverable_local", "INTEGER NOT NULL DEFAULT 0"),
            ("metadata_version", "INTEGER NULL"),
            ("metadata_blob_locator", "TEXT NULL"),
            ("avatar_blob_locator", "TEXT NULL"),
            ("avatar_bytes", "BLOB NULL"),
            ("avatar_content_type", "TEXT NULL"),
            // ── Layer 3 quarantine (catbird-mls f363fd1) ──
            // `quarantine_reason_tag` matches `QuarantineReason::tag()` so
            // we never serialize the enum directly — keeps schema robust
            // across enum extensions in catbird-mls.
            ("quarantine_reason_tag", "TEXT NULL"),
            ("quarantine_since_ms", "INTEGER NULL"),
            // JSON array of suspected DID strings.
            ("quarantine_suspected_dids", "TEXT NULL"),
        ];
        for (col, decl) in recovery_columns {
            let existing: Option<(String,)> = sqlx::query_as(
                "SELECT name FROM pragma_table_info('conversations') WHERE name = ?1",
            )
            .bind(col)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| CatmosError::Storage(format!("Probe column '{col}' failed: {e}")))?;
            if existing.is_some() {
                continue;
            }
            let stmt = format!("ALTER TABLE conversations ADD COLUMN {col} {decl}");
            sqlx::query(sqlx::AssertSqlSafe(stmt))
                .execute(&self.pool)
                .await
                .map_err(|e| CatmosError::Storage(format!("Add column '{col}' failed: {e}")))?;
        }

        // ── Field-level encryption columns on `messages` ──────────────────
        //
        // Adds the columns that hold the AES-GCM ciphertext, the HMAC entry
        // tag, and the key-version stamp for the field-level encryption
        // layer (`catbird_mls::field_encryption`). `content_type` /
        // `content_json` stay `NOT NULL` because making them nullable
        // requires a full SQLite table rebuild; encrypted rows write
        // placeholder values into those legacy columns and put the real
        // payload in `payload_encrypted`.
        //
        // The tombstone columns are added now for schema parity with
        // iOS/Android. catmos-cli does not currently expose user-initiated
        // message delete, but landing the columns up-front means a later
        // delete path can soft-delete without another schema migration
        // breaking the HMAC chain. Read paths filter
        // `COALESCE(is_tombstone, 0) = 0` so existing rows surface
        // unaffected.
        let message_columns: &[(&str, &str)] = &[
            ("payload_encrypted", "BLOB"),
            ("entry_hmac", "BLOB"),
            ("payload_key_version", "INTEGER"),
            ("is_tombstone", "INTEGER NOT NULL DEFAULT 0"),
            ("deleted_at", "INTEGER"),
        ];
        for (col, decl) in message_columns {
            let existing: Option<(String,)> =
                sqlx::query_as("SELECT name FROM pragma_table_info('messages') WHERE name = ?1")
                    .bind(col)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|e| {
                        CatmosError::Storage(format!("Probe messages column '{col}' failed: {e}"))
                    })?;
            if existing.is_some() {
                continue;
            }
            let stmt = format!("ALTER TABLE messages ADD COLUMN {col} {decl}");
            sqlx::query(sqlx::AssertSqlSafe(stmt)).execute(&self.pool).await.map_err(|e| {
                CatmosError::Storage(format!("Add messages column '{col}' failed: {e}"))
            })?;
        }

        // ── MLSMessageFieldMigrationV1: drop pre-cutover plaintext rows ──
        //
        // First-run drop of any pre-field-encryption message rows. Matches
        // the `MLSPlaintextHeaderMigration` precedent on iOS / Android /
        // catmos desktop: existing transcripts cannot satisfy the
        // encrypted-row invariants (no HMAC chain seed, no per-conversation
        // content key derivation history), so we drop them once and record
        // the migration in a `migration_status` table so it never re-runs.
        // The DROP is bounded — fresh installs have no messages yet, so
        // this is a no-op on first boot.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS migration_status (
                name TEXT PRIMARY KEY,
                applied_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| CatmosError::Storage(format!("Create migration_status failed: {e}")))?;

        let applied: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM migration_status WHERE name = 'MLSMessageFieldMigrationV1'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| CatmosError::Storage(format!("Probe migration_status failed: {e}")))?;
        if applied == 0 {
            sqlx::query("DELETE FROM messages")
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    CatmosError::Storage(format!("Drop pre-cutover messages failed: {e}"))
                })?;
            sqlx::query(
                "INSERT INTO migration_status (name, applied_at) VALUES (?1, strftime('%s','now'))",
            )
            .bind("MLSMessageFieldMigrationV1")
            .execute(&self.pool)
            .await
            .map_err(|e| {
                CatmosError::Storage(format!("Record MLSMessageFieldMigrationV1 failed: {e}"))
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

    /// Commit related credentials together so interruption cannot split a
    /// rotated access/refresh pair. Unrelated session/device rows are retained.
    pub(crate) async fn store_session_values(&self, values: &[(&str, &str)]) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        for (key, value) in values {
            sqlx::query("INSERT OR REPLACE INTO session (key, value) VALUES (?1, ?2)")
                .bind(key).bind(value).execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// A completed refresh may race a newer login or another process. Compare
    /// the complete auth snapshot under a short writer transaction before
    /// publishing the new pair. No network work occurs while this lock is held.
    pub(crate) async fn compare_and_store_session_values(
        &self,
        expected: &std::collections::HashMap<String, String>,
        values: &[(&str, &str)],
    ) -> Result<bool> {
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        for (key, _) in values {
            let current: Option<String> = sqlx::query_scalar("SELECT value FROM session WHERE key = ?1")
                .bind(key).fetch_optional(&mut *transaction).await?;
            if current.as_ref() != expected.get(*key) {
                transaction.rollback().await?;
                return Ok(false);
            }
        }
        for (key, value) in values {
            sqlx::query("INSERT OR REPLACE INTO session (key, value) VALUES (?1, ?2)")
                .bind(key).bind(value).execute(&mut *transaction).await?;
        }
        transaction.commit().await?;
        Ok(true)
    }

    /// Read a consistent snapshot even if another process replaces auth while
    /// this process is restoring its session.
    pub(crate) async fn get_session_values(&self, keys: &[&str]) -> Result<std::collections::HashMap<String, String>> {
        let mut transaction = self.pool.begin().await?;
        let mut values = std::collections::HashMap::new();
        for key in keys {
            let value: Option<String> = sqlx::query_scalar("SELECT value FROM session WHERE key = ?1")
                .bind(key).fetch_optional(&mut *transaction).await?;
            if let Some(value) = value { values.insert((*key).to_string(), value); }
        }
        transaction.commit().await?;
        Ok(values)
    }

    pub async fn get_session_value(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM session WHERE key = ?1")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.map(|r| r.get("value")))
    }

    pub async fn delete_session_value(&self, key: &str) -> Result<()> {
        sqlx::query("DELETE FROM session WHERE key = ?1")
            .bind(key)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn clear_auth_session(&self) -> Result<()> {
        for key in [
            "auth_method",
            "session_cookie",
            "did",
            "handle",
            "nest_url",
            "access_jwt",
            "refresh_jwt",
            "pds_url",
        ] {
            self.delete_session_value(key).await?;
        }
        Ok(())
    }

    // ── Conversations ────────────────────────────────────────────────────

    /// Remember a group ID under its stable conversation owner. Historical
    /// message rows remain keyed by this source group because field-level
    /// encryption/HMAC bind the exact stored conversation ID.
    pub async fn record_conversation_group_alias(
        &self,
        conversation_id: &str,
        group_id: &str,
    ) -> Result<()> {
        if conversation_id.is_empty() || group_id.is_empty() {
            return Ok(());
        }
        sqlx::query(
            "INSERT OR IGNORE INTO conversation_group_aliases
             (conversation_id, group_id) VALUES (?1, ?2)",
        )
        .bind(conversation_id)
        .bind(group_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Return every current and historical group source owned by a stable
    /// conversation, in no particular order. Callers must decrypt each
    /// bucket using its returned source ID before normalizing for display.
    pub async fn list_conversation_group_ids(&self, conversation_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            "SELECT group_id FROM conversations WHERE conversation_id = ?1
             UNION
             SELECT group_id FROM conversation_group_aliases WHERE conversation_id = ?1",
        )
        .bind(conversation_id)
        .fetch_all(&self.pool)
        .await?;
        let group_ids: Vec<String> = rows.iter().map(|row| row.get("group_id")).collect();
        for group_id in &group_ids {
            let owners = self.find_conversation_ids_by_group_id(group_id).await?;
            let owner_ids: std::collections::HashSet<&str> =
                owners.iter().map(|(owner, _)| owner.as_str()).collect();
            if owner_ids.len() > 1
                || owner_ids
                    .iter()
                    .next()
                    .is_some_and(|owner| *owner != conversation_id)
            {
                return Err(CatmosError::Storage(format!(
                    "historical MLS group {group_id} has ambiguous ownership"
                )));
            }
        }
        Ok(group_ids)
    }

    /// Find stable owners for a legacy/current group source. The caller must
    /// reject more than one owner as an ambiguity rather than guessing.
    pub async fn find_conversation_ids_by_group_id(
        &self,
        group_id: &str,
    ) -> Result<Vec<(String, String)>> {
        let rows = sqlx::query(
            "SELECT conversation_id, group_id FROM conversations WHERE group_id = ?1
             UNION
             SELECT conversation_id, group_id FROM conversation_group_aliases WHERE group_id = ?1",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await?;
        let all: std::collections::HashSet<(String, String)> = rows
            .iter()
            .map(|row| (row.get("conversation_id"), row.get("group_id")))
            .collect();
        // Legacy source rows can use the group ID as their conversation ID.
        // If a stable owner also claims that source, expose the non-self
        // owner(s) for ambiguity checking instead of counting the spelling
        // twice as two conversations.
        let canonical: std::collections::HashSet<(String, String)> = all
            .iter()
            .filter(|(conversation_id, _)| conversation_id != group_id)
            .cloned()
            .collect();
        Ok(if canonical.is_empty() {
            all.into_iter().collect()
        } else {
            canonical.into_iter().collect()
        })
    }

    pub async fn store_conversation(&self, convo: &Conversation) -> Result<()> {
        // Hydration-order safety (post-MLS-metadata-cutover):
        // After the cutover the server returns no plaintext title/description,
        // so `convo_resp_to_conversation` produces `name = None` /
        // `description = None` from `getConvos` responses. A naive
        // `INSERT OR REPLACE` would clobber any locally-decrypted metadata
        // each time we refresh. We use `INSERT ... ON CONFLICT ... DO UPDATE`
        // with `COALESCE(excluded.col, conversations.col)` for every field
        // populated by the encrypted-bootstrap path (name, description,
        // metadata_version, metadata_blob_locator, avatar_*) so that
        // server-driven refreshes never overwrite local-only state with NULL.
        //
        // Server-authoritative columns (group_id, epoch, members
        // table, etc.) still take the new value unconditionally — those move
        // forward on every refresh and must reflect the server's view.
        let previous_group_id: Option<String> =
            sqlx::query_scalar("SELECT group_id FROM conversations WHERE conversation_id = ?1")
                .bind(&convo.conversation_id)
                .fetch_optional(&self.pool)
                .await?;
        if let Some(previous_group_id) = previous_group_id {
            self.record_conversation_group_alias(&convo.conversation_id, &previous_group_id)
                .await?;
        }
        self.record_conversation_group_alias(&convo.conversation_id, &convo.group_id)
            .await?;

        sqlx::query(
            "INSERT INTO conversations
             (conversation_id, group_id, name, description, creator, epoch,
              cipher_suite, created_at, last_message_at, unread_count, alias,
              metadata_version, metadata_blob_locator,
              avatar_blob_locator, avatar_bytes, avatar_content_type)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                     ?12, ?13, ?14, ?15, ?16)
             ON CONFLICT(conversation_id) DO UPDATE SET
                 group_id        = excluded.group_id,
                 name            = COALESCE(excluded.name,            conversations.name),
                 description     = COALESCE(excluded.description,     conversations.description),
                 creator         = COALESCE(NULLIF(excluded.creator, ''), conversations.creator),
                 epoch           = excluded.epoch,
                 cipher_suite    = excluded.cipher_suite,
                 created_at      = COALESCE(NULLIF(excluded.created_at, ''), conversations.created_at),
                 last_message_at = excluded.last_message_at,
                 unread_count    = excluded.unread_count,
                 alias           = COALESCE(excluded.alias,           conversations.alias),
                 metadata_version       = COALESCE(excluded.metadata_version,       conversations.metadata_version),
                 metadata_blob_locator  = COALESCE(excluded.metadata_blob_locator,  conversations.metadata_blob_locator),
                 avatar_blob_locator    = COALESCE(excluded.avatar_blob_locator,    conversations.avatar_blob_locator),
                 avatar_bytes           = COALESCE(excluded.avatar_bytes,           conversations.avatar_bytes),
                 avatar_content_type    = COALESCE(excluded.avatar_content_type,    conversations.avatar_content_type)",
        )
        .bind(&convo.conversation_id)
        .bind(&convo.group_id)
        .bind(&convo.name)
        .bind(&convo.description)
        .bind(convo.creator.as_deref().unwrap_or_default())
        .bind(convo.epoch as i64)
        .bind(&convo.cipher_suite)
        .bind(convo.created_at.map(|value| value.to_rfc3339()).unwrap_or_default())
        .bind(convo.last_message_at.map(|t| t.to_rfc3339()))
        .bind(convo.unread_count as i32)
        .bind(&convo.alias)
        .bind(convo.metadata_version)
        .bind(&convo.metadata_blob_locator)
        .bind(&convo.avatar_blob_locator)
        .bind(convo.avatar_bytes.as_deref())
        .bind(&convo.avatar_content_type)
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
            .bind(&convo.conversation_id)
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
                    created_at, last_message_at, unread_count, alias,
                    metadata_version, metadata_blob_locator,
                    avatar_blob_locator, avatar_bytes, avatar_content_type
             FROM conversations ORDER BY last_message_at DESC NULLS LAST",
        )
        .fetch_all(&self.pool)
        .await?;

        let convos = rows
            .iter()
            .map(|row| {
                let last_msg_str: Option<String> = row.get("last_message_at");
                Conversation {
                    conversation_id: row.get("conversation_id"),
                    group_id: row.get("group_id"),
                    name: row.get("name"),
                    description: row.get("description"),
                    // Historical rows may contain inventory-generated guesses.
                    // Keep their bytes, but do not promote them as evidence.
                    creator: None,
                    epoch: row.get::<i64, _>("epoch") as u64,
                    cipher_suite: row.get("cipher_suite"),
                    members: vec![], // loaded separately
                    created_at: None,
                    last_message_at: last_msg_str.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .ok()
                            .map(|dt| dt.with_timezone(&Utc))
                    }),
                    unread_count: row.get::<i32, _>("unread_count") as u32,
                    alias: row.get("alias"),
                    metadata_version: row.get("metadata_version"),
                    metadata_blob_locator: row.get("metadata_blob_locator"),
                    avatar_blob_locator: row.get("avatar_blob_locator"),
                    avatar_bytes: row.get("avatar_bytes"),
                    avatar_content_type: row.get("avatar_content_type"),
                }
            })
            .collect();

        Ok(convos)
    }

    /// Persist decrypted group metadata for a conversation. Called from
    /// `bootstrap_group_metadata` after a successful Welcome / external-commit
    /// join / metadata-update commit merge. NULLs the avatar columns when the
    /// caller supplies `avatar_bytes = None` so an avatar removal is reflected.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_decrypted_metadata(
        &self,
        convo_id: &str,
        title: Option<&str>,
        description: Option<&str>,
        metadata_version: Option<i64>,
        metadata_blob_locator: Option<&str>,
        avatar_blob_locator: Option<&str>,
        avatar_bytes: Option<&[u8]>,
        avatar_content_type: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE conversations SET
                 name                  = ?1,
                 description           = ?2,
                 metadata_version      = ?3,
                 metadata_blob_locator = ?4,
                 avatar_blob_locator   = ?5,
                 avatar_bytes          = ?6,
                 avatar_content_type   = ?7
             WHERE conversation_id = ?8",
        )
        .bind(title)
        .bind(description)
        .bind(metadata_version)
        .bind(metadata_blob_locator)
        .bind(avatar_blob_locator)
        .bind(avatar_bytes)
        .bind(avatar_content_type)
        .bind(convo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── Messages ─────────────────────────────────────────────────────────

    pub async fn store_message(&self, msg: &Message) -> Result<()> {
        let (content_type, content_json) = serialize_content(&msg.content);

        // Attempt field-level encryption. Falls back to legacy plaintext
        // when the content-root key is not yet installed (initial sync may
        // run before login completes). Encryption + HMAC failures also fall
        // back with a warning rather than panic — the row still lands so
        // the orchestrator can keep going, and a later session with the
        // key bound will surface the plaintext columns.
        let sealed = self
            .try_encrypt_message_body(msg, &content_type, &content_json)
            .await;

        match sealed {
            Some((encrypted, entry_hmac)) => {
                sqlx::query(
                    "INSERT OR REPLACE INTO messages
                     (id, convo_id, sender_did, content_type, content_json, epoch, seq, created_at,
                      payload_encrypted, entry_hmac, payload_key_version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )
                .bind(&msg.id)
                .bind(&msg.convo_id)
                .bind(&msg.sender_did)
                // Placeholder values for the NOT NULL legacy columns when
                // the encrypted payload is the source of truth. The read
                // path checks `payload_encrypted IS NOT NULL` first and
                // ignores these on sealed rows.
                .bind("sealed")
                .bind("")
                .bind(msg.epoch as i64)
                .bind(msg.seq as i64)
                .bind(msg.created_at.to_rfc3339())
                .bind(encrypted)
                .bind(entry_hmac)
                .bind(PAYLOAD_KEY_VERSION_V1)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query(
                    "INSERT OR REPLACE INTO messages
                     (id, convo_id, sender_did, content_type, content_json, epoch, seq, created_at,
                      payload_encrypted, entry_hmac, payload_key_version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL)",
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
            }
        }
        Ok(())
    }

    /// Look up the most recent (highest seq) `entry_hmac` for a
    /// conversation so the next encrypted row can extend the HMAC chain.
    /// Returns `None` for the first row in a conversation (chain seed = 32
    /// zero bytes is supplied by `compute_entry_hmac` when `prev_hmac =
    /// None`) or when prior rows are legacy plaintext (no chain to extend).
    async fn last_entry_hmac(&self, convo_id: &str) -> Option<Vec<u8>> {
        sqlx::query_scalar::<_, Option<Vec<u8>>>(
            "SELECT entry_hmac FROM messages
             WHERE convo_id = ?1 AND entry_hmac IS NOT NULL
             ORDER BY seq DESC LIMIT 1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten()
        .flatten()
    }

    /// Seal a message body via `catbird_mls::field_encryption`. Returns
    /// `None` when the content-root key is not installed, so the caller can
    /// fall back to legacy plaintext columns and keep the orchestrator
    /// running through the bootstrap window. Errors from the encryption /
    /// HMAC primitives are also surfaced as `None` (with a `warn!` log)
    /// rather than panicking — landing the row is more important than the
    /// field-level layer for a transient cryptographic edge case, and a
    /// later session can replay the row.
    async fn try_encrypt_message_body(
        &self,
        msg: &Message,
        content_type: &str,
        content_json: &str,
    ) -> Option<(Vec<u8>, Vec<u8>)> {
        let root = self.content_root_key_snapshot()?;
        let body = CanonicalMessageBody {
            content_type: content_type.to_string(),
            content_json: content_json.to_string(),
        };
        let plaintext = match serde_json::to_vec(&body) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(
                    message_id = %msg.id,
                    error = %err,
                    "try_encrypt_message_body: canonical body serialization failed; falling back to plaintext"
                );
                return None;
            }
        };
        let encrypted = match catbird_mls::field_encryption::encrypt_payload(
            &root,
            &msg.convo_id,
            &plaintext,
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                tracing::warn!(
                    message_id = %msg.id,
                    error = %err,
                    "try_encrypt_message_body: encrypt_payload failed; falling back to plaintext"
                );
                return None;
            }
        };
        let prev_hmac = self.last_entry_hmac(&msg.convo_id).await;
        let hmac = match catbird_mls::field_encryption::compute_entry_hmac(
            &root,
            &msg.convo_id,
            prev_hmac.as_deref(),
            &msg.id,
            &encrypted,
        ) {
            Ok(tag) => tag,
            Err(err) => {
                tracing::warn!(
                    message_id = %msg.id,
                    error = %err,
                    "try_encrypt_message_body: compute_entry_hmac failed; falling back to plaintext"
                );
                return None;
            }
        };
        Some((encrypted, hmac.to_vec()))
    }

    pub async fn get_messages(
        &self,
        convo_id: &str,
        limit: u32,
        before_seq: Option<u64>,
    ) -> Result<Vec<Message>> {
        // Fetch the complete source bucket before applying the page boundary:
        // entry HMACs chain across rows, so verifying a suffix as if it were a
        // new chain would reject a valid page or miss a tampered predecessor.
        let rows = sqlx::query(
            "SELECT id, convo_id, sender_did, content_type, content_json, epoch, seq, created_at,
                    payload_encrypted, entry_hmac, is_tombstone
             FROM messages WHERE convo_id = ?1
             ORDER BY seq ASC",
        )
        .bind(convo_id)
        .fetch_all(&self.pool)
        .await?;
        let root = self.content_root_key_snapshot();
        verify_message_bucket(&rows, root.as_deref(), convo_id)?;
        let mut messages: Vec<Message> = rows
            .iter()
            .filter(|row| before_seq.map_or(true, |seq| row.get::<i64, _>("seq") < seq as i64))
            .filter(|row| row.get::<i64, _>("is_tombstone") == 0)
            .map(|r| map_message_row(r, root.as_deref()))
            .collect();
        if messages.len() > limit as usize {
            messages.drain(..messages.len() - limit as usize);
        }
        Ok(messages)
    }

    /// Get the highest seq number stored locally for a conversation.
    /// Used to request only newer messages from the server via `sinceSeq`.
    pub async fn get_max_seq(&self, convo_id: &str) -> Result<Option<i64>> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT MAX(seq) FROM messages WHERE convo_id = ?1 AND seq > 0")
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
                    last_rejoin_attempt_ms, unrecoverable_local,
                    quarantine_reason_tag, quarantine_since_ms,
                    quarantine_suspected_dids
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
        let q_tag: Option<String> = row.get("quarantine_reason_tag");
        let q_since: Option<i64> = row.get("quarantine_since_ms");
        let q_dids_json: Option<String> = row.get("quarantine_suspected_dids");

        let reset = match (reset_new_group_id, reset_generation, reset_notified_at_ms) {
            (Some(gid), Some(gen), Some(ts)) => Some(ResetPendingPayload {
                new_group_id: gid,
                reset_generation: gen,
                notified_at_ms: ts,
            }),
            _ => None,
        };

        let quarantine = match (q_tag, q_since) {
            (Some(tag), Some(since_ms)) => {
                let reason = quarantine_reason_from_tag(&tag);
                let suspected_dids = q_dids_json
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
                    .unwrap_or_default();
                Some(QuarantinePayload {
                    reason,
                    since_ms,
                    suspected_dids,
                })
            }
            _ => None,
        };

        Ok(PersistedRecoveryFlags {
            needs_rejoin: needs_rejoin != 0,
            unrecoverable_local: unrecoverable_local != 0,
            reset,
            recovery_attempt_count: recovery_attempt_count.max(0) as u32,
            last_rejoin_attempt_ms,
            quarantine,
        })
    }

    /// Persist a quarantine payload (Layer 3, mirrors
    /// `MLSStorageBackend::mark_quarantined` from catbird-mls f363fd1).
    pub async fn mark_quarantined(
        &self,
        convo_id: &str,
        reason: QuarantineReason,
        since_ms: i64,
        suspected_dids: &[String],
    ) -> Result<()> {
        let dids_json = serde_json::to_string(suspected_dids).unwrap_or_else(|_| "[]".to_string());
        sqlx::query(
            "UPDATE conversations
             SET quarantine_reason_tag = ?1,
                 quarantine_since_ms = ?2,
                 quarantine_suspected_dids = ?3
             WHERE conversation_id = ?4",
        )
        .bind(reason.tag())
        .bind(since_ms)
        .bind(dids_json)
        .bind(convo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Clear the persisted quarantine state. Mirrors
    /// `MLSStorageBackend::clear_quarantine`.
    pub async fn clear_quarantine(&self, convo_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE conversations
             SET quarantine_reason_tag = NULL,
                 quarantine_since_ms = NULL,
                 quarantine_suspected_dids = NULL
             WHERE conversation_id = ?1",
        )
        .bind(convo_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark a conversation as needing a deferred External Commit rejoin
    /// (§8.2). Idempotent.
    pub async fn mark_needs_rejoin(&self, convo_id: &str) -> Result<()> {
        sqlx::query("UPDATE conversations SET needs_rejoin = 1 WHERE conversation_id = ?1")
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
        sqlx::query("UPDATE conversations SET unrecoverable_local = 0 WHERE conversation_id = ?1")
            .bind(convo_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Persist a `RESET_PENDING` payload received via `GroupResetEvent`
    /// (§8.2 / §8.6). The triple is required.
    ///
    /// The same statement also clears any persisted quarantine. A server
    /// reset is a documented quarantine exit (ruling 2a, 2026-08-15), so the
    /// payload and the quarantine clear are one commit — not a commit
    /// followed by a separate clear. The callers still invoke
    /// `exit_quarantine` afterwards for the in-memory tracker and the
    /// `QuarantineEvent::Cleared` notification, but that call is now a
    /// backstop rather than the only thing standing between a crash and a row
    /// that is simultaneously reset-pending and quarantined. Such a row
    /// rehydrates quarantined forever, because a replayed reset event resolves
    /// to the same generation and never re-clears it.
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
                 reset_notified_at_ms = ?3,
                 quarantine_reason_tag = NULL,
                 quarantine_since_ms = NULL,
                 quarantine_suspected_dids = NULL
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

    /// Atomically replace the target of an already committed ResetPending
    /// tuple with a server-verified winner. A mismatch is a clean CAS miss.
    pub async fn adopt_reset_pending_target(
        &self,
        convo_id: &str,
        expected_generation: i64,
        expected_old_target: &str,
        authoritative_new_target: &str,
    ) -> Result<bool> {
        if authoritative_new_target.is_empty() {
            return Ok(false);
        }
        let result = sqlx::query(
            "UPDATE conversations
             SET reset_new_group_id = ?1,
                 needs_rejoin = 1
             WHERE conversation_id = ?2
               AND ?1 <> ''
               AND reset_new_group_id = ?3
               AND reset_new_group_id <> ''
               AND reset_generation = ?4
               AND reset_notified_at_ms IS NOT NULL",
        )
        .bind(authoritative_new_target)
        .bind(convo_id)
        .bind(expected_old_target)
        .bind(expected_generation)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Reread durable ResetPending authority after a clean CAS miss or a
    /// commit-ambiguous storage error.
    pub async fn reset_pending_matches(
        &self,
        convo_id: &str,
        expected_generation: i64,
        expected_target: &str,
    ) -> Result<bool> {
        if expected_target.is_empty() {
            return Ok(false);
        }
        let row = sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM conversations
             WHERE conversation_id = ?1
               AND reset_new_group_id = ?2
               AND reset_new_group_id <> ''
               AND reset_generation = ?3
               AND reset_notified_at_ms IS NOT NULL
             LIMIT 1",
        )
        .bind(convo_id)
        .bind(expected_target)
        .bind(expected_generation)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    /// Project a completed reset only when the durable generation and target
    /// exactly match the MLS/server-verified group.
    pub async fn complete_reset_pending(
        &self,
        convo_id: &str,
        expected_generation: i64,
        expected_new_target: &str,
        landed_epoch: u64,
    ) -> Result<bool> {
        let landed_epoch = i64::try_from(landed_epoch)
            .map_err(|_| CatmosError::Storage("landed reset epoch exceeds SQLite range".into()))?;
        let mut tx = self.pool.begin().await?;
        let previous_group_id: Option<String> =
            sqlx::query_scalar("SELECT group_id FROM conversations WHERE conversation_id = ?1")
                .bind(convo_id)
                .fetch_optional(&mut *tx)
                .await?;
        let result = sqlx::query(
            "UPDATE conversations
             SET group_id = ?1,
                 epoch = ?4,
                 reset_new_group_id = NULL,
                 reset_generation = NULL,
                 reset_notified_at_ms = NULL,
                 needs_rejoin = 0
             WHERE conversation_id = ?2
               AND reset_new_group_id = ?1
               AND reset_new_group_id <> ''
               AND reset_generation = ?3
               AND reset_notified_at_ms IS NOT NULL",
        )
        .bind(expected_new_target)
        .bind(convo_id)
        .bind(expected_generation)
        .bind(landed_epoch)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 1 {
            if let Some(previous_group_id) = previous_group_id {
                sqlx::query(
                    "INSERT OR IGNORE INTO conversation_group_aliases
                     (conversation_id, group_id) VALUES (?1, ?2)",
                )
                .bind(convo_id)
                .bind(previous_group_id)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query(
                "INSERT OR IGNORE INTO conversation_group_aliases
                 (conversation_id, group_id) VALUES (?1, ?2)",
            )
            .bind(convo_id)
            .bind(expected_new_target)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn get_members(&self, group_id: &str) -> Result<Vec<Member>> {
        let rows = sqlx::query(
            "SELECT did, user_did, device_id, device_name, is_admin, is_moderator, joined_at
             FROM members WHERE group_id = ?1 OR group_id IN (SELECT conversation_id FROM conversations WHERE group_id = ?1)",
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
            creator: Some(String::new()),
            epoch: 0,
            cipher_suite: String::new(),
            members: vec![],
            created_at: Some(Utc::now()),
            last_message_at: None,
            unread_count: 0,
            alias: None,
            metadata_version: None,
            metadata_blob_locator: None,
            avatar_blob_locator: None,
            avatar_bytes: None,
            avatar_content_type: None,
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
    async fn complete_reset_pending_requires_exact_generation_and_target() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
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

        assert!(!db
            .complete_reset_pending(convo_id, 0, new_group_id, 1)
            .await
            .unwrap());
        assert!(!db
            .complete_reset_pending(convo_id, 1, "attacker-group", 1)
            .await
            .unwrap());
        assert_eq!(read_group_id(&db, convo_id).await, old_group_id);

        assert!(db
            .complete_reset_pending(convo_id, 1, new_group_id, 1)
            .await
            .unwrap());

        let post = read_group_id(&db, convo_id).await;
        assert_eq!(
            post, new_group_id,
            "exact completion must project the verified reset target"
        );
        let mut sources = db.list_conversation_group_ids(convo_id).await.unwrap();
        sources.sort();
        let mut expected_sources = vec![old_group_id.to_string(), new_group_id.to_string()];
        expected_sources.sort();
        assert_eq!(sources, expected_sources);
        assert!(db
            .get_recovery_flags(convo_id)
            .await
            .unwrap()
            .reset
            .is_none());
    }

    #[tokio::test]
    async fn stable_group_source_reads_reject_multiple_historical_owners() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("aliases-ownership.db");
        let db = Database::open_unencrypted(&path).await.unwrap();
        db.store_conversation(&fixture_convo("owner-a", "group-a"))
            .await
            .unwrap();
        db.store_conversation(&fixture_convo("owner-b", "group-b"))
            .await
            .unwrap();
        db.record_conversation_group_alias("owner-b", "group-a")
            .await
            .unwrap();

        assert!(
            db.list_conversation_group_ids("owner-a").await.is_err(),
            "stable source reads must fail closed on historical ownership collision"
        );
    }

    #[tokio::test]
    async fn completion_atomically_projects_landed_epoch_and_preserves_mismatch() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
        let db = Database::open_unencrypted(&path).await.unwrap();
        let convo_id = "convo-landed-epoch";
        db.store_conversation(&fixture_convo(convo_id, "old-group"))
            .await
            .unwrap();
        sqlx::query("UPDATE conversations SET epoch = 741 WHERE conversation_id = ?1")
            .bind(convo_id)
            .execute(db.pool_for_test())
            .await
            .unwrap();
        db.mark_needs_rejoin(convo_id).await.unwrap();
        db.mark_reset_pending(convo_id, "new-group", 23, 1_717_000_000_023)
            .await
            .unwrap();

        let snapshot = || async {
            sqlx::query_as::<_, (String, i64, Option<String>, Option<i64>, Option<i64>, i64)>(
                "SELECT group_id, epoch, reset_new_group_id, reset_generation,
                        reset_notified_at_ms, needs_rejoin
                 FROM conversations WHERE conversation_id = ?1",
            )
            .bind(convo_id)
            .fetch_one(db.pool_for_test())
            .await
            .unwrap()
        };
        let pending = snapshot().await;
        assert!(!db
            .complete_reset_pending(convo_id, 22, "new-group", 3)
            .await
            .unwrap());
        assert_eq!(snapshot().await, pending, "mismatch preserves every field");

        assert!(db
            .complete_reset_pending(convo_id, 23, "new-group", 3)
            .await
            .unwrap());
        assert_eq!(
            snapshot().await,
            ("new-group".into(), 3, None, None, None, 0)
        );
    }

    #[tokio::test]
    async fn adopt_reset_pending_target_is_exact_and_preserves_authority() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
        let db = Database::open_unencrypted(&path).await.unwrap();
        let convo_id = "convo-competing-reset-winners";
        db.store_conversation(&fixture_convo(convo_id, "old-group"))
            .await
            .unwrap();
        db.mark_needs_rejoin(convo_id).await.unwrap();
        db.mark_reset_pending(convo_id, "losing-group", 23, 1_717_000_000_023)
            .await
            .unwrap();

        assert!(!db
            .adopt_reset_pending_target(convo_id, 23, "losing-group", "")
            .await
            .unwrap());

        assert!(!db
            .adopt_reset_pending_target(convo_id, 22, "losing-group", "winner-a")
            .await
            .unwrap());
        assert!(!db
            .adopt_reset_pending_target(convo_id, 23, "other-loser", "winner-a")
            .await
            .unwrap());
        assert!(db
            .adopt_reset_pending_target(convo_id, 23, "losing-group", "winner-a")
            .await
            .unwrap());
        assert!(db
            .reset_pending_matches(convo_id, 23, "winner-a")
            .await
            .expect("durable reread confirms winner after a response-loss equivalent"));
        assert!(db
            .adopt_reset_pending_target(convo_id, 23, "winner-a", "winner-a")
            .await
            .unwrap());
        assert!(!db
            .adopt_reset_pending_target(convo_id, 23, "losing-group", "winner-b")
            .await
            .unwrap());

        let flags = db.get_recovery_flags(convo_id).await.unwrap();
        let pending = flags.reset.expect("reset authority remains pending");
        assert_eq!(pending.new_group_id, "winner-a");
        assert_eq!(pending.reset_generation, 23);
        assert_eq!(pending.notified_at_ms, 1_717_000_000_023);
        assert!(flags.needs_rejoin);
        assert_eq!(read_group_id(&db, convo_id).await, "old-group");
    }

    /// Phase 2.5 Stage 1 dual-emission safety: the server emits BOTH
    /// `groupResetEvent` AND `resetRequestedEvent` for the same trigger
    /// during the migration window (plan §5 Stage 1). Both event handlers
    /// in `ChatService` write through `mark_reset_pending`, so the DB
    /// layer must remain consistent regardless of arrival order.
    ///
    /// This test validates that two `mark_reset_pending` calls at the same
    /// generation with the SAME group id (the realistic dual-emission case
    /// — an admin-initiated reset where `expectedNewMlsGroupId` matches the
    /// legacy `newGroupId`) leave the row in the same final state.
    /// Idempotency at the handler level (skip the second write entirely on
    /// matching generation) is enforced in
    /// `ChatService::handle_reset_requested_event`; this test exercises the
    /// underlying DB invariant that makes that policy safe.
    #[tokio::test]
    async fn mark_reset_pending_is_idempotent_at_same_generation() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
        let db = Database::open_unencrypted(&path).await.unwrap();

        let convo_id = "convo-dual-emit";
        let new_group_id = "post-reset-group-hex";
        db.store_conversation(&fixture_convo(convo_id, "pre-reset-group"))
            .await
            .unwrap();

        // First write — simulates the legacy `groupResetEvent` arriving.
        db.mark_reset_pending(convo_id, new_group_id, 5, 1_000_000)
            .await
            .unwrap();
        let after_first = db.get_recovery_flags(convo_id).await.unwrap();
        let payload_first = after_first
            .reset
            .as_ref()
            .expect("reset payload must be set after first write");
        assert_eq!(payload_first.new_group_id, new_group_id);
        assert_eq!(payload_first.reset_generation, 5);

        // Second write at the same generation with the same group id —
        // simulates the Phase 2.5 `resetRequestedEvent` arriving second
        // for the same admin reset. The DB row must not regress.
        db.mark_reset_pending(convo_id, new_group_id, 5, 2_000_000)
            .await
            .unwrap();
        let after_second = db.get_recovery_flags(convo_id).await.unwrap();
        let payload_second = after_second
            .reset
            .as_ref()
            .expect("reset payload must remain set");
        assert_eq!(
            payload_second.new_group_id, new_group_id,
            "same-generation re-write at the DB layer must keep the group id"
        );
        assert_eq!(
            payload_second.reset_generation, 5,
            "generation must not regress on a same-generation re-write"
        );
    }

    /// Ruling 2a (2026-08-15): a server reset is a documented quarantine
    /// exit, and the exit must be committed by the same statement that
    /// publishes the reset authority. The callers in `recovery_ops` do call
    /// `exit_quarantine` right after this, but a crash (or a failed clear)
    /// between the two writes would mint a row that is simultaneously
    /// reset-pending and quarantined — and that row rehydrates quarantined
    /// forever, because the replayed reset event lands on the same generation
    /// and never reaches the clear again. Mirrors the same requirement on
    /// `MLSStorageBackend::mark_reset_pending` in
    /// `catbird-mls/src/orchestrator/storage.rs`.
    #[tokio::test]
    async fn mark_reset_pending_clears_quarantine_in_the_same_commit() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
        let db = Database::open_unencrypted(&path).await.unwrap();

        let convo_id = "convo-reset-clears-quarantine";
        db.store_conversation(&fixture_convo(convo_id, "pre-reset-group"))
            .await
            .unwrap();

        db.mark_quarantined(
            convo_id,
            QuarantineReason::PeerBadCommit,
            1_000,
            &["did:plc:suspect".to_string()],
        )
        .await
        .unwrap();
        assert!(
            db.get_recovery_flags(convo_id)
                .await
                .unwrap()
                .quarantine
                .is_some(),
            "precondition: the conversation must start quarantined"
        );

        // The reset write alone — no `exit_quarantine` backstop — must leave
        // the row unquarantined.
        db.mark_reset_pending(convo_id, "post-reset-group-hex", 7, 2_000)
            .await
            .unwrap();

        let flags = db.get_recovery_flags(convo_id).await.unwrap();
        assert!(
            flags.quarantine.is_none(),
            "ruling 2a: the reset commit must clear persisted quarantine on its own"
        );
        let payload = flags
            .reset
            .as_ref()
            .expect("reset authority must still be published");
        assert_eq!(payload.new_group_id, "post-reset-group-hex");
        assert_eq!(payload.reset_generation, 7);
    }

    /// Phase 2.5: a higher generation supersedes a lower one (mirrors the
    /// orchestrator-side rule in
    /// `catbird-mls/src/orchestrator/recovery.rs:1413-1424`). A stale
    /// pending row from generation N must be overwritten by an authoritative
    /// new request at generation N+1 — otherwise the deferred-recovery loop
    /// would chase the wrong group id.
    #[tokio::test]
    async fn mark_reset_pending_higher_generation_supersedes() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
        let db = Database::open_unencrypted(&path).await.unwrap();

        let convo_id = "convo-supersede";
        db.store_conversation(&fixture_convo(convo_id, "pre-reset"))
            .await
            .unwrap();

        db.mark_reset_pending(convo_id, "stale-group", 3, 1_000_000)
            .await
            .unwrap();

        db.mark_reset_pending(convo_id, "fresh-group", 4, 2_000_000)
            .await
            .unwrap();
        let payload = db
            .get_recovery_flags(convo_id)
            .await
            .unwrap()
            .reset
            .expect("payload must be set after supersede");
        assert_eq!(payload.new_group_id, "fresh-group");
        assert_eq!(payload.reset_generation, 4);
        assert_eq!(payload.notified_at_ms, 2_000_000);
    }

    /// Regression guard for the §8.6 External Commit exhaustion path
    /// (`ChatService::transition_unrecoverable_local`). The platform layer
    /// fires `reportRecoveryFailure` only after `mark_unrecoverable_local`
    /// flips the row, so the persisted invariants matter:
    /// - `unrecoverable_local` becomes `true`
    /// - `needs_rejoin` is cleared (otherwise the deferred-recovery loop
    ///   would keep retrying a convo we just declared dead)
    #[tokio::test]
    async fn mark_unrecoverable_local_sets_flag_and_clears_needs_rejoin() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
        let db = Database::open_unencrypted(&path).await.unwrap();

        let convo_id = "convo-exhausted";
        db.store_conversation(&fixture_convo(convo_id, "group-hex"))
            .await
            .unwrap();
        db.mark_needs_rejoin(convo_id).await.unwrap();

        let pre = db.get_recovery_flags(convo_id).await.unwrap();
        assert!(
            pre.needs_rejoin,
            "needs_rejoin must be set before exhaustion"
        );
        assert!(!pre.unrecoverable_local);

        db.mark_unrecoverable_local(convo_id).await.unwrap();

        let post = db.get_recovery_flags(convo_id).await.unwrap();
        assert!(
            post.unrecoverable_local,
            "mark_unrecoverable_local must set unrecoverable_local=true"
        );
        assert!(
            !post.needs_rejoin,
            "mark_unrecoverable_local must clear needs_rejoin so deferred recovery stops"
        );
    }

    /// Hydration-order safety for the MLS metadata cutover: after the
    /// server stops returning plaintext titles, every refresh
    /// (`fetch_conversations` → `convo_resp_to_conversation`) hands the
    /// DB layer a `Conversation` with `name: None` / `description: None`.
    /// The COALESCE upsert on `store_conversation` MUST preserve the
    /// locally-decrypted fields written by `update_decrypted_metadata`.
    /// Without this guarantee group titles vanish on every refresh —
    /// silent regression that would only show up when a user logs in,
    /// opens the TUI, and sees blanks where their group titles used to be.
    #[tokio::test]
    async fn store_conversation_preserves_decrypted_metadata_across_refresh() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
        let db = Database::open_unencrypted(&path).await.unwrap();

        let convo_id = "convo-coalesce";
        let group_id = "group-coalesce";

        // 1. Initial insert from a server refresh — name/description are
        //    None because the API no longer carries plaintext metadata.
        db.store_conversation(&fixture_convo(convo_id, group_id))
            .await
            .unwrap();

        // 2. Encrypted-bootstrap pipeline writes the decrypted metadata.
        db.update_decrypted_metadata(
            convo_id,
            Some("Saved Title"),
            Some("Saved Description"),
            Some(7),
            Some("locator-uuid-7"),
            Some("avatar-uuid-7"),
            Some(&[1u8, 2, 3]),
            Some("image/png"),
        )
        .await
        .unwrap();

        let after_bootstrap = db.list_conversations().await.unwrap();
        let row = after_bootstrap
            .iter()
            .find(|c| c.conversation_id == convo_id)
            .expect("convo present after bootstrap");
        assert_eq!(row.name.as_deref(), Some("Saved Title"));
        assert_eq!(row.description.as_deref(), Some("Saved Description"));
        assert_eq!(row.metadata_version, Some(7));
        assert_eq!(row.metadata_blob_locator.as_deref(), Some("locator-uuid-7"));
        assert_eq!(row.avatar_blob_locator.as_deref(), Some("avatar-uuid-7"));
        assert_eq!(row.avatar_bytes.as_deref(), Some(&[1u8, 2, 3][..]));
        assert_eq!(row.avatar_content_type.as_deref(), Some("image/png"));

        // 3. The exact thing fetch_conversations does on the next refresh:
        //    overwrite the row with a server-derived `Conversation` whose
        //    name/description/metadata_* are all None.
        db.store_conversation(&fixture_convo(convo_id, group_id))
            .await
            .unwrap();

        let after_refresh = db.list_conversations().await.unwrap();
        let row = after_refresh
            .iter()
            .find(|c| c.conversation_id == convo_id)
            .expect("convo present after refresh");
        assert_eq!(
            row.name.as_deref(),
            Some("Saved Title"),
            "name must survive a NULL refresh via COALESCE"
        );
        assert_eq!(
            row.description.as_deref(),
            Some("Saved Description"),
            "description must survive a NULL refresh via COALESCE"
        );
        assert_eq!(
            row.metadata_version,
            Some(7),
            "metadata_version must survive a NULL refresh via COALESCE"
        );
        assert_eq!(
            row.metadata_blob_locator.as_deref(),
            Some("locator-uuid-7"),
            "metadata_blob_locator must survive a NULL refresh via COALESCE"
        );
        assert_eq!(
            row.avatar_blob_locator.as_deref(),
            Some("avatar-uuid-7"),
            "avatar_blob_locator must survive a NULL refresh via COALESCE"
        );
        assert_eq!(
            row.avatar_bytes.as_deref(),
            Some(&[1u8, 2, 3][..]),
            "avatar_bytes must survive a NULL refresh via COALESCE"
        );
        assert_eq!(
            row.avatar_content_type.as_deref(),
            Some("image/png"),
            "avatar_content_type must survive a NULL refresh via COALESCE"
        );
    }

    /// Sanity check the inverse: when `update_decrypted_metadata` is
    /// called with explicit `None` for the avatar columns, the row should
    /// reflect the deletion. This is the "user removed the avatar" path —
    /// COALESCE only protects against NULLs from the *refresh* path, not
    /// against an authoritative bootstrap that says "the avatar is gone".
    #[tokio::test]
    async fn update_decrypted_metadata_can_clear_avatar() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));
        let db = Database::open_unencrypted(&path).await.unwrap();

        let convo_id = "convo-avatar-clear";
        db.store_conversation(&fixture_convo(convo_id, "g"))
            .await
            .unwrap();
        db.update_decrypted_metadata(
            convo_id,
            Some("T"),
            None,
            Some(1),
            Some("loc"),
            Some("avatar-loc"),
            Some(&[9u8]),
            Some("image/png"),
        )
        .await
        .unwrap();

        // Now publish v=2 with no avatar.
        db.update_decrypted_metadata(
            convo_id,
            Some("T"),
            None,
            Some(2),
            Some("loc-2"),
            None,
            None,
            None,
        )
        .await
        .unwrap();

        let row = db
            .list_conversations()
            .await
            .unwrap()
            .into_iter()
            .find(|c| c.conversation_id == convo_id)
            .unwrap();
        assert_eq!(row.metadata_version, Some(2));
        assert_eq!(row.avatar_blob_locator, None);
        assert_eq!(row.avatar_bytes, None);
        assert_eq!(row.avatar_content_type, None);
    }

    /// Layer 3 quarantine persistence: mark → drop the `Database` instance
    /// → reopen against the same path → `get_recovery_flags` must return
    /// the persisted reason / timestamp / suspected DIDs. This is the
    /// fundamental invariant the task requires (quarantine survives a CLI
    /// restart). Mirrors the iOS `MLSConversationModel.isQuarantined` GRDB
    /// migration test.
    #[tokio::test]
    async fn quarantine_persists_across_database_reopen() {
        let path =
            std::env::temp_dir().join(format!("catmos-core-test-{}.db", uuid::Uuid::new_v4()));

        let convo_id = "convo-quarantined";
        let suspected = vec![
            "did:plc:peer-one".to_string(),
            "did:plc:peer-two".to_string(),
        ];

        // ── 1. Mark and drop ───────────────────────────────────────────
        {
            let db = Database::open_unencrypted(&path).await.unwrap();
            db.store_conversation(&fixture_convo(convo_id, "group-q"))
                .await
                .unwrap();
            db.mark_quarantined(
                convo_id,
                QuarantineReason::MultiPeerBadCommits,
                1_700_000_000_000,
                &suspected,
            )
            .await
            .unwrap();
        } // db dropped here — pool flushed.

        // ── 2. Reopen and verify rehydration ───────────────────────────
        {
            let db = Database::open_unencrypted(&path).await.unwrap();
            let flags = db.get_recovery_flags(convo_id).await.unwrap();
            let q = flags
                .quarantine
                .as_ref()
                .expect("quarantine must rehydrate after reopen");
            assert_eq!(q.reason, QuarantineReason::MultiPeerBadCommits);
            assert_eq!(q.since_ms, 1_700_000_000_000);
            assert_eq!(q.suspected_dids, suspected);

            // ── 3. Clear and verify it sticks across another reopen ────
            db.clear_quarantine(convo_id).await.unwrap();
        }
        {
            let db = Database::open_unencrypted(&path).await.unwrap();
            let flags = db.get_recovery_flags(convo_id).await.unwrap();
            assert!(
                flags.quarantine.is_none(),
                "clear_quarantine must remove the persisted payload"
            );
        }
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

/// Verify one source bucket using its original stored conversation ID. The
/// HMAC chain is intentionally walked before any UI-facing normalization, so
/// a stable-ID projection cannot make an old group-keyed row unverifiable.
fn verify_message_bucket(
    rows: &[sqlx::sqlite::SqliteRow],
    root_key: Option<&[u8]>,
    convo_id: &str,
) -> Result<()> {
    let Some(root_key) = root_key else {
        return Ok(());
    };

    let mut previous_hmac: Option<Vec<u8>> = None;
    for row in rows {
        let payload: Option<Vec<u8>> = row.get("payload_encrypted");
        let stored_hmac: Option<Vec<u8>> = row.get("entry_hmac");
        let Some(payload) = payload.filter(|payload| !payload.is_empty()) else {
            if stored_hmac.is_some() {
                return Err(CatmosError::Storage(format!(
                    "message HMAC exists without encrypted payload in bucket {convo_id}"
                )));
            }
            continue;
        };
        let Some(stored_hmac) = stored_hmac else {
            return Err(CatmosError::Storage(format!(
                "encrypted message is missing HMAC in bucket {convo_id}"
            )));
        };
        let message_id: String = row.get("id");
        let valid = catbird_mls::field_encryption::verify_entry_hmac(
            root_key,
            convo_id,
            previous_hmac.as_deref(),
            &message_id,
            &payload,
            &stored_hmac,
        )
        .map_err(|error| {
            CatmosError::Storage(format!("message HMAC verification failed: {error}"))
        })?;
        if !valid {
            return Err(CatmosError::Storage(format!(
                "message HMAC mismatch in bucket {convo_id} for {message_id}"
            )));
        }
        previous_hmac = Some(stored_hmac);
    }
    Ok(())
}

fn map_message_row(row: &sqlx::sqlite::SqliteRow, root_key: Option<&[u8]>) -> Message {
    let id: String = row.get("id");
    let convo_id: String = row.get("convo_id");
    let legacy_content_type: String = row.get("content_type");
    let legacy_content_json: String = row.get("content_json");
    let created_str: String = row.get("created_at");
    let payload_encrypted: Option<Vec<u8>> = row.get("payload_encrypted");

    // Prefer the encrypted column when present and the content-root key is
    // installed; fall back to the legacy plaintext columns for rows written
    // during a bootstrap-race window or before the field-encryption
    // migration ran. A sealed row read without a key bound surfaces as
    // `MessageContent::Unknown` (placeholder `content_type = "sealed"` is
    // not parseable as plaintext) — preferable to a panic.
    let (content_type, content_json) = match (payload_encrypted.as_deref(), root_key) {
        (Some(wire), Some(root)) if !wire.is_empty() => {
            match catbird_mls::field_encryption::decrypt_payload(root, &convo_id, wire) {
                Ok(plaintext) => match serde_json::from_slice::<CanonicalMessageBody>(&plaintext) {
                    Ok(body) => (body.content_type, body.content_json),
                    Err(err) => {
                        tracing::warn!(
                            message_id = %id,
                            error = %err,
                            "map_message_row: canonical body deserialize failed; row will surface as Unknown"
                        );
                        (legacy_content_type, legacy_content_json)
                    }
                },
                Err(err) => {
                    tracing::warn!(
                        message_id = %id,
                        error = %err,
                        "map_message_row: decrypt_payload failed; falling back to legacy columns"
                    );
                    (legacy_content_type, legacy_content_json)
                }
            }
        }
        (Some(_), None) => {
            tracing::error!(
                message_id = %id,
                "map_message_row: sealed row read with no content-root key bound; \
                 payload will surface as Unknown until the key is installed"
            );
            (legacy_content_type, legacy_content_json)
        }
        _ => (legacy_content_type, legacy_content_json),
    };

    Message {
        id,
        convo_id,
        sender_did: row.get("sender_did"),
        content: deserialize_content(&content_type, &content_json),
        epoch: row.get::<i64, _>("epoch") as u64,
        seq: row.get::<i64, _>("seq") as u64,
        created_at: DateTime::parse_from_rfc3339(&created_str)
            .unwrap_or_default()
            .with_timezone(&Utc),
    }
}
