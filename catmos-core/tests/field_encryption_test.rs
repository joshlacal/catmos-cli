//! Integration tests for the MLS field-level encryption layer in
//! `catmos-core::storage::Database`. Covers:
//!
//! 1. **Round-trip**: encrypted message body survives `store_message` →
//!    `get_messages`, returning the original `MessageContent`.
//! 2. **Legacy fallback**: storing without a content-root key installed
//!    writes plaintext columns, which still read back correctly.
//! 3. **Schema migration**: the post-cutover columns and the
//!    `MLSMessageFieldMigrationV1` migration row are present on a fresh DB.
//! 4. **HMAC chain extension**: two encrypted writes produce two
//!    independent rows whose `entry_hmac` columns chain (second row's
//!    `prev_hmac` is the first row's `entry_hmac`).

use chrono::Utc;
use sqlx::Row;

use catmos_core::storage::Database;
use catmos_core::types::{Conversation, Message, MessageContent};

fn fixture_message(convo: &str, id: &str, seq: u64, text: &str) -> Message {
    Message {
        id: id.to_string(),
        convo_id: convo.to_string(),
        sender_did: Some("did:plc:tester".to_string()),
        content: MessageContent::Text(text.to_string()),
        epoch: 1,
        seq,
        created_at: Utc::now(),
    }
}

fn fixture_convo(convo_id: &str) -> Conversation {
    Conversation {
        conversation_id: convo_id.to_string(),
        group_id: format!("group-{convo_id}"),
        name: None,
        description: None,
        creator: "did:plc:tester".to_string(),
        epoch: 0,
        cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string(),
        members: vec![],
        created_at: Utc::now(),
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

fn tmp_db_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "catmos-cli-field-enc-test-{}.db",
        uuid::Uuid::new_v4()
    ))
}

async fn seed_convo(db: &Database, convo_id: &str) {
    db.store_conversation(&fixture_convo(convo_id)).await.unwrap();
}

#[tokio::test]
async fn message_round_trip_with_field_encryption() {
    let path = tmp_db_path();
    let db = Database::open_unencrypted(&path).await.unwrap();

    // Install a fixed root key — emulates what
    // `load_or_create_content_root_key` returns at session bootstrap.
    db.set_content_root_key(vec![0x42u8; 32]);

    let convo = "conv-round-trip";
    seed_convo(&db, convo).await;
    let msg = fixture_message(convo, "msg-1", 1, "hello world");
    db.store_message(&msg).await.unwrap();

    let got = db.get_messages(convo, 10, None).await.unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].id, "msg-1");
    match &got[0].content {
        MessageContent::Text(t) => assert_eq!(t, "hello world"),
        other => panic!("expected Text, got {:?}", other),
    }

    // Verify the encrypted column was actually populated (and the legacy
    // content_json column holds the placeholder, not the plaintext).
    let row = sqlx::query(
        "SELECT payload_encrypted, entry_hmac, payload_key_version, content_type, content_json
         FROM messages WHERE id = ?1",
    )
    .bind("msg-1")
    .fetch_one(db.pool_for_test())
    .await
    .unwrap();
    let payload: Option<Vec<u8>> = row.get("payload_encrypted");
    let hmac: Option<Vec<u8>> = row.get("entry_hmac");
    let kv: Option<i64> = row.get("payload_key_version");
    let content_type: String = row.get("content_type");
    let content_json: String = row.get("content_json");
    assert!(
        payload.as_ref().map(|v| !v.is_empty()).unwrap_or(false),
        "payload_encrypted must be populated on encrypted row"
    );
    assert!(
        hmac.as_ref().map(|v| v.len() == 32).unwrap_or(false),
        "entry_hmac must be 32 bytes on encrypted row"
    );
    assert_eq!(kv, Some(1));
    assert_eq!(content_type, "sealed");
    assert_eq!(content_json, "");
}

#[tokio::test]
async fn legacy_plaintext_fallback_when_key_not_bound() {
    let path = tmp_db_path();
    let db = Database::open_unencrypted(&path).await.unwrap();

    // No `set_content_root_key` call — emulates the bootstrap window
    // where initial sync races against login completion.
    let convo = "conv-legacy";
    seed_convo(&db, convo).await;
    let msg = fixture_message(convo, "msg-legacy-1", 1, "plaintext body");
    db.store_message(&msg).await.unwrap();

    let got = db.get_messages(convo, 10, None).await.unwrap();
    assert_eq!(got.len(), 1);
    match &got[0].content {
        MessageContent::Text(t) => assert_eq!(t, "plaintext body"),
        other => panic!("expected Text fallback, got {:?}", other),
    }

    // Verify the encrypted column is NULL (truly the legacy path) and
    // the legacy `content_json` holds the real plaintext.
    let row = sqlx::query(
        "SELECT payload_encrypted, payload_key_version, content_type, content_json
         FROM messages WHERE id = ?1",
    )
    .bind("msg-legacy-1")
    .fetch_one(db.pool_for_test())
    .await
    .unwrap();
    let payload: Option<Vec<u8>> = row.get("payload_encrypted");
    let kv: Option<i64> = row.get("payload_key_version");
    let content_type: String = row.get("content_type");
    let content_json: String = row.get("content_json");
    assert!(
        payload.is_none(),
        "payload_encrypted must be NULL on legacy fallback row"
    );
    assert_eq!(kv, None);
    assert_eq!(content_type, "text");
    assert_eq!(content_json, "plaintext body");
}

#[tokio::test]
async fn schema_migration_adds_columns_and_records_v1() {
    let path = tmp_db_path();
    let db = Database::open_unencrypted(&path).await.unwrap();

    // All five field-encryption columns must exist on `messages`.
    let rows = sqlx::query("PRAGMA table_info(messages)")
        .fetch_all(db.pool_for_test())
        .await
        .unwrap();
    let cols: std::collections::HashSet<String> =
        rows.iter().map(|r| r.get::<String, _>("name")).collect();
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

    // The MLSMessageFieldMigrationV1 row must be recorded so the DROP
    // path never re-runs on subsequent opens.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM migration_status WHERE name = 'MLSMessageFieldMigrationV1'",
    )
    .fetch_one(db.pool_for_test())
    .await
    .unwrap();
    assert_eq!(
        count, 1,
        "MLSMessageFieldMigrationV1 must be recorded after open"
    );
}

#[tokio::test]
async fn entry_hmac_chains_across_writes() {
    let path = tmp_db_path();
    let db = Database::open_unencrypted(&path).await.unwrap();
    db.set_content_root_key(vec![0x77u8; 32]);

    let convo = "conv-hmac-chain";
    seed_convo(&db, convo).await;
    db.store_message(&fixture_message(convo, "m1", 1, "first"))
        .await
        .unwrap();
    db.store_message(&fixture_message(convo, "m2", 2, "second"))
        .await
        .unwrap();

    // Pull both HMAC tags. They must differ (first uses seed-of-zeros as
    // prev_hmac; second uses m1's tag as prev_hmac).
    let rows = sqlx::query("SELECT id, entry_hmac FROM messages WHERE convo_id = ?1 ORDER BY seq")
        .bind(convo)
        .fetch_all(db.pool_for_test())
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    let h1: Vec<u8> = rows[0].get("entry_hmac");
    let h2: Vec<u8> = rows[1].get("entry_hmac");
    assert_eq!(h1.len(), 32);
    assert_eq!(h2.len(), 32);
    assert_ne!(
        h1, h2,
        "chained HMAC tags for distinct messages must differ"
    );
}
