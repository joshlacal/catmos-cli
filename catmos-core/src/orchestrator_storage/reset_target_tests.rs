use super::*;
use rusqlite::types::Value;
use std::path::Path;

const CID: &str = "reset-fixture-stable-id";
const DID: &str = "did:plc:resetfixture";
const OLD: &str = "00112233445566778899aabbccddeeff00";
const LOSER: &str = "11112222333344445555666677778888";
const WINNER: &str = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899";
const NEXT: &str = "99aabbccddeeff001122334455667788";
const KEY: &str = "reset-cycle-test-only";

fn open(path: &Path) -> SqliteStorage {
    SqliteStorage::new(path.to_str().unwrap(), KEY).unwrap()
}

fn table(storage: &SqliteStorage, name: &str) -> Vec<Vec<Value>> {
    let conn = storage.conn.lock().unwrap();
    let mut statement = conn
        .prepare(&format!("SELECT * FROM {name} ORDER BY rowid"))
        .unwrap();
    let columns = statement.column_count();
    statement
        .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

fn all_rows(storage: &SqliteStorage) -> Vec<Vec<Vec<Value>>> {
    [
        "conversations",
        "conversation_group_aliases",
        "messages",
        "group_states",
        "sync_cursors",
        "recovery_backoffs",
        "recovery_globals",
    ]
    .into_iter()
    .map(|name| table(storage, name))
    .collect()
}

fn execute(storage: &SqliteStorage, sql: &str) {
    storage.conn.lock().unwrap().execute_batch(sql).unwrap();
}

async fn seed(storage: &SqliteStorage) {
    storage
        .ensure_conversation_exists(DID, CID, OLD)
        .await
        .unwrap();
    storage
        .set_group_state(&GroupState {
            group_id: OLD.into(),
            conversation_id: CID.into(),
            epoch: 91,
            members: vec![],
        })
        .await
        .unwrap();
    storage
        .set_sync_cursor(
            DID,
            &SyncCursor {
                conversations_cursor: Some("inventory-retained".into()),
                messages_cursor: Some("messages-retained".into()),
            },
        )
        .await
        .unwrap();
    // The whole SQLCipher database is encrypted; these existing field ciphertext
    // and HMAC bytes are opaque to reset projection and must never be rewritten.
    execute(storage, "INSERT INTO messages(id,conversation_id,sender_did,text,timestamp,epoch,sequence_number,is_own,payload_encrypted,entry_hmac,payload_key_version,hmac_sequence) VALUES ('retained','reset-fixture-stable-id','did:plc:peer','','2026-09-05T00:00:00Z',91,1,0,X'01020304',X'05060708',1,1); UPDATE conversations SET epoch=91,join_epoch=90,metadata_json='{\"name\":\"kept\"}',updated_at='unchanged';");
}

fn pending(group: &str, generation: i32, time: i64) -> ConversationState {
    ConversationState::ResetPending {
        new_group_id: group.into(),
        reset_generation: generation,
        notified_at_ms: time,
    }
}

#[tokio::test]
async fn mark_publishes_full_authority_and_clears_quarantine_in_one_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reset.db");
    let storage = open(&path);
    seed(&storage).await;
    execute(&storage, "UPDATE conversations SET quarantine_reason_tag='peer',quarantine_since_ms=9,needs_rejoin=0;");
    execute(&storage, "INSERT INTO recovery_backoffs VALUES ('reset-fixture-stable-id',4,10,999),('other-conversation',3,11,1000); INSERT INTO recovery_globals VALUES ('last_global_rejoin_attempt_at',12);");
    let global = table(&storage, "recovery_globals");
    let other = table(&storage, "recovery_backoffs")[1].clone();
    let history = table(&storage, "messages");
    let native = table(&storage, "group_states");
    let aliases = table(&storage, "conversation_group_aliases");
    storage
        .mark_reset_pending(CID, LOSER, 0, 123)
        .await
        .unwrap();
    assert_eq!(
        storage.get_conversation_state(CID).await.unwrap(),
        Some(pending(LOSER, 0, 123))
    );
    assert!(storage.needs_rejoin(CID).await.unwrap());
    let fields: (String, i64, i64, Option<String>, Option<i64>) = storage.conn.lock().unwrap().query_row(
        "SELECT group_id,epoch,join_epoch,quarantine_reason_tag,quarantine_since_ms FROM conversations", [],
        |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?))).unwrap();
    assert_eq!(fields, (OLD.into(), 91, 90, None, None));
    let snapshot = all_rows(&storage);
    storage
        .mark_reset_pending(CID, LOSER, 0, 123)
        .await
        .unwrap();
    assert_eq!(
        all_rows(&storage),
        snapshot,
        "exact replay must not rewrite rows"
    );
    assert_eq!(table(&storage, "messages"), history);
    assert_eq!(table(&storage, "group_states"), native);
    assert_eq!(table(&storage, "conversation_group_aliases"), aliases);
    drop(storage);
    let reopened = open(&path);
    assert_eq!(
        reopened.get_conversation_state(CID).await.unwrap(),
        Some(pending(LOSER, 0, 123))
    );
    assert!(reopened.needs_rejoin(CID).await.unwrap());
    assert_eq!(table(&reopened, "recovery_backoffs"), vec![other]);
    assert_eq!(table(&reopened, "recovery_globals"), global);
}

#[tokio::test]
async fn mark_adopt_complete_preserves_history_and_generation_fence_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reset.db");
    let storage = open(&path);
    seed(&storage).await;
    let history = table(&storage, "messages");
    let native = table(&storage, "group_states");
    let cursors = table(&storage, "sync_cursors");
    storage
        .mark_reset_pending(CID, LOSER, 7, 123)
        .await
        .unwrap();
    assert!(storage
        .adopt_reset_pending_target(CID, 7, LOSER, WINNER)
        .await
        .unwrap());
    assert_eq!(
        storage.get_conversation_state(CID).await.unwrap(),
        Some(pending(WINNER, 7, 123))
    );
    let unchanged = all_rows(&storage);
    assert!(storage
        .adopt_reset_pending_target(CID, 7, WINNER, WINNER)
        .await
        .unwrap());
    assert_eq!(all_rows(&storage), unchanged);
    assert!(!storage
        .complete_reset_pending(CID, 6, WINNER, 2)
        .await
        .unwrap());
    assert!(!storage
        .complete_reset_pending(CID, 7, LOSER, 2)
        .await
        .unwrap());
    assert_eq!(
        all_rows(&storage),
        unchanged,
        "CAS misses must not add aliases"
    );
    drop(storage);
    let storage = open(&path);
    assert!(storage
        .complete_reset_pending(CID, 7, WINNER, 2)
        .await
        .unwrap());
    let projection:(String,i64,i64,Option<i64>,Option<String>,Option<i64>,i64)=storage.conn.lock().unwrap().query_row(
        "SELECT group_id,epoch,join_epoch,reset_generation,reset_new_group_id,reset_notified_at_ms,needs_rejoin FROM conversations",[],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).unwrap();
    assert_eq!(projection, (WINNER.into(), 2, 2, Some(7), None, None, 0));
    assert_eq!(
        storage.get_conversation_state(CID).await.unwrap(),
        Some(ConversationState::Active)
    );
    assert_eq!(table(&storage, "messages"), history);
    assert_eq!(table(&storage, "group_states"), native);
    assert_eq!(table(&storage, "sync_cursors"), cursors);
    let exact = all_rows(&storage);
    execute(&storage,"CREATE TRIGGER no_completion_rewrite BEFORE UPDATE ON conversations BEGIN SELECT RAISE(ABORT,'completed replay rewrote state'); END;");
    assert!(storage
        .complete_reset_pending(CID, 7, WINNER, 2)
        .await
        .unwrap());
    assert_eq!(all_rows(&storage), exact);
    execute(&storage, "DROP TRIGGER no_completion_rewrite;");
    let aliases = storage.list_conversation_group_ids(CID).unwrap();
    assert!(
        aliases.contains(&OLD.into())
            && aliases.contains(&WINNER.into())
            && !aliases.contains(&LOSER.into())
    );
    drop(storage);
    let storage = open(&path);
    let unchanged = all_rows(&storage);
    assert!(storage
        .mark_reset_pending(CID, LOSER, 6, 200)
        .await
        .is_err());
    assert!(storage
        .mark_reset_pending(CID, LOSER, 7, 200)
        .await
        .is_err());
    assert!(!storage
        .complete_reset_pending(CID, 7, WINNER, 3)
        .await
        .unwrap());
    assert_eq!(all_rows(&storage), unchanged);
    storage.mark_reset_pending(CID, NEXT, 8, 201).await.unwrap();
    let newest = all_rows(&storage);
    assert!(!storage
        .adopt_reset_pending_target(CID, 7, WINNER, LOSER)
        .await
        .unwrap());
    assert!(!storage
        .complete_reset_pending(CID, 7, WINNER, 3)
        .await
        .unwrap());
    assert_eq!(all_rows(&storage), newest);
    assert!(storage
        .implemented_optional_methods()
        .contains(&"adopt_reset_pending_target"));
}

#[tokio::test]
async fn reset_callbacks_reject_malformed_ambiguous_and_terminal_authority_without_writes() {
    for corruption in [
        "UPDATE conversations SET state='\"Closed\"'",
        "UPDATE conversations SET state='\"DeviceRemoved\"'",
        "UPDATE conversations SET state='Active'",
        "UPDATE conversations SET state='not-json'",
        "UPDATE conversations SET reset_new_group_id=NULL",
        "UPDATE conversations SET reset_notified_at_ms=NULL",
        "UPDATE conversations SET reset_notified_at_ms=124",
        "UPDATE conversations SET reset_generation=8",
        "UPDATE conversations SET needs_rejoin=0",
        "UPDATE conversations SET quarantine_reason_tag='peer',quarantine_since_ms=2",
        "INSERT INTO recovery_backoffs VALUES ('reset-fixture-stable-id',4,10,999)",
        "INSERT INTO conversations SELECT conversation_id,'did:plc:other',group_id,epoch,state,join_method,join_epoch,needs_rejoin,members_json,metadata_json,metadata_version,metadata_blob_locator,avatar_blob_locator,avatar_bytes,avatar_content_type,created_at,updated_at,sequencer_did,reset_new_group_id,reset_generation,reset_notified_at_ms,quarantine_reason_tag,quarantine_since_ms FROM conversations",
        "DELETE FROM conversations",
    ] {
        let dir=tempfile::tempdir().unwrap(); let storage=open(&dir.path().join("reset.db")); seed(&storage).await;
        storage.mark_reset_pending(CID,LOSER,7,123).await.unwrap(); execute(&storage,corruption);
        let unchanged=all_rows(&storage);
        assert!(!storage.adopt_reset_pending_target(CID,7,LOSER,WINNER).await.unwrap(),"{corruption}");
        assert!(!storage.complete_reset_pending(CID,7,LOSER,2).await.unwrap(),"{corruption}");
        assert_eq!(all_rows(&storage),unchanged,"{corruption}");
    }
}

#[tokio::test]
async fn reset_transactions_roll_back_full_state_and_alias_writes_on_database_errors() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open(&dir.path().join("reset.db"));
    seed(&storage).await;
    execute(&storage,"CREATE TRIGGER reject_projection AFTER UPDATE ON conversations BEGIN SELECT RAISE(ABORT,'injected projection write failure'); END;");
    let before = all_rows(&storage);
    assert!(storage
        .mark_reset_pending(CID, LOSER, 7, 123)
        .await
        .is_err());
    assert_eq!(all_rows(&storage), before);
    execute(&storage, "DROP TRIGGER reject_projection;");
    storage
        .mark_reset_pending(CID, LOSER, 7, 123)
        .await
        .unwrap();
    execute(&storage,"CREATE TRIGGER reject_projection AFTER UPDATE ON conversations BEGIN SELECT RAISE(ABORT,'injected projection write failure'); END;");
    let before = all_rows(&storage);
    assert!(storage
        .adopt_reset_pending_target(CID, 7, LOSER, WINNER)
        .await
        .is_err());
    assert_eq!(all_rows(&storage), before);
    assert!(storage
        .complete_reset_pending(CID, 7, LOSER, 2)
        .await
        .is_err());
    assert_eq!(
        all_rows(&storage),
        before,
        "completion aliases must roll back with projection failure"
    );
}

#[test]
fn competing_connections_choose_one_reset_target_and_preserve_newer_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reset.db");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let storage = open(&path);
    runtime.block_on(async {
        seed(&storage).await;
        storage
            .mark_reset_pending(CID, LOSER, 7, 123)
            .await
            .unwrap();
    });
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles: [_; 2] = [WINNER, NEXT].map(|winner| {
        let path = path.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let store = open(&path);
            barrier.wait();
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(store.adopt_reset_pending_target(CID, 7, LOSER, winner))
                .unwrap()
        })
    });
    let results = handles.map(|h| h.join().unwrap());
    assert_eq!(results.into_iter().filter(|v| *v).count(), 1);
    let target = runtime
        .block_on(storage.get_conversation_state(CID))
        .unwrap()
        .unwrap();
    assert!(target == pending(WINNER, 7, 123) || target == pending(NEXT, 7, 123));
    runtime
        .block_on(storage.mark_reset_pending(CID, OLD, 8, 200))
        .unwrap();
    let before = all_rows(&storage);
    for old in [LOSER, WINNER, NEXT] {
        assert!(!runtime
            .block_on(storage.adopt_reset_pending_target(CID, 7, old, LOSER))
            .unwrap());
        assert!(!runtime
            .block_on(storage.complete_reset_pending(CID, 7, old, 1))
            .unwrap());
    }
    assert_eq!(all_rows(&storage), before);
}

#[tokio::test]
async fn mark_keeps_closed_permanent_but_permits_fresh_device_removed_reset() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open(&dir.path().join("reset.db"));
    seed(&storage).await;
    execute(
        &storage,
        "UPDATE conversations SET state='\"DeviceRemoved\"',reset_generation=7;",
    );
    let before = all_rows(&storage);
    assert!(storage
        .mark_reset_pending(CID, LOSER, 7, 123)
        .await
        .is_err());
    assert_eq!(all_rows(&storage), before);
    storage
        .mark_reset_pending(CID, LOSER, 8, 123)
        .await
        .unwrap();
    assert_eq!(
        storage.get_conversation_state(CID).await.unwrap(),
        Some(pending(LOSER, 8, 123))
    );
    execute(&storage,"UPDATE conversations SET state='\"Closed\"',reset_new_group_id=NULL,reset_notified_at_ms=NULL;");
    let before = all_rows(&storage);
    assert!(storage
        .mark_reset_pending(CID, WINNER, 9, 200)
        .await
        .is_err());
    assert_eq!(all_rows(&storage), before);
}

#[tokio::test]
async fn reset_completion_cannot_rewind_the_current_target_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open(&dir.path().join("reset.db"));
    seed(&storage).await;
    storage.mark_reset_pending(CID, OLD, 7, 123).await.unwrap();
    let before = all_rows(&storage);
    assert!(!storage
        .complete_reset_pending(CID, 7, OLD, 90)
        .await
        .unwrap());
    assert_eq!(all_rows(&storage), before);
    assert!(storage
        .complete_reset_pending(CID, 7, OLD, 91)
        .await
        .unwrap());
}

#[tokio::test]
async fn reset_callbacks_match_native_bounds_and_reject_invalid_targets_without_writes() {
    for target in [
        String::new(),
        "zz".repeat(16),
        "ab".repeat(15),
        "ab".repeat(65),
        "a".repeat(33),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let storage = open(&dir.path().join("reset.db"));
        seed(&storage).await;
        let before = all_rows(&storage);
        assert!(storage
            .mark_reset_pending(CID, &target, 0, 123)
            .await
            .is_err());
        assert_eq!(all_rows(&storage), before);
        storage
            .mark_reset_pending(CID, LOSER, 0, 123)
            .await
            .unwrap();
        let before = all_rows(&storage);
        assert!(!storage
            .adopt_reset_pending_target(CID, 0, LOSER, &target)
            .await
            .unwrap());
        assert!(!storage
            .complete_reset_pending(CID, 0, &target, 1)
            .await
            .unwrap());
        assert_eq!(all_rows(&storage), before);
    }
    let dir = tempfile::tempdir().unwrap();
    let storage = open(&dir.path().join("reset.db"));
    seed(&storage).await;
    let max_target = "AB".repeat(64);
    storage
        .mark_reset_pending(CID, &max_target, 0, 123)
        .await
        .unwrap();
    assert!(storage
        .adopt_reset_pending_target(CID, 0, &max_target, LOSER)
        .await
        .unwrap());
    assert!(storage
        .complete_reset_pending(CID, 0, LOSER, 1)
        .await
        .unwrap());
}

#[tokio::test]
async fn reset_callbacks_reject_duplicate_or_unknown_serialized_authority_fields() {
    let encoded = serde_json::to_string(&pending(LOSER, 7, 123)).unwrap();
    let duplicate_target = encoded.replacen(
        "\"new_group_id\":",
        &format!("\"new_group_id\":\"{LOSER}\",\"new_group_id\":"),
        1,
    );
    let duplicate_generation = encoded.replacen(
        "\"reset_generation\":",
        "\"reset_generation\":7,\"reset_generation\":",
        1,
    );
    let unknown_field = encoded.replacen(
        "\"notified_at_ms\":123",
        "\"notified_at_ms\":123,\"future_authority\":true",
        1,
    );
    for malformed in [duplicate_target, duplicate_generation, unknown_field] {
        let dir = tempfile::tempdir().unwrap();
        let storage = open(&dir.path().join("reset.db"));
        seed(&storage).await;
        storage
            .mark_reset_pending(CID, LOSER, 7, 123)
            .await
            .unwrap();
        storage
            .conn
            .lock()
            .unwrap()
            .execute("UPDATE conversations SET state=?1", [malformed])
            .unwrap();
        let before = all_rows(&storage);
        assert!(storage.mark_reset_pending(CID, NEXT, 8, 124).await.is_err());
        assert!(!storage
            .adopt_reset_pending_target(CID, 7, LOSER, WINNER)
            .await
            .unwrap());
        assert!(!storage
            .complete_reset_pending(CID, 7, LOSER, 2)
            .await
            .unwrap());
        assert_eq!(all_rows(&storage), before);
    }
}

#[tokio::test]
async fn suppressed_sqlite_updates_never_acknowledge_uncommitted_reset_authority() {
    let dir = tempfile::tempdir().unwrap();
    let storage = open(&dir.path().join("reset.db"));
    seed(&storage).await;
    execute(&storage, "CREATE TRIGGER suppress_projection BEFORE UPDATE ON conversations BEGIN SELECT RAISE(IGNORE); END;");
    let before = all_rows(&storage);
    assert!(storage
        .mark_reset_pending(CID, LOSER, 7, 123)
        .await
        .is_err());
    assert_eq!(all_rows(&storage), before);
    execute(&storage, "DROP TRIGGER suppress_projection;");
    storage
        .mark_reset_pending(CID, LOSER, 7, 123)
        .await
        .unwrap();
    execute(&storage, "CREATE TRIGGER suppress_projection BEFORE UPDATE ON conversations BEGIN SELECT RAISE(IGNORE); END;");
    let before = all_rows(&storage);
    assert!(!storage
        .adopt_reset_pending_target(CID, 7, LOSER, WINNER)
        .await
        .unwrap());
    assert!(!storage
        .complete_reset_pending(CID, 7, LOSER, 2)
        .await
        .unwrap());
    assert_eq!(
        all_rows(&storage),
        before,
        "completion aliases must roll back when no projection changed"
    );
}
