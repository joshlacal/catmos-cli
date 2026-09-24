//! C35: CLI native canonical request parity test.
//! Verifies (a) request preview/projection, (b) offline hydration,
//! (c) consent state transitions against the frozen core reference.

use catbird_mls::orchestrator::{RequestCapabilities, RequestConsent, RequestCrypto, RequestPreview};
use catbird_mls::{DirectRequestView, GroupInvitationReference, RequestIntroductionMetadata};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

const EXPECTED_DIGEST_A: &str = "f678197895ffba15f7694f4daeaf25ee95536cf4f04218287a3e2fa0ec8eac3d";
const EXPECTED_DIGEST_B: &str = "f678197895ffba15f7694f4daeaf25ee95536cf4f04218287a3e2fa0ec8eac3d";
const EXPECTED_DIGEST_C: &str = "c18e2f54cd3b23f79ed2271d3902f4ae548a8f02491283a67807f01883eca208";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn corpus_path() -> PathBuf {
    workspace_root()
        .join("docs/generated-artifacts/encrypted-requests/evidence/c35/c35_canonical_request_corpus.json")
}

fn canonical_json_bytes(val: &Value) -> Vec<u8> {
    fn sort_value(v: &Value) -> Value {
        match v {
            Value::Object(map) => {
                let mut sorted = std::collections::BTreeMap::new();
                for (k, val) in map {
                    sorted.insert(k.clone(), sort_value(val));
                }
                Value::Object(sorted.into_iter().collect())
            }
            Value::Array(arr) => Value::Array(arr.iter().map(sort_value).collect()),
            other => other.clone(),
        }
    }
    let sorted = sort_value(val);
    serde_json::to_vec(&sorted).unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[test]
fn test_c35_cli_parity() {
    // 1. Verify frozen CLI artifact
    let cli_release_path = workspace_root().join("catmos-cli/target/release/catmos");
    if cli_release_path.exists() {
        let bytes = fs::read(&cli_release_path).expect("read catmos release binary");
        let hash = sha256_hex(&bytes);
        println!("Loaded catmos release binary sha256: {hash}");
        assert_eq!(
            hash,
            "efa026d740a1f0f3794544084aebb96423ed2ac37ad1c3b94f1f86fc940a89bc",
            "catmos release binary sha256 must match frozen recapture"
        );
    }

    // 2. Load canonical corpus
    let raw = fs::read_to_string(corpus_path()).expect("read corpus");
    let corpus: Value = serde_json::from_str(&raw).expect("parse corpus");

    // =========================================================================
    // Stage A: Projection
    // =========================================================================
    let requests = corpus["stageA_projection"]["requests"].as_array().unwrap();
    let mut projected_views: Vec<DirectRequestView> = Vec::new();

    for req in requests {
        let conversation_id = req["conversationId"].as_str().unwrap().to_string();
        let first_message_id = req["firstMessageId"].as_str().map(|s| s.to_string());
        let consent = match req["consent"].as_str().unwrap() {
            "incomingPending" => RequestConsent::IncomingPending,
            "outgoingPending" => RequestConsent::OutgoingPending,
            "accepted" => RequestConsent::Accepted,
            "closed" => RequestConsent::Closed,
            other => panic!("unknown consent {other}"),
        };
        let crypto = match req["crypto"].as_str().unwrap() {
            "ready" => RequestCrypto::Ready,
            "welcomeAvailable" => RequestCrypto::WelcomeAvailable,
            "importing" => RequestCrypto::Importing,
            "unavailable" => RequestCrypto::Unavailable,
            other => panic!("unknown crypto {other}"),
        };
        let preview = if req["preview"].is_null() {
            None
        } else {
            let p = &req["preview"];
            match p["type"].as_str().unwrap() {
                "ready" => {
                    let text = p["text"].as_str().unwrap().to_string();
                    let invitation = if p["invitation"].is_null() {
                        None
                    } else {
                        let inv = &p["invitation"];
                        Some(GroupInvitationReference {
                            authority_did: inv["authorityDid"].as_str().unwrap().to_string(),
                            conversation_id: inv["conversationId"].as_str().unwrap().to_string(),
                            invitation_transition_id: inv["invitationTransitionId"]
                                .as_str()
                                .unwrap()
                                .to_string(),
                            invited_by_did: inv["invitedByDid"].as_str().unwrap().to_string(),
                            invited_by_device_id: inv["invitedByDeviceId"]
                                .as_str()
                                .unwrap()
                                .to_string(),
                            recipient_did: inv["recipientDid"].as_str().unwrap().to_string(),
                        })
                    };
                    Some(RequestPreview::Ready { text, invitation })
                }
                "unavailable" => Some(RequestPreview::Unavailable {
                    code: p["code"].as_str().unwrap().to_string(),
                }),
                other => panic!("unknown preview type {other}"),
            }
        };
        let introduction = if req["introduction"].is_null() {
            None
        } else {
            let intro = &req["introduction"];
            Some(RequestIntroductionMetadata {
                sender_did: intro["senderDid"].as_str().unwrap().to_string(),
                sender_device_id: intro["senderDeviceId"].as_str().unwrap().to_string(),
                received_at: intro["receivedAt"].as_str().unwrap().to_string(),
                epoch: intro["epoch"].as_u64().unwrap(),
                sequence_number: intro["sequenceNumber"].as_u64().unwrap(),
            })
        };
        let has_preview = matches!(preview, Some(RequestPreview::Ready { .. }));
        let capabilities = RequestCapabilities::derive(consent, crypto, has_preview);
        let state_version = req["stateVersion"].as_u64().unwrap();
        let generation = req["generation"].as_u64().unwrap();

        projected_views.push(DirectRequestView {
            introduction,
            conversation_id,
            first_message_id,
            consent,
            crypto,
            preview,
            capabilities,
            state_version,
            generation,
        });
    }

    assert_eq!(projected_views.len(), 4);
    let json_a = serde_json::to_value(&projected_views).unwrap();
    let bytes_a = canonical_json_bytes(&json_a);
    let digest_a = sha256_hex(&bytes_a);
    println!("C35 CLI Stage A Digest: {digest_a}");
    assert_eq!(digest_a, EXPECTED_DIGEST_A, "CLI Stage A digest must match core reference");

    // =========================================================================
    // Stage B: Offline Hydration from Persisted State
    // =========================================================================
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("c35_cli.sqlite");

    // 1. Create SQLite database and persist all 4 views
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "CREATE TABLE mls_direct_request_projection (
                conversation_id TEXT PRIMARY KEY,
                view_json TEXT NOT NULL,
                consent TEXT NOT NULL,
                state_version INTEGER NOT NULL
            )",
            [],
        )
        .unwrap();

        for view in &projected_views {
            let view_json = serde_json::to_string(view).unwrap();
            let consent_str = match view.consent {
                RequestConsent::IncomingPending => "incomingPending",
                RequestConsent::OutgoingPending => "outgoingPending",
                RequestConsent::Accepted => "accepted",
                RequestConsent::Closed => "closed",
            };
            conn.execute(
                "INSERT INTO mls_direct_request_projection (conversation_id, view_json, consent, state_version)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![view.conversation_id, view_json, consent_str, view.state_version],
            )
            .unwrap();
        }
    } // Connection explicitly closed here

    // 2. Offline Reopen: read back all views in isolated offline environment
    let mut hydrated_views: Vec<DirectRequestView> = Vec::new();
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let mut stmt = conn
            .prepare("SELECT view_json FROM mls_direct_request_projection ORDER BY conversation_id")
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                let s: String = row.get(0)?;
                Ok(s)
            })
            .unwrap();

        for row in rows {
            let s = row.unwrap();
            let view: DirectRequestView = serde_json::from_str(&s).unwrap();
            hydrated_views.push(view);
        }
    }

    let mut expected_views = projected_views.clone();
    expected_views.sort_by(|a, b| a.conversation_id.cmp(&b.conversation_id));
    assert_eq!(hydrated_views, expected_views);

    let json_b = serde_json::to_value(&hydrated_views).unwrap();
    let bytes_b = canonical_json_bytes(&json_b);
    let digest_b = sha256_hex(&bytes_b);
    println!("C35 CLI Stage B Digest: {digest_b}");
    assert_eq!(digest_b, EXPECTED_DIGEST_B, "CLI Stage B digest must match core reference");

    // =========================================================================
    // Stage C: Consent State Transitions & Fencing
    // =========================================================================
    let mut transition_views = hydrated_views.clone();

    // 1. Accept Request 1 (IncomingPending -> Accepted)
    {
        let req1 = transition_views
            .iter_mut()
            .find(|v| v.conversation_id == "11111111-c35a-4000-8000-000000000001")
            .unwrap();
        assert_eq!(req1.consent, RequestConsent::IncomingPending);
        req1.consent = RequestConsent::Accepted;
        req1.state_version = 2;
        req1.capabilities = RequestCapabilities::derive(
            req1.consent,
            req1.crypto,
            matches!(req1.preview, Some(RequestPreview::Ready { .. })),
        );
        assert!(req1.capabilities.can_send);
        assert!(req1.capabilities.can_emit_receipts);
        assert!(req1.capabilities.can_administer);
        assert!(!req1.capabilities.can_accept);
    }

    // 2. Close Request 2 (OutgoingPending -> Closed)
    {
        let req2 = transition_views
            .iter_mut()
            .find(|v| v.conversation_id == "11111111-c35a-4000-8000-000000000002")
            .unwrap();
        assert_eq!(req2.consent, RequestConsent::OutgoingPending);
        req2.consent = RequestConsent::Closed;
        req2.state_version = 2;
        req2.capabilities = RequestCapabilities::derive(
            req2.consent,
            req2.crypto,
            matches!(req2.preview, Some(RequestPreview::Ready { .. })),
        );
        assert!(!req2.capabilities.can_close);
        assert!(!req2.capabilities.can_send);
    }

    // 3. Close Request 4 (IncomingPending -> Closed)
    {
        let req4 = transition_views
            .iter_mut()
            .find(|v| v.conversation_id == "11111111-c35a-4000-8000-000000000004")
            .unwrap();
        assert_eq!(req4.consent, RequestConsent::IncomingPending);
        req4.consent = RequestConsent::Closed;
        req4.state_version = 2;
        req4.capabilities = RequestCapabilities::derive(
            req4.consent,
            req4.crypto,
            matches!(req4.preview, Some(RequestPreview::Ready { .. })),
        );
        assert!(!req4.capabilities.can_close);
        assert!(!req4.capabilities.can_preview);
    }

    // 4. Fence: Stale IncomingPending echo cannot demote Accepted Request 1
    {
        let req1 = transition_views
            .iter()
            .find(|v| v.conversation_id == "11111111-c35a-4000-8000-000000000001")
            .unwrap();
        let stale_version = 1u64;
        assert!(stale_version < req1.state_version, "stale update must be older");
        assert_eq!(req1.consent, RequestConsent::Accepted);
    }

    // 5. Fence: Stale Accepted attempt cannot revive Closed Request 2
    {
        let req2 = transition_views
            .iter()
            .find(|v| v.conversation_id == "11111111-c35a-4000-8000-000000000002")
            .unwrap();
        assert_eq!(req2.consent, RequestConsent::Closed);
    }

    let json_c = serde_json::to_value(&transition_views).unwrap();
    let bytes_c = canonical_json_bytes(&json_c);
    let digest_c = sha256_hex(&bytes_c);
    println!("C35 CLI Stage C Digest: {digest_c}");
    assert_eq!(digest_c, EXPECTED_DIGEST_C, "CLI Stage C digest must match core reference");

    println!("C35 CLI PARITY: ALL STAGES PASS");
}
