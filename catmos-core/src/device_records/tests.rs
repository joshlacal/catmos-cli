use super::*;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

const DID: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const DEVICE: &str = "11111111-1111-4111-8111-111111111111";

fn record(device: &str, key: &[u8]) -> Value {
    json!({"uri": format!("at://{DID}/{COLLECTION}/{device}"), "value": {
        "$type": COLLECTION, "algorithm": "ed25519", "createdAt": "2026-09-05T00:00:00Z",
        "mlsSignaturePublicKey": {"$bytes": STANDARD.encode(key)}
    }})
}

#[test]
fn did_authority_is_exact_https_and_unambiguous() {
    let document = json!({"id": DID, "service": [{"id": "#atproto_pds",
        "type": "AtprotoPersonalDataServer", "serviceEndpoint": "https://pds.catbird.blue/base"}]});
    let pds = pds_from_document(DID, &document).unwrap();
    assert_eq!(
        xrpc_url(&pds, "com.atproto.repo.listRecords").as_str(),
        "https://pds.catbird.blue/base/xrpc/com.atproto.repo.listRecords"
    );
    assert_eq!(
        did_document_url("did:web:catbird.blue").unwrap().as_str(),
        "https://catbird.blue/.well-known/did.json"
    );
    for endpoint in [
        "http://pds.catbird.blue",
        "https://user:secret@pds.catbird.blue",
        "https://pds.catbird.blue?x=1",
        "https://pds.catbird.blue#x",
    ] {
        let mut invalid = document.clone();
        invalid["service"][0]["serviceEndpoint"] = json!(endpoint);
        assert!(pds_from_document(DID, &invalid).is_err());
    }
    let mut foreign = document.clone();
    foreign["id"] = json!("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(pds_from_document(DID, &foreign).is_err());
    let mut foreign = document.clone();
    foreign["service"][0]["id"] = json!("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb#atproto_pds");
    assert!(pds_from_document(DID, &foreign).is_err());
    let mut duplicate = document.clone();
    duplicate["service"]
        .as_array_mut()
        .unwrap()
        .push(document["service"][0].clone());
    assert!(pds_from_document(DID, &duplicate).is_err());
    for did in [
        "did:web:catbird.blue:folder",
        "did:web:catbird.blue%3A444",
        "did:plc:invalid",
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#device",
    ] {
        assert!(did_document_url(did).is_err());
    }
}

#[test]
fn repository_records_require_scope_schema_key_and_date() {
    let original = record(DEVICE, &[3; 32]);
    assert_eq!(parse_record(DID, &original).unwrap().key, vec![3; 32]);
    let mut compatible = original.clone();
    compatible["value"]["algorithm"] = json!("Ed25519");
    compatible["value"]["mlsSignaturePublicKey"]["$bytes"] = json!(STANDARD_NO_PAD.encode([3; 32]));
    assert!(parse_record(DID, &compatible).is_ok());
    for (pointer, replacement) in [
        (
            "/uri",
            json!(format!(
                "at://did:plc:bbbbbbbbbbbbbbbbbbbbbbbb/{COLLECTION}/{DEVICE}"
            )),
        ),
        (
            "/uri",
            json!(format!("at://{DID}/blue.catbird.mlsChat.device/{DEVICE}")),
        ),
        (
            "/uri",
            json!(format!("at://{DID}/{COLLECTION}/{DEVICE}/extra")),
        ),
        ("/value/$type", json!("blue.catbird.mlsChat.device")),
        ("/value/algorithm", json!("p256")),
        ("/value/createdAt", json!("invalid")),
        (
            "/value/mlsSignaturePublicKey",
            json!(STANDARD.encode([3; 32])),
        ),
        (
            "/value/mlsSignaturePublicKey/$bytes",
            json!(STANDARD.encode([3; 31])),
        ),
        ("/value/mlsSignaturePublicKey/$bytes", json!("not-base64")),
    ] {
        let mut invalid = original.clone();
        *invalid.pointer_mut(pointer).unwrap() = replacement;
        assert!(parse_record(DID, &invalid).is_err(), "accepted {pointer}");
    }
}

#[derive(Default)]
struct Fixture {
    pages: VecDeque<(StatusCode, Value)>,
    queries: Vec<HashMap<String, String>>,
}
async fn pds_handler(
    State(state): State<Arc<Mutex<Fixture>>>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    assert!(
        headers.get("authorization").is_none(),
        "public PDS read carried credentials"
    );
    let mut state = state.lock().unwrap();
    state.queries.push(query);
    let (status, body) = state.pages.pop_front().expect("unexpected PDS request");
    (status, Json(body))
}

async fn server(
    pages: Vec<(StatusCode, Value)>,
) -> (Url, Arc<Mutex<Fixture>>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Mutex::new(Fixture {
        pages: pages.into(),
        ..Default::default()
    }));
    let app = Router::new()
        .route(
            "/base/xrpc/com.atproto.repo.listRecords",
            get(pds_handler),
        )
        .route(
            "/base/xrpc/com.atproto.repo.getRecord",
            get(pds_handler),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!("http://{}/base", listener.local_addr().unwrap())).unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, state, handle)
}

#[tokio::test]
async fn complete_public_pagination_never_sends_authentication() {
    let (url, state, handle) = server(vec![
        (
            StatusCode::OK,
            json!({"records": [record(DEVICE, &[1;32])], "cursor": "page two/+="}),
        ),
        (
            StatusCode::OK,
            json!({"records": [record("second", &[2;32])]}),
        ),
    ])
    .await;
    let records = read_records(&public_client().unwrap(), &url, DID)
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    let state = state.lock().unwrap();
    assert_eq!(state.queries[0]["repo"], DID);
    assert_eq!(state.queries[0]["collection"], COLLECTION);
    assert_eq!(state.queries[1]["cursor"], "page two/+=");
    handle.abort();
}

#[tokio::test]
async fn incomplete_or_failed_inventories_never_authorize_partial_keys() {
    for pages in [
        vec![(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error": "unavailable"}),
        )],
        vec![(StatusCode::OK, json!({}))],
        vec![(StatusCode::OK, json!({"records": [], "cursor": ""}))],
        vec![
            (StatusCode::OK, json!({"records": [], "cursor": "same"})),
            (StatusCode::OK, json!({"records": [], "cursor": "same"})),
        ],
        vec![
            (
                StatusCode::OK,
                json!({"records": [record(DEVICE, &[1;32])], "cursor": "next"}),
            ),
            (
                StatusCode::OK,
                json!({"records": [record(DEVICE, &[1;32])]}),
            ),
        ],
        vec![
            (
                StatusCode::OK,
                json!({"records": [record(DEVICE, &[1;32])], "cursor": "next"}),
            ),
            (StatusCode::FORBIDDEN, json!({"error": "denied"})),
        ],
        (0..MAX_PAGES)
            .map(|index| {
                (
                    StatusCode::OK,
                    json!({"records": [], "cursor": index.to_string()}),
                )
            })
            .collect(),
    ] {
        let (url, _, handle) = server(pages).await;
        assert!(read_records(&public_client().unwrap(), &url, DID)
            .await
            .is_err());
        handle.abort();
    }
    let (url, _, handle) = server(vec![(StatusCode::OK, json!({"records": []}))]).await;
    assert!(read_records(&public_client().unwrap(), &url, DID)
        .await
        .unwrap()
        .is_empty());
    handle.abort();
}

#[tokio::test]
async fn publication_is_create_only_idempotent_and_preserves_existing_keys() {
    let key = [7; 32];
    for fail_ack in [false, true] {
        let (url, state, handle) = server(vec![(StatusCode::OK, json!({"records": []}))]).await;
        ensure_published(
            &public_client().unwrap(),
            &url,
            DID,
            DEVICE,
            &key,
            |body| async move {
                assert_eq!(body["repo"], DID);
                assert_eq!(body["rkey"], DEVICE);
                assert!(body.as_object().unwrap().contains_key("swapRecord"));
                assert_eq!(body["swapRecord"], Value::Null);
                assert_eq!(
                    body["record"]["mlsSignaturePublicKey"]["$bytes"],
                    STANDARD.encode(key)
                );
                state
                    .lock()
                    .unwrap()
                    .pages
                    .push_back((StatusCode::OK, json!({"records": [record(DEVICE, &key)]})));
                if fail_ack {
                    Err(CatmosError::Network("simulated lost ACK".into()))
                } else {
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        handle.abort();
    }
    let (url, _, handle) = server(vec![(
        StatusCode::OK,
        json!({"records": [record(DEVICE, &key)]}),
    )])
    .await;
    ensure_published(
        &public_client().unwrap(),
        &url,
        DID,
        DEVICE,
        &key,
        |_| async {
            panic!("idempotent enrollment attempted a write");
        },
    )
    .await
    .unwrap();
    handle.abort();
    let (url, _, handle) = server(vec![(
        StatusCode::OK,
        json!({"records": [record(DEVICE, &[8;32])]}),
    )])
    .await;
    let error = ensure_published(
        &public_client().unwrap(),
        &url,
        DID,
        DEVICE,
        &key,
        |_| async {
            panic!("mismatched existing key was overwritten");
        },
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("existing keys and records were preserved"));
    handle.abort();
}

#[tokio::test]
async fn publication_failure_or_concurrent_conflict_requires_exact_readback() {
    for final_records in [vec![], vec![record(DEVICE, &[8; 32])]] {
        let (url, state, handle) = server(vec![(StatusCode::OK, json!({"records": []}))]).await;
        let error = ensure_published(
            &public_client().unwrap(),
            &url,
            DID,
            DEVICE,
            &[7; 32],
            |_| async {
                state
                    .lock()
                    .unwrap()
                    .pages
                    .push_back((StatusCode::OK, json!({"records": final_records})));
                Err(CatmosError::Xrpc("InvalidSwap".into()))
            },
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("InvalidSwap")
                || error
                    .to_string()
                    .contains("existing keys and records were preserved")
        );
        assert_eq!(state.lock().unwrap().queries.len(), 2);
        handle.abort();
    }
}

#[test]
fn chat_declaration_requires_exact_scope_uri_and_valid_authority_did() {
    let valid = json!({
        "uri": format!("at://{DID}/{CHAT_DECLARATION_COLLECTION}/{DECLARATION_RKEY}"),
        "value": {
            "$type": CHAT_DECLARATION_COLLECTION,
            "deliveryService": "did:web:chat.catbird.blue",
            "protocolVersion": "1",
            "allowIncoming": "all",
            "createdAt": "2026-09-01T00:00:00Z"
        }
    });
    assert_eq!(
        parse_chat_declaration(DID, &valid).unwrap(),
        "did:web:chat.catbird.blue"
    );

    let mut wrong_repo = valid.clone();
    wrong_repo["uri"] = json!(format!(
        "at://did:plc:bbbbbbbbbbbbbbbbbbbbbbbb/{CHAT_DECLARATION_COLLECTION}/{DECLARATION_RKEY}"
    ));
    assert!(parse_chat_declaration(DID, &wrong_repo).is_err());

    let mut wrong_rkey = valid.clone();
    wrong_rkey["uri"] = json!(format!("at://{DID}/{CHAT_DECLARATION_COLLECTION}/other"));
    assert!(parse_chat_declaration(DID, &wrong_rkey).is_err());

    let mut wrong_type = valid.clone();
    wrong_type["value"]["$type"] = json!("blue.catbird.chat.other");
    assert!(parse_chat_declaration(DID, &wrong_type).is_err());

    for invalid_did in [
        "not-a-did",
        "did:web:chat.catbird.blue:folder",
        "did:web:chat.catbird.blue%3A444",
        "did:plc:invalid#frag",
    ] {
        let mut bad_auth = valid.clone();
        bad_auth["value"]["deliveryService"] = json!(invalid_did);
        assert!(parse_chat_declaration(DID, &bad_auth).is_err());
    }
}

#[tokio::test]
async fn chat_declaration_get_record_distinguishes_record_not_found_from_unavailability() {
    let (url, state, handle) = server(vec![
        (
            StatusCode::BAD_REQUEST,
            json!({"error": "RecordNotFound", "message": "Record not found"}),
        ),
        (
            StatusCode::OK,
            json!({
                "uri": format!("at://{DID}/{CHAT_DECLARATION_COLLECTION}/{DECLARATION_RKEY}"),
                "value": {
                    "$type": CHAT_DECLARATION_COLLECTION,
                    "deliveryService": "did:web:chat.catbird.blue",
                    "protocolVersion": "1",
                    "allowIncoming": "all",
                    "createdAt": "2026-09-01T00:00:00Z"
                }
            }),
        ),
        (
            StatusCode::BAD_REQUEST,
            json!({"error": "InvalidRequest", "message": "Bad request"}),
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "InternalServerError"}),
        ),
    ])
    .await;

    let client = public_client().unwrap();

    let res1 = read_chat_declaration(&client, &url, DID).await.unwrap();
    assert_eq!(res1, None);

    let res2 = read_chat_declaration(&client, &url, DID).await.unwrap();
    assert_eq!(res2.as_deref(), Some("did:web:chat.catbird.blue"));

    assert!(read_chat_declaration(&client, &url, DID).await.is_err());

    assert!(read_chat_declaration(&client, &url, DID).await.is_err());

    let state = state.lock().unwrap();
    assert_eq!(state.queries[0]["repo"], DID);
    assert_eq!(state.queries[0]["collection"], CHAT_DECLARATION_COLLECTION);
    assert_eq!(state.queries[0]["rkey"], DECLARATION_RKEY);
    drop(state);
    handle.abort();
}
