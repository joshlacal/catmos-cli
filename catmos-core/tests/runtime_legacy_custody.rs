use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use catbird_mls::orchestrator::credentials::CredentialStore;
use catmos_core::auth::oauth::OAuthAuth;
use catmos_core::mls::MlsManager;
use catmos_core::orchestrator_credentials::KeyringCredentialStore;
use catmos_core::runtime::{Runtime, RuntimeStartup};
use catmos_core::storage::config::Config;
use catmos_core::storage::db::Database;
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct ServerState {
    projection: Arc<RwLock<Projection>>,
    enrollments: Arc<AtomicUsize>,
}

#[derive(Clone, Default)]
struct Projection {
    did: String,
    device_id: String,
    public_key: Vec<u8>,
}

async fn session(State(state): State<ServerState>, _headers: HeaderMap) -> Json<serde_json::Value> {
    let projection = state.projection.read().unwrap().clone();
    Json(serde_json::json!({
        "did": projection.did,
        "handle": "runtime-migration.invalid"
    }))
}

async fn own_devices(State(state): State<ServerState>) -> Json<serde_json::Value> {
    let projection = state.projection.read().unwrap().clone();
    let key_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(&projection.public_key));
    Json(serde_json::json!({
        "items": [{
            "device": {
                "deviceId": projection.device_id,
                "keyId": key_id,
                "signaturePublicKey": {
                    "$bytes": base64::engine::general_purpose::STANDARD.encode(&projection.public_key)
                },
                "authGeneration": 1,
                "status": "active",
                "availablePackageCount": 1,
                "reservedPackageCount": 0
            }
        }]
    }))
}

struct SeededLegacyAccount {
    did: String,
    device_id: String,
    mls_did: String,
    signing_key: Vec<u8>,
    public_key: Vec<u8>,
}

async fn seed_legacy_account(endpoint: &str, legacy_fields: &[&str]) -> SeededLegacyAccount {
    let did = format!("did:web:{}.runtime-migration.invalid", uuid::Uuid::new_v4());
    let device_id = uuid::Uuid::new_v4().to_string();
    let mls_did = format!("{did}#{device_id}");

    let mut config = Config::default();
    config.default_account = Some(did.clone());
    config.server.nest_url = endpoint.to_string();
    config.server.mls_url = endpoint.to_string();
    config.save().unwrap();

    let mls = MlsManager::new(&Config::data_dir().unwrap().join("mls"), &did).unwrap();
    let package = mls
        .context()
        .create_key_package(mls_did.as_bytes().to_vec())
        .unwrap();
    let signing_key = mls.context().export_identity_key(mls_did.clone()).unwrap();

    let account_dir = Config::account_data_dir(&did).unwrap();
    let database_key = catmos_core::mls::context::get_or_create_db_key(&did).unwrap();
    let database = Database::open(&account_dir.join("catmos.db"), &database_key)
        .await
        .unwrap();
    OAuthAuth {
        session_cookie: "old-tui-session".into(),
        did: did.clone(),
        handle: "runtime-migration.invalid".into(),
        nest_url: endpoint.to_string(),
    }
    .save(&database)
    .await
    .unwrap();
    if legacy_fields.contains(&"mls_device_id") {
        database
            .store_session_value("mls_device_id", &device_id)
            .await
            .unwrap();
    }
    if legacy_fields.contains(&"mls_did") {
        database
            .store_session_value("mls_did", &mls_did)
            .await
            .unwrap();
    }
    if legacy_fields.contains(&"device_uuid") {
        database
            .store_session_value("device_uuid", &device_id)
            .await
            .unwrap();
    }
    drop(database);
    drop(mls);

    SeededLegacyAccount {
        did,
        device_id,
        mls_did,
        signing_key,
        public_key: package.signature_public_key,
    }
}

fn select_projection(projection: &RwLock<Projection>, account: &SeededLegacyAccount) {
    *projection.write().unwrap() = Projection {
        did: account.did.clone(),
        device_id: account.device_id.clone(),
        public_key: account.public_key.clone(),
    };
}

async fn enroll(State(state): State<ServerState>) -> (StatusCode, Json<serde_json::Value>) {
    state.enrollments.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({"error": "TooManyDevices"})),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn public_startup_adopts_an_old_tui_identity_without_enrollment() {
    // This integration test has its own process, so its profile and MLS test
    // key provider cannot race the library test binary's process globals.
    std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
    std::env::set_var("CATMOS_TEST_SHARED_KEYCHAIN_FALLBACK", "1");
    let profile = format!("runtime-migration-{}", uuid::Uuid::new_v4());
    Config::initialize_profile(Some(&profile)).unwrap();

    let enrollments = Arc::new(AtomicUsize::new(0));
    let projection = Arc::new(RwLock::new(Projection::default()));
    let state = ServerState {
        projection: Arc::clone(&projection),
        enrollments: Arc::clone(&enrollments),
    };
    let app = Router::new()
        .route("/auth/session", get(session))
        .route("/xrpc/blue.catbird.chat.getOwnDevices", get(own_devices))
        .route("/xrpc/blue.catbird.chat.enrollDevice", post(enroll))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let account =
        seed_legacy_account(&endpoint, &["mls_device_id", "mls_did", "device_uuid"]).await;
    select_projection(&projection, &account);

    // Device-record publication is expected to fail against the deliberately
    // non-resolving .invalid DID. Registration reconciliation happens first.
    let startup = Runtime::initialize(RuntimeStartup::command(false)).await;
    assert!(startup.is_err());
    assert_eq!(
        enrollments.load(Ordering::SeqCst),
        0,
        "an old TUI identity must never enter fresh enrollment"
    );

    let credentials = KeyringCredentialStore::new();
    assert_eq!(
        credentials
            .get_mls_did(&account.did)
            .await
            .unwrap()
            .as_deref(),
        Some(account.mls_did.as_str())
    );
    assert_eq!(
        credentials
            .get_device_uuid(&account.did)
            .await
            .unwrap()
            .as_deref(),
        Some(account.device_id.as_str())
    );
    assert_eq!(
        credentials.get_signing_key(&account.did).await.unwrap(),
        Some(account.signing_key.clone())
    );

    let matching =
        seed_legacy_account(&endpoint, &["mls_device_id", "mls_did", "device_uuid"]).await;
    select_projection(&projection, &matching);
    credentials
        .store_signing_key(&matching.did, &matching.signing_key)
        .await
        .unwrap();
    credentials
        .store_mls_did(&matching.did, &matching.mls_did)
        .await
        .unwrap();
    credentials
        .store_device_uuid(&matching.did, &matching.device_id)
        .await
        .unwrap();
    let matching_startup = Runtime::initialize(RuntimeStartup::command(false)).await;
    assert!(matching_startup.is_err());
    assert_eq!(enrollments.load(Ordering::SeqCst), 0);
    assert_eq!(
        credentials.get_mls_did(&matching.did).await.unwrap(),
        Some(matching.mls_did.clone())
    );
    assert_eq!(
        credentials.get_device_uuid(&matching.did).await.unwrap(),
        Some(matching.device_id.clone())
    );
    assert_eq!(
        credentials.get_signing_key(&matching.did).await.unwrap(),
        Some(matching.signing_key.clone())
    );

    let conflicting =
        seed_legacy_account(&endpoint, &["mls_device_id", "mls_did", "device_uuid"]).await;
    select_projection(&projection, &conflicting);
    let conflicting_device = uuid::Uuid::new_v4().to_string();
    credentials
        .store_signing_key(&conflicting.did, &conflicting.signing_key)
        .await
        .unwrap();
    credentials
        .store_mls_did(
            &conflicting.did,
            &format!("{}#{conflicting_device}", conflicting.did),
        )
        .await
        .unwrap();
    credentials
        .store_device_uuid(&conflicting.did, &conflicting_device)
        .await
        .unwrap();
    let conflict_error = match Runtime::initialize(RuntimeStartup::command(false)).await {
        Ok(_) => panic!("conflicting custody must stop startup"),
        Err(error) => error,
    };
    assert!(conflict_error.to_string().contains("conflicts"));
    assert_eq!(enrollments.load(Ordering::SeqCst), 0);

    let partial_credentials =
        seed_legacy_account(&endpoint, &["mls_device_id", "mls_did", "device_uuid"]).await;
    select_projection(&projection, &partial_credentials);
    credentials
        .store_mls_did(&partial_credentials.did, &partial_credentials.mls_did)
        .await
        .unwrap();
    let partial_credentials_error = match Runtime::initialize(RuntimeStartup::command(false)).await
    {
        Ok(_) => panic!("partial orchestrator credentials must stop startup"),
        Err(error) => error,
    };
    assert!(partial_credentials_error
        .to_string()
        .contains("incomplete orchestrator credentials"));
    assert_eq!(enrollments.load(Ordering::SeqCst), 0);

    let partial = seed_legacy_account(&endpoint, &["mls_device_id", "mls_did"]).await;
    select_projection(&projection, &partial);
    let partial_error = match Runtime::initialize(RuntimeStartup::command(false)).await {
        Ok(_) => panic!("partial legacy custody must stop startup"),
        Err(error) => error,
    };
    assert!(partial_error.to_string().contains("incomplete"));
    assert_eq!(enrollments.load(Ordering::SeqCst), 0);

    server.abort();
}
