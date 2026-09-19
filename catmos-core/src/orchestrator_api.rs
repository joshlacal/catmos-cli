use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::canonical_transport::{GatewayResponse, PreparedRequest};
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;
use reqwest::header::CONTENT_TYPE;

#[cfg(test)]
use crate::chat::entries::entry_ciphertext;
use crate::chat::service::ChatService;

/// Native CLI transport for Rust-prepared MLS requests.
///
/// The orchestrator owns canonicalization and signing. This type only obtains
/// the existing service-auth credential and submits the exact prepared bytes.
#[derive(Clone)]
pub struct CliApiClient {
    service: Arc<ChatService>,
}

fn prepared_http_request(
    http: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    mut headers: reqwest::header::HeaderMap,
    body: Vec<u8>,
) -> Result<reqwest::Request> {
    if !body.is_empty() {
        headers.insert(
            CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
    }
    http.request(method, url)
        .headers(headers)
        .body(body)
        .build()
        .map_err(|error| OrchestratorError::Api(error.to_string()))
}

#[cfg(test)]
mod prepared_request_tests {
    use super::*;

    #[test]
    fn renewed_authorization_preserves_exact_prepared_request() {
        let http = reqwest::Client::new();
        let url =
            "https://chat.catbird.blue/xrpc/blue.catbird.chat.requestLeafRecovery?exact=1%2B2";
        let body = b"{\"signedRequest\":{\"preserve\":\"exact bytes\"}}".to_vec();
        let make = |token: &str| {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
            prepared_http_request(&http, reqwest::Method::POST, url, headers, body.clone()).unwrap()
        };
        let initial = make("old-scoped-token");
        let renewed = make("renewed-scoped-token");
        assert_eq!(initial.method(), renewed.method());
        assert_eq!(initial.url(), renewed.url());
        assert_eq!(renewed.url().query(), Some("exact=1%2B2"));
        assert_eq!(
            initial.body().unwrap().as_bytes(),
            renewed.body().unwrap().as_bytes()
        );
        assert_eq!(renewed.body().unwrap().as_bytes(), Some(body.as_slice()));
        assert_eq!(initial.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(renewed.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(
            renewed.headers()[reqwest::header::AUTHORIZATION],
            "Bearer renewed-scoped-token"
        );
    }
}

impl CliApiClient {
    pub fn new(service: Arc<ChatService>) -> Self {
        Self { service }
    }

    fn unsupported<T>(&self, operation: &str) -> Result<T> {
        Err(OrchestratorError::Api(format!(
            "CLI API operation {operation} is not implemented"
        )))
    }
}

#[async_trait]
impl MLSAPIClient for CliApiClient {
    async fn is_authenticated_as(&self, did: &str) -> bool {
        self.service.did() == did
    }

    async fn current_did(&self) -> Option<String> {
        Some(self.service.did().to_owned())
    }

    async fn submit_prepared_request(&self, request: PreparedRequest) -> Result<GatewayResponse> {
        let nsid = request
            .path
            .trim_start_matches("/xrpc/")
            .split('?')
            .next()
            .unwrap_or_default();
        if nsid.is_empty() {
            return Err(OrchestratorError::Api(
                "prepared request has no XRPC route".into(),
            ));
        }
        let bearer = self
            .service
            .get_service_token(nsid)
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let (mut url, headers) = self
            .service
            .build_request(nsid, &bearer)
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if let Some(query) = request.path.split_once('?').map(|(_, query)| query) {
            url.push('?');
            url.push_str(query);
        }
        let req_body = request.body.unwrap_or_default();
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let initial_request = prepared_http_request(
            &self.service.http,
            method.clone(),
            &url,
            headers,
            req_body.clone(),
        )?;
        let mut response = self
            .service
            .http
            .execute(initial_request)
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let mut status = response.status().as_u16();
        if status == 401 {
            if self.service.refresh_bearer().await.is_ok() {
                let fresh_bearer = self
                    .service
                    .get_service_token(nsid)
                    .await
                    .map_err(|error| OrchestratorError::Api(error.to_string()))?;
                if let Ok((mut retry_url, retry_headers)) =
                    self.service.build_request(nsid, &fresh_bearer)
                {
                    if let Some(query) = request.path.split_once('?').map(|(_, query)| query) {
                        retry_url.push('?');
                        retry_url.push_str(query);
                    }
                    let retry_request = prepared_http_request(
                        &self.service.http,
                        method,
                        &retry_url,
                        retry_headers,
                        req_body,
                    )?;
                    if let Ok(retry_resp) = self.service.http.execute(retry_request).await {
                        response = retry_resp;
                        status = response.status().as_u16();
                    }
                }
            }
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = response
            .bytes()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?
            .to_vec();
        if status != 200 {
            tracing::warn!(status, nsid, response = %String::from_utf8_lossy(&body), "submit_prepared_request received non-200");
        }
        Ok(GatewayResponse {
            status,
            content_type,
            body,
        })
    }

    async fn get_conversations(
        &self,
        _limit: u32,
        _cursor: Option<&str>,
    ) -> Result<ConversationListPage> {
        let (convos, mut canonical_states) = self
            .service
            .fetch_conversations_with_states()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let views = convos
            .into_iter()
            .map(|c| ConversationView {
                canonical_state: canonical_states.remove(&c.conversation_id),
                group_id: c.group_id,
                conversation_id: c.conversation_id,
                epoch: c.epoch,
                members: c
                    .members
                    .into_iter()
                    .map(|m| MemberView {
                        did: m.user_did,
                        role: if m.is_admin {
                            MemberRole::Admin
                        } else {
                            MemberRole::Member
                        },
                    })
                    .collect(),
                metadata: Some(ConversationMetadata {
                    name: c.name,
                    description: c.description,
                    avatar_url: None,
                }),
                created_at: c.created_at,
                updated_at: c.last_message_at,
                sequencer_did: None,
            })
            .collect();
        Ok(ConversationListPage {
            conversations: views,
            cursor: None,
        })
    }

    async fn get_messages(
        &self,
        convo_id: &str,
        cursor: Option<&str>,
        limit: u32,
        _message_type: Option<&str>,
        _from_epoch: Option<u32>,
        _to_epoch: Option<u32>,
    ) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        let actor_device_id = self
            .service
            .actor_device_id()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let convo_uuid = if let Ok(parsed) = uuid::Uuid::parse_str(convo_id) {
            parsed.to_string()
        } else {
            self.service
                .conversations()
                .await
                .iter()
                .find(|c| c.group_id == convo_id)
                .map(|c| c.conversation_id.clone())
                .unwrap_or_else(|| convo_id.to_string())
        };

        let after_seq_str = cursor.unwrap_or("0");
        let limit_str = (limit.clamp(1, 100)).to_string();

        let resp: serde_json::Value = self
            .service
            .xrpc_query(
                "blue.catbird.chat.getEntries",
                &[
                    ("actorDeviceId", &actor_device_id),
                    ("conversationId", &convo_uuid),
                    ("afterSeq", after_seq_str),
                    ("limit", &limit_str),
                ],
            )
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        let mut envelopes = Vec::new();
        let mut next_cursor = None;

        if let Some(items) = resp.get("entries").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(envelope) = IncomingEnvelope::from_canonical_entry(item, &convo_uuid)? {
                    envelopes.push(envelope);
                }
            }
        }

        let has_more = resp
            .get("hasMore")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if has_more {
            if let Some(next_after_seq) = resp.get("nextAfterSeq").and_then(|v| v.as_i64()) {
                if next_after_seq > after_seq_str.parse::<i64>().unwrap_or(0) {
                    next_cursor = Some(next_after_seq.to_string());
                }
            }
        }

        Ok((envelopes, next_cursor))
    }

    async fn get_key_packages(
        &self,
        _actor_device_id: &str,
        dids: &[String],
    ) -> Result<Vec<KeyPackageRef>> {
        let refs = self
            .service
            .fetch_key_packages(dids)
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        Ok(refs
            .into_iter()
            .map(|r| KeyPackageRef {
                did: r.did,
                key_package_data: r.key_package,
                hash: r.key_package_hash,
                cipher_suite: crate::mls::MLS_CIPHER_SUITE.to_string(),
            })
            .collect())
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let status = self
            .service
            .get_key_package_status()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        Ok(KeyPackageStats {
            available: status.available as u32,
            total: status.target as u32,
        })
    }

    async fn sync_key_packages(
        &self,
        _local_hashes: &[String],
        _device_id: &str,
    ) -> Result<KeyPackageSyncResult> {
        Ok(KeyPackageSyncResult {
            orphaned_count: 0,
            deleted_count: 0,
        })
    }

    async fn list_devices(&self, actor_device_id: &str) -> Result<Vec<DeviceInfo>> {
        let resp: serde_json::Value = self
            .service
            .xrpc_query(
                "blue.catbird.chat.getOwnDevices",
                &[("actorDeviceId", actor_device_id)],
            )
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;

        let mut devices = Vec::new();
        if let Some(items) = resp.get("items").and_then(|v| v.as_array()) {
            for item in items {
                let dev = item.get("device").unwrap_or(item);
                let device_id = dev
                    .get("deviceId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let key_id = dev
                    .get("keyId")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let signature_public_key = dev.get("signaturePublicKey").and_then(|v| {
                    if let Some(s) = v.as_str() {
                        BASE64.decode(s).ok()
                    } else if let Some(b) = v.get("$bytes").and_then(|x| x.as_str()) {
                        BASE64.decode(b).ok()
                    } else {
                        None
                    }
                });
                let auth_generation = dev.get("authGeneration").and_then(|v| v.as_i64());
                let status = dev
                    .get("status")
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                let available_package_count = dev
                    .get("availablePackageCount")
                    .or_else(|| item.get("availablePackageCount"))
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32);
                let reserved_package_count = dev
                    .get("reservedPackageCount")
                    .or_else(|| item.get("reservedPackageCount"))
                    .and_then(|v| v.as_u64())
                    .map(|n| n as u32);
                let mls_did = format!("{}#{}", self.service.did(), device_id);
                if device_id == actor_device_id && status.as_deref() == Some("active") {
                    let local = self
                        .service
                        .mls
                        .context()
                        .identity_public_key(format!("{}#{}", self.service.did(), device_id))
                        .map_err(OrchestratorError::Mls)?;
                    if signature_public_key.as_deref() != Some(local.as_slice())
                        || key_id.as_deref()
                            != Some(
                                catbird_mls::orchestrator::canonical_transport::derive_key_id(
                                    &local,
                                )
                                .as_str(),
                            )
                    {
                        return Err(OrchestratorError::Credential(
                            "Authenticated device key differs from local custody".into(),
                        ));
                    }
                    // First enrollment stores the signing tuple immediately after
                    // its response; the runtime repeats this exact read afterwards.
                    use catbird_mls::orchestrator::CredentialStore;
                    let credentials =
                        crate::orchestrator_credentials::KeyringCredentialStore::new();
                    if credentials
                        .get_signing_key(self.service.did())
                        .await?
                        .is_some()
                    {
                        crate::orchestrator_credentials::KeyringCredentialStore::retain_generation(
                            self.service.did(),
                            &device_id,
                            key_id.as_deref().unwrap(),
                            auth_generation.ok_or_else(|| {
                                OrchestratorError::Credential(
                                    "Missing authenticated generation".into(),
                                )
                            })?,
                        )
                        .await?;
                    }
                }
                devices.push(DeviceInfo {
                    device_id: device_id.clone(),
                    mls_did,
                    device_uuid: device_id,
                    created_at: None,
                    key_id,
                    signature_public_key,
                    auth_generation,
                    status,
                    available_package_count,
                    reserved_package_count,
                });
            }
        }
        Ok(devices)
    }

    /// Clean-chat exposes no GroupInfo read; External Commit is never an
    /// option. Failing here routes the orchestrator to leaf recovery / reset.
    async fn get_group_info(&self, _convo_id: &str) -> Result<Vec<u8>> {
        Err(OrchestratorError::ServerError {
            status: 404,
            body: "GroupInfo is not retrievable under blue.catbird.chat".into(),
        })
    }

    /// The newest pending Welcome addressed to this device for `convo_id`
    /// from the device-scoped `getPendingWelcomes` inventory. The welcome
    /// page is served from the inventory session `getConversations` minted.
    async fn get_welcome(&self, convo_id: &str) -> Result<Vec<u8>> {
        use sha2::Digest as _;
        let device_id = self
            .service
            .actor_device_id()
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let mut session = self.service.inventory_session.read().await.clone();
        let mut refreshed = false;
        let mut cursor: Option<String> = None;
        let mut seen_cursors = std::collections::HashSet::new();
        let mut latest_welcome: Option<serde_json::Value> = None;
        loop {
            if session.is_none() {
                // Mint a fresh read-only inventory without recursively running
                // conversation hydration or repairing unrelated conversations.
                let inventory: serde_json::Value = self
                    .service
                    .xrpc_query(
                        "blue.catbird.chat.getConversations",
                        &[
                            ("actorDeviceId", device_id.as_str()),
                            ("limit", "100"),
                            ("supportedProtocolVersions", "1"),
                            ("supportedProtocolVersions", "2"),
                        ],
                    )
                    .await
                    .map_err(|error| OrchestratorError::Api(error.to_string()))?;
                let session_id = inventory
                    .get("inventorySessionId")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        OrchestratorError::Api(
                            "getConversations minted no inventory session".into(),
                        )
                    })?;
                let event_cursor = inventory
                    .get("snapshotEventCursor")
                    .and_then(|value| value.as_str())
                    .ok_or_else(|| {
                        OrchestratorError::Api(
                            "getConversations omitted snapshot event cursor".into(),
                        )
                    })?;
                session = Some((session_id.to_owned(), event_cursor.to_owned()));
                *self.service.inventory_session.write().await = session.clone();
            }
            let (session_id, event_cursor) =
                session.as_ref().expect("inventory session initialized");
            let mut parameters = vec![
                ("actorDeviceId", device_id.as_str()),
                ("inventorySessionId", session_id.as_str()),
                ("limit", "100"),
                ("supportedProtocolVersions", "1"),
                ("supportedProtocolVersions", "2"),
            ];
            if let Some(cursor) = cursor.as_deref() {
                parameters.push(("pageCursor", cursor));
            }
            let response: serde_json::Value = match self
                .service
                .xrpc_query("blue.catbird.chat.getPendingWelcomes", &parameters)
                .await
            {
                Ok(response) => response,
                Err(error) if !refreshed && welcome_inventory_needs_refresh(&error) => {
                    refreshed = true;
                    session = None;
                    cursor = None;
                    seen_cursors.clear();
                    latest_welcome = None;
                    continue;
                }
                Err(error) => return Err(OrchestratorError::Api(error.to_string())),
            };
            let page = validate_welcome_page(&response, session_id, event_cursor)?;
            for item in page.items {
                if item.get("conversationId").and_then(|value| value.as_str()) == Some(convo_id)
                    && item.get("status").and_then(|value| value.as_str()) == Some("pending")
                    && item
                        .get("recipientDeviceId")
                        .and_then(|value| value.as_str())
                        == Some(device_id.as_str())
                    && latest_welcome.as_ref().is_none_or(|current| {
                        item.get("transitionSeq")
                            .and_then(|value| value.as_u64())
                            .unwrap_or(0)
                            > current
                                .get("transitionSeq")
                                .and_then(|value| value.as_u64())
                                .unwrap_or(0)
                    })
                {
                    latest_welcome = Some(item.clone());
                }
            }
            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            if !seen_cursors.insert(next_cursor.to_owned()) || seen_cursors.len() > 1000 {
                return Err(OrchestratorError::Api(
                    "Welcome inventory pagination did not advance".into(),
                ));
            }
            cursor = Some(next_cursor.to_owned());
        }
        let bytes_of = |v: Option<&serde_json::Value>| -> Option<Vec<u8>> {
            let v = v?;
            let s = v
                .as_str()
                .or_else(|| v.get("$bytes").and_then(|b| b.as_str()))?;
            BASE64.decode(s).ok()
        };
        let Some(welcome) = latest_welcome else {
            return Err(OrchestratorError::ServerError {
                status: 404,
                body: "Welcome not found".into(),
            });
        };
        let opaque = bytes_of(welcome.get("opaqueWelcome"))
            .ok_or_else(|| OrchestratorError::Api("pending Welcome has no opaqueWelcome".into()))?;
        let expected = bytes_of(welcome.get("sha256"))
            .ok_or_else(|| OrchestratorError::Api("pending Welcome has no sha256".into()))?;
        if sha2::Sha256::digest(&opaque).as_slice() != expected.as_slice() {
            return Err(OrchestratorError::Api("Welcome digest mismatch".into()));
        }
        Ok(opaque)
    }

    async fn get_group_metadata_blob(
        &self,
        convo_id: &str,
        group_id_hex: &str,
        blob_locator: &str,
    ) -> Result<Vec<u8>> {
        let bytes_opt = self
            .service
            .get_group_metadata_blob(
                Some(blob_locator),
                Some(convo_id),
                Some(group_id_hex),
                None,
                None,
                None,
            )
            .await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        bytes_opt.ok_or_else(|| {
            OrchestratorError::Api(format!("metadata blob {blob_locator} not found"))
        })
    }
}

/// Only explicit stale inventory errors authorize one fresh inventory retry.
fn welcome_inventory_needs_refresh(error: &crate::error::CatmosError) -> bool {
    let crate::error::CatmosError::Xrpc(message) = error else {
        return false;
    };
    let Some(start) = message.find('{') else {
        return false;
    };
    let Ok(body) = serde_json::from_str::<serde_json::Value>(&message[start..]) else {
        return false;
    };
    matches!(
        body.get("error").and_then(|value| value.as_str()),
        Some("InventorySessionMismatch" | "InventorySessionExpired" | "CursorExpired")
    )
}

struct WelcomeInventoryPage<'a> {
    items: &'a [serde_json::Value],
    next_cursor: Option<&'a str>,
}

fn validate_welcome_page<'a>(
    response: &'a serde_json::Value,
    session: &str,
    event_cursor: &str,
) -> Result<WelcomeInventoryPage<'a>> {
    if response
        .get("inventorySessionId")
        .and_then(|value| value.as_str())
        != Some(session)
        || response
            .get("snapshotEventCursor")
            .and_then(|value| value.as_str())
            != Some(event_cursor)
    {
        return Err(OrchestratorError::Api(
            "Welcome inventory response changed session or event cursor".into(),
        ));
    }
    let items = response
        .get("items")
        .and_then(|value| value.as_array())
        .ok_or_else(|| OrchestratorError::Api("Welcome inventory response omitted items".into()))?;
    let has_more = response
        .get("hasMore")
        .and_then(|value| value.as_bool())
        .ok_or_else(|| {
            OrchestratorError::Api("Welcome inventory response omitted pagination status".into())
        })?;
    let next_cursor = response
        .get("nextPageCursor")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty());
    if has_more != next_cursor.is_some() {
        return Err(OrchestratorError::Api(
            "Welcome inventory returned inconsistent pagination".into(),
        ));
    }
    Ok(WelcomeInventoryPage { items, next_cursor })
}

#[cfg(test)]
mod welcome_inventory_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn welcome_fetch_refreshes_stale_inventory_once_and_searches_later_pages() {
        use crate::auth::AuthMethod;
        use crate::mls::MlsManager;
        use crate::storage::{aliases::AliasStore, config::Config, db::Database};
        use sha2::Digest;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::RwLock;

        #[derive(Clone, Default)]
        struct Calls {
            inventory: Arc<AtomicUsize>,
            welcomes: Arc<AtomicUsize>,
        }
        async fn inventory(
            axum::extract::State(calls): axum::extract::State<Calls>,
            axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
        ) -> axum::Json<serde_json::Value> {
            assert!(uri
                .query()
                .unwrap()
                .contains("supportedProtocolVersions=1&supportedProtocolVersions=2"));
            calls.inventory.fetch_add(1, Ordering::Relaxed);
            axum::Json(
                serde_json::json!({"inventorySessionId": "fresh", "snapshotEventCursor": "fence", "items": [], "hasMore": false}),
            )
        }
        async fn welcomes(
            axum::extract::State(calls): axum::extract::State<Calls>,
            axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
            axum::extract::Query(query): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >,
        ) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
            assert!(uri
                .query()
                .unwrap()
                .contains("supportedProtocolVersions=1&supportedProtocolVersions=2"));
            calls.welcomes.fetch_add(1, Ordering::Relaxed);
            if query.get("inventorySessionId").map(String::as_str) == Some("stale") {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({"error": "InventorySessionMismatch"})),
                );
            }
            let second_page = query.get("pageCursor").map(String::as_str) == Some("page-2");
            let mut response = serde_json::json!({
                "inventorySessionId": "fresh", "snapshotEventCursor": "fence", "hasMore": !second_page,
                "items": [{
                    "conversationId": "target", "status": "pending",
                    "recipientDeviceId": if second_page { "device" } else { "another-device" },
                    "transitionSeq": if second_page { 2 } else { 99 },
                    "opaqueWelcome": BASE64.encode(b"welcome payload"),
                    "sha256": BASE64.encode(sha2::Sha256::digest(b"welcome payload")),
                }],
            });
            if !second_page {
                response["nextPageCursor"] = serde_json::json!("page-2");
            }
            (axum::http::StatusCode::OK, axum::Json(response))
        }
        let calls = Calls::default();
        let app = axum::Router::new()
            .route(
                "/xrpc/blue.catbird.chat.getConversations",
                axum::routing::get(inventory),
            )
            .route(
                "/xrpc/blue.catbird.chat.getPendingWelcomes",
                axum::routing::get(welcomes),
            )
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let temporary = tempfile::tempdir().unwrap();
        let db = Arc::new(
            Database::open_unencrypted(&temporary.path().join("test.db"))
                .await
                .unwrap(),
        );
        db.store_session_value("mls_device_id", "device")
            .await
            .unwrap();
        let service = Arc::new(ChatService::new(
            AuthMethod::OAuth {
                session_cookie: "test-cookie".into(),
                did: "did:plc:test".into(),
                nest_url: endpoint,
            },
            None,
            Arc::new(MlsManager::new(&temporary.path().join("mls"), "did:plc:test").unwrap()),
            db,
            Config::default(),
            Arc::new(RwLock::new(AliasStore::with_path(
                temporary.path().join("aliases.json"),
            ))),
        ));
        *service.inventory_session.write().await = Some(("stale".into(), "stale-fence".into()));
        let api = CliApiClient::new(service);
        assert_eq!(api.get_welcome("target").await.unwrap(), b"welcome payload");
        assert_eq!(calls.inventory.load(Ordering::Relaxed), 1);
        assert_eq!(calls.welcomes.load(Ordering::Relaxed), 3);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn entries_preserve_add_and_leave_commits_before_following_messages() {
        use crate::auth::AuthMethod;
        use crate::mls::MlsManager;
        use crate::storage::{aliases::AliasStore, config::Config, db::Database};
        use catbird_mls::chat_v2::wire::{
            APPLICATION_ENTRY_KIND, LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND,
            LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
        };
        use catbird_mls::{KeyPackageData, ProcessedContent};
        use tokio::sync::RwLock;

        std::env::set_var("CATMOS_TEST_KEYCHAIN_FALLBACK", "1");
        let temporary = tempfile::tempdir().unwrap();
        let alice = MlsManager::new(&temporary.path().join("alice"), "did:plc:alice").unwrap();
        let bob = Arc::new(MlsManager::new(&temporary.path().join("bob"), "did:plc:bob").unwrap());
        let charlie =
            MlsManager::new(&temporary.path().join("charlie"), "did:plc:charlie").unwrap();
        let group = vec![7; 32];
        alice
            .context()
            .create_group_with_id(b"did:plc:alice".to_vec(), group.clone(), None)
            .unwrap();
        let bob_package = bob
            .context()
            .create_key_package(b"did:plc:bob".to_vec())
            .unwrap();
        let initial = alice
            .context()
            .add_members(
                group.clone(),
                vec![KeyPackageData {
                    data: bob_package.key_package_data,
                }],
            )
            .unwrap();
        alice.context().merge_pending_commit(group.clone()).unwrap();
        bob.context()
            .process_welcome(initial.welcome_data, b"did:plc:bob".to_vec(), None)
            .unwrap();
        let charlie_package = charlie
            .context()
            .create_key_package(b"did:plc:charlie".to_vec())
            .unwrap();
        let add = alice
            .context()
            .add_members(
                group.clone(),
                vec![KeyPackageData {
                    data: charlie_package.key_package_data,
                }],
            )
            .unwrap();
        alice.context().merge_pending_commit(group.clone()).unwrap();
        let after_add = alice
            .context()
            .encrypt_message(group.clone(), b"after add".to_vec())
            .unwrap();
        let leave = alice
            .context()
            .remove_members(group.clone(), vec![b"did:plc:charlie".to_vec()])
            .unwrap();
        alice.context().merge_pending_commit(group.clone()).unwrap();
        let after_leave = alice
            .context()
            .encrypt_message(group.clone(), b"after leave".to_vec())
            .unwrap();
        let conversation = "550e8400-e29b-41d4-a716-446655440000";
        let entry = |kind: &str, seq: u64, field: &str, bytes: &[u8]| {
            let epoch = if seq < 4 { 2 } else { 3 };
            let mut body = serde_json::json!({"actorDid": "did:plc:alice", "prior": {"conversationId": conversation, "epoch": if field == "commit" { epoch-1 } else { epoch }}, "next": {"conversationId": conversation, "epoch": epoch}});
            body[field] = serde_json::json!({"bytes": {"$bytes": BASE64.encode(bytes)}});
            serde_json::json!({
                "$type": kind, "conversationId": conversation,
                "entryId": uuid::Uuid::new_v4().to_string(), "seq": seq,
                "signedRequest": {"body": body}, "receivedAt": "2026-09-05T00:00:00.000Z",
            })
        };
        let response = serde_json::json!({"entries": [
            entry(LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND, 2, "commit", &add.commit_data),
            entry(APPLICATION_ENTRY_KIND, 3, "applicationMessage", &after_add.ciphertext),
            entry(LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND, 4, "commit", &leave),
            entry(APPLICATION_ENTRY_KIND, 5, "applicationMessage", &after_leave.ciphertext),
        ], "hasMore": false, "nextAfterSeq": 5});
        let app = axum::Router::new().route(
            "/xrpc/blue.catbird.chat.getEntries",
            axum::routing::get(move || {
                let response = response.clone();
                async move { axum::Json(response) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let db = Arc::new(
            Database::open_unencrypted(&temporary.path().join("chat.db"))
                .await
                .unwrap(),
        );
        db.store_session_value("mls_device_id", "device")
            .await
            .unwrap();
        let service = Arc::new(ChatService::new(
            AuthMethod::OAuth {
                session_cookie: "test-cookie".into(),
                did: "did:plc:bob".into(),
                nest_url: endpoint,
            },
            None,
            bob.clone(),
            db,
            Config::default(),
            Arc::new(RwLock::new(AliasStore::with_path(
                temporary.path().join("aliases.json"),
            ))),
        ));
        let (envelopes, cursor) = CliApiClient::new(service)
            .get_messages(conversation, None, 50, None, None, None)
            .await
            .unwrap();
        assert_eq!(envelopes.len(), 4);
        assert!(cursor.is_none());
        use crate::orchestrator_storage::SqliteStorage;
        use catbird_mls::orchestrator::MLSStorageBackend;
        bob.context().set_content_root_key(vec![0x6b; 32]).unwrap();
        let storage_path = temporary.path().join("authenticated-messages.db");
        let storage = SqliteStorage::new(storage_path.to_str().unwrap(), "fixture-key").unwrap();
        storage.set_mls_context(bob.context().clone());
        let mut stored_messages = Vec::new();
        let mut plaintexts = Vec::new();
        for (index, envelope) in envelopes.into_iter().enumerate() {
            assert_eq!(envelope.server_sequence, Some(index as u64 + 2));
            assert_eq!(envelope.server_epoch, Some(if index < 2 { 2 } else { 3 }));
            assert_eq!(
                envelope
                    .timestamp
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                "2026-09-05T00:00:00.000Z"
            );
            assert_eq!(envelope.conversation_id, conversation);
            match bob
                .context()
                .process_message(group.clone(), envelope.ciphertext)
                .unwrap()
            {
                ProcessedContent::StagedCommit { new_epoch, .. } => {
                    bob.context()
                        .merge_incoming_commit(group.clone(), new_epoch)
                        .unwrap();
                }
                ProcessedContent::ApplicationMessage { plaintext, .. } => {
                    let message = Message {
                        id: envelope.server_message_id.unwrap(),
                        conversation_id: conversation.into(),
                        sender_did: "did:plc:alice".into(),
                        text: String::from_utf8(plaintext.clone()).unwrap(),
                        timestamp: envelope.timestamp,
                        epoch: envelope.server_epoch.unwrap(),
                        sequence_number: envelope.server_sequence.unwrap(),
                        is_own: false,
                        delivery_status: None,
                        payload_json: None,
                    };
                    storage.store_message(&message).await.unwrap();
                    stored_messages.push(message);
                    plaintexts.push(plaintext);
                }
                _ => panic!("unexpected MLS proposal"),
            }
        }
        assert_eq!(plaintexts, [b"after add".to_vec(), b"after leave".to_vec()]);
        assert_eq!(bob.context().get_epoch(group).unwrap(), 3);
        let ciphertext_snapshot = || {
            let conn = rusqlite::Connection::open(&storage_path).unwrap();
            conn.execute_batch("PRAGMA key = 'fixture-key';").unwrap();
            let mut query = conn.prepare("SELECT id,payload_encrypted,entry_hmac,hmac_sequence FROM messages ORDER BY rowid").unwrap();
            query
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, u64>(3)?,
                    ))
                })
                .unwrap()
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap()
        };
        let original_ciphertext = ciphertext_snapshot();
        assert_eq!(original_ciphertext.len(), 2);
        drop(storage);
        let restored = SqliteStorage::new(storage_path.to_str().unwrap(), "fixture-key").unwrap();
        restored.set_mls_context(bob.context().clone());
        let loaded = restored.get_messages(conversation, 20, None).await.unwrap();
        assert_eq!(
            loaded.iter().map(|m| m.sequence_number).collect::<Vec<_>>(),
            [3, 5]
        );
        assert_eq!(loaded.iter().map(|m| m.epoch).collect::<Vec<_>>(), [2, 3]);
        for message in &stored_messages {
            restored.store_message(message).await.unwrap();
        }
        assert_eq!(
            ciphertext_snapshot(),
            original_ciphertext,
            "reload and exact duplicates preserve original encrypted bytes, tags and append order"
        );
        assert_eq!(
            serde_json::to_value(restored.get_messages(conversation, 20, None).await.unwrap())
                .unwrap(),
            serde_json::to_value(loaded).unwrap()
        );
        server.abort();
    }

    #[test]
    fn entry_kind_matching_is_exact_and_malformed_known_artifacts_fail() {
        use catbird_mls::chat_v2::wire::COMMIT_ENTRY_KIND;
        assert!(entry_ciphertext(&serde_json::json!({"$type": "attacker.commitEntry", "signedRequest": {"body": {"commit": "AQ=="}}})).unwrap().is_none());
        assert!(entry_ciphertext(&serde_json::json!({"$type": COMMIT_ENTRY_KIND, "signedRequest": {"body": {"commit": "!invalid!"}}})).is_err());
        assert!(entry_ciphertext(&serde_json::json!({"$type": COMMIT_ENTRY_KIND})).is_err());
    }

    #[test]
    fn only_explicit_expired_inventory_errors_are_retried() {
        for code in [
            "InventorySessionMismatch",
            "InventorySessionExpired",
            "CursorExpired",
        ] {
            let error = crate::error::CatmosError::Xrpc(format!(
                "endpoint returned 400: {{\"error\":\"{code}\"}}"
            ));
            assert!(welcome_inventory_needs_refresh(&error));
        }
        for body in [
            r#"{"error":"NotAuthorized"}"#,
            r#"{"error":"DeviceRevoked","message":"InventorySessionMismatch"}"#,
            "InventorySessionMismatch",
        ] {
            assert!(!welcome_inventory_needs_refresh(
                &crate::error::CatmosError::Xrpc(body.into())
            ));
        }
    }

    #[test]
    fn welcome_pages_stay_bound_and_require_a_continuation_until_complete() {
        let mut response = serde_json::json!({
            "inventorySessionId": "session", "snapshotEventCursor": "fence", "items": [],
            "hasMore": true, "nextPageCursor": "page-2",
        });
        assert_eq!(
            validate_welcome_page(&response, "session", "fence")
                .unwrap()
                .next_cursor,
            Some("page-2")
        );
        assert!(validate_welcome_page(&response, "other-session", "fence").is_err());
        assert!(validate_welcome_page(&response, "session", "other-fence").is_err());
        response.as_object_mut().unwrap().remove("nextPageCursor");
        assert!(validate_welcome_page(&response, "session", "fence").is_err());
        response["hasMore"] = serde_json::json!(false);
        assert!(validate_welcome_page(&response, "session", "fence")
            .unwrap()
            .next_cursor
            .is_none());
    }
}
