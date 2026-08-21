use std::sync::Arc;

use async_trait::async_trait;
use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::canonical_transport::{GatewayResponse, PreparedRequest};
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;
use reqwest::header::CONTENT_TYPE;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::chat::service::ChatService;

/// Native CLI transport for Rust-prepared MLS requests.
///
/// The orchestrator owns canonicalization and signing. This type only obtains
/// the existing service-auth credential and submits the exact prepared bytes.
#[derive(Clone)]
pub struct CliApiClient {
    service: Arc<ChatService>,
}

impl CliApiClient {
    pub fn new(service: Arc<ChatService>) -> Self { Self { service } }

    fn unsupported<T>(&self, operation: &str) -> Result<T> {
        Err(OrchestratorError::Api(format!("CLI API operation {operation} is not implemented")))
    }
}

#[async_trait]
impl MLSAPIClient for CliApiClient {
    async fn is_authenticated_as(&self, did: &str) -> bool { self.service.did() == did }

    async fn current_did(&self) -> Option<String> { Some(self.service.did().to_owned()) }

    async fn submit_prepared_request(&self, request: PreparedRequest) -> Result<GatewayResponse> {
        let nsid = request.path.trim_start_matches("/xrpc/").split('?').next().unwrap_or_default();
        if nsid.is_empty() {
            return Err(OrchestratorError::Api("prepared request has no XRPC route".into()));
        }
        let bearer = self.service.get_service_token(nsid).await.map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let (mut url, mut headers) = self.service.build_request(nsid, &bearer).map_err(|e| OrchestratorError::Api(e.to_string()))?;
        if let Some(query) = request.path.split_once('?').map(|(_, query)| query) {
            url.push('?');
            url.push_str(query);
        }
        let req_body = request.body.unwrap_or_default();
        if !req_body.is_empty() {
            headers.insert(CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/json"));
            let _ = std::fs::write(format!("/tmp/last_{nsid}_body.json"), &req_body);
            tracing::info!(nsid, body = %String::from_utf8_lossy(&req_body), "submit_prepared_request body");
        }
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let response = self.service.http.request(method, url).headers(headers)
            .body(req_body).send().await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let status = response.status().as_u16();
        let content_type = response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let body = response.bytes().await.map_err(|e| OrchestratorError::Api(e.to_string()))?.to_vec();
        if status != 200 {
            tracing::warn!(status, nsid, response = %String::from_utf8_lossy(&body), "submit_prepared_request received non-200");
        }
        Ok(GatewayResponse { status, content_type, body })
    }

    async fn get_conversations(&self, _limit: u32, _cursor: Option<&str>) -> Result<ConversationListPage> {
        let convos = self.service.fetch_conversations().await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let views = convos.into_iter().map(|c| ConversationView {
            group_id: c.group_id,
            conversation_id: c.conversation_id,
            epoch: c.epoch,
            members: c.members.into_iter().map(|m| MemberView {
                did: m.user_did,
                role: if m.is_admin { MemberRole::Admin } else { MemberRole::Member },
            }).collect(),
            metadata: Some(ConversationMetadata {
                name: c.name,
                description: c.description,
                avatar_url: None,
            }),
            created_at: Some(c.created_at),
            updated_at: c.last_message_at,
            sequencer_did: None,
        }).collect();
        Ok(ConversationListPage { conversations: views, cursor: None })
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
                let entry_type = item.get("$type").and_then(|v| v.as_str()).unwrap_or("");
                let entry_id = item
                    .get("entryId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let received_at_str = item.get("receivedAt").and_then(|v| v.as_str());
                let timestamp = received_at_str
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(chrono::Utc::now);
                let signed_request = item.get("signedRequest");
                let body = signed_request.and_then(|sr| sr.get("body"));
                let sender_did = signed_request
                    .and_then(|sr| {
                        sr.get("body").and_then(|b| b.get("actorDid"))
                            .or_else(|| sr.get("actorDid"))
                            .or_else(|| sr.get("did"))
                            .or_else(|| sr.get("signerDid"))
                    })
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let ciphertext_opt = if entry_type.contains("applicationEntry") || entry_type == "application" {
                    body.and_then(|b| {
                        b.get("applicationMessage")
                            .or_else(|| b.get("messageData"))
                            .or_else(|| b.get("message"))
                    })
                    .and_then(|v| {
                        if let Some(s) = v.as_str() {
                            BASE64.decode(s).ok()
                        } else if let Some(b_str) =
                            v.get("bytes").or_else(|| v.get("$bytes")).and_then(|x| x.as_str())
                        {
                            BASE64.decode(b_str).ok()
                        } else {
                            None
                        }
                    })
                } else if entry_type.contains("commitEntry") || entry_type == "commit" {
                    body.and_then(|b| b.get("commit").or_else(|| b.get("commitData")))
                        .and_then(|v| {
                            if let Some(s) = v.as_str() {
                                BASE64.decode(s).ok()
                            } else if let Some(b_str) =
                                v.get("bytes").or_else(|| v.get("$bytes")).and_then(|x| x.as_str())
                            {
                                BASE64.decode(b_str).ok()
                            } else {
                                None
                            }
                        })
                } else {
                    None
                };

                if let Some(ciphertext) = ciphertext_opt {
                    envelopes.push(IncomingEnvelope {
                        conversation_id: convo_id.to_string(),
                        sender_did,
                        ciphertext,
                        timestamp,
                        server_message_id: if entry_id.is_empty() {
                            None
                        } else {
                            Some(entry_id)
                        },
                        server_epoch: None,
                    });
                }
            }
        }

        let has_more = resp.get("hasMore").and_then(|v| v.as_bool()).unwrap_or(false);
        if has_more {
            if let Some(next_after_seq) = resp.get("nextAfterSeq").and_then(|v| v.as_i64()) {
                if next_after_seq > after_seq_str.parse::<i64>().unwrap_or(0) {
                    next_cursor = Some(next_after_seq.to_string());
                }
            }
        }

        Ok((envelopes, next_cursor))
    }

    async fn get_key_packages(&self, _actor_device_id: &str, dids: &[String]) -> Result<Vec<KeyPackageRef>> {
        let refs = self.service.fetch_key_packages(dids).await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        Ok(refs.into_iter().map(|r| KeyPackageRef {
            did: r.did,
            key_package_data: r.key_package,
            hash: r.key_package_hash,
            cipher_suite: crate::mls::MLS_CIPHER_SUITE.to_string(),
        }).collect())
    }

    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> {
        let status = self.service.get_key_package_status().await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        Ok(KeyPackageStats { available: status.available as u32, total: status.target as u32 })
    }

    async fn sync_key_packages(&self, _local_hashes: &[String], _device_id: &str) -> Result<KeyPackageSyncResult> {
        Ok(KeyPackageSyncResult { orphaned_count: 0, deleted_count: 0 })
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
                let device_id = dev.get("deviceId").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let key_id = dev.get("keyId").and_then(|v| v.as_str()).map(str::to_string);
                let signature_public_key = dev
                    .get("signaturePublicKey")
                    .and_then(|v| {
                        if let Some(s) = v.as_str() {
                            BASE64.decode(s).ok()
                        } else if let Some(b) = v.get("$bytes").and_then(|x| x.as_str()) {
                            BASE64.decode(b).ok()
                        } else {
                            None
                        }
                    });
                let auth_generation = dev.get("authGeneration").and_then(|v| v.as_i64());
                let status = dev.get("status").and_then(|v| v.as_str()).map(str::to_string);
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

    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>> {
        let state = self.service.get_group_state(convo_id).await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let encoded = state.get("groupInfo").and_then(|v| v.as_str())
            .ok_or_else(|| OrchestratorError::Api("group state did not contain groupInfo".into()))?;
        BASE64.decode(encoded).map_err(|e| OrchestratorError::Api(e.to_string()))
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
