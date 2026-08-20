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
        if request.body.is_some() { headers.insert(CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/json")); }
        let method = reqwest::Method::from_bytes(request.method.as_bytes()).map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let response = self.service.http.request(method, url).headers(headers)
            .body(request.body.unwrap_or_default()).send().await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let status = response.status().as_u16();
        let content_type = response.headers().get(CONTENT_TYPE).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let body = response.bytes().await.map_err(|e| OrchestratorError::Api(e.to_string()))?.to_vec();
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

    async fn get_messages(&self, _convo_id: &str, _cursor: Option<&str>, _limit: u32, _message_type: Option<&str>, _from_epoch: Option<u32>, _to_epoch: Option<u32>) -> Result<(Vec<IncomingEnvelope>, Option<String>)> {
        Err(OrchestratorError::Api("CLI canonical message read is not implemented".into()))
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

    async fn list_devices(&self, _actor_device_id: &str) -> Result<Vec<DeviceInfo>> {
        let devices = self.service.list_devices().await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        Ok(devices.into_iter().map(|d| DeviceInfo {
            device_id: d.device_id,
            mls_did: d.mls_did,
            device_uuid: String::new(),
            created_at: None,
            key_id: None,
            signature_public_key: None,
            auth_generation: None,
            status: None,
            available_package_count: None,
            reserved_package_count: None,
        }).collect())
    }

    async fn get_group_info(&self, convo_id: &str) -> Result<Vec<u8>> {
        let state = self.service.get_group_state(convo_id).await
            .map_err(|e| OrchestratorError::Api(e.to_string()))?;
        let encoded = state.get("groupInfo").and_then(|v| v.as_str())
            .ok_or_else(|| OrchestratorError::Api("group state did not contain groupInfo".into()))?;
        BASE64.decode(encoded).map_err(|e| OrchestratorError::Api(e.to_string()))
    }
}
