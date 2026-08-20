use std::sync::Arc;

use async_trait::async_trait;
use catbird_mls::orchestrator::api_client::MLSAPIClient;
use catbird_mls::orchestrator::canonical_transport::{GatewayResponse, PreparedRequest};
use catbird_mls::orchestrator::error::{OrchestratorError, Result};
use catbird_mls::orchestrator::types::*;
use reqwest::header::CONTENT_TYPE;

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

    async fn get_conversations(&self, _limit: u32, _cursor: Option<&str>) -> Result<ConversationListPage> { self.unsupported("get_conversations") }
    async fn get_messages(&self, _convo_id: &str, _cursor: Option<&str>, _limit: u32, _message_type: Option<&str>, _from_epoch: Option<u32>, _to_epoch: Option<u32>) -> Result<(Vec<IncomingEnvelope>, Option<String>)> { self.unsupported("get_messages") }
    async fn get_key_packages(&self, _actor_device_id: &str, _dids: &[String]) -> Result<Vec<KeyPackageRef>> { self.unsupported("get_key_packages") }
    async fn get_key_package_stats(&self) -> Result<KeyPackageStats> { self.unsupported("get_key_package_stats") }
    async fn sync_key_packages(&self, _local_hashes: &[String], _device_id: &str) -> Result<KeyPackageSyncResult> { self.unsupported("sync_key_packages") }
    async fn list_devices(&self, _actor_device_id: &str) -> Result<Vec<DeviceInfo>> { self.unsupported("list_devices") }
    async fn get_group_info(&self, _convo_id: &str) -> Result<Vec<u8>> { self.unsupported("get_group_info") }
}
