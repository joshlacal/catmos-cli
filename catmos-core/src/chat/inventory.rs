//! Fetch and retain one authenticated three-inventory snapshot. Only shared
//! Rust applies it and releases the fence used by event subscriptions.
use super::ChatService;
use crate::error::{CatmosError, Result};
use catbird_mls::orchestrator::{
    authenticated_inventory::{AppliedInventoryFence, AuthenticatedInventorySnapshot},
    canonical_transport::{CanonicalOperation, PreparedRequest},
    credentials::CredentialStore,
    MLSAPIClient,
};
use serde_json::Value;
use std::collections::HashSet;

fn invalid(reason: impl std::fmt::Display) -> CatmosError {
    CatmosError::Other(format!("Inventory snapshot: {reason}"))
}
fn text(page: &Value, field: &str) -> Result<String> {
    page[field]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(format!("missing {field}")))
}
impl ChatService {
    pub async fn refresh_authenticated_inventory(&self) -> Result<AppliedInventoryFence> {
        let authority = self.request_authority().await?;
        let actor = self.actor_device_id().await?;
        let generation = authority
            .credentials()
            .get_auth_generation(self.did())
            .await
            .map_err(invalid)?
            .ok_or_else(|| invalid("device generation unavailable"))?;
        let mut snapshot: Option<AuthenticatedInventorySnapshot> = None;
        let mut total = 0usize;
        for (operation, nsid) in [
            (CanonicalOperation::GetConversations, "getConversations"),
            (CanonicalOperation::GetPendingWelcomes, "getPendingWelcomes"),
            (
                CanonicalOperation::GetLeafRecoveryInbox,
                "getLeafRecoveryInbox",
            ),
        ] {
            let mut cursor: Option<String> = None;
            let mut seen = HashSet::new();
            let mut pages = Vec::new();
            loop {
                if pages.len() >= 100 {
                    return Err(invalid("page bound exceeded"));
                }
                let query_string = {
                    let mut query = url::form_urlencoded::Serializer::new(String::new());
                    query
                        .append_pair("actorDeviceId", &actor)
                        .append_pair("limit", "100");
                    if operation == CanonicalOperation::GetConversations {
                        query
                            .append_pair("supportedProtocolVersions", "1")
                            .append_pair("supportedProtocolVersions", "2");
                    } else {
                        query.append_pair(
                            "inventorySessionId",
                            &snapshot
                                .as_ref()
                                .ok_or_else(|| invalid("missing session"))?
                                .inventory_session_id,
                        );
                    }
                    if let Some(value) = &cursor {
                        query.append_pair("pageCursor", value);
                    }
                    query.finish()
                };
                let response = authority
                    .api_client()
                    .submit_prepared_request(PreparedRequest {
                        operation,
                        path: format!("/xrpc/blue.catbird.chat.{nsid}?{}", query_string),
                        method: "GET".into(),
                        body: None,
                    })
                    .await
                    .map_err(invalid)?;
                if response.status != 200 {
                    return Err(invalid(format!("{nsid} returned HTTP {}", response.status)));
                }
                total = total
                    .checked_add(response.body.len())
                    .ok_or_else(|| invalid("size overflow"))?;
                if response.body.len() > 16 * 1024 * 1024 || total > 64 * 1024 * 1024 {
                    return Err(invalid("snapshot byte bound exceeded"));
                }
                let page: Value = serde_json::from_slice(&response.body).map_err(invalid)?;
                if snapshot.is_none() {
                    let digest = page["inventoryScope"]["scopeDigest"]
                        .as_str()
                        .or_else(|| page["inventoryScope"]["scopeDigest"]["$bytes"].as_str())
                        .ok_or_else(|| invalid("scope digest missing"))?
                        .to_owned();
                    snapshot = Some(AuthenticatedInventorySnapshot {
                        owner_did: self.did().into(),
                        actor_device_id: actor.clone(),
                        auth_generation: generation,
                        inventory_session_id: text(&page, "inventorySessionId")?,
                        event_cursor: text(&page, "snapshotEventCursor")?,
                        expires_at: text(&page, "snapshotExpiresAt")?,
                        scope_digest: digest,
                        conversation_pages: vec![],
                        welcome_pages: vec![],
                        recovery_pages: vec![],
                    });
                }
                let next = match page.get("nextPageCursor") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
                    _ => return Err(invalid("invalid cursor")),
                };
                if page["hasMore"].as_bool() != Some(next.is_some()) {
                    return Err(invalid("incomplete page"));
                }
                pages.push(response.body);
                let Some(next) = next else { break };
                if !seen.insert(next.clone()) {
                    return Err(invalid("cursor cycle"));
                }
                cursor = Some(next);
            }
            let state = snapshot.as_mut().ok_or_else(|| invalid("empty snapshot"))?;
            match operation {
                CanonicalOperation::GetConversations => state.conversation_pages = pages,
                CanonicalOperation::GetPendingWelcomes => state.welcome_pages = pages,
                CanonicalOperation::GetLeafRecoveryInbox => state.recovery_pages = pages,
                _ => unreachable!(),
            }
        }
        let snapshot = snapshot.ok_or_else(|| invalid("missing snapshot"))?;
        self.db
            .retain_authenticated_inventory(
                self.did(),
                &serde_json::to_vec(&snapshot).map_err(invalid)?,
            )
            .await?;
        let fence = authority
            .ingest_authenticated_inventory_snapshot(&snapshot)
            .await
            .map_err(invalid)?;
        if !fence.matches_snapshot(&snapshot) {
            return Err(invalid("completion fence mismatch"));
        }
        *self.inventory_session.write().await = Some((
            fence.inventory_session_id().into(),
            fence.event_cursor().into(),
        ));
        Ok(fence)
    }
}
