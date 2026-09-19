use serde::Serialize;
use tracing::debug;

use super::service::ChatService;
use crate::error::Result;

/// Owned request body matching the generated `UpdateCursor` field names.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateCursorReq {
    convo_id: String,
    cursor: String,
}

impl ChatService {
    /// Full sync: fetch conversations from the server, cache locally, then run
    /// the spec §8.5 deferred recovery loop (Phase 1 RESET_PENDING, Phase 2
    /// NEEDS_REJOIN). Recovery is best-effort; failures don't propagate to the
    /// caller of `full_sync`.
    pub async fn full_sync(&self) -> Result<()> {
        debug!("Starting full sync");
        self.fetch_conversations().await?;
        // Spec §8.5: run AFTER the conversation list is refreshed so that
        // newly-arrived RESET_PENDING flags from the server are visible and
        // dropped conversations are not retried.
        self.run_deferred_recovery().await;
        debug!("Full sync complete");
        Ok(())
    }

    /// Update the read cursor for a conversation on the server.
    pub async fn update_cursor(&self, convo_id: &str, cursor: &str) -> Result<()> {
        self.require_ordinary_effects(convo_id).await?;
        let req = UpdateCursorReq {
            convo_id: convo_id.to_string(),
            cursor: cursor.to_string(),
        };
        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.chat.submitTransition", &req)
            .await?;
        Ok(())
    }
}
