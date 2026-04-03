use serde::Serialize;
use tracing::debug;

use catbird_atproto::catbird::mls_chat;

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
    /// Full sync: fetch conversations from the server and cache locally.
    pub async fn full_sync(&self) -> Result<()> {
        debug!("Starting full sync");
        self.fetch_conversations().await?;
        debug!("Full sync complete");
        Ok(())
    }

    /// Update the read cursor for a conversation on the server.
    pub async fn update_cursor(&self, convo_id: &str, cursor: &str) -> Result<()> {
        let req = UpdateCursorReq {
            convo_id: convo_id.to_string(),
            cursor: cursor.to_string(),
        };
        let _: serde_json::Value = self
            .xrpc_procedure("blue.catbird.mlsChat.updateCursor", &req)
            .await?;
        Ok(())
    }
}
