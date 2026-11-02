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
        if self.unified_client().await.is_some() {
            debug!("Full sync complete (unified CatbirdMlsClient)");
            return Ok(());
        }
        // Spec §8.5: run AFTER the conversation list is refreshed so that
        // newly-arrived RESET_PENDING flags from the server are visible and
        // dropped conversations are not retried.
        self.run_deferred_recovery().await;
        debug!("Full sync complete");
        Ok(())
    }

    /// Update the read cursor / acknowledge entries up to `seq` on the server (`I14`).
    pub async fn update_cursor(&self, convo_id: &str, cursor: &str) -> Result<()> {
        if let Some(unified) = self.unified_client().await {
            if let Ok(seq) = cursor.trim().parse::<i64>() {
                if seq >= 1 {
                    let cid = convo_id.to_string();
                    let sdk = unified.sdk().clone();
                    tokio::task::spawn_blocking(move || sdk.acknowledge_entries_up_to(&cid, seq))
                        .await
                        .map_err(|e| crate::error::CatmosError::Other(format!("join error: {e}")))?
                        .map_err(crate::error::CatmosError::Mls)?;
                }
            }
            return Ok(());
        }

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
