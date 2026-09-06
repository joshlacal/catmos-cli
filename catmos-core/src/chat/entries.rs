//! Shared projection of the commit-bearing v2 entry variants and MLS artifacts.

use crate::error::{CatmosError, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

/// Keep every commit-bearing v2 entry in sequence before its next application.
/// A malformed known artifact must fail instead of silently losing an epoch.
pub(crate) fn entry_ciphertext(entry: &serde_json::Value) -> Result<Option<Vec<u8>>> {
    use catbird_mls::chat_v2::wire::{
        APPLICATION_ENTRY_KIND, COMMIT_ENTRY_KIND, LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND,
        LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
    };
    let field = match entry.get("$type").and_then(|value| value.as_str()) {
        Some(APPLICATION_ENTRY_KIND) => "applicationMessage",
        Some(
            COMMIT_ENTRY_KIND
            | LEAF_RECOVERY_FULFILLMENT_ENTRY_KIND
            | LEAVE_COMMIT_FULFILLMENT_ENTRY_KIND,
        ) => "commit",
        _ => return Ok(None),
    };
    let artifact = entry
        .get("signedRequest")
        .and_then(|request| request.get("body"))
        .and_then(|body| body.get(field))
        .ok_or_else(|| CatmosError::Xrpc(format!("Conversation entry omitted {field}")))?;
    artifact_bytes(artifact, field).map(Some)
}

pub(crate) fn artifact_bytes(artifact: &serde_json::Value, field: &str) -> Result<Vec<u8>> {
    let encoded = artifact
        .as_str()
        .or_else(|| artifact.get("$bytes").and_then(|value| value.as_str()))
        .or_else(|| {
            artifact.get("bytes").and_then(|value| {
                value
                    .as_str()
                    .or_else(|| value.get("$bytes").and_then(|value| value.as_str()))
            })
        })
        .ok_or_else(|| {
            CatmosError::Xrpc(format!("Conversation entry has invalid {field} bytes"))
        })?;
    let decoded = BASE64
        .decode(encoded)
        .map_err(|_| CatmosError::Xrpc(format!("Conversation entry has invalid {field} base64")))?;
    if decoded.is_empty() {
        return Err(CatmosError::Xrpc(format!(
            "Conversation entry has empty {field}"
        )));
    }
    Ok(decoded)
}
