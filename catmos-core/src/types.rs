use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Canonical sequence owns confirmed display order. Zero represents an
/// unconfirmed or legacy row, retained at the end in timestamp/ID order.
pub(crate) fn message_order_key<'a>(
    sequence: u64,
    timestamp: &'a DateTime<Utc>,
    id: &'a str,
) -> (bool, u64, &'a DateTime<Utc>, &'a str) {
    (sequence == 0, sequence, timestamp, id)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub conversation_id: String,
    pub group_id: String,
    /// Decrypted group title. Populated from `bootstrap_group_metadata` after
    /// a Welcome / external-commit join / metadata-update commit merge.
    /// **Never read from API responses** — the server is cryptographically
    /// blind to group titles after the metadata cutover.
    pub name: Option<String>,
    /// Decrypted group description. Same provenance rules as `name`.
    pub description: Option<String>,
    /// Present only when an explicit conversation response provides it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    pub epoch: u64,
    pub cipher_suite: String,
    pub members: Vec<Member>,
    /// Canonical inventory does not supply a creation timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    pub last_message_at: Option<DateTime<Utc>>,
    pub unread_count: u32,
    pub alias: Option<String>,
    /// `MetadataReference.metadata_version` for the most recent bootstrap.
    /// Used to skip redundant blob fetches when we already hold the same version.
    pub metadata_version: Option<i64>,
    /// `MetadataReference.blob_locator` for the most recent bootstrap.
    pub metadata_blob_locator: Option<String>,
    /// Locator for the avatar blob referenced by the last decrypted
    /// `GroupMetadataV1`. May be `None` even when `name` is set.
    pub avatar_blob_locator: Option<String>,
    /// Decrypted avatar image bytes (raw, not base64). Persisted so the TUI
    /// can render the avatar across restarts without re-fetching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar_bytes: Option<Vec<u8>>,
    /// MIME type of `avatar_bytes`, e.g. `"image/jpeg"`.
    pub avatar_content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub did: String,
    pub user_did: String,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub is_admin: bool,
    pub is_moderator: bool,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub convo_id: String,
    pub sender_did: Option<String>,
    pub content: MessageContent,
    pub epoch: u64,
    pub seq: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    Reaction {
        target_message_id: String,
        emoji: String,
        action: ReactionAction,
    },
    System(String),
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReactionAction {
    Add,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub mls_did: String,
    pub device_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageStatus {
    pub available: u64,
    pub target: u64,
    pub needs_replenish: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobUsage {
    pub used_bytes: i64,
    pub quota_bytes: i64,
    pub blob_count: i64,
}

/// The local native terminal pipeline reserves this deterministic receipt ID.
/// A peer-supplied System payload alone is not evidence that our account left.
pub fn is_local_membership_left_marker(
    message: &catbird_mls::orchestrator::types::Message,
    own_did: &str,
    own_device_id: &str,
    has_durable_terminal_state: bool,
) -> bool {
    use catbird_mls::orchestrator::types::MLSMessageType;
    if !has_durable_terminal_state || !message.is_own || message.sender_did != own_did {
        return false;
    }
    let Some((entry_id, device_id)) = message.id.strip_prefix("membership-left:").and_then(|value| value.split_once(':')) else {
        return false;
    };
    let canonical_uuid = |value: &str| uuid::Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 4 && id.hyphenated().to_string() == value);
    device_id == own_device_id && canonical_uuid(entry_id) && canonical_uuid(device_id)
        && message.payload().is_some_and(|payload| payload.version == 1
            && payload.message_type == MLSMessageType::System
            && payload.text.as_deref() == Some("membership.left"))
}
