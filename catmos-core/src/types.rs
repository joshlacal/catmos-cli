use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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
    pub creator: String,
    pub epoch: u64,
    pub cipher_suite: String,
    pub members: Vec<Member>,
    pub created_at: DateTime<Utc>,
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
