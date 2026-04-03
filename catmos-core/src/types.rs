use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversation {
    pub group_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub creator: String,
    pub epoch: u64,
    pub cipher_suite: String,
    pub members: Vec<Member>,
    pub created_at: DateTime<Utc>,
    pub last_message_at: Option<DateTime<Utc>>,
    pub unread_count: u32,
    pub alias: Option<String>,
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
