//! Canonical clean-chat XRPC route contract.
//!
//! Endpoint names are sourced from the generated `blue.catbird.chat` Jacquard
//! markers. This is an inventory/seam for the future typed migration; runtime
//! transport remains on the legacy endpoints until canonical request signing,
//! DPoP, and payload adapters are available.

#![allow(dead_code)]

use catbird_atproto::jacquard_common::xrpc::{SubscriptionResp, XrpcResp};

/// Deliberately disabled until canonical typed adapters and DPoP are landed.
pub(crate) const RUNTIME_MIGRATION_ENABLED: bool = false;

pub(crate) const CREATE_CONVERSATION: &str =
    catbird_atproto::blue_catbird::chat::create_conversation::CreateConversationResponse::NSID;
pub(crate) const GET_CONVERSATIONS: &str =
    catbird_atproto::blue_catbird::chat::get_conversations::GetConversationsResponse::NSID;
pub(crate) const GET_ENTRIES: &str =
    catbird_atproto::blue_catbird::chat::get_entries::GetEntriesResponse::NSID;
pub(crate) const SEND_MESSAGE: &str =
    catbird_atproto::blue_catbird::chat::send_message::SendMessageResponse::NSID;
#[allow(dead_code)]
pub(crate) const DELETE_BLOB: &str =
    catbird_atproto::blue_catbird::chat::delete_blob::DeleteBlobResponse::NSID;
pub(crate) const GET_BLOB: &str =
    catbird_atproto::blue_catbird::chat::get_blob::GetBlobResponse::NSID;
pub(crate) const GET_BLOB_USAGE: &str =
    catbird_atproto::blue_catbird::chat::get_blob_usage::GetBlobUsageResponse::NSID;
pub(crate) const GET_CONVERSATION_STATE: &str =
    catbird_atproto::blue_catbird::chat::get_conversation_state::GetConversationStateResponse::NSID;
pub(crate) const REQUEST_RESET: &str =
    catbird_atproto::blue_catbird::chat::request_reset::RequestResetResponse::NSID;
pub(crate) const REQUEST_LEAF_RECOVERY: &str =
    catbird_atproto::blue_catbird::chat::request_leaf_recovery::RequestLeafRecoveryResponse::NSID;
pub(crate) const SUBMIT_TRANSITION: &str =
    catbird_atproto::blue_catbird::chat::submit_transition::SubmitTransitionResponse::NSID;
pub(crate) const SUBSCRIBE_EVENTS: &str =
    catbird_atproto::blue_catbird::chat::subscribe_events::SubscribeEventsStream::NSID;
pub(crate) const GET_SUBSCRIPTION_TICKET: &str = catbird_atproto::blue_catbird::chat::get_subscription_ticket::GetSubscriptionTicketResponse::NSID;
#[allow(dead_code)]
pub(crate) const CLOSE_CONVERSATION: &str =
    catbird_atproto::blue_catbird::chat::close_conversation::CloseConversationResponse::NSID;
pub(crate) const REQUEST_LEAVE: &str =
    catbird_atproto::blue_catbird::chat::request_leave::RequestLeaveResponse::NSID;
pub(crate) const ENROLL_DEVICE: &str =
    catbird_atproto::blue_catbird::chat::enroll_device::EnrollDeviceResponse::NSID;
pub(crate) const GET_DEVICES: &str =
    catbird_atproto::blue_catbird::chat::get_devices::GetDevicesResponse::NSID;
pub(crate) const REVOKE_DEVICE: &str =
    catbird_atproto::blue_catbird::chat::revoke_device::RevokeDeviceResponse::NSID;
pub(crate) const REPLENISH_KEY_PACKAGES: &str =
    catbird_atproto::blue_catbird::chat::replenish_key_packages::ReplenishKeyPackagesResponse::NSID;
pub(crate) const UPLOAD_BLOB: &str =
    catbird_atproto::blue_catbird::chat::upload_blob::UploadBlobResponse::NSID;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_use_generated_clean_chat_namespace() {
        let routes = [
            CREATE_CONVERSATION,
            GET_CONVERSATIONS,
            GET_ENTRIES,
            SEND_MESSAGE,
            DELETE_BLOB,
            GET_BLOB,
            GET_BLOB_USAGE,
            GET_CONVERSATION_STATE,
            REQUEST_RESET,
            REQUEST_LEAF_RECOVERY,
            SUBMIT_TRANSITION,
            SUBSCRIBE_EVENTS,
            GET_SUBSCRIPTION_TICKET,
            CLOSE_CONVERSATION,
            REQUEST_LEAVE,
            ENROLL_DEVICE,
            GET_DEVICES,
            REVOKE_DEVICE,
            REPLENISH_KEY_PACKAGES,
            UPLOAD_BLOB,
        ];
        assert!(routes
            .iter()
            .all(|route| route.starts_with("blue.catbird.chat.")));
    }

    #[test]
    fn generated_markers_are_the_route_authority() {
        assert_eq!(
            CREATE_CONVERSATION,
            catbird_atproto::blue_catbird::chat::create_conversation::CreateConversationResponse::NSID
        );
        assert_eq!(
            GET_CONVERSATIONS,
            catbird_atproto::blue_catbird::chat::get_conversations::GetConversationsResponse::NSID
        );
        assert_eq!(
            GET_ENTRIES,
            catbird_atproto::blue_catbird::chat::get_entries::GetEntriesResponse::NSID
        );
        assert_eq!(
            SEND_MESSAGE,
            catbird_atproto::blue_catbird::chat::send_message::SendMessageResponse::NSID
        );
        assert_eq!(
            SUBSCRIBE_EVENTS,
            catbird_atproto::blue_catbird::chat::subscribe_events::SubscribeEventsStream::NSID
        );
    }

    #[test]
    fn inventory_is_not_enabled_for_runtime_transport() {
        assert!(!RUNTIME_MIGRATION_ENABLED);
    }
}
