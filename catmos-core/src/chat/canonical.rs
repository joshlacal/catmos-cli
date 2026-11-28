//! Canonical clean-chat XRPC route contract.
//!
//! Endpoint names are sourced from the generated `blue.catbird.chat` Petrel
//! markers. This is an inventory/seam for the future typed migration; runtime
//! transport remains on the legacy endpoints until canonical request signing,
//! DPoP, and payload adapters are available.

#![allow(dead_code)]

/// Deliberately disabled until canonical typed adapters and DPoP are landed.
pub(crate) const RUNTIME_MIGRATION_ENABLED: bool = false;

pub(crate) const CREATE_CONVERSATION: &str =
    petrel_catbird::generated::blue::catbird::chat::create_conversation::NSID;
pub(crate) const GET_CONVERSATIONS: &str =
    petrel_catbird::generated::blue::catbird::chat::get_conversations::NSID;
pub(crate) const GET_ENTRIES: &str =
    petrel_catbird::generated::blue::catbird::chat::get_entries::NSID;
pub(crate) const SEND_MESSAGE: &str =
    petrel_catbird::generated::blue::catbird::chat::send_message::NSID;
pub(crate) const GET_CONVERSATION_STATE: &str =
    petrel_catbird::generated::blue::catbird::chat::get_conversation_state::NSID;
pub(crate) const REQUEST_RESET: &str =
    petrel_catbird::generated::blue::catbird::chat::request_reset::NSID;
pub(crate) const REQUEST_LEAF_RECOVERY: &str =
    petrel_catbird::generated::blue::catbird::chat::request_leaf_recovery::NSID;
pub(crate) const SUBMIT_TRANSITION: &str =
    petrel_catbird::generated::blue::catbird::chat::submit_transition::NSID;
pub(crate) const SUBSCRIBE_EVENTS: &str =
    petrel_catbird::generated::blue::catbird::chat::subscribe_events::NSID;
pub(crate) const GET_SUBSCRIPTION_TICKET: &str =
    petrel_catbird::generated::blue::catbird::chat::get_subscription_ticket::NSID;
#[allow(dead_code)]
pub(crate) const CLOSE_CONVERSATION: &str =
    petrel_catbird::generated::blue::catbird::chat::close_conversation::NSID;
pub(crate) const REQUEST_LEAVE: &str =
    petrel_catbird::generated::blue::catbird::chat::request_leave::NSID;
pub(crate) const ENROLL_DEVICE: &str =
    petrel_catbird::generated::blue::catbird::chat::enroll_device::NSID;
pub(crate) const GET_DEVICES: &str =
    petrel_catbird::generated::blue::catbird::chat::get_devices::NSID;
pub(crate) const REVOKE_DEVICE: &str =
    petrel_catbird::generated::blue::catbird::chat::revoke_device::NSID;
pub(crate) const REPLENISH_KEY_PACKAGES: &str =
    petrel_catbird::generated::blue::catbird::chat::replenish_key_packages::NSID;

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
        ];
        assert!(routes
            .iter()
            .all(|route| route.starts_with("blue.catbird.chat.")));
    }

    #[test]
    fn generated_markers_are_the_route_authority() {
        assert_eq!(
            CREATE_CONVERSATION,
            petrel_catbird::generated::blue::catbird::chat::create_conversation::NSID
        );
        assert_eq!(
            GET_CONVERSATIONS,
            petrel_catbird::generated::blue::catbird::chat::get_conversations::NSID
        );
        assert_eq!(
            GET_ENTRIES,
            petrel_catbird::generated::blue::catbird::chat::get_entries::NSID
        );
        assert_eq!(
            SEND_MESSAGE,
            petrel_catbird::generated::blue::catbird::chat::send_message::NSID
        );
        assert_eq!(
            SUBSCRIBE_EVENTS,
            petrel_catbird::generated::blue::catbird::chat::subscribe_events::NSID
        );
    }

    #[test]
    fn inventory_is_not_enabled_for_runtime_transport() {
        assert!(!RUNTIME_MIGRATION_ENABLED);
    }
}
