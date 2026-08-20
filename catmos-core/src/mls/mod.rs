pub mod context;
pub mod key_packages;
pub mod onboarding;

pub const MLS_CIPHER_SUITE: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";
pub const DEFAULT_ATPROTO_PROXY_DID: &str = "did:web:chat.catbird.blue#atproto_mls";
pub const KEY_PACKAGE_TARGET: u64 = 25;
pub const KEY_PACKAGE_LOW_THRESHOLD: u64 = 10;

pub fn atproto_proxy_header_value() -> String {
    std::env::var("ATPROTO_PROXY_HEADER")
        .or_else(|_| std::env::var("ATPROTO_PROXY_DID"))
        .unwrap_or_else(|_| DEFAULT_ATPROTO_PROXY_DID.to_string())
}

pub use context::MlsManager;
pub use onboarding::{DeviceInfo, GroupMetadata};
