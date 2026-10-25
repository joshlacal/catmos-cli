//! Explicit maintained keyring backends with the pre-upgrade identifiers.
//!
//! keyring 4's convenience defaults switch Linux from keyutils to Secret Service,
//! and the new keyutils store changes its default description. Either change
//! would hide existing SQLCipher keys, so choose the backend and name explicitly.
use keyring::api::CredentialStoreApi;
use keyring::{Entry, Result};

pub(crate) fn entry(service: &str, user: &str) -> Result<Entry> {
    #[cfg(target_os = "macos")]
    {
        apple_native_keyring_store::keychain::Store::new()?.build(service, user, None)
    }
    #[cfg(target_os = "linux")]
    {
        let description = format!("keyring-rs:{user}@{service}");
        let modifiers = std::collections::HashMap::from([("description", description.as_str())]);
        linux_keyutils_keyring_store::Store::new()?.build(service, user, Some(&modifiers))
    }
    #[cfg(target_os = "windows")]
    {
        windows_native_keyring_store::Store::new()?.build(service, user, None)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (service, user);
        Err(keyring::Error::NoDefaultStore)
    }
}
