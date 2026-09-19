use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::OnceLock;

static PROFILE: OnceLock<Option<String>> = OnceLock::new();

use crate::error::{CatmosError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub ui: UiConfig,
    /// DID of the currently active account (e.g. "did:plc:abc123").
    #[serde(default)]
    pub default_account: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub nest_url: String,
    pub mls_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub sidebar_visible: bool,
    pub member_panel_visible: bool,
    pub timestamp_format: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                nest_url: "https://api.catbird.blue".into(),
                mls_url: "https://chat.catbird.blue".into(),
            },
            ui: UiConfig {
                sidebar_visible: true,
                member_panel_visible: false,
                timestamp_format: "%H:%M".into(),
            },
            default_account: None,
        }
    }
}

impl Config {
    /// Select a separate local device before opening any configuration or keys.
    /// Omitting the profile preserves existing storage and keychain names.
    pub fn initialize_profile(profile: Option<&str>) -> Result<()> {
        let profile = profile
            .map(validate_profile)
            .transpose()?
            .map(str::to_owned);
        if let Some(existing) = PROFILE.get() {
            return if existing == &profile {
                Ok(())
            } else {
                Err(CatmosError::Config(
                    "Cannot change profile after initialization".into(),
                ))
            };
        }
        PROFILE
            .set(profile)
            .map_err(|_| CatmosError::Config("Profile was initialized concurrently".into()))
    }

    fn profile() -> Option<&'static str> {
        PROFILE.get_or_init(|| None).as_deref()
    }

    #[cfg(feature = "local-runtime-fixture")]
    pub(crate) fn fixture_profile() -> Option<&'static str> {
        Self::profile()
    }

    /// Preserve default keychain services; profiles always use independent entries.
    pub fn keychain_service(base: &str) -> String {
        profile_keychain_service(base, Self::profile())
    }

    pub fn config_dir() -> Result<PathBuf> {
        let base = dirs::config_dir()
            .ok_or_else(|| CatmosError::Config("Cannot determine config directory".into()))?
            .join("catmos-cli");
        let dir = profile_directory(base, Self::profile());
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    pub fn data_dir() -> Result<PathBuf> {
        let base = dirs::data_dir()
            .ok_or_else(|| CatmosError::Config("Cannot determine data directory".into()))?
            .join("catmos-cli");
        let dir = profile_directory(base, Self::profile());
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Per-account data directory, using SHA-256 hash of DID for the directory name.
    pub fn account_data_dir(did: &str) -> Result<PathBuf> {
        let mut hasher = Sha256::new();
        hasher.update(did.as_bytes());
        let hash = hex::encode(hasher.finalize());
        let dir = Self::data_dir()?.join("accounts").join(&hash[..16]);
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Load config from disk, falling back to defaults.
    pub fn load() -> Result<Self> {
        let path = Self::config_dir()?.join("config.toml");
        if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            toml::from_str(&contents).map_err(|e| CatmosError::Config(e.to_string()))
        } else {
            let config = Self::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Persist config to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::config_dir()?.join("config.toml");
        let contents =
            toml::to_string_pretty(self).map_err(|e| CatmosError::Config(e.to_string()))?;
        std::fs::write(&path, contents)?;
        Ok(())
    }
}

fn validate_profile(profile: &str) -> Result<&str> {
    if profile.is_empty()
        || profile.len() > 64
        || !profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(CatmosError::Config(
            "Profile must contain 1-64 ASCII letters, numbers, hyphens, or underscores".into(),
        ));
    }
    Ok(profile)
}

fn profile_directory(base: PathBuf, profile: Option<&str>) -> PathBuf {
    match profile {
        Some(profile) => base.join("profiles").join(profile),
        None => base,
    }
}

fn profile_keychain_service(base: &str, profile: Option<&str>) -> String {
    match profile {
        Some(profile) => format!("{base}.profile.{profile}"),
        None => base.to_owned(),
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn profile_names_cannot_escape_their_storage_directory() {
        for name in ["", ".", "..", "../device", "a/b", "a\\b", "a b", "é"] {
            assert!(validate_profile(name).is_err(), "accepted {name:?}");
        }
        assert!(validate_profile(&"a".repeat(65)).is_err());
        assert!(validate_profile("mlsv2-alice_phone-2").is_ok());
    }

    #[test]
    fn default_storage_and_credentials_keep_compatibility() {
        let base = PathBuf::from("/tmp/catmos-cli");
        assert_eq!(profile_directory(base.clone(), None), base);
        assert_eq!(
            profile_keychain_service("blue.catbird.catmos", None),
            "blue.catbird.catmos"
        );
    }

    #[test]
    fn same_account_on_two_profiles_has_independent_files_and_keychain_services() {
        let base = PathBuf::from("/tmp/catmos-cli");
        let first = profile_directory(base.clone(), Some("device-a"));
        let second = profile_directory(base, Some("device-b"));
        assert_ne!(first, second);
        assert_eq!(first, PathBuf::from("/tmp/catmos-cli/profiles/device-a"));
        for service in ["blue.catbird.catmos", "catmos-mls-db", "catmos-mls-didhash"] {
            assert_ne!(profile_keychain_service(service, Some("device-a")), service);
            assert_ne!(
                profile_keychain_service(service, Some("device-a")),
                profile_keychain_service(service, Some("device-b"))
            );
        }
    }
}
