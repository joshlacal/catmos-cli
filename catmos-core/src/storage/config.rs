use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::error::{CatmosError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub ui: UiConfig,
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
                nest_url: "https://nest.catbird.blue".into(),
                mls_url: "https://mlschat.catbird.blue".into(),
            },
            ui: UiConfig {
                sidebar_visible: true,
                member_panel_visible: false,
                timestamp_format: "%H:%M".into(),
            },
        }
    }
}

impl Config {
    /// XDG config directory: ~/.config/catmos/
    pub fn config_dir() -> Result<PathBuf> {
        let dir = dirs::config_dir()
            .ok_or_else(|| CatmosError::Config("Cannot determine config directory".into()))?
            .join("catmos");
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// XDG data directory: ~/.local/share/catmos/
    pub fn data_dir() -> Result<PathBuf> {
        let dir = dirs::data_dir()
            .ok_or_else(|| CatmosError::Config("Cannot determine data directory".into()))?
            .join("catmos");
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
