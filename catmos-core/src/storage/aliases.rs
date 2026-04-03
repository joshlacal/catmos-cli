use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{CatmosError, Result};
use crate::storage::config::Config;
use crate::types::Conversation;

/// Maps user-defined aliases to conversation (group) IDs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AliasStore {
    aliases: HashMap<String, String>,
}

impl AliasStore {
    /// Load aliases from disk. Returns empty store if file doesn't exist.
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        if path.exists() {
            let contents = std::fs::read_to_string(&path)?;
            serde_json::from_str(&contents).map_err(|e| CatmosError::Config(e.to_string()))
        } else {
            Ok(Self::default())
        }
    }

    /// Persist aliases to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, contents)?;
        Ok(())
    }

    /// Set an alias for a conversation.
    pub fn set(&mut self, alias: String, convo_id: String) -> Result<()> {
        self.aliases.insert(alias, convo_id);
        self.save()
    }

    /// Remove an alias.
    pub fn remove(&mut self, alias: &str) -> Result<Option<String>> {
        let removed = self.aliases.remove(alias);
        self.save()?;
        Ok(removed)
    }

    /// Look up a conversation ID by alias.
    pub fn get(&self, alias: &str) -> Option<&String> {
        self.aliases.get(alias)
    }

    /// All current aliases.
    pub fn all(&self) -> &HashMap<String, String> {
        &self.aliases
    }

    /// Resolve user input to a conversation ID.
    /// Resolution order:
    /// 1. Exact alias match
    /// 2. Exact conversation title match (case-insensitive)
    /// 3. Conversation ID prefix match
    pub fn resolve(&self, input: &str, conversations: &[Conversation]) -> Option<String> {
        // 1. Alias
        if let Some(id) = self.aliases.get(input) {
            return Some(id.clone());
        }

        // 2. Title match (case-insensitive)
        let input_lower = input.to_lowercase();
        for convo in conversations {
            if let Some(ref name) = convo.name {
                if name.to_lowercase() == input_lower {
                    return Some(convo.group_id.clone());
                }
            }
        }

        // 3. ID prefix match
        let mut matches: Vec<_> = conversations
            .iter()
            .filter(|c| c.group_id.starts_with(input))
            .collect();
        if matches.len() == 1 {
            return Some(matches.remove(0).group_id.clone());
        }

        None
    }

    fn path() -> Result<PathBuf> {
        Ok(Config::config_dir()?.join("aliases.json"))
    }
}
