//! Per-DID content-root key storage for the MLS field-level encryption layer.
//!
//! The content-root key is a 32-byte secret used by
//! `catbird_mls::field_encryption` to derive per-conversation AES-GCM content
//! keys and HMAC chain keys. It is held in process memory inside the
//! `Database` (and the orchestrator's `MLSContext`) and must be available on
//! every cold start, so we persist it as a binary file under
//! `{config_dir}/mls-content-root/{sha256(did)}.key`.
//!
//! The file is protected by OS-level filesystem permissions (`0o600` on
//! Unix). It is **not** the SQLCipher database key — the two are stored
//! separately so that compromise of the database key alone does not directly
//! expose decrypted message bodies (the threat model the field-level layer
//! addresses).
//!
//! Precedent: this mirrors `catmos/src-tauri/src/keys.rs` from the desktop
//! client (commit `a6ab65b`). The CLI uses `dirs::config_dir()` →
//! `~/.config/catmos-cli/` rather than a Tauri-resolved `app_data_dir`, so
//! the call site supplies the directory explicitly.

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const KEY_LEN: usize = 32;

fn did_filename(user_did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(user_did.as_bytes());
    let did_hash = hex::encode(hasher.finalize());
    format!("{}.key", did_hash)
}

/// Load the content-root key for `user_did` from
/// `{config_dir}/mls-content-root/`, creating a fresh random 32-byte key on
/// first use. Permissions are tightened to `0o600` on Unix-likes; on other
/// platforms the OS default applies.
pub fn load_or_create_content_root_key(config_dir: &Path, user_did: &str) -> Result<Vec<u8>> {
    let dir = config_dir.join("mls-content-root");
    fs::create_dir_all(&dir).context("create mls-content-root dir")?;
    let path = dir.join(did_filename(user_did));

    if path.exists() {
        let buf = fs::read(&path).context("read existing content root key")?;
        if buf.len() != KEY_LEN {
            return Err(anyhow!(
                "content root key file at {} has wrong length: {}",
                path.display(),
                buf.len(),
            ));
        }
        return Ok(buf);
    }

    let mut buf = vec![0u8; KEY_LEN];
    rand::thread_rng().fill_bytes(&mut buf);
    fs::write(&path, &buf).context("write new content root key")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    Ok(buf)
}

/// Remove the content-root key file for `user_did`, if present. Reserved for
/// the eventual "wipe this account from this device" flow; not yet wired
/// into `logout` (which only clears the in-memory key so re-login on the
/// same machine resumes the same HMAC chain seed).
#[allow(dead_code)]
pub fn delete_content_root_key(config_dir: &Path, user_did: &str) -> Result<()> {
    let path = config_dir
        .join("mls-content-root")
        .join(did_filename(user_did));
    if path.exists() {
        fs::remove_file(&path).context("remove content root key file")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_then_load_returns_same_bytes() {
        let tmp = std::env::temp_dir().join(format!(
            "catmos-cli-keys-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let did = "did:plc:catmos-cli-test-user";
        let first = load_or_create_content_root_key(&tmp, did).unwrap();
        let second = load_or_create_content_root_key(&tmp, did).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), KEY_LEN);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn different_dids_get_different_keys() {
        let tmp = std::env::temp_dir().join(format!(
            "catmos-cli-keys-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let a = load_or_create_content_root_key(&tmp, "did:plc:a").unwrap();
        let b = load_or_create_content_root_key(&tmp, "did:plc:b").unwrap();
        assert_ne!(a, b);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rejects_wrong_length_file() {
        let tmp = std::env::temp_dir().join(format!(
            "catmos-cli-keys-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let did = "did:plc:bad";
        let dir = tmp.join("mls-content-root");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(did_filename(did)), b"too-short").unwrap();
        let err = load_or_create_content_root_key(&tmp, did).unwrap_err();
        assert!(err.to_string().contains("wrong length"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn delete_removes_file() {
        let tmp = std::env::temp_dir().join(format!(
            "catmos-cli-keys-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        let did = "did:plc:delete-me";
        let _ = load_or_create_content_root_key(&tmp, did).unwrap();
        delete_content_root_key(&tmp, did).unwrap();
        // Deleting again is a no-op.
        delete_content_root_key(&tmp, did).unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
