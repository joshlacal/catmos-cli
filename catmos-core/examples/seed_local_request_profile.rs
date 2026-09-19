//! Synthetic local service qualification only. Receives a newly issued opaque
//! session through stdin and retains native keys in the selected OS keychain.
//! Output contains public identity metadata only; private keys never leave this
//! process except through the normal protected credential/storage interfaces.
use std::io::Read;

use anyhow::{ensure, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use catbird_mls::orchestrator::credentials::CredentialStore;
use catmos_core::{
    auth::oauth::OAuthAuth,
    mls::MlsManager,
    orchestrator_credentials::KeyringCredentialStore,
    storage::{config::Config, db::Database},
};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Seed {
    profile: String,
    did: String,
    device_id: String,
    proxy_url: String,
    service_url: String,
    session_cookie: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut raw = Vec::new();
    std::io::stdin().take(16_385).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 16_384, "fixture input exceeds bound");
    let seed: Seed = serde_json::from_slice(&raw).context("fixture seed input")?;
    let profile_id = seed
        .profile
        .strip_prefix("t17-cli-")
        .context("synthetic profile required")?;
    ensure!(
        uuid::Uuid::parse_str(profile_id)?.to_string() == profile_id,
        "canonical profile required"
    );
    catbird_mls::chat_v2::ids::BareDid::parse(&seed.did)?;
    ensure!(
        seed.did.starts_with("did:web:") && seed.did.ends_with(".request-fixture.catbird.blue"),
        "synthetic account required"
    );
    ensure!(
        uuid::Uuid::parse_str(&seed.device_id)?.to_string() == seed.device_id,
        "canonical device required"
    );
    let proxy = url::Url::parse(&seed.proxy_url)?;
    ensure!(
        proxy.scheme() == "https"
            && proxy
                .host_str()
                .is_some_and(|h| h.ends_with(".request-fixture.catbird.blue"))
            && proxy.username().is_empty()
            && proxy.password().is_none(),
        "synthetic HTTPS proxy required"
    );
    ensure!(
        seed.session_cookie.len() >= 32 && seed.session_cookie.len() <= 256,
        "bounded random session required"
    );
    ensure!(
        std::env::var_os("CATMOS_TEST_KEYCHAIN_FALLBACK").is_none()
            && std::env::var_os("CATMOS_TEST_SHARED_KEYCHAIN_FALLBACK").is_none(),
        "actual process qualification requires OS keychain custody"
    );
    Config::initialize_profile(Some(&seed.profile))?;
    ensure!(
        !Config::config_dir()?.join("config.toml").exists(),
        "refusing to replace existing profile"
    );
    let mut config = Config::default();
    config.default_account = Some(seed.did.clone());
    config.server.nest_url = seed.proxy_url.clone();
    config.server.mls_url = seed.service_url;
    config.save()?;

    let identity = format!("{}#{}", seed.did, seed.device_id);
    let mls = MlsManager::new(&Config::data_dir()?.join("mls"), &seed.did)?;
    let package = mls
        .context()
        .create_key_package(identity.as_bytes().to_vec())?;
    let signing = mls.context().export_identity_key(identity.clone())?;
    let credentials = KeyringCredentialStore::try_new()?;
    credentials.store_signing_key(&seed.did, &signing).await?;
    credentials.store_mls_did(&seed.did, &identity).await?;
    credentials
        .store_device_uuid(&seed.did, &seed.device_id)
        .await?;

    let key = catmos_core::mls::context::get_or_create_db_key(&seed.did)?;
    let db = Database::open(
        &Config::account_data_dir(&seed.did)?.join("catmos.db"),
        &key,
    )
    .await?;
    OAuthAuth {
        session_cookie: seed.session_cookie,
        did: seed.did.clone(),
        handle: seed.did.trim_start_matches("did:web:").into(),
        nest_url: seed.proxy_url,
    }
    .save(&db)
    .await?;
    use sha2::{Digest, Sha256};
    let fallback = Config::data_dir()?.join("credentials").join(format!(
        "{}.key",
        hex::encode(Sha256::digest(
            format!("signing_key:{}", seed.did).as_bytes()
        ))
    ));
    ensure!(
        !fallback.exists(),
        "private signing key was mirrored into a legacy file"
    );
    println!(
        "{}",
        serde_json::json!({"did":seed.did,"deviceId":seed.device_id,"signaturePublicKey":STANDARD.encode(package.signature_public_key),"privateSigningKeyFallbackPresent":false})
    );
    Ok(())
}
