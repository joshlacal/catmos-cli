use super::service::ChatService;
use crate::auth::AuthMethod;
use crate::device_records::{
    ensure_published, https_base, public_client, resolve_pds, response_json, xrpc_url, COLLECTION,
};
use crate::error::{CatmosError, Result};

impl ChatService {
    /// Publish the registered identity's existing public key before conversation
    /// reconciliation. Never creates, exports, or replaces private key material.
    pub async fn ensure_device_record_published(&self) -> Result<()> {
        let orchestrator = self
            .orchestrator()
            .await
            .ok_or_else(|| CatmosError::Other("Secure chat runtime is not initialized".into()))?;
        let device = orchestrator
            .require_actor_device_id()
            .await
            .map_err(|error| CatmosError::Other(error.to_string()))?;
        let identity = format!("{}#{device}", self.did());
        let public_key = self.mls.context().identity_public_key(identity)?;
        let client = public_client()?;
        let pds = resolve_pds(&client, self.did()).await?;
        let own_repo = https_base(&self.atproto_repo_base()?)?;
        // App-password credentials belong only to the configured, currently
        // authoritative own PDS. OAuth writes use the configured session proxy.
        if matches!(self.auth, AuthMethod::AppPassword { .. })
            && own_repo.as_str().trim_end_matches('/') != pds.as_str().trim_end_matches('/')
        {
            return Err(CatmosError::AuthFailed(
                "Your account's PDS has changed. Log in again to publish this device's public key."
                    .into(),
            ));
        }
        let write_url = xrpc_url(&own_repo, "com.atproto.repo.putRecord");
        let write_client = client.clone();
        let write_device = device.clone();
        ensure_published(&client, &pds, self.did(), &device, &public_key, |body| async move {
            let send = |bearer: String| {
                let client = write_client.clone();
                let write_url = write_url.clone();
                let body = body.clone();
                async move {
                    let response = client.post(write_url)
                        .headers(self.bearer_headers(&bearer)?)
                        .json(&body).send().await
                        .map_err(|_| CatmosError::Network("Could not publish device public key; please retry".into()))?;
                    let status = response.status();
                    let value = response_json(response).await?;
                    Ok::<_, CatmosError>((status, value))
                }
            };
            let (mut status, mut value) = send(self.current_bearer().await?).await?;
            if self.should_retry_after_refresh(status, &serde_json::to_vec(&value)?) {
                (status, value) = send(self.refresh_bearer().await?).await?;
            }
            if !status.is_success() {
                return Err(CatmosError::Xrpc(format!(
                    "Device public-key publication returned {status}; please retry or log in again")));
            }
            let expected = format!("at://{}/{COLLECTION}/{write_device}", self.did());
            if value.get("uri").and_then(|value| value.as_str()) != Some(expected.as_str()) {
                return Err(CatmosError::Xrpc("Device publication returned a different record URI".into()));
            }
            Ok(())
        }).await
    }
}
