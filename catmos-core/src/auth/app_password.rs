use serde::Deserialize;

use crate::error::{CatmosError, Result};
use crate::storage::db::Database;

/// Authentication via AT Protocol app password (direct PDS login).
pub struct AppPasswordAuth {
    pub handle: String,
    pub did: String,
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub pds_url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    did: String,
    handle: String,
    access_jwt: String,
    refresh_jwt: String,
}

#[derive(Deserialize)]
struct PlcService {
    id: String,
    #[serde(rename = "type")]
    _type: String,
    #[serde(rename = "serviceEndpoint")]
    service_endpoint: String,
}

#[derive(Deserialize)]
struct PlcDocument {
    #[serde(default)]
    service: Vec<PlcService>,
}

impl AppPasswordAuth {
    /// Log in using an AT Protocol handle and app password.
    ///
    /// Resolution order:
    /// 1. Fetch `https://{handle}/.well-known/atproto-did` to get the DID
    /// 2. Resolve the DID via PLC directory to find the PDS service endpoint
    /// 3. Fall back to `https://{handle}` as PDS if resolution fails
    /// 4. Call `com.atproto.server.createSession` on the PDS
    pub async fn login(handle: &str, app_password: &str) -> Result<Self> {
        let client = reqwest::Client::new();

        // Step 1: Resolve DID from handle
        let pds_url = match resolve_pds(&client, handle).await {
            Ok(url) => url,
            Err(_) => format!("https://{handle}"),
        };

        // Step 2: Create session on the PDS
        let url = format!("{pds_url}/xrpc/com.atproto.server.createSession");
        let body = serde_json::json!({
            "identifier": handle,
            "password": app_password,
        });

        let resp = client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(CatmosError::AuthFailed(format!(
                "createSession failed ({status}): {text}"
            )));
        }

        let session: CreateSessionResponse = resp
            .json()
            .await
            .map_err(|e| CatmosError::AuthFailed(format!("invalid session response: {e}")))?;

        Ok(Self {
            handle: session.handle,
            did: session.did,
            access_jwt: session.access_jwt,
            refresh_jwt: session.refresh_jwt,
            pds_url,
        })
    }

    /// Persist auth credentials to the session store.
    pub async fn save(&self, db: &Database) -> Result<()> {
        db.store_session_value("auth_method", "app_password")
            .await?;
        db.store_session_value("handle", &self.handle).await?;
        db.store_session_value("did", &self.did).await?;
        db.store_session_value("access_jwt", &self.access_jwt)
            .await?;
        db.store_session_value("refresh_jwt", &self.refresh_jwt)
            .await?;
        db.store_session_value("pds_url", &self.pds_url).await?;
        Ok(())
    }

    /// Load previously-saved app password auth from the session store.
    pub async fn load(db: &Database) -> Result<Option<Self>> {
        let method = db.get_session_value("auth_method").await?;
        if method.as_deref() != Some("app_password") {
            return Ok(None);
        }

        let handle = db.get_session_value("handle").await?;
        let did = db.get_session_value("did").await?;
        let access_jwt = db.get_session_value("access_jwt").await?;
        let refresh_jwt = db.get_session_value("refresh_jwt").await?;
        let pds_url = db.get_session_value("pds_url").await?;

        match (handle, did, access_jwt, refresh_jwt, pds_url) {
            (Some(handle), Some(did), Some(access_jwt), Some(refresh_jwt), Some(pds_url)) => {
                Ok(Some(Self {
                    handle,
                    did,
                    access_jwt,
                    refresh_jwt,
                    pds_url,
                }))
            }
            _ => Ok(None),
        }
    }
}

/// Resolve the PDS URL for a given handle.
///
/// 1. GET `https://{handle}/.well-known/atproto-did` → DID string
/// 2. GET `https://plc.directory/{did}` → PLC document with service endpoints
/// 3. Extract the `atproto_pds` service endpoint
async fn resolve_pds(client: &reqwest::Client, handle: &str) -> Result<String> {
    // Fetch DID from .well-known
    let did_url = format!("https://{handle}/.well-known/atproto-did");
    let did = client
        .get(&did_url)
        .send()
        .await
        .map_err(|e| CatmosError::Network(e.to_string()))?
        .text()
        .await
        .map_err(|e| CatmosError::Network(e.to_string()))?
        .trim()
        .to_string();

    if !did.starts_with("did:") {
        return Err(CatmosError::AuthFailed(format!(
            "invalid DID from .well-known: {did}"
        )));
    }

    // Resolve DID via PLC directory
    let plc_url = format!("https://plc.directory/{did}");
    let doc: PlcDocument = client
        .get(&plc_url)
        .send()
        .await
        .map_err(|e| CatmosError::Network(e.to_string()))?
        .json()
        .await
        .map_err(|e| CatmosError::Network(e.to_string()))?;

    // Find the PDS service endpoint
    for svc in &doc.service {
        if svc.id.contains("atproto_pds") || svc.id.ends_with("#atproto_pds") {
            return Ok(svc.service_endpoint.trim_end_matches('/').to_string());
        }
    }

    Err(CatmosError::AuthFailed(format!(
        "no atproto_pds service found in PLC document for {did}"
    )))
}
