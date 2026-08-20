//! Bluesky block record (`app.bsky.graph.block`) helpers.
//!
//! Minimal bridge to `com.atproto.repo.*` endpoints on the user's PDS so the
//! CLI can create, delete, and list the authenticated user's own block records.
//! Used by the `catmos block add|remove|list` subcommands and by startup
//! reconciliation to auto-leave MLS groups containing blocked users.
//!
//! Routing:
//! - OAuth sessions go through nest (`nest_url`), which already understands
//!   `com.atproto.repo.createRecord` / `deleteRecord` and will signal the
//!   moderation cache on the server side.
//! - AppPassword sessions go directly to the user's PDS (`pds_url`).

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use serde::Deserialize;

use crate::auth::AuthMethod;
use crate::error::{CatmosError, Result};

use super::service::ChatService;

const BLOCK_COLLECTION: &str = "app.bsky.graph.block";

#[derive(Debug, Deserialize)]
struct CreateRecordResp {
    uri: String,
    #[allow(dead_code)]
    #[serde(default)]
    cid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListRecordsResp {
    #[serde(default)]
    records: Vec<ListRecordEntry>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListRecordEntry {
    uri: String,
    #[serde(default)]
    value: serde_json::Value,
}

impl ChatService {
    /// Base URL for `com.atproto.repo.*` calls (user's PDS for AppPassword,
    /// nest proxy for OAuth).
    fn atproto_repo_base(&self) -> Result<String> {
        match &self.auth {
            AuthMethod::OAuth { nest_url, .. } => Ok(nest_url.trim_end_matches('/').to_string()),
            AuthMethod::AppPassword { pds_url, .. } => {
                Ok(pds_url.trim_end_matches('/').to_string())
            }
        }
    }

    fn bearer_headers(&self, bearer: &str) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| CatmosError::AuthFailed(e.to_string()))?,
        );
        Ok(headers)
    }

    /// Publish an `app.bsky.graph.block` record for `subject_did`.
    ///
    /// Returns the AT-URI of the created record. Callers should verify there
    /// isn't already a block via `list_own_blocks` if they want dedup.
    pub async fn create_block(&self, subject_did: &str) -> Result<String> {
        let base = self.atproto_repo_base()?;
        let url = format!("{base}/xrpc/com.atproto.repo.createRecord");
        let body = serde_json::json!({
            "repo": self.did(),
            "collection": BLOCK_COLLECTION,
            "record": {
                "$type": BLOCK_COLLECTION,
                "subject": subject_did,
                "createdAt": chrono::Utc::now().to_rfc3339(),
            }
        });

        let bearer = self.current_bearer().await?;
        let headers = self.bearer_headers(&bearer)?;
        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let body_bytes = if self.should_retry_after_refresh(status, &body_bytes) {
            let new_bearer = self.refresh_bearer().await?;
            let headers = self.bearer_headers(&new_bearer)?;
            let retry_resp = self
                .http
                .post(&url)
                .headers(headers)
                .json(&body)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            let retry_status = retry_resp.status();
            let retry_bytes = retry_resp
                .bytes()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            if !retry_status.is_success() {
                let err_body = String::from_utf8_lossy(&retry_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "createRecord({BLOCK_COLLECTION}) returned {retry_status}: {err_body}"
                )));
            }
            retry_bytes
        } else {
            if !status.is_success() {
                let err_body = String::from_utf8_lossy(&body_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "createRecord({BLOCK_COLLECTION}) returned {status}: {err_body}"
                )));
            }
            body_bytes
        };

        let parsed: CreateRecordResp = serde_json::from_slice(&body_bytes)
            .map_err(|e| CatmosError::Xrpc(format!("createRecord parse: {e}")))?;
        Ok(parsed.uri)
    }

    /// Delete all `app.bsky.graph.block` records whose subject is `subject_did`.
    ///
    /// Returns the number of records deleted. The ATProto data model allows
    /// multiple block records per subject (one per rkey), so we iterate.
    pub async fn remove_block(&self, subject_did: &str) -> Result<usize> {
        let records = self.list_block_records().await?;
        let matches: Vec<String> = records
            .into_iter()
            .filter_map(|(rkey, subject)| (subject == subject_did).then_some(rkey))
            .collect();

        if matches.is_empty() {
            return Ok(0);
        }

        let mut deleted = 0usize;
        for rkey in &matches {
            if let Err(e) = self.delete_block_record(rkey).await {
                tracing::warn!("delete block rkey={rkey} failed: {e}");
            } else {
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    /// List the subject DIDs of all block records authored by this account.
    pub async fn list_own_blocks(&self) -> Result<Vec<String>> {
        Ok(self
            .list_block_records()
            .await?
            .into_iter()
            .map(|(_rkey, subject)| subject)
            .collect())
    }

    /// Internal: return (rkey, subject_did) for every block record.
    async fn list_block_records(&self) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = self.list_block_records_page(cursor.as_deref()).await?;
            for entry in page.records {
                let rkey = entry
                    .uri
                    .rsplit('/')
                    .next()
                    .unwrap_or(&entry.uri)
                    .to_string();
                let subject = entry
                    .value
                    .get("subject")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                if let Some(subject) = subject {
                    out.push((rkey, subject));
                }
            }
            match page.cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(out)
    }

    async fn list_block_records_page(&self, cursor: Option<&str>) -> Result<ListRecordsResp> {
        let base = self.atproto_repo_base()?;
        let url = format!("{base}/xrpc/com.atproto.repo.listRecords");
        let did = self.did().to_string();
        let limit = "100".to_string();

        let mut params: Vec<(&str, &str)> = vec![
            ("repo", did.as_str()),
            ("collection", BLOCK_COLLECTION),
            ("limit", limit.as_str()),
        ];
        if let Some(c) = cursor {
            params.push(("cursor", c));
        }

        let bearer = self.current_bearer().await?;
        let headers = self.bearer_headers(&bearer)?;
        let resp = self
            .http
            .get(&url)
            .headers(headers)
            .query(&params)
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let body_bytes = if self.should_retry_after_refresh(status, &body_bytes) {
            let new_bearer = self.refresh_bearer().await?;
            let headers = self.bearer_headers(&new_bearer)?;
            let retry_resp = self
                .http
                .get(&url)
                .headers(headers)
                .query(&params)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            let retry_status = retry_resp.status();
            let retry_bytes = retry_resp
                .bytes()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            if !retry_status.is_success() {
                let err_body = String::from_utf8_lossy(&retry_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "listRecords({BLOCK_COLLECTION}) returned {retry_status}: {err_body}"
                )));
            }
            retry_bytes
        } else {
            if !status.is_success() {
                let err_body = String::from_utf8_lossy(&body_bytes);
                return Err(CatmosError::Xrpc(format!(
                    "listRecords({BLOCK_COLLECTION}) returned {status}: {err_body}"
                )));
            }
            body_bytes
        };

        let parsed = serde_json::from_slice::<ListRecordsResp>(&body_bytes)
            .map_err(|e| CatmosError::Xrpc(format!("listRecords parse: {e}")))?;
        Ok(parsed)
    }

    async fn delete_block_record(&self, rkey: &str) -> Result<()> {
        let base = self.atproto_repo_base()?;
        let url = format!("{base}/xrpc/com.atproto.repo.deleteRecord");
        let body = serde_json::json!({
            "repo": self.did(),
            "collection": BLOCK_COLLECTION,
            "rkey": rkey,
        });

        let bearer = self.current_bearer().await?;
        let headers = self.bearer_headers(&bearer)?;
        let resp = self
            .http
            .post(&url)
            .headers(headers)
            .json(&body)
            .send()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        let status = resp.status();
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|e| CatmosError::Network(e.to_string()))?;

        if self.should_retry_after_refresh(status, &body_bytes) {
            let new_bearer = self.refresh_bearer().await?;
            let headers = self.bearer_headers(&new_bearer)?;
            let retry_resp = self
                .http
                .post(&url)
                .headers(headers)
                .json(&body)
                .send()
                .await
                .map_err(|e| CatmosError::Network(e.to_string()))?;
            let retry_status = retry_resp.status();
            if !retry_status.is_success() {
                let err_body = retry_resp.text().await.unwrap_or_default();
                return Err(CatmosError::Xrpc(format!(
                    "deleteRecord({BLOCK_COLLECTION}) returned {retry_status}: {err_body}"
                )));
            }
        } else if !status.is_success() {
            let err_body = String::from_utf8_lossy(&body_bytes);
            return Err(CatmosError::Xrpc(format!(
                "deleteRecord({BLOCK_COLLECTION}) returned {status}: {err_body}"
            )));
        }
        Ok(())
    }
}
