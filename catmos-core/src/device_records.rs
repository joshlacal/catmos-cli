//! Repository-rooted MLS device authorization (ADR-009). Public reads never
//! carry the caller's credentials or use the delivery service as DID authority.

use std::collections::HashSet;
use std::time::Duration;

use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine,
};
use catbird_mls::chat_v2::ids::BareDid;
use reqwest::{Client, Response, StatusCode};
use serde_json::Value;
use url::Url;

use crate::error::{CatmosError, Result};

pub(crate) const COLLECTION: &str = "blue.catbird.chat.device";
pub(crate) const CHAT_DECLARATION_COLLECTION: &str = "blue.catbird.chat.declaration";
pub(crate) const DECLARATION_RKEY: &str = "self";
const MAX_PAGES: usize = 20;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

fn invalid(detail: &str) -> CatmosError {
    CatmosError::Other(format!("Could not verify repository device keys: {detail}"))
}

pub(crate) fn public_client() -> Result<Client> {
    crate::http_client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|_| invalid("HTTP client initialization failed"))
}

pub(crate) async fn response_bytes(mut response: Response) -> Result<Vec<u8>> {
    if response.status().is_redirection() {
        return Err(invalid("redirect response rejected"));
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BYTES as u64)
    {
        return Err(invalid("response exceeds the size limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| invalid("response read failed"))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(invalid("response exceeds the size limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) async fn response_json(response: Response) -> Result<Value> {
    let body = response_bytes(response).await?;
    serde_json::from_slice(&body).map_err(|_| invalid("invalid JSON response"))
}

pub(crate) fn https_base(endpoint: &str) -> Result<Url> {
    let url = Url::parse(endpoint).map_err(|_| invalid("invalid PDS endpoint"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "PDS endpoint must be HTTPS without credentials, query, or fragment",
        ));
    }
    Ok(url)
}

pub(crate) fn xrpc_url(base: &Url, method: &str) -> Url {
    let mut url = base.clone();
    url.set_path(&format!(
        "{}/xrpc/{method}",
        base.path().trim_end_matches('/')
    ));
    url
}

pub(crate) fn did_document_url(did: &str) -> Result<Url> {
    BareDid::parse(did).map_err(|_| invalid("invalid bare DID"))?;
    let url = if let Some(host) = did.strip_prefix("did:web:") {
        format!("https://{host}/.well-known/did.json")
    } else {
        format!("https://plc.directory/{did}")
    };
    Url::parse(&url).map_err(|_| invalid("invalid DID document URL"))
}

pub(crate) fn pds_from_document(did: &str, document: &Value) -> Result<Url> {
    if document.get("id").and_then(Value::as_str) != Some(did) {
        return Err(invalid("DID document identity does not match"));
    }
    let services = document
        .get("service")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("DID document has no PDS services"))?;
    let mut found = None;
    for service in services {
        if service.get("type").and_then(Value::as_str) != Some("AtprotoPersonalDataServer") {
            continue;
        }
        let full_id = format!("{did}#atproto_pds");
        let id = service.get("id").and_then(Value::as_str);
        if id != Some("#atproto_pds") && id != Some(full_id.as_str()) {
            return Err(invalid("PDS service identity does not match"));
        }
        let endpoint = service
            .get("serviceEndpoint")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("PDS service has no endpoint"))?;
        if found.replace(https_base(endpoint)?).is_some() {
            return Err(invalid("DID document has ambiguous PDS services"));
        }
    }
    found.ok_or_else(|| invalid("DID document has no authoritative PDS"))
}

pub(crate) async fn resolve_pds(client: &Client, did: &str) -> Result<Url> {
    let response = client
        .get(did_document_url(did)?)
        .send()
        .await
        .map_err(|_| invalid("DID resolution failed; please retry"))?;
    if !response.status().is_success() {
        return Err(invalid(&format!(
            "DID resolution returned {}",
            response.status()
        )));
    }
    pds_from_document(did, &response_json(response).await?)
}

#[derive(Debug)]
pub(crate) struct DeviceRecord {
    pub(crate) uri: String,
    pub(crate) key: Vec<u8>,
}

pub(crate) fn parse_record(did: &str, record: &Value) -> Result<DeviceRecord> {
    let uri = record
        .get("uri")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("record has no URI"))?;
    let prefix = format!("at://{did}/{COLLECTION}/");
    let rkey = uri
        .strip_prefix(&prefix)
        .ok_or_else(|| invalid("record belongs to another repository or collection"))?;
    if rkey.is_empty()
        || rkey.len() > 512
        || rkey == "."
        || rkey == ".."
        || !rkey
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._~:-".contains(&c))
    {
        return Err(invalid("record has an invalid record key"));
    }
    let value = record
        .get("value")
        .ok_or_else(|| invalid("record has no value"))?;
    if value.get("$type").and_then(Value::as_str) != Some(COLLECTION)
        || !value
            .get("algorithm")
            .and_then(Value::as_str)
            .is_some_and(|algorithm| algorithm.eq_ignore_ascii_case("ed25519"))
    {
        return Err(invalid(
            "record has an unsupported type or signature algorithm",
        ));
    }
    let date = value
        .get("createdAt")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("record has no creation date"))?;
    chrono::DateTime::parse_from_rfc3339(date)
        .map_err(|_| invalid("record has an invalid creation date"))?;
    let bytes = value
        .get("mlsSignaturePublicKey")
        .and_then(Value::as_object)
        .filter(|object| object.len() == 1)
        .and_then(|object| object.get("$bytes"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("record has no encoded signature public key"))?;
    let key = STANDARD
        .decode(bytes)
        .or_else(|_| STANDARD_NO_PAD.decode(bytes))
        .map_err(|_| invalid("record has an invalid signature public key encoding"))?;
    if key.len() != 32 {
        return Err(invalid("record signature public key must contain 32 bytes"));
    }
    Ok(DeviceRecord {
        uri: uri.to_string(),
        key,
    })
}

pub(crate) async fn read_records(
    client: &Client,
    pds: &Url,
    did: &str,
) -> Result<Vec<DeviceRecord>> {
    BareDid::parse(did).map_err(|_| invalid("invalid bare DID"))?;
    let mut cursor: Option<String> = None;
    let mut seen_cursors = HashSet::new();
    let mut seen_uris = HashSet::new();
    let mut records = Vec::new();
    for _ in 0..MAX_PAGES {
        let mut url = xrpc_url(pds, "com.atproto.repo.listRecords");
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("repo", did)
                .append_pair("collection", COLLECTION)
                .append_pair("limit", "100");
            if let Some(cursor) = &cursor {
                query.append_pair("cursor", cursor);
            }
        }
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|_| invalid("PDS read failed; please retry"))?;
        if !response.status().is_success() {
            return Err(invalid(&format!("PDS returned {}", response.status())));
        }
        let page = response_json(response).await?;
        let values = page
            .get("records")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("PDS omitted its records array"))?;
        if values.len() > 100 {
            return Err(invalid("PDS exceeded the requested page size"));
        }
        for value in values {
            let record = parse_record(did, value)?;
            if !seen_uris.insert(record.uri.clone()) {
                return Err(invalid("PDS repeated a record"));
            }
            records.push(record);
        }
        cursor = match page.get("cursor") {
            None | Some(Value::Null) => return Ok(records),
            Some(Value::String(value)) if !value.is_empty() && value.len() <= 2048 => {
                Some(value.clone())
            }
            _ => return Err(invalid("PDS returned an invalid cursor")),
        };
        if !seen_cursors.insert(cursor.clone().unwrap()) {
            return Err(invalid("PDS pagination did not advance"));
        }
    }
    Err(invalid("PDS device inventory exceeded the page limit"))
}

pub(crate) async fn authorized_keys(did: &str) -> Result<Vec<Vec<u8>>> {
    let client = public_client()?;
    let pds = resolve_pds(&client, did).await?;
    let mut keys: Vec<Vec<u8>> = read_records(&client, &pds, did)
        .await?
        .into_iter()
        .map(|record| record.key)
        .collect();
    keys.sort();
    keys.dedup();
    Ok(keys)
}

pub(crate) fn parse_chat_declaration(did: &str, record_value: &Value) -> Result<String> {
    let expected_uri = format!("at://{did}/{CHAT_DECLARATION_COLLECTION}/{DECLARATION_RKEY}");
    if record_value.get("uri").and_then(Value::as_str) != Some(&expected_uri) {
        return Err(invalid("declaration record URI does not match expected identity"));
    }
    let record = record_value
        .get("value")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("declaration record has no value"))?;
    if let Some(record_type) = record.get("$type").and_then(Value::as_str) {
        if record_type != CHAT_DECLARATION_COLLECTION {
            return Err(invalid("declaration record has an unsupported type"));
        }
    }
    let delivery_service = record
        .get("deliveryService")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("declaration record has no deliveryService"))?;
    BareDid::parse(delivery_service)
        .map_err(|_| invalid("declaration deliveryService is not a valid bare DID"))?;
    Ok(delivery_service.to_owned())
}

pub(crate) async fn read_chat_declaration(
    client: &Client,
    pds: &Url,
    did: &str,
) -> Result<Option<String>> {
    BareDid::parse(did).map_err(|_| invalid("invalid bare DID"))?;
    let mut url = xrpc_url(pds, "com.atproto.repo.getRecord");
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("repo", did)
            .append_pair("collection", CHAT_DECLARATION_COLLECTION)
            .append_pair("rkey", DECLARATION_RKEY);
    }
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| invalid("PDS read failed; please retry"))?;
    if response.status().is_redirection() {
        return Err(invalid("PDS redirected declaration getRecord request"));
    }
    let status = response.status();
    let bytes = response_bytes(response).await?;
    if status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND {
        let error_body: Value = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid error JSON from PDS"))?;
        if error_body.get("error").and_then(Value::as_str) == Some("RecordNotFound") {
            return Ok(None);
        }
        return Err(invalid(&format!(
            "PDS returned error: {:?}",
            error_body.get("error")
        )));
    }
    if !status.is_success() {
        return Err(invalid(&format!("PDS returned status {}", status)));
    }
    let record = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("invalid declaration JSON response"))?;
    parse_chat_declaration(did, &record).map(Some)
}

pub(crate) async fn chat_declaration_authority(did: &str) -> Result<Option<String>> {
    let client = public_client()?;
    let pds = resolve_pds(&client, did).await?;
    read_chat_declaration(&client, &pds, did).await
}

pub(crate) async fn receipt_authority_document(expected_did: &str) -> Result<Vec<u8>> {
    BareDid::parse(expected_did).map_err(|_| invalid("invalid bare DID"))?;
    let client = public_client()?;
    let url = did_document_url(expected_did)?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|_| invalid("authority DID resolution failed; please retry"))?;
    if response.status().is_redirection() {
        return Err(invalid("authority DID resolution redirected"));
    }
    if !response.status().is_success() {
        return Err(invalid(&format!(
            "authority DID resolution returned {}",
            response.status()
        )));
    }
    let bytes = response_bytes(response).await?;
    let doc: Value = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("invalid authority DID document JSON"))?;
    if doc.get("id").and_then(Value::as_str) != Some(expected_did) {
        return Err(invalid("authority DID document identity does not match"));
    }
    Ok(bytes)
}

/// Publish only an absent UUID record. A concurrent writer or a lost write ACK
/// is reconciled through a fresh authoritative read, never an unconditional put.
pub(crate) async fn ensure_published<F, Fut>(
    client: &Client,
    pds: &Url,
    did: &str,
    device: &str,
    key: &[u8],
    send: F,
) -> Result<()>
where
    F: FnOnce(Value) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    catbird_mls::chat_v2::ids::DeviceId::parse(device)
        .map_err(|_| invalid("local device ID is invalid"))?;
    if key.len() != 32 {
        return Err(invalid("local signature key must contain 32 bytes"));
    }
    let uri = format!("at://{did}/{COLLECTION}/{device}");
    let check = |records: &[DeviceRecord]| -> Result<bool> {
        match records.iter().find(|record| record.uri == uri) {
            Some(record) if record.key == key => Ok(true),
            Some(_) => Err(invalid("this device's record contains another key; existing keys and records were preserved")),
            None => Ok(false),
        }
    };
    if check(&read_records(client, pds, did).await?)? {
        return Ok(());
    }
    let result = send(serde_json::json!({
        "repo": did, "collection": COLLECTION, "rkey": device, "swapRecord": null,
        "record": {
            "$type": COLLECTION, "algorithm": "ed25519",
            "mlsSignaturePublicKey": {"$bytes": STANDARD.encode(key)},
            "createdAt": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        },
    }))
    .await;
    if check(&read_records(client, pds, did).await?)? {
        return Ok(());
    }
    result?;
    Err(invalid(
        "published device key is not yet visible at the authoritative PDS; please retry",
    ))
}

#[cfg(test)]
mod tests;
