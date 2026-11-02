//! Unified `CatbirdMlsClient` + Labyrinth 1.1 adapter for `catmos-cli` (`Spec §6.3`, `G2`, `D4`, `I8`, `I15`, `I16`, `ctl #2`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use catbird_mls::client::{
    account_did_hash_hex, normalize_account_did, CatbirdMlsClient, CatbirdMlsClientConfig,
    EnrollmentReceipt, LabyrinthBackupStatus, OtcPairingCompletion, OtcPairingOffer,
    PlatformChangeEvent, PlatformChangeObserver, PlatformHttpHeader, PlatformHttpRequest,
    PlatformHttpResponse, PlatformKeyStore, PlatformTransport, REQUIRED_LABYRINTH_OAUTH_SCOPES,
};
use catbird_mls::MLSError;
use rand::Rng as _;

const CLI_KEYRING_SERVICE: &str = "blue.catbird.catmos-cli.clean-slate";

pub struct CliPlatformKeyStore {
    use_os_keyring: bool,
    memory: Mutex<HashMap<String, Vec<u8>>>,
    dpop: Mutex<HashMap<String, (String, i64)>>,
}

impl CliPlatformKeyStore {
    pub fn new_os_keyring() -> Self {
        Self {
            use_os_keyring: true,
            memory: Mutex::new(HashMap::new()),
            dpop: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_in_memory() -> Self {
        Self {
            use_os_keyring: false,
            memory: Mutex::new(HashMap::new()),
            dpop: Mutex::new(HashMap::new()),
        }
    }

    fn read_secret(&self, label: &str) -> Result<Option<Vec<u8>>, MLSError> {
        if self.use_os_keyring {
            if let Ok(entry) = crate::native_keyring::entry(CLI_KEYRING_SERVICE, label) {
                match entry.get_password() {
                    Ok(b64) => {
                        let bytes = BASE64_STANDARD.decode(b64.trim()).map_err(|e| {
                            MLSError::Internal(format!("decode keyring `{label}`: {e}"))
                        })?;
                        return Ok(Some(bytes));
                    }
                    Err(keyring::Error::NoEntry) => return Ok(None),
                    Err(_) => {}
                }
            }
        }
        let guard = self
            .memory
            .lock()
            .map_err(|_| MLSError::Internal("keystore mutex poisoned".to_string()))?;
        Ok(guard.get(label).cloned())
    }

    fn write_secret(&self, label: &str, bytes: &[u8]) -> Result<(), MLSError> {
        if self.use_os_keyring {
            if let Ok(entry) = crate::native_keyring::entry(CLI_KEYRING_SERVICE, label) {
                let encoded = BASE64_STANDARD.encode(bytes);
                if entry.set_password(&encoded).is_ok() {
                    return Ok(());
                }
            }
        }
        let mut guard = self
            .memory
            .lock()
            .map_err(|_| MLSError::Internal("keystore mutex poisoned".to_string()))?;
        guard.insert(label.to_string(), bytes.to_vec());
        Ok(())
    }

    fn delete_secret(&self, label: &str) {
        if self.use_os_keyring {
            if let Ok(entry) = crate::native_keyring::entry(CLI_KEYRING_SERVICE, label) {
                let _ = entry.delete_credential();
            }
        }
        if let Ok(mut guard) = self.memory.lock() {
            guard.remove(label);
        }
    }
}

impl PlatformKeyStore for CliPlatformKeyStore {
    fn load_or_create_db_key(&self, account_did_hash: String) -> Result<Vec<u8>, MLSError> {
        let label = format!("db-key:{account_did_hash}");
        if let Some(existing) = self.read_secret(&label)? {
            if existing.len() == 32 {
                return Ok(existing);
            }
        }
        let mut fresh = vec![0u8; 32];
        rand::rng().fill_bytes(&mut fresh);
        self.write_secret(&label, &fresh)?;
        Ok(fresh)
    }

    fn load_signature_keypair(&self, key_id: String) -> Result<Option<Vec<u8>>, MLSError> {
        self.read_secret(&format!("sig:{key_id}"))
    }

    fn store_signature_keypair(
        &self,
        key_id: String,
        keypair_bytes: Vec<u8>,
    ) -> Result<(), MLSError> {
        self.write_secret(&format!("sig:{key_id}"), &keypair_bytes)
    }

    fn delete_account_keys(&self, account_did_hash: String) -> Result<(), MLSError> {
        self.delete_secret(&format!("db-key:{account_did_hash}"));
        self.delete_secret(&format!("sig:mls-signer:{account_did_hash}"));
        if let Ok(mut guard) = self.dpop.lock() {
            guard.remove(&account_did_hash);
        }
        Ok(())
    }

    fn load_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
    ) -> Result<Option<String>, MLSError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let guard = self
            .dpop
            .lock()
            .map_err(|_| MLSError::Internal("dpop mutex poisoned".to_string()))?;
        Ok(guard.get(&account_did_hash).and_then(|(tok, exp)| {
            if *exp > now_ms {
                Some(tok.clone())
            } else {
                None
            }
        }))
    }

    fn store_cached_chat_dpop_token(
        &self,
        account_did_hash: String,
        token: String,
        expires_at_ms: i64,
    ) -> Result<(), MLSError> {
        let mut guard = self
            .dpop
            .lock()
            .map_err(|_| MLSError::Internal("dpop mutex poisoned".to_string()))?;
        guard.insert(account_did_hash, (token, expires_at_ms));
        Ok(())
    }
}

type SpaceRecordKey = (String, String, String);

fn origin_key(url_str: &str) -> Option<(String, String, Option<u16>)> {
    let parsed = reqwest::Url::parse(url_str).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some((
        parsed.scheme().to_ascii_lowercase(),
        host,
        parsed.port_or_known_default(),
    ))
}

fn extract_xrpc_nsid(url_str: &str) -> Option<String> {
    let path_part = url_str.split('?').next().unwrap_or(url_str);
    let (_, nsid) = path_part.rsplit_once("/xrpc/")?;
    let trimmed = nsid.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub struct CliPlatformTransport {
    http: reqwest::Client,
    bearer_token: RwLock<Option<String>>,
    pds_endpoint: RwLock<String>,
    home_ds_endpoint: RwLock<String>,
    home_ds_did: RwLock<String>,
    offline_spaces_probe_override: Option<bool>,
    mock_space_store: Option<Mutex<std::collections::BTreeMap<SpaceRecordKey, serde_json::Value>>>,
}

fn decode_query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            return Some(percent_decode_str(v));
        }
    }
    None
}

fn percent_decode_str(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

impl CliPlatformTransport {
    pub fn new(offline_spaces_probe_override: Option<bool>) -> Self {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let mock_space_store =
            offline_spaces_probe_override.map(|_| Mutex::new(std::collections::BTreeMap::new()));
        Self {
            http,
            bearer_token: RwLock::new(None),
            pds_endpoint: RwLock::new("https://swan.place".to_string()),
            home_ds_endpoint: RwLock::new("https://chat.catbird.blue".to_string()),
            home_ds_did: RwLock::new("did:web:chat.catbird.blue".to_string()),
            offline_spaces_probe_override,
            mock_space_store,
        }
    }

    pub fn configure_endpoints(
        &self,
        pds_endpoint: &str,
        home_ds_endpoint: &str,
        home_ds_did: &str,
    ) {
        if let Ok(mut g) = self.pds_endpoint.write() {
            *g = pds_endpoint.trim_end_matches('/').to_string();
        }
        if let Ok(mut g) = self.home_ds_endpoint.write() {
            *g = home_ds_endpoint.trim_end_matches('/').to_string();
        }
        if let Ok(mut g) = self.home_ds_did.write() {
            *g = home_ds_did
                .split('#')
                .next()
                .unwrap_or(home_ds_did)
                .to_string();
        }
    }

    pub fn set_bearer_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.bearer_token.write() {
            *guard = token;
        }
    }

    fn execute_mock_http(
        &self,
        supports_spaces: bool,
        store_mutex: &Mutex<std::collections::BTreeMap<SpaceRecordKey, serde_json::Value>>,
        request: PlatformHttpRequest,
    ) -> Result<PlatformHttpResponse, MLSError> {
        let (path, query) = request
            .url
            .split_once('?')
            .map_or((request.url.as_str(), ""), |(p, q)| (p, q));

        if path.ends_with("/xrpc/com.atproto.space.getSpace") {
            return Ok(PlatformHttpResponse {
                status: if supports_spaces { 401 } else { 501 },
                headers: Vec::new(),
                body: if supports_spaces {
                    b"{\"error\":\"AuthMissing\"}".to_vec()
                } else {
                    b"{\"error\":\"XRPCNotSupported\"}".to_vec()
                },
            });
        }

        if !supports_spaces && path.contains("/xrpc/com.atproto.space.") {
            return Ok(PlatformHttpResponse {
                status: 501,
                headers: Vec::new(),
                body: b"{\"error\":\"XRPCNotSupported\"}".to_vec(),
            });
        }

        let mut store = store_mutex
            .lock()
            .map_err(|_| MLSError::Internal("mock space store mutex poisoned".to_string()))?;

        if path.ends_with("/xrpc/com.atproto.space.applyWrites") {
            let parsed: serde_json::Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}"))
                    .map_err(|e| MLSError::Internal(format!("parse mock applyWrites: {e}")))?;
            let space = parsed
                .get("space")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if let Some(writes) = parsed.get("writes").and_then(|v| v.as_array()) {
                for w in writes {
                    let op = w.get("$type").and_then(|v| v.as_str()).unwrap_or_default();
                    let col = w
                        .get("collection")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let rkey = w
                        .get("rkey")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if op.ends_with("#delete") {
                        store.remove(&(space.clone(), col, rkey));
                    } else if let Some(val) = w.get("value") {
                        store.insert((space.clone(), col, rkey), val.clone());
                    }
                }
            }
            return Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"{\"results\":[]}".to_vec(),
            });
        }

        if path.ends_with("/xrpc/com.atproto.space.putRecord")
            || path.ends_with("/xrpc/com.atproto.space.createRecord")
        {
            let parsed: serde_json::Value =
                serde_json::from_slice(request.body.as_deref().unwrap_or(b"{}"))
                    .map_err(|e| MLSError::Internal(format!("parse mock putRecord: {e}")))?;
            let space = parsed
                .get("space")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let col = parsed
                .get("collection")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let rkey = parsed
                .get("rkey")
                .and_then(|v| v.as_str())
                .unwrap_or("self")
                .to_string();
            if let Some(val) = parsed.get("record") {
                store.insert((space.clone(), col.clone(), rkey.clone()), val.clone());
            }
            let body = serde_json::to_vec(&serde_json::json!({
                "uri": format!("{space}/{col}/{rkey}"),
            }))
            .unwrap_or_else(|_| b"{}".to_vec());
            return Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body,
            });
        }

        if path.ends_with("/xrpc/com.atproto.space.listRecords") {
            let space = decode_query_param(query, "space").unwrap_or_default();
            let col = decode_query_param(query, "collection").unwrap_or_default();
            let records: Vec<serde_json::Value> = store
                .iter()
                .filter(|((s, c, _), _)| s == &space && c == &col)
                .map(|((s, c, r), val)| {
                    serde_json::json!({
                        "uri": format!("{s}/{c}/{r}"),
                        "value": val,
                    })
                })
                .collect();
            let body = serde_json::to_vec(&serde_json::json!({ "records": records }))
                .map_err(|e| MLSError::Internal(format!("serialize mock listRecords: {e}")))?;
            return Ok(PlatformHttpResponse {
                status: 200,
                headers: Vec::new(),
                body,
            });
        }

        if path.ends_with("/xrpc/com.atproto.space.getRecord") {
            let space = decode_query_param(query, "space").unwrap_or_default();
            let col = decode_query_param(query, "collection").unwrap_or_default();
            let rkey = decode_query_param(query, "rkey").unwrap_or_default();
            if let Some(val) = store.get(&(space.clone(), col.clone(), rkey.clone())) {
                let body = serde_json::to_vec(&serde_json::json!({
                    "uri": format!("{space}/{col}/{rkey}"),
                    "value": val,
                }))
                .map_err(|e| MLSError::Internal(format!("serialize mock getRecord: {e}")))?;
                return Ok(PlatformHttpResponse {
                    status: 200,
                    headers: Vec::new(),
                    body,
                });
            }
            return Ok(PlatformHttpResponse {
                status: 404,
                headers: Vec::new(),
                body: b"{\"error\":\"RecordNotFound\"}".to_vec(),
            });
        }

        Ok(PlatformHttpResponse {
            status: 200,
            headers: Vec::new(),
            body: b"{}".to_vec(),
        })
    }
}

impl PlatformTransport for CliPlatformTransport {
    fn execute_http(&self, request: PlatformHttpRequest) -> Result<PlatformHttpResponse, MLSError> {
        if let (Some(supports), Some(ref store_mutex)) =
            (self.offline_spaces_probe_override, &self.mock_space_store)
        {
            return self.execute_mock_http(supports, store_mutex, request);
        }

        let http = self.http.clone();
        let bearer = self.bearer_token.read().ok().and_then(|g| g.clone());
        let pds_endpoint = self
            .pds_endpoint
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "https://swan.place".to_string());
        let home_ds_endpoint = self
            .home_ds_endpoint
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "https://chat.catbird.blue".to_string());
        let home_ds_did = self
            .home_ds_did
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "did:web:chat.catbird.blue".to_string());

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| MLSError::Internal(format!("build runtime: {e}")))?;
            rt.block_on(async move {
                let method = reqwest::Method::from_bytes(request.method.as_bytes())
                    .map_err(|e| MLSError::invalid_input(format!("invalid HTTP method: {e}")))?;
                let mut builder = http.request(method, &request.url);
                let mut has_auth = false;
                for h in &request.headers {
                    if h.name.eq_ignore_ascii_case("authorization") {
                        has_auth = true;
                    }
                    builder = builder.header(&h.name, &h.value);
                }
                if !has_auth {
                    if let Some(tok) = bearer {
                        let req_origin = origin_key(&request.url);
                        if req_origin.is_some() && req_origin == origin_key(&pds_endpoint) {
                            builder = builder.bearer_auth(tok);
                        } else if req_origin.is_some()
                            && req_origin == origin_key(&home_ds_endpoint)
                        {
                            if let Some(nsid) = extract_xrpc_nsid(&request.url)
                                .filter(|n| n.starts_with("blue.catbird.chat."))
                            {
                                let sa_url = format!(
                                    "{}/xrpc/com.atproto.server.getServiceAuth",
                                    pds_endpoint.trim_end_matches('/')
                                );
                                let sa_resp = http
                                    .get(&sa_url)
                                    .query(&[("aud", home_ds_did.as_str()), ("lxm", nsid.as_str())])
                                    .bearer_auth(&tok)
                                    .send()
                                    .await
                                    .map_err(|e| {
                                        MLSError::Internal(format!(
                                            "mint getServiceAuth `{nsid}` failed: {e}"
                                        ))
                                    })?;
                                if !sa_resp.status().is_success() {
                                    let status = sa_resp.status().as_u16();
                                    let text = sa_resp.text().await.unwrap_or_default();
                                    return Err(MLSError::Internal(format!(
                                        "getServiceAuth `{nsid}` returned HTTP {status}: {text}"
                                    )));
                                }
                                let sa_json: serde_json::Value =
                                    sa_resp.json().await.map_err(|e| {
                                        MLSError::Internal(format!(
                                            "decode getServiceAuth `{nsid}` JSON: {e}"
                                        ))
                                    })?;
                                let service_jwt = sa_json
                                    .get("token")
                                    .and_then(|v| v.as_str())
                                    .ok_or_else(|| {
                                        MLSError::Internal(format!(
                                            "getServiceAuth `{nsid}` response missing token"
                                        ))
                                    })?;
                                builder = builder.bearer_auth(service_jwt);
                            }
                        }
                    }
                }
                if let Some(body) = request.body {
                    builder = builder.body(body);
                }
                let resp = builder
                    .send()
                    .await
                    .map_err(|e| MLSError::Internal(format!("HTTP transport failed: {e}")))?;
                let status = resp.status().as_u16();
                let headers = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        v.to_str().ok().map(|val| PlatformHttpHeader {
                            name: k.as_str().to_string(),
                            value: val.to_string(),
                        })
                    })
                    .collect();
                let body = resp
                    .bytes()
                    .await
                    .map_err(|e| MLSError::Internal(format!("read HTTP body: {e}")))?
                    .to_vec();
                Ok(PlatformHttpResponse {
                    status,
                    headers,
                    body,
                })
            })
        })
        .join()
        .map_err(|_| MLSError::Internal("HTTP transport thread panicked".to_string()))?
    }

    fn connect_realtime_stream(
        &self,
        _home_ds_endpoint: String,
        _cursor_seq: Option<i64>,
    ) -> Result<(), MLSError> {
        Ok(())
    }

    fn disconnect_realtime_stream(&self) -> Result<(), MLSError> {
        Ok(())
    }
}

struct CliChangeObserver;

impl PlatformChangeObserver for CliChangeObserver {
    fn on_change(&self, event: PlatformChangeEvent) {
        tracing::debug!(?event, "catmos-cli unified MLS state change");
    }
}

pub struct CliUnifiedMlsClient {
    storage_root: PathBuf,
    normalized_did: String,
    did_hash: String,
    transport: Arc<CliPlatformTransport>,
    sdk: Arc<CatbirdMlsClient>,
}

impl CliUnifiedMlsClient {
    pub fn is_opted_in(storage_root: &Path, account_did: &str) -> bool {
        let Ok(norm) = normalize_account_did(account_did) else {
            return false;
        };
        let Ok(hash) = account_did_hash_hex(&norm) else {
            return false;
        };
        storage_root
            .join("mls-opt-in")
            .join(format!("{hash}.enabled"))
            .exists()
    }

    pub fn set_opted_in(
        storage_root: &Path,
        account_did: &str,
        enabled: bool,
    ) -> anyhow::Result<()> {
        let norm = normalize_account_did(account_did)?;
        let hash = account_did_hash_hex(&norm)?;
        let dir = storage_root.join("mls-opt-in");
        std::fs::create_dir_all(&dir)?;
        let marker = dir.join(format!("{hash}.enabled"));
        if enabled {
            std::fs::write(&marker, b"1")?;
        } else if marker.exists() {
            let _ = std::fs::remove_file(&marker);
        }
        Ok(())
    }

    pub fn open_desktop(
        storage_root: PathBuf,
        account_did: &str,
        home_ds_did: String,
        home_ds_endpoint: String,
        pds_endpoint: String,
    ) -> anyhow::Result<Self> {
        Self::open_inner(
            storage_root,
            account_did,
            home_ds_did,
            home_ds_endpoint,
            pds_endpoint,
            Arc::new(CliPlatformKeyStore::new_os_keyring()),
            Arc::new(CliPlatformTransport::new(None)),
        )
    }

    pub fn set_bearer_token(&self, token: Option<String>) {
        self.transport.set_bearer_token(token);
    }

    pub fn open_for_testing(
        storage_root: PathBuf,
        account_did: &str,
        pds_supports_spaces: bool,
    ) -> anyhow::Result<Self> {
        Self::open_inner(
            storage_root,
            account_did,
            "did:web:chat.catbird.blue".to_string(),
            "https://chat.catbird.blue".to_string(),
            "https://swan.place".to_string(),
            Arc::new(CliPlatformKeyStore::new_in_memory()),
            Arc::new(CliPlatformTransport::new(Some(pds_supports_spaces))),
        )
    }

    fn open_inner(
        storage_root: PathBuf,
        account_did: &str,
        home_ds_did: String,
        home_ds_endpoint: String,
        pds_endpoint: String,
        keystore: Arc<CliPlatformKeyStore>,
        transport: Arc<CliPlatformTransport>,
    ) -> anyhow::Result<Self> {
        let normalized_did = normalize_account_did(account_did)?;
        let did_hash = account_did_hash_hex(&normalized_did)?;
        let dev_dir = storage_root.join("mls-opt-in");
        std::fs::create_dir_all(&dev_dir)?;
        let dev_file = dev_dir.join(format!("{did_hash}.device"));
        let device_id = std::fs::read_to_string(&dev_file)
            .ok()
            .and_then(|raw| {
                uuid::Uuid::parse_str(raw.trim())
                    .ok()
                    .filter(|u| u.get_version_num() == 4)
                    .map(|u| u.hyphenated().to_string())
            })
            .map(Ok::<String, std::io::Error>)
            .unwrap_or_else(|| {
                let d = uuid::Uuid::new_v4().hyphenated().to_string();
                std::fs::write(&dev_file, d.as_bytes())?;
                Ok(d)
            })?;

        transport.configure_endpoints(&pds_endpoint, &home_ds_endpoint, &home_ds_did);

        let cfg = CatbirdMlsClientConfig {
            storage_root: storage_root.to_string_lossy().to_string(),
            account_did: normalized_did.clone(),
            device_id,
            home_ds_did,
            home_ds_endpoint,
            pds_endpoint,
        };
        let observer: Arc<dyn PlatformChangeObserver> = Arc::new(CliChangeObserver);
        let sdk = CatbirdMlsClient::open(cfg, keystore, transport.clone(), Some(observer))?;
        Ok(Self {
            storage_root,
            normalized_did,
            did_hash,
            transport,
            sdk,
        })
    }

    pub fn enable_and_enroll(
        &self,
        granted_scopes: Option<&[String]>,
    ) -> anyhow::Result<(EnrollmentReceipt, LabyrinthBackupStatus)> {
        let default_scopes: Vec<String> = REQUIRED_LABYRINTH_OAUTH_SCOPES
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let scopes = granted_scopes.unwrap_or(&default_scopes);
        let receipt = self.sdk.enroll_device(scopes)?;
        Self::set_opted_in(&self.storage_root, &self.normalized_did, true)?;
        let status = self.sdk.labyrinth_status()?;
        Ok((receipt, status))
    }

    pub fn sdk(&self) -> &Arc<CatbirdMlsClient> {
        &self.sdk
    }

    pub fn home_ds_did(&self) -> String {
        self.transport
            .home_ds_did
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| "did:web:chat.catbird.blue".to_string())
    }

    pub fn did_hash(&self) -> &str {
        &self.did_hash
    }

    pub fn status(&self) -> anyhow::Result<LabyrinthBackupStatus> {
        Ok(self.sdk.labyrinth_status()?)
    }

    pub fn setup_recovery_code(&self) -> anyhow::Result<String> {
        Ok(self.sdk.setup_recovery_code()?)
    }

    pub fn restore_recovery_code(&self, code: &str) -> anyhow::Result<LabyrinthBackupStatus> {
        Ok(self.sdk.restore_with_recovery_code(code)?)
    }

    pub fn initiate_otc(&self) -> anyhow::Result<OtcPairingOffer> {
        Ok(self.sdk.initiate_otc_pairing()?)
    }

    pub fn complete_otc(&self, six_digit_code: &str) -> anyhow::Result<OtcPairingCompletion> {
        Ok(self.sdk.complete_otc_pairing(six_digit_code)?)
    }

    pub fn revoke_device(&self, target_device_id: &str) -> anyhow::Result<LabyrinthBackupStatus> {
        Ok(self.sdk.revoke_labyrinth_device(target_device_id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_unified_client_enforces_ctl2_and_completes_labyrinth_flows() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let did = "did:plc:catmoscliunified00001";
        assert!(!CliUnifiedMlsClient::is_opted_in(tmp.path(), did));

        // Seed a legacy non-UUIDv4 `.device` file and verify migration to canonical lowercase UUIDv4.
        let did_hash = account_did_hash_hex(did).expect("did hash");
        let opt_dir = tmp.path().join("mls-opt-in");
        std::fs::create_dir_all(&opt_dir).expect("mkdir mls-opt-in");
        std::fs::write(
            opt_dir.join(format!("{did_hash}.device")),
            b"catmos-cli-not-a-uuid",
        )
        .expect("seed legacy device file");

        let client = CliUnifiedMlsClient::open_for_testing(tmp.path().to_path_buf(), did, true)
            .expect("open unified client");
        let (receipt, status) = client.enable_and_enroll(None).expect("enroll");
        let parsed_uuid =
            uuid::Uuid::parse_str(&receipt.device_id).expect("device_id must be valid UUID");
        assert_eq!(parsed_uuid.get_version_num(), 4);
        assert_eq!(receipt.device_id, parsed_uuid.hyphenated().to_string());
        assert!(CliUnifiedMlsClient::is_opted_in(tmp.path(), did));
        assert!(receipt.labyrinth_backup_enabled);
        assert_eq!(status.epoch_seq, 1);

        let code = client.setup_recovery_code().expect("recovery code");
        assert_eq!(
            code.chars().filter(|c| c.is_ascii_alphanumeric()).count(),
            40
        );

        let after_restore = client.restore_recovery_code(&code).expect("restore");
        assert_eq!(after_restore.epoch_seq, 2);

        let offer = client.initiate_otc().expect("initiate OTC");
        let otc_done = client
            .complete_otc(&offer.six_digit_code)
            .expect("complete PQ OTC");
        assert_eq!(otc_done.initiator_mlkem768_ek_len, 1184);
        assert_eq!(otc_done.responder_mlkem768_ct_len, 1088);
        assert_eq!(otc_done.new_epoch_seq, 3);
    }

    #[test]
    fn cli_unified_client_restores_recovery_code_on_fresh_device_from_space_records() {
        let shared_transport = Arc::new(CliPlatformTransport::new(Some(true)));
        let did = "did:plc:catmosclifreshdev00002";

        let dev_a_dir = tempfile::tempdir().expect("dev_a tempdir");
        let dev_a = CliUnifiedMlsClient::open_inner(
            dev_a_dir.path().to_path_buf(),
            did,
            "did:web:chat.catbird.blue".to_string(),
            "https://chat.catbird.blue".to_string(),
            "https://swan.place".to_string(),
            Arc::new(CliPlatformKeyStore::new_in_memory()),
            shared_transport.clone(),
        )
        .expect("open dev_a");
        let (_receipt, status_a) = dev_a.enable_and_enroll(None).expect("enroll dev_a");
        assert_eq!(status_a.epoch_seq, 1);
        let code = dev_a.setup_recovery_code().expect("recovery code on dev_a");

        // Fresh Device B has empty local SQLite storage and restores purely via Space listRecords.
        let dev_b_dir = tempfile::tempdir().expect("dev_b tempdir");
        let dev_b = CliUnifiedMlsClient::open_inner(
            dev_b_dir.path().to_path_buf(),
            did,
            "did:web:chat.catbird.blue".to_string(),
            "https://chat.catbird.blue".to_string(),
            "https://swan.place".to_string(),
            Arc::new(CliPlatformKeyStore::new_in_memory()),
            shared_transport,
        )
        .expect("open dev_b");
        let (_receipt_b, _) = dev_b.enable_and_enroll(None).expect("enroll dev_b");
        let restored_b = dev_b
            .restore_recovery_code(&code)
            .expect("restore on fresh dev_b from Space listRecords");
        assert!(restored_b.epoch_seq >= 2);
    }
}
