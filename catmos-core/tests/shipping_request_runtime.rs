//! Actual CLI processes against the shipping delivery-service router. The local
//! session/PDS facade is synthetic; cryptography, service JWT admission,
//! canonical reads/mutations, SQLCipher and OS-keychain reopening are real.
#![cfg(feature = "local-runtime-fixture")]

use anyhow::{ensure, Context};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use mls_e2e_tests::local_runtime_fixture::{
    connect_guarded_request_database, seed_service_device, HttpsDidFixture, ServiceIdentity,
    ShippingServerFixture,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    future::IntoFuture,
    io::BufRead,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::io::AsyncWriteExt;

struct Actor {
    identity: ServiceIdentity,
    session: String,
    profile: String,
    manifest: PathBuf,
    public_key: Vec<u8>,
    record: Mutex<Option<Value>>,
}
struct Proxy {
    actors: Vec<Arc<Actor>>,
    documents: BTreeMap<String, Value>,
    service: String,
    http: reqwest::Client,
    trace: Mutex<Vec<Value>>,
    /// Every HTTP request reaching the TLS-terminated fixture, including
    /// synthetic PDS/session endpoints and requests refused while offline.
    /// This is the process transport boundary used for zero-effect counts.
    seen: Mutex<Vec<Value>>,
    /// While set, every request is recorded and refused before any handler or
    /// upstream service can observe it.
    offline: AtomicBool,
    evidence: PathBuf,
    drop_publication_response: AtomicBool,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        if let Ok(trace) = self.trace.lock() {
            if let Ok(raw) = serde_json::to_vec_pretty(&*trace) {
                let _ = std::fs::write(self.evidence.join("http-metadata.json"), raw);
            }
        }
        if let Ok(seen) = self.seen.lock() {
            if let Ok(raw) = serde_json::to_vec_pretty(&*seen) {
                let _ = std::fs::write(self.evidence.join("transport-requests.json"), raw);
            }
        }
    }
}
struct TlsProcess(Child);
impl Drop for TlsProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn response(status: StatusCode, value: Value) -> Response {
    (status, axum::Json(value)).into_response()
}
fn rejected() -> Response {
    response(
        StatusCode::UNAUTHORIZED,
        json!({"error":"AuthenticationRequired"}),
    )
}
fn actor_for_session<'a>(proxy: &'a Proxy, request: &Request) -> Option<&'a Arc<Actor>> {
    let bearer = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let cookie = request
        .headers()
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("catbird_session="));
    proxy
        .actors
        .iter()
        .find(|actor| Some(actor.session.as_str()) == bearer.or(cookie))
}
async fn serve(State(proxy): State<Arc<Proxy>>, request: Request) -> Response {
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or("").to_owned();
    let offline = proxy.offline.load(Ordering::SeqCst);
    proxy.seen.lock().unwrap().push(json!({
        "method": request.method().as_str(),
        "path": path,
        "refusedOffline": offline,
    }));
    if offline {
        return response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"error":"FixtureNetworkOffline"}),
        );
    }
    let host = request
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    if path == "/.well-known/did.json" && request.method() == Method::GET {
        return match proxy.documents.get(host) {
            Some(doc) => response(StatusCode::OK, doc.clone()),
            None => response(StatusCode::NOT_FOUND, json!({"error":"NotFound"})),
        };
    }
    if path == "/xrpc/com.atproto.repo.listRecords" && request.method() == Method::GET {
        let params: BTreeMap<_, _> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let Some(actor) = proxy.actors.iter().find(|a| {
            params.get("repo") == Some(&a.identity.did)
                && host == a.identity.did.trim_start_matches("did:web:")
        }) else {
            return rejected();
        };
        if params.get("collection").map(String::as_str) != Some("blue.catbird.chat.device") {
            return response(StatusCode::BAD_REQUEST, json!({"error":"InvalidRequest"}));
        }
        return response(
            StatusCode::OK,
            json!({"records":actor.record.lock().unwrap().iter().cloned().collect::<Vec<_>>()}),
        );
    }
    if path == "/xrpc/app.bsky.actor.getProfile" && request.method() == Method::GET {
        let params: BTreeMap<_, _> = url::form_urlencoded::parse(query.as_bytes())
            .into_owned()
            .collect();
        let Some(actor) = proxy
            .actors
            .iter()
            .find(|a| params.get("actor") == Some(&a.identity.did))
        else {
            return rejected();
        };
        return response(
            StatusCode::OK,
            json!({"did":actor.identity.did,"handle":actor.identity.did.trim_start_matches("did:web:"),"displayName":"Synthetic request fixture"}),
        );
    }
    let Some(actor) = actor_for_session(&proxy, &request).cloned() else {
        return rejected();
    };
    if path == "/auth/session" && request.method() == Method::GET {
        return response(
            StatusCode::OK,
            json!({"did":actor.identity.did,"handle":actor.identity.did.trim_start_matches("did:web:")}),
        );
    }
    if path == "/xrpc/app.bsky.graph.getBlocks" && request.method() == Method::GET {
        return response(StatusCode::OK, json!({"blocks":[]}));
    }
    let method = request.method().clone();
    let bytes = match to_bytes(request.into_body(), 16 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return response(StatusCode::PAYLOAD_TOO_LARGE, json!({"error":"TooLarge"})),
    };
    if path == "/xrpc/com.atproto.repo.putRecord" && method == Method::POST {
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            return response(StatusCode::BAD_REQUEST, json!({"error":"InvalidRequest"}));
        };
        if value["repo"] != actor.identity.did
            || value["rkey"] != actor.identity.device_id.to_string()
            || value["collection"] != "blue.catbird.chat.device"
            || value["record"]["mlsSignaturePublicKey"]["$bytes"]
                != STANDARD.encode(&actor.public_key)
            || !value["swapRecord"].is_null()
        {
            return response(StatusCode::FORBIDDEN, json!({"error":"InvalidRecord"}));
        }
        let uri = format!(
            "at://{}/blue.catbird.chat.device/{}",
            actor.identity.did, actor.identity.device_id
        );
        let mut record = actor.record.lock().unwrap();
        if record.is_some() {
            return response(StatusCode::CONFLICT, json!({"error":"InvalidSwap"}));
        }
        *record = Some(
            json!({"uri":uri,"value":value["record"],"cid":"bafkreigh2akiscaildc5uysbroqbuq43uqudpjxckcmchwwyk7r6xnsgma"}),
        );
        return response(
            StatusCode::OK,
            json!({"uri":uri,"cid":"bafkreigh2akiscaildc5uysbroqbuq43uqudpjxckcmchwwyk7r6xnsgma"}),
        );
    }
    let Some(nsid) = path
        .strip_prefix("/xrpc/")
        .filter(|s| s.starts_with("blue.catbird.chat."))
    else {
        return response(
            StatusCode::NOT_FOUND,
            json!({"error":"UnsupportedFixtureEndpoint"}),
        );
    };
    if method != Method::GET && method != Method::POST {
        return response(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error":"MethodNotAllowed"}),
        );
    }
    match actor
        .identity
        .forward_exact_service_request(
            &proxy.http,
            &proxy.service,
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
            nsid,
            Some(&query),
            if method == Method::GET {
                None
            } else {
                Some(&bytes)
            },
        )
        .await
    {
        Ok((status, body)) => {
            use sha2::{Digest, Sha256};
            let publication = nsid == "blue.catbird.chat.publishDirectRequest";
            let lost = publication
                && status.is_success()
                && proxy
                    .drop_publication_response
                    .swap(false, Ordering::SeqCst);
            proxy.trace.lock().unwrap().push(json!({"did":actor.identity.did,"method":method.as_str(),"nsid":nsid,"status":status.as_u16(),"requestBodySha256":publication.then(||hex::encode(Sha256::digest(&bytes))),"responseBodySha256":publication.then(||hex::encode(Sha256::digest(&body))),"responseDropped":lost}));
            if lost {
                // Only the local TLS terminator consumes this marker. The real
                // service already committed and returned 200; no receipt bytes
                // or HTTP status are forwarded to the actual CLI process.
                return Response::builder()
                    .status(200)
                    .header("x-catmos-fixture-drop-response", "1")
                    .body(Body::empty())
                    .unwrap();
            }
            Response::builder()
                .status(status.as_u16())
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap()
        }
        Err(err) => {
            eprintln!("forward_exact_service_request error for {nsid} (query: {query:?}): {err:#}");
            response(
                StatusCode::BAD_GATEWAY,
                json!({"error":"FixtureUpstreamFailed"}),
            )
        }
    }
}

async fn child(
    binary: &Path,
    actor: &Actor,
    arguments: &[&str],
    input: &[u8],
) -> anyhow::Result<std::process::Output> {
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["--profile", &actor.profile, "--no-startup-sync"])
        .args(arguments)
        .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &actor.manifest)
        .env("RUST_LOG", "error")
        .env_remove("CATMOS_TEST_KEYCHAIN_FALLBACK")
        .env_remove("CATMOS_TEST_SHARED_KEYCHAIN_FALLBACK")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut process = command.spawn()?;
    process
        .stdin
        .take()
        .context("child stdin")?
        .write_all(input)
        .await?;
    tokio::time::timeout(Duration::from_secs(90), process.wait_with_output())
        .await
        .context("actual CLI process timeout")?
        .context("actual CLI process")
}
async fn json_command(
    binary: &Path,
    actor: &Actor,
    arguments: &[&str],
    input: &[u8],
) -> anyhow::Result<Value> {
    let output = child(binary, actor, arguments, input).await?;
    ensure!(
        output.status.success(),
        "CLI command {:?} failed: {}",
        arguments,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).context("actual CLI JSON output")
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires the guarded local shipping service, retained signed binaries and real OS keychain"]
async fn actual_cli_publishes_previews_accepts_replies_and_reopens() -> anyhow::Result<()> {
    shipping_cli_scenario(false).await
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires guarded shipping service, retained signed binaries and real OS keychain"]
async fn actual_cli_lost_publication_response_replays_after_process_restart() -> anyhow::Result<()>
{
    shipping_cli_scenario(true).await
}

/// Live shipping service, synthetic session/PDS facade, TLS terminator and two
/// seeded actual-CLI profiles. Dropping it stops every process it started.
struct Fixture {
    binary: PathBuf,
    evidence: PathBuf,
    proxy: Arc<Proxy>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    tls: Option<TlsProcess>,
    _server: ShippingServerFixture,
    _https: HttpsDidFixture,
}
impl Fixture {
    /// Close the socket and the request handler: later processes observe a
    /// connection failure instead of any server response.
    fn stop_network(&mut self) {
        self.tls.take();
        self.task.abort();
    }
    /// Index of the next request that will reach the transport boundary.
    fn transport_mark(&self) -> usize {
        self.proxy.seen.lock().unwrap().len()
    }
    fn transport_since(&self, mark: usize) -> Vec<Value> {
        self.proxy.seen.lock().unwrap()[mark..].to_vec()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop_network();
    }
}

async fn start_fixture(lose_publication_response: bool) -> anyhow::Result<Fixture> {
    connect_guarded_request_database(4).await?;
    let binary = PathBuf::from(
        std::env::var("CATMOS_RUNTIME_CLI").context("retained fixture-only CLI path")?,
    );
    let seeder = PathBuf::from(
        std::env::var("CATMOS_RUNTIME_SEED")
            .context("retained fixture-only profile seeder path")?,
    );
    ensure!(
        binary.is_absolute() && seeder.is_absolute(),
        "retained binaries require absolute paths"
    );
    let evidence = PathBuf::from(
        std::env::var("CATMOS_RUNTIME_EVIDENCE").context("unique retained evidence directory")?,
    );
    ensure!(
        evidence.is_absolute() && !evidence.exists(),
        "refusing to overwrite evidence directory"
    );
    std::fs::create_dir_all(&evidence)?;
    std::fs::write(
        evidence.join("result.json"),
        br#"{"status":"started","fixtureOnly":true}"#,
    )?;
    let test_runner = std::env::current_exe()?;
    let service_binary = PathBuf::from(std::env::var("REQUEST_SERVER_FIXTURE_BINARY")?);
    let binaries = [&binary, &seeder, &test_runner, &service_binary]
        .into_iter()
        .map(|path| -> anyhow::Result<Value> {
            Ok(json!({"path":path,"sha256":artifact_sha256(path)?}))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    std::fs::write(
        evidence.join("artifact-manifest.json"),
        serde_json::to_vec_pretty(
            &json!({"fixtureOnly":true,"features":["local-runtime-fixture"],"binaries":binaries}),
        )?,
    )?;
    let run = uuid::Uuid::new_v4().simple().to_string();
    let identities = vec![
        ServiceIdentity::new(format!("did:web:alice-{run}.request-fixture.catbird.blue")),
        ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue")),
    ];
    let gateway = format!("gateway-{run}.request-fixture.catbird.blue");
    let mut docs = identities
        .iter()
        .map(|i| (i.did.clone(), i.did_document()))
        .collect::<Vec<_>>();
    docs.push((
        "did:web:chat.catbird.blue".into(),
        json!({"id":"did:web:chat.catbird.blue"}),
    ));
    docs.push((
        format!("did:web:{gateway}"),
        json!({"id":format!("did:web:{gateway}")}),
    ));
    let https = HttpsDidFixture::start(HttpsDidFixture::reserve_port()?, &docs)?;
    let server = ShippingServerFixture::start(&https)?;
    let tls_port = HttpsDidFixture::reserve_port()?;
    let proxy_url = format!("https://{gateway}");
    let mut actors = Vec::new();
    for identity in identities {
        let profile = format!("t17-cli-{}", uuid::Uuid::new_v4());
        let manifest = evidence.join(format!("{profile}.transport.json"));
        let mappings = https
            .hosts
            .iter()
            .filter(|h| {
                h.as_str() == "chat.catbird.blue" || h.ends_with(".request-fixture.catbird.blue")
            })
            .map(|h| (h.clone(), format!("127.0.0.1:{tls_port}")))
            .collect::<BTreeMap<_, _>>();
        std::fs::write(
            &manifest,
            serde_json::to_vec_pretty(
                &json!({"profile":profile,"ca_pem":https.ca_pem,"hosts":mappings}),
            )?,
        )?;
        let session = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let seed = json!({"profile":profile,"did":identity.did,"deviceId":identity.device_id.to_string(),"proxyUrl":proxy_url,"serviceUrl":server.base_url,"sessionCookie":session});
        let mut child = tokio::process::Command::new(&seeder)
            .env("CATMOS_LOCAL_RUNTIME_TRANSPORT", &manifest)
            .env_remove("CATMOS_TEST_KEYCHAIN_FALLBACK")
            .env_remove("CATMOS_TEST_SHARED_KEYCHAIN_FALLBACK")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&seed)?)
            .await?;
        let output = tokio::time::timeout(Duration::from_secs(45), child.wait_with_output())
            .await
            .context("profile seed timeout")??;
        ensure!(
            output.status.success(),
            "profile seed failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let public: Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            public["privateSigningKeyFallbackPresent"] == false,
            "seed used unprotected signing-key fallback"
        );
        ensure!(
            public["did"] == identity.did && public["deviceId"] == identity.device_id.to_string(),
            "seed public identity mismatch"
        );
        let public_key = STANDARD.decode(
            public["signaturePublicKey"]
                .as_str()
                .context("public key")?,
        )?;
        seed_service_device(&identity, &public_key)?;
        actors.push(Arc::new(Actor {
            identity,
            session,
            profile,
            manifest,
            public_key,
            record: Mutex::new(None),
        }));
    }
    let mut documents = docs
        .into_iter()
        .map(|(did, doc)| (did.trim_start_matches("did:web:").to_string(), doc))
        .collect::<BTreeMap<_, _>>();
    documents.insert(
        "chat.catbird.blue".into(),
        serde_json::from_slice(&server.receipt_document)?,
    );
    let proxy = Arc::new(Proxy {
        actors,
        documents,
        service: server.base_url.clone(),
        http: reqwest::Client::new(),
        trace: Mutex::new(Vec::new()),
        seen: Mutex::new(Vec::new()),
        offline: AtomicBool::new(false),
        evidence: evidence.clone(),
        drop_publication_response: AtomicBool::new(lose_publication_response),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let upstream = listener.local_addr()?.port();
    let task = tokio::spawn(
        axum::serve(
            listener,
            Router::new().fallback(serve).with_state(proxy.clone()),
        )
        .into_future(),
    );
    let hosts = evidence.join("tls-hosts.json");
    std::fs::write(&hosts, serde_json::to_vec(&https.hosts)?)?;
    let mut tls = Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/local_runtime_tls.py"))
        .arg(https.root.join("server.pem"))
        .arg(https.root.join("server-key.pem"))
        .arg(tls_port.to_string())
        .arg(upstream.to_string())
        .arg(&hosts)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut ready = String::new();
    std::io::BufReader::new(tls.stdout.take().unwrap()).read_line(&mut ready)?;
    ensure!(
        serde_json::from_str::<Value>(&ready)?["port"] == tls_port,
        "TLS proxy readiness mismatch"
    );
    let tls = Some(TlsProcess(tls));
    let address = format!("127.0.0.1:{tls_port}").parse()?;
    let untrusted = reqwest::Client::builder()
        .no_proxy()
        .resolve(&gateway, address)
        .build()?;
    ensure!(
        untrusted
            .get(format!("{proxy_url}/auth/session"))
            .send()
            .await
            .is_err(),
        "fixture TLS accepted an untrusted CA"
    );
    let certificate = reqwest::Certificate::from_pem(&std::fs::read(&https.ca_pem)?)?;
    let trusted = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(certificate.clone())
        .resolve(&gateway, address)
        .build()?;
    ensure!(
        trusted
            .get(format!("{proxy_url}/auth/session"))
            .send()
            .await?
            .status()
            == StatusCode::UNAUTHORIZED,
        "fixture session accepted missing credentials"
    );
    let wrong_name = "not-in-certificate.request-fixture.catbird.blue";
    let wrong_host = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(certificate)
        .resolve(wrong_name, address)
        .build()?;
    ensure!(
        wrong_host
            .get(format!("https://{wrong_name}/auth/session"))
            .send()
            .await
            .is_err(),
        "fixture TLS ignored hostname mismatch"
    );
    Ok(Fixture {
        binary,
        evidence,
        proxy,
        task,
        tls,
        _server: server,
        _https: https,
    })
}

async fn shipping_cli_scenario(lose_publication_response: bool) -> anyhow::Result<()> {
    let mut fixture = start_fixture(lose_publication_response).await?;
    let (binary, evidence, proxy) = (
        fixture.binary.clone(),
        fixture.evidence.clone(),
        fixture.proxy.clone(),
    );

    let alice = &proxy.actors[0];
    let bob = &proxy.actors[1];
    eprintln!("local CLI fixture: explicit recipient delivery");
    let delivery = json_command(&binary, bob, &["request", "delivery", "--enable"], b"").await?;
    ensure!(delivery["enabled"] == true, "delivery not acknowledged");
    let draft = uuid::Uuid::new_v4().to_string();
    let introduction = b"Synthetic T17 CLI encrypted introduction";
    eprintln!("local CLI fixture: actual request publication");
    let mut sent = json_command(
        &binary,
        alice,
        &[
            "request",
            "send",
            &bob.identity.did,
            "--file",
            "-",
            "--draft-id",
            &draft,
        ],
        introduction,
    )
    .await?;
    let mut replay_graph = None;
    if lose_publication_response {
        ensure!(
            sent["outcome"]["type"] == "outcomeUnknown",
            "lost HTTP response was not retained as uncertain: {}",
            sent
        );
        let request_id = sent["outcome"]["requestId"]
            .as_str()
            .context("uncertain request identity")?;
        let request_id = uuid::Uuid::parse_str(request_id)?;
        let before = publication_graph(request_id)?;
        // json_command has waited for the first OS process to exit. This is a
        // new CLI process reading its SQLCipher/OS-keychain profile, not a
        // second invocation on an existing native context.
        sent = json_command(&binary, alice, &["request", "resume", &draft], b"").await?;
        let after = publication_graph(request_id)?;
        ensure!(
            before == after,
            "publication replay changed authoritative graph identity/counts"
        );
        let publications = proxy
            .trace
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["nsid"] == "blue.catbird.chat.publishDirectRequest")
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            publications.len() >= 2
                && publications[0]["responseDropped"] == true
                && publications
                    .iter()
                    .skip(1)
                    .all(|row| row["responseDropped"] == false
                        && row["status"] == 200
                        && row["requestBodySha256"] == publications[0]["requestBodySha256"]
                        && row["responseBodySha256"] == publications[0]["responseBodySha256"]),
            "retry did not preserve exact publication and receipt bytes"
        );
        replay_graph = Some(before);
    }
    ensure!(
        sent["outcome"]["type"] == "requestSent",
        "CLI did not return RequestSent: {}",
        sent
    );
    let conversation = sent["outcome"]["conversationId"]
        .as_str()
        .context("RequestSent conversation")?
        .to_string();
    eprintln!("local CLI fixture: list and protected preview");
    let list = json_command(&binary, bob, &["request", "list"], b"").await?;
    ensure!(
        list["requests"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|r| r["conversationId"] == conversation)),
        "request absent from actual CLI list"
    );
    ensure!(
        !serde_json::to_string(&list)?.contains(std::str::from_utf8(introduction)?),
        "list exposed introduction"
    );
    let shown = json_command(&binary, bob, &["request", "show", &conversation], b"").await?;
    ensure!(
        serde_json::to_string(&shown)?.contains(std::str::from_utf8(introduction)?),
        "preview did not decrypt exact introduction"
    );
    let before = proxy
        .trace
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["nsid"] == "blue.catbird.chat.sendMessage")
        .count();
    let blocked = child(
        &binary,
        bob,
        &["send", &conversation, "--file", "-"],
        b"must remain blocked",
    )
    .await?;
    ensure!(
        !blocked.status.success(),
        "pending CLI reply unexpectedly succeeded"
    );
    ensure!(
        proxy
            .trace
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["nsid"] == "blue.catbird.chat.sendMessage")
            .count()
            == before,
        "pending reply reached service"
    );
    eprintln!("local CLI fixture: acceptance and ordinary encrypted reply");
    let accepted = json_command(&binary, bob, &["request", "accept", &conversation], b"").await?;
    ensure!(accepted["consent"] == "accepted", "acceptance not verified");
    let reply = b"Synthetic T17 CLI accepted reply";
    let output = child(&binary, bob, &["send", &conversation, "--file", "-"], reply).await?;
    ensure!(
        output.status.success(),
        "accepted reply failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let history = child(&binary, alice, &["messages", &conversation], b"").await?;
    ensure!(
        history.status.success()
            && String::from_utf8_lossy(&history.stdout).contains(std::str::from_utf8(reply)?),
        "sender did not decrypt reply after process restart"
    );
    fixture.stop_network();
    let offline = json_command(&binary, bob, &["request", "list", "--offline"], b"").await?;
    ensure!(
        offline["requests"]
            .as_array()
            .is_some_and(|r| !r.is_empty()),
        "offline protected projection missing"
    );
    std::fs::write(
        evidence.join("result.json"),
        serde_json::to_vec_pretty(
            &json!({"status":"passed","auth":"synthetic confidential session facade","service":"shipping router and real scoped ES256 admission","profiles":[alice.profile,bob.profile],"conversationId":conversation,"previewMatches":true,"pendingReplyBlockedBeforeHttp":true,"acceptedReplyDecryptedAfterRestart":true,"offlineReopen":true,"fixtureOnly":true,"lostResponseProcessRestart":lose_publication_response,"unchangedPublicationGraph":replay_graph}),
        )?,
    )?;
    std::fs::write(
        evidence.join("http-metadata.json"),
        serde_json::to_vec_pretty(&*proxy.trace.lock().unwrap())?,
    )?;
    Ok(())
}

/// The actual interactive `catmos` executable under a pseudo-terminal. The
/// driver returns only match booleans; rendered protected text never leaves it.
struct Tui {
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    lines: tokio::io::Lines<tokio::io::BufReader<tokio::process::ChildStdout>>,
}
impl Tui {
    async fn start(binary: &Path, actor: &Actor) -> anyhow::Result<Self> {
        let mut child = tokio::process::Command::new("python3")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/tui_pty_driver.py"))
            .arg(binary)
            .arg(&actor.profile)
            .arg(&actor.manifest)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child.stdin.take().context("driver stdin")?;
        let stdout = child.stdout.take().context("driver stdout")?;
        use tokio::io::AsyncBufReadExt;
        Ok(Self {
            child,
            stdin,
            lines: tokio::io::BufReader::new(stdout).lines(),
        })
    }
    async fn call(&mut self, command: Value) -> anyhow::Result<Value> {
        let mut line = serde_json::to_vec(&command)?;
        line.push(b'\n');
        self.stdin.write_all(&line).await?;
        self.stdin.flush().await?;
        let reply = tokio::time::timeout(Duration::from_secs(180), self.lines.next_line())
            .await
            .context("TUI driver reply timeout")??
            .context("TUI driver closed")?;
        Ok(serde_json::from_str(&reply)?)
    }
    async fn expect(&mut self, text: &str, timeout: u64) -> anyhow::Result<()> {
        let reply = self
            .call(json!({"op":"expect","text":text,"timeout":timeout}))
            .await?;
        ensure!(reply["found"] == true, "actual TUI never rendered {text:?}");
        Ok(())
    }
    async fn keys(&mut self, data: &str) -> anyhow::Result<()> {
        self.call(json!({"op":"keys","data":data})).await?;
        Ok(())
    }
    async fn quit(mut self) -> anyhow::Result<()> {
        self.keys("\u{11}").await?;
        let reply = self.call(json!({"op":"exit","timeout":30})).await?;
        ensure!(reply["code"] == 0, "actual TUI exit: {reply}");
        let _ = self.child.wait().await;
        Ok(())
    }
}

/// Wait until no request has reached the transport for `quiet`, bounded.
/// Background reads may continue; the caller classifies its measured window.
async fn settle_transport(fixture: &Fixture, quiet: Duration, bound: Duration) {
    let start = std::time::Instant::now();
    let mut last = (fixture.transport_mark(), std::time::Instant::now());
    while start.elapsed() < bound {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let now = fixture.transport_mark();
        if now != last.0 {
            last = (now, std::time::Instant::now());
        } else if last.1.elapsed() >= quiet {
            return;
        }
    }
}

/// Any request that could create or advance a conversation, request, upload,
/// membership or group transition. Plain reads are reported, not hidden.
fn remote_effects(window: &[Value]) -> Vec<Value> {
    const EFFECT_WORDS: [&str; 9] = [
        "DirectRequest",
        "Blob",
        "Convo",
        "Conversation",
        "sendMessage",
        "Welcome",
        "Member",
        "Commit",
        "Group",
    ];
    window
        .iter()
        .filter(|row| {
            let path = row["path"].as_str().unwrap_or("");
            path.contains("uploadBlob")
                || (row["method"] != "GET" && EFFECT_WORDS.iter().any(|w| path.contains(w)))
        })
        .cloned()
        .collect()
}

/// Authoritative server rows an actor could have created: request attempts,
/// publications and conversation memberships.
fn service_rows(did: &str) -> anyhow::Result<Value> {
    ensure!(
        did.starts_with("did:web:") && !did.contains('\''),
        "synthetic DID required"
    );
    let query = format!(
        r#"SELECT json_build_object(
      'attempts',(SELECT count(*) FROM chat.direct_request_attempts WHERE actor_did='{did}'),
      'publications',(SELECT count(*) FROM chat.direct_request_publications WHERE actor_did='{did}'),
      'memberships',(SELECT count(*) FROM chat.member_devices WHERE user_did='{did}'))"#
    );
    let output = Command::new("psql")
        .arg(std::env::var("REQUEST_TEST_DATABASE_URL")?)
        .args(["-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", &query])
        .output()?;
    ensure!(output.status.success(), "guarded service row query failed");
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn find_draft<'a>(list: &'a Value, draft: &str) -> anyhow::Result<&'a Value> {
    list["drafts"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["draftId"] == draft))
        .with_context(|| format!("draft {draft} absent from actual CLI list"))
}

/// C29: the actual TUI's contact selection, composer and local draft, and the
/// actual CLI's attachment-first upload on a pending request, produce no
/// request/conversation/upload at the transport or in the service database.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires guarded shipping service, retained signed binaries and real OS keychain"]
async fn actual_tui_draft_and_attachment_first_create_no_remote_effects() -> anyhow::Result<()> {
    let fixture = start_fixture(false).await?;
    let (binary, evidence, proxy) = (
        fixture.binary.clone(),
        fixture.evidence.clone(),
        fixture.proxy.clone(),
    );
    let alice = &proxy.actors[0];
    let bob = &proxy.actors[1];

    eprintln!("C29: actual TUI startup");
    let mut tui = Tui::start(&binary, alice).await?;
    tui.expect("ready ·", 120).await?;
    settle_transport(&fixture, Duration::from_secs(4), Duration::from_secs(45)).await;
    let rows_before = service_rows(&alice.identity.did)?;
    let mark = fixture.transport_mark();

    eprintln!("C29: TUI contact selection, composer and local draft");
    tui.keys("\u{12}").await?; // Ctrl-R: Requests
    tui.expect("n new draft", 30).await?;
    tui.keys("n").await?;
    tui.expect("recipient DID", 30).await?;
    tui.keys(&bob.identity.did).await?;
    tui.keys("\r").await?;
    tui.expect("One encrypted introduction", 30).await?;
    tui.keys("Synthetic C29 TUI draft-only introduction").await?;
    tui.expect("Draft is saved on this device", 30).await?;
    tui.keys("\u{1b}").await?; // Esc: leave the composer without sending
    // Deferred effects would have to happen inside this window.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let tui_window = fixture.transport_since(mark);
    tui.quit().await?;
    let rows_after = service_rows(&alice.identity.did)?;
    ensure!(
        remote_effects(&tui_window).is_empty(),
        "TUI draft reached a remote effect: {:?}",
        remote_effects(&tui_window)
    );
    ensure!(
        rows_before == rows_after,
        "TUI draft changed service rows: {rows_before} -> {rows_after}"
    );
    let local = json_command(&binary, alice, &["request", "list", "--offline"], b"").await?;
    let drafts = local["drafts"]
        .as_array()
        .context("local drafts")?
        .iter()
        .filter(|row| row["recipientDid"] == bob.identity.did.as_str())
        .cloned()
        .collect::<Vec<_>>();
    ensure!(
        drafts.len() == 1 && drafts[0]["attempted"] == false && drafts[0]["outcome"].is_null(),
        "TUI did not retain exactly one unattempted local draft: {drafts:?}"
    );
    let tui_draft = drafts[0]["draftId"].as_str().context("draft id")?.to_owned();

    eprintln!("C29: attachment-first on a pending request");
    let delivery = json_command(&binary, bob, &["request", "delivery", "--enable"], b"").await?;
    ensure!(delivery["enabled"] == true, "delivery not acknowledged");
    let sent = json_command(
        &binary,
        alice,
        &["request", "send", &bob.identity.did, "--file", "-"],
        b"Synthetic C29 introduction before attachment attempt",
    )
    .await?;
    ensure!(
        sent["outcome"]["type"] == "requestSent",
        "request send: {sent}"
    );
    let conversation = sent["outcome"]["conversationId"]
        .as_str()
        .context("conversation")?
        .to_owned();
    let attachment = tempfile::NamedTempFile::new()?;
    std::fs::write(attachment.path(), b"synthetic attachment bytes")?;
    let attachment = attachment.path().to_str().context("attachment path")?;
    let mark = fixture.transport_mark();
    let mut attachment_rejections = Vec::new();
    for actor in [bob, alice] {
        let output = child(
            &binary,
            actor,
            &["blob", "upload", &conversation, attachment],
            b"",
        )
        .await?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        ensure!(
            !output.status.success()
                && stderr.contains("Operation requires verified account consent and device readiness"),
            "attachment-first upload was not rejected by the consent gate: {stderr}"
        );
        attachment_rejections.push(actor.identity.did.clone());
    }
    let upload_window = fixture.transport_since(mark);
    ensure!(
        remote_effects(&upload_window).is_empty(),
        "attachment-first reached a remote effect: {:?}",
        remote_effects(&upload_window)
    );
    let declined = json_command(&binary, bob, &["request", "decline", &conversation], b"").await?;
    ensure!(declined["consent"] == "closed", "decline: {declined}");

    std::fs::write(
        evidence.join("c29-result.json"),
        serde_json::to_vec_pretty(&json!({
            "status": "passed",
            "fixtureOnly": true,
            "profiles": [alice.profile, bob.profile],
            "tui": {
                "entrypoint": "actual catmos TUI under a pseudo-terminal",
                "keys": ["Ctrl-R", "n", "recipient DID", "Enter", "introduction text", "Esc"],
                "transportRequestsInWindow": tui_window,
                "remoteEffectsInWindow": 0,
                "serviceRowsBefore": rows_before,
                "serviceRowsAfter": rows_after,
                "retainedLocalDraftId": tui_draft,
            },
            "attachmentFirst": {
                "conversationId": conversation,
                "rejectedActors": attachment_rejections,
                "transportRequestsInWindow": upload_window,
                "uploadRequestsAtTransport": 0,
                "requestReleasedBy": "recipient decline",
            },
        }))?,
    )?;
    Ok(())
}

/// C35: an actual CLI process and the actual TUI start with an unresolved
/// published-response-lost journal while the network refuses every request.
/// Both reach Ready from offline hydration; the attempt stays owned and later
/// resolves to the identical publication without a second candidate.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires guarded shipping service, retained signed binaries and real OS keychain"]
async fn actual_offline_hydration_reaches_ready_and_holds_pending_ownership() -> anyhow::Result<()>
{
    let fixture = start_fixture(true).await?;
    let (binary, evidence, proxy) = (
        fixture.binary.clone(),
        fixture.evidence.clone(),
        fixture.proxy.clone(),
    );
    let alice = &proxy.actors[0];
    let bob = &proxy.actors[1];
    let delivery = json_command(&binary, bob, &["request", "delivery", "--enable"], b"").await?;
    ensure!(delivery["enabled"] == true, "delivery not acknowledged");
    let draft = uuid::Uuid::new_v4().to_string();
    let introduction = b"Synthetic C35 introduction with lost publication response";
    let sent = json_command(
        &binary,
        alice,
        &["request", "send", &bob.identity.did, "--file", "-", "--draft-id", &draft],
        introduction,
    )
    .await?;
    ensure!(
        sent["outcome"]["type"] == "outcomeUnknown",
        "lost publication response was not retained as unknown: {sent}"
    );
    let request_id = sent["outcome"]["requestId"]
        .as_str()
        .context("unknown request id")?
        .to_owned();
    let graph_before = publication_graph(uuid::Uuid::parse_str(&request_id)?)?;

    eprintln!("C35: network refuses every request; actual CLI offline start");
    proxy.offline.store(true, Ordering::SeqCst);
    let mark = fixture.transport_mark();
    let started = std::time::Instant::now();
    let listed = json_command(&binary, alice, &["request", "list", "--offline"], b"").await?;
    let status = json_command(&binary, alice, &["request", "status", &draft], b"").await?;
    let offline_elapsed = started.elapsed();
    let cli_window = fixture.transport_since(mark);
    ensure!(
        cli_window.is_empty(),
        "offline hydration contacted the transport: {cli_window:?}"
    );
    for row in [find_draft(&listed, &draft)?, &status] {
        ensure!(
            row["attempted"] == true
                && row["outcome"]["type"] == "outcomeUnknown"
                && row["outcome"]["requestId"] == request_id.as_str(),
            "offline Ready lost the owned unknown attempt: {row}"
        );
    }
    ensure!(
        offline_elapsed < Duration::from_secs(30),
        "offline hydration was blocked for {offline_elapsed:?}"
    );

    eprintln!("C35: actual interactive TUI start while the network refuses");
    let mark = fixture.transport_mark();
    let started = std::time::Instant::now();
    let mut tui = Tui::start(&binary, alice).await?;
    tui.expect("list unavailable", 90).await?;
    let tui_ready_after = started.elapsed();
    tui.keys("\u{12}").await?;
    tui.expect(&request_id, 30).await?;
    tui.quit().await?;
    let tui_window = fixture.transport_since(mark);
    ensure!(
        !tui_window.is_empty()
            && tui_window.iter().all(|row| row["refusedOffline"] == true),
        "interactive start did not attempt the refused network: {tui_window:?}"
    );
    proxy.offline.store(false, Ordering::SeqCst);

    eprintln!("C35: ownership fence after the network returns");
    let publications = |proxy: &Proxy| {
        proxy
            .trace
            .lock()
            .unwrap()
            .iter()
            .filter(|r| {
                r["nsid"] == "blue.catbird.chat.publishDirectRequest"
                    || r["nsid"] == "blue.catbird.chat.prepareDirectRequest"
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    let before_conflict = publications(&proxy).len();
    let conflict = child(
        &binary,
        alice,
        &["request", "send", &bob.identity.did, "--file", "-", "--draft-id", &draft],
        b"Different content must not replace the owned attempt",
    )
    .await?;
    ensure!(
        !conflict.status.success()
            && String::from_utf8_lossy(&conflict.stderr)
                .contains("Draft ID already binds different content"),
        "changed content for an owned draft was not refused: {}",
        String::from_utf8_lossy(&conflict.stderr)
    );
    ensure!(
        publications(&proxy).len() == before_conflict,
        "refused content change reached preparation/publication"
    );
    let resumed = json_command(&binary, alice, &["request", "resume", &draft], b"").await?;
    ensure!(
        resumed["outcome"]["type"] == "requestSent",
        "resume did not recover the publication: {resumed}"
    );
    let graph_after = publication_graph(uuid::Uuid::parse_str(&request_id)?)?;
    ensure!(
        graph_before == graph_after,
        "resume changed the authoritative publication graph"
    );
    let rows = publications(&proxy)
        .into_iter()
        .filter(|r| r["nsid"] == "blue.catbird.chat.publishDirectRequest")
        .collect::<Vec<_>>();
    ensure!(
        rows.len() >= 2
            && rows[0]["responseDropped"] == true
            && rows.iter().skip(1).all(|row| row["responseDropped"] == false
                && row["status"] == 200
                && row["requestBodySha256"] == rows[0]["requestBodySha256"]
                && row["responseBodySha256"] == rows[0]["responseBodySha256"]),
        "resume did not replay the exact owned publication"
    );
    let conversation = resumed["outcome"]["conversationId"]
        .as_str()
        .context("conversation")?
        .to_owned();
    ensure!(
        graph_after["conversationId"] == conversation.as_str(),
        "resume adopted a different conversation"
    );
    let declined = json_command(&binary, bob, &["request", "decline", &conversation], b"").await?;
    ensure!(declined["consent"] == "closed", "decline: {declined}");

    std::fs::write(
        evidence.join("c35-hydration-result.json"),
        serde_json::to_vec_pretty(&json!({
            "status": "passed",
            "fixtureOnly": true,
            "profiles": [alice.profile, bob.profile],
            "draftId": draft,
            "requestId": request_id,
            "cliOffline": {
                "commands": ["request list --offline", "request status"],
                "transportRequests": cli_window.len(),
                "elapsedMs": offline_elapsed.as_millis() as u64,
                "outcome": "outcomeUnknown retained",
            },
            "tuiOffline": {
                "readyStatusAfterMs": tui_ready_after.as_millis() as u64,
                "refusedTransportRequests": tui_window.len(),
                "requestsScreenShowedOwnedAttempt": true,
            },
            "ownership": {
                "changedContentRefused": true,
                "preparationsOrPublicationsDuringRefusal": 0,
                "resumeOutcome": "requestSent",
                "publicationGraphUnchanged": true,
                "exactPublicationReplayed": rows.len(),
            },
            "conversationId": conversation,
            "requestReleasedBy": "recipient decline",
        }))?,
    )?;
    Ok(())
}

/// Retains hashes and public row identities, never ciphertext/private keys.
/// The helper's guarded connection has already pinned this synthetic database.
fn publication_graph(request: uuid::Uuid) -> anyhow::Result<Value> {
    let query = format!(
        r#"SELECT json_build_object(
      'requestId',p.request_id,'conversationId',p.conversation_id,'generation',p.generation,
      'stateVersion',p.state_version,'firstMessageId',p.first_message_id,
      'publicationDigest',encode(p.publication_digest,'hex'),
      'groupId',(SELECT encode(g.group_id,'hex') FROM chat.generations g WHERE g.conversation_id=p.conversation_id AND g.generation=p.generation),
      'entries',(SELECT count(*) FROM chat.entries e WHERE e.conversation_id=p.conversation_id),
      'transitions',(SELECT count(*) FROM chat.transitions t WHERE t.conversation_id=p.conversation_id),
      'members',(SELECT count(*) FROM chat.member_devices m WHERE m.conversation_id=p.conversation_id),
      'deliveries',(SELECT count(*) FROM chat.direct_request_device_deliveries d WHERE d.request_id=p.request_id),
      'pushEvents',(SELECT count(*) FROM chat.direct_request_push_events e WHERE e.request_id=p.request_id),
      'pushRecipients',(SELECT count(*) FROM chat.direct_request_push_event_recipients r WHERE r.request_id=p.request_id),
      'entryIdentity',(SELECT json_agg(json_build_array(e.seq,e.entry_id,encode(e.accepted_payload_sha256,'hex')) ORDER BY e.seq) FROM chat.entries e WHERE e.conversation_id=p.conversation_id),
      'transitionIdentity',(SELECT json_agg(json_build_array(t.transition_id,encode(t.request_digest,'hex')) ORDER BY t.transition_id) FROM chat.transitions t WHERE t.conversation_id=p.conversation_id),
      'memberIdentity',(SELECT json_agg(json_build_array(m.leaf_period_id,m.participant_period_id,m.user_did,m.device_id,m.leaf_index) ORDER BY m.leaf_period_id) FROM chat.member_devices m WHERE m.conversation_id=p.conversation_id),
      'deliveryIdentity',(SELECT json_agg(json_build_array(d.owner_did,d.owner_device_id,encode(d.key_package_ref,'hex'),d.grant_id,d.leaf_index) ORDER BY d.owner_did,d.owner_device_id) FROM chat.direct_request_device_deliveries d WHERE d.request_id=p.request_id),
      'pushIdentity',(SELECT json_agg(json_build_array(e.event_id,e.event_position,e.outbox_id,encode(e.payload_digest,'hex')) ORDER BY e.event_id) FROM chat.direct_request_push_events e WHERE e.request_id=p.request_id)
    ) FROM chat.direct_request_publications p WHERE p.request_id='{request}'::uuid"#
    );
    let output = Command::new("psql")
        .arg(std::env::var("REQUEST_TEST_DATABASE_URL")?)
        .args(["-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", &query])
        .output()?;
    ensure!(
        output.status.success(),
        "guarded publication metadata query failed"
    );
    let value: Value = serde_json::from_slice(&output.stdout).context("publication metadata")?;
    ensure!(
        value["pushEvents"] == 1 && value["entries"] == 1 && value["transitions"] == 1,
        "publication did not create exactly one canonical entry/transition/push event"
    );
    Ok(value)
}

/// File provenance only: use optimized system hashing so debug-build SHA256
/// does not dominate the runtime fixture. Protocol transcript hashing stays in
/// the production Rust implementation.
fn artifact_sha256(path: &Path) -> anyhow::Result<String> {
    ensure!(path.is_absolute(), "artifact path must be absolute");
    let output = Command::new("openssl")
        .args(["dgst", "-sha256"])
        .arg(path)
        .output()?;
    ensure!(output.status.success(), "artifact SHA256 command failed");
    let text = std::str::from_utf8(&output.stdout)?;
    let hash = text
        .split_whitespace()
        .last()
        .context("artifact SHA256 missing")?;
    ensure!(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "artifact SHA256 format invalid"
    );
    Ok(hash.to_owned())
}

#[test]
fn artifact_provenance_hash_matches_known_sha256_vector() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("known-vector");
    std::fs::write(&file, b"abc").unwrap();
    assert_eq!(
        artifact_sha256(&file).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
