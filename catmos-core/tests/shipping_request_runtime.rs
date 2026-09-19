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
        Err(_) => response(
            StatusCode::BAD_GATEWAY,
            json!({"error":"FixtureUpstreamFailed"}),
        ),
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

async fn shipping_cli_scenario(lose_publication_response: bool) -> anyhow::Result<()> {
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
    use sha2::{Digest, Sha256};
    let test_runner = std::env::current_exe()?;
    let service_binary = PathBuf::from(std::env::var("REQUEST_SERVER_FIXTURE_BINARY")?);
    let binaries = [&binary, &seeder, &test_runner, &service_binary]
        .into_iter()
        .map(|path| -> anyhow::Result<Value> {
            Ok(json!({"path":path,"sha256":hex::encode(Sha256::digest(std::fs::read(path)?))}))
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
    let tls = TlsProcess(tls);
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
    drop(tls);
    task.abort();
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
      'pushRecipients',(SELECT count(*) FROM chat.direct_request_push_event_recipients r WHERE r.request_id=p.request_id)
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
