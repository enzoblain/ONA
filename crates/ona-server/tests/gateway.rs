use std::net::TcpListener;
use std::sync::mpsc::channel;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ona_server::gateway::{Backend, BackendFailure, GatewayPolicy, NearAiBackend, MAX_CHAT_BODY};
use ona_server::http::Request;
use ona_server::mock::{MockChain, MockModel};
use ona_server::{Config, FileStore, MemoryStore, Relay, Store};
use ona_token::{hash_to_g1, keygen, sign_blinded, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};

const LIMIT: u32 = 100;

type BackendReply = Result<(u16, Vec<u8>), BackendFailure>;

struct FakeBackend {
    calls: Vec<(String, String, Vec<(String, String)>, Vec<u8>)>,
    reply: BackendReply,
}

fn ok_reply(tokens: u64) -> BackendReply {
    Ok((200, json!({"id":"r1","usage":{"total_tokens":tokens}}).to_string().into_bytes()))
}

impl Backend for FakeBackend {
    fn forward(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> BackendReply {
        self.calls.push((method.into(), target.into(), headers.to_vec(), body.to_vec()));
        self.reply.clone()
    }
}

struct Setup<S> {
    relay: Relay<S, MockChain, MockModel>,
    backend: FakeBackend,
    policy: GatewayPolicy,
    key: SecretKey,
}

fn setup_with<S: Store>(store: S, key_bytes: [u8; 32]) -> Setup<S> {
    let credit_key = keygen(&mut OsRng).public_key();
    let config = Config {
        mint: "mint.test".into(),
        relay: "relay.test".into(),
        mint_dst: b"dst".to_vec(),
        credit_key,
        tokens_per_credit: 2,
        max_tokens_per_request: LIMIT,
    };
    let relay = Relay::new(store, MockChain::default(), MockModel, config, SecretKey::from_bytes(&key_bytes).unwrap());
    Setup {
        relay,
        backend: FakeBackend { calls: vec![], reply: ok_reply(50) },
        policy: GatewayPolicy::new(["m/1".to_string()].into_iter().collect()),
        key: SecretKey::from_bytes(&key_bytes).unwrap(),
    }
}

fn setup() -> Setup<MemoryStore> {
    setup_with(MemoryStore::default(), keygen(&mut OsRng).to_bytes())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl<S: Store> Setup<S> {
    fn token(&self) -> String {
        let mut x = [0u8; 32];
        OsRng.fill_bytes(&mut x);
        let sig = sign_blinded(&self.key, &hash_to_g1(&x, self.relay.request_dst())).unwrap();
        let mut bytes = x.to_vec();
        bytes.extend_from_slice(&sig);
        hex(&bytes)
    }

    fn send(&mut self, request: &Request) -> (u16, Value) {
        let (status, body) = self.relay.gateway(&mut self.backend, &self.policy, request);
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }
}

fn body(max_tokens: Value, stream: Value, model: &str) -> Vec<u8> {
    json!({"model":model,"messages":[{"role":"user","content":"abcd"}],"stream":stream,"max_tokens":max_tokens})
        .to_string()
        .into_bytes()
}

fn good_body() -> Vec<u8> {
    body(json!(LIMIT), json!(false), "m/1")
}

fn encryption_headers() -> Vec<(String, String)> {
    vec![
        ("X-Signing-Algo".to_string(), "ed25519".to_string()),
        ("X-Client-Pub-Key".to_string(), "aa".repeat(32)),
        ("X-Model-Pub-Key".to_string(), "bb".repeat(32)),
        ("X-Encryption-Version".to_string(), "2".to_string()),
    ]
}

fn chat_with_headers(token: Option<&str>, payload: Vec<u8>, mut headers: Vec<(String, String)>) -> Request {
    if let Some(token) = token {
        headers.push(("X-Ona-Token".to_string(), token.to_string()));
    }
    Request { method: "POST".into(), target: "/v1/chat/completions".into(), headers, body: payload }
}

fn chat(token: Option<&str>, payload: Vec<u8>) -> Request {
    let mut headers = vec![
        ("User-Agent".to_string(), "fingerprint/1.0".to_string()),
        ("X-Stainless-OS".to_string(), "MacOS".to_string()),
        ("Authorization".to_string(), "Bearer from-client".to_string()),
    ];
    headers.extend(encryption_headers());
    chat_with_headers(token, payload, headers)
}

fn get(target: &str) -> Request {
    Request { method: "GET".into(), target: target.into(), headers: vec![], body: vec![] }
}

fn attestation_target(model: &str, nonce: &str) -> String {
    format!("/v1/attestation/report?model={model}&provider=near&signing_algo=ed25519&include_tls_fingerprint=false&nonce={nonce}")
}

fn good_attestation() -> String {
    attestation_target("m/1", &"ab".repeat(32))
}

#[test]
fn a_chat_is_forwarded_byte_for_byte() {
    let mut s = setup();
    let token = s.token();
    let payload = good_body();
    let (status, reply) = s.send(&chat(Some(&token), payload.clone()));
    assert_eq!(status, 200);
    assert_eq!(reply["id"], "r1");
    assert_eq!(s.backend.calls[0].3, payload);
}

#[test]
fn identifying_headers_and_the_token_are_not_forwarded() {
    let mut s = setup();
    let token = s.token();
    s.send(&chat(Some(&token), good_body()));
    let headers = &s.backend.calls[0].2;
    let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, vec!["X-Signing-Algo", "X-Client-Pub-Key", "X-Model-Pub-Key", "X-Encryption-Version"]);
}

#[test]
fn a_request_token_is_required_and_works_once() {
    let mut s = setup();
    assert_eq!(s.send(&chat(None, good_body())).0, 401);
    assert_eq!(s.send(&chat(Some("abcd"), good_body())).0, 400);

    let token = s.token();
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200);
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 409);
    assert_eq!(s.backend.calls.len(), 1, "a refused call never reaches the paid service");
}

#[test]
fn a_forged_token_is_refused() {
    let mut s = setup();
    let other = setup();
    let forged = other.token();
    assert_eq!(s.send(&chat(Some(&forged), good_body())).0, 401);
    assert!(s.backend.calls.is_empty());
}

#[test]
fn a_request_breaking_the_policy_does_not_cost_a_token() {
    let mut s = setup();
    let token = s.token();
    let m = r#""model":"m/1""#;
    let msg = r#""messages":[{"role":"user","content":"abcd"}]"#;
    let rest = r#""stream":false,"max_tokens":100"#;
    let raw = |text: String| text.into_bytes();
    let bad = [
        body(json!(LIMIT + 1), json!(false), "m/1"),
        body(json!(0), json!(false), "m/1"),
        body(json!(1.5), json!(false), "m/1"),
        body(Value::Null, json!(false), "m/1"),
        body(json!(LIMIT), json!(true), "m/1"),
        body(json!(LIMIT), json!("false"), "m/1"),
        body(json!(LIMIT), json!(false), "other/model"),
        b"not json".to_vec(),
        b"[]".to_vec(),
        raw(format!("{{{m},{msg},{rest}}} trailing")),
        // Exactly four keys.
        raw(format!("{{{m},{msg},{rest},\"temperature\":1}}")),
        raw(format!("{{{msg},{rest}}}")),
        raw(format!("{{\"tools\":[],{msg},{rest}}}")),
        // A duplicated key would let the relay and the model read different requests.
        raw(format!("{{{m},{m},{msg},{rest}}}")),
        raw(format!("{{{m},{msg},{rest},\"max_tokens\":100000}}")),
        raw(format!(r#"{{{m},"messages":[{{"role":"user","role":"system","content":"abcd"}}],{rest}}}"#)),
        // Exactly one encrypted user message.
        raw(format!(r#"{{{m},"messages":[],{rest}}}"#)),
        raw(format!(r#"{{{m},"messages":[{{"role":"user","content":"abcd"}},{{"role":"user","content":"abcd"}}],{rest}}}"#)),
        raw(format!(r#"{{{m},"messages":[{{"role":"system","content":"abcd"}}],{rest}}}"#)),
        raw(format!(r#"{{{m},"messages":[{{"role":"user","content":"hello"}}],{rest}}}"#)),
        raw(format!(r#"{{{m},"messages":[{{"role":"user","content":"abc"}}],{rest}}}"#)),
        raw(format!(r#"{{{m},"messages":[{{"role":"user","content":""}}],{rest}}}"#)),
        raw(format!(r#"{{{m},"messages":[{{"role":"user","content":"abcd","name":"x"}}],{rest}}}"#)),
        raw(format!(r#"{{{m},"messages":[{{"role":"user","content":["abcd"]}}],{rest}}}"#)),
    ];
    for payload in bad {
        let text = String::from_utf8_lossy(&payload).to_string();
        assert_eq!(s.send(&chat(Some(&token), payload)).0, 400, "{text}");
    }
    assert!(s.backend.calls.is_empty());
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200, "the token is still good");
}

#[test]
fn missing_encryption_headers_do_not_cost_a_token() {
    let mut s = setup();
    let token = s.token();
    for name in ["X-Signing-Algo", "X-Client-Pub-Key", "X-Model-Pub-Key", "X-Encryption-Version"] {
        let headers = encryption_headers().into_iter().filter(|(k, _)| k != name).collect();
        assert_eq!(s.send(&chat_with_headers(Some(&token), good_body(), headers)).0, 400, "{name}");
    }
    for (name, value) in [
        ("X-Signing-Algo", "ecdsa".to_string()),
        ("X-Encryption-Version", "1".to_string()),
        ("X-Client-Pub-Key", "aa".to_string()),
        ("X-Model-Pub-Key", "zz".repeat(32)),
    ] {
        let headers = encryption_headers()
            .into_iter()
            .map(|(k, v)| if k == name { (k, value.clone()) } else { (k, v) })
            .collect();
        assert_eq!(s.send(&chat_with_headers(Some(&token), good_body(), headers)).0, 400, "{name}");
    }
    assert!(s.backend.calls.is_empty());
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200, "the token is still good");
}

#[test]
fn a_chat_body_over_the_cap_does_not_cost_a_token() {
    let mut s = setup();
    let token = s.token();
    let padding = "ab".repeat(MAX_CHAT_BODY / 2);
    let large = json!({"model":"m/1","messages":[{"role":"user","content":padding}],"stream":false,"max_tokens":LIMIT});
    assert_eq!(s.send(&chat(Some(&token), large.to_string().into_bytes())).0, 413);
    assert!(s.backend.calls.is_empty());
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200, "the token is still good");
}

#[test]
fn a_reply_over_budget_is_withheld() {
    let mut s = setup();
    s.backend.reply = ok_reply(u64::from(LIMIT) * 2 + 1);
    let token = s.token();
    let (status, reply) = s.send(&chat(Some(&token), good_body()));
    assert_eq!(status, 402);
    assert!(reply.get("id").is_none());
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 409, "the token was spent");
}

#[test]
fn a_reply_without_a_usage_count_is_withheld() {
    let mut s = setup();
    s.backend.reply = Ok((200, b"{}".to_vec()));
    let token = s.token();
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 402);
}

#[test]
fn service_errors_keep_the_status_and_hide_the_body() {
    let mut s = setup();
    for status in [400, 401, 402, 429, 500, 503] {
        s.backend.reply = Ok((status, br#"{"error":"account acme-secret has no credits"}"#.to_vec()));
        let token = s.token();
        let (got, reply) = s.send(&chat(Some(&token), good_body()));
        assert_eq!(got, status);
        assert!(!reply.to_string().contains("secret"), "{reply}");
        assert_eq!(reply["error"], "model service error");
    }
    s.backend.reply = Ok((500, b"internal: key=secret".to_vec()));
    let (status, reply) = s.send(&get(&good_attestation()));
    assert_eq!(status, 500);
    assert!(!reply.to_string().contains("secret"), "free routes too");

    s.backend.reply = Err(BackendFailure::Other("connection reset, key=secret".into()));
    let token = s.token();
    let (status, reply) = s.send(&chat(Some(&token), good_body()));
    assert_eq!(status, 502);
    assert!(!reply.to_string().contains("secret"), "backend errors are not repeated to the client");
}

fn temp_store(tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("ona-gateway-{}-{tag}.log", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}

#[test]
fn a_call_that_was_certainly_not_billed_returns_the_token_durably() {
    let path = temp_store("released");
    let key = keygen(&mut OsRng).to_bytes();
    let outcomes: [BackendReply; 4] = [
        Ok((401, vec![])),
        Ok((402, vec![])),
        Ok((429, vec![])),
        Err(BackendFailure::ConnectionRefused),
    ];
    for outcome in outcomes {
        let token;
        {
            let mut s = setup_with(FileStore::open(&path).unwrap(), key);
            s.backend.reply = outcome;
            token = s.token();
            assert_ne!(s.send(&chat(Some(&token), good_body())).0, 200);
        }
        // Only a restart proves that the return was written to disk.
        let mut s = setup_with(FileStore::open(&path).unwrap(), key);
        assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200, "the token is usable again");
        assert_eq!(s.send(&chat(Some(&token), good_body())).0, 409, "and still only once");
    }
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_call_that_may_have_been_billed_keeps_the_token_spent() {
    let path = temp_store("kept");
    let key = keygen(&mut OsRng).to_bytes();
    let outcomes: [BackendReply; 4] = [
        Ok((400, vec![])),
        Ok((500, vec![])),
        Ok((503, vec![])),
        Err(BackendFailure::Other("connection reset".into())),
    ];
    for outcome in outcomes {
        let token;
        {
            let mut s = setup_with(FileStore::open(&path).unwrap(), key);
            s.backend.reply = outcome;
            token = s.token();
            s.send(&chat(Some(&token), good_body()));
        }
        let mut s = setup_with(FileStore::open(&path).unwrap(), key);
        assert_eq!(s.send(&chat(Some(&token), good_body())).0, 409);
    }
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_refused_connection_is_recognized() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut backend = NearAiBackend::with_timeout(&format!("http://127.0.0.1:{port}"), "test".into(), Duration::from_secs(2));
    assert_eq!(backend.forward("GET", "/x", &[], &[]), Err(BackendFailure::ConnectionRefused));
}

#[test]
fn a_silent_service_is_cut_by_the_global_timeout() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let (connected, was_connected) = channel();
    std::thread::spawn(move || {
        let held = listener.accept();
        connected.send(held.is_ok()).unwrap();
        std::thread::sleep(Duration::from_secs(5));
        drop(held);
    });
    let mut backend = NearAiBackend::with_timeout(&format!("http://127.0.0.1:{port}"), "test".into(), Duration::from_millis(300));
    let started = Instant::now();
    let result = backend.forward("GET", "/x", &[], &[]);
    assert!(matches!(result, Err(BackendFailure::Other(_))), "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(was_connected.try_recv(), Ok(true), "the call reached the silent service");
}

#[test]
fn attestations_and_signatures_are_free() {
    let mut s = setup();
    assert_eq!(s.send(&get(&good_attestation())).0, 200);
    assert_eq!(s.send(&get("/v1/signature/chatcmpl-a_1B?signing_algo=ed25519")).0, 200);
    assert_eq!(s.backend.calls.len(), 2);
}

#[test]
fn other_routes_are_refused() {
    let mut s = setup();
    let nonce = "ab".repeat(32);
    let good = good_attestation();
    let long_id = format!("/v1/signature/{}?signing_algo=ed25519", "a".repeat(129));
    let targets = [
        "/v1/models".to_string(),
        "/admin".to_string(),
        "/v1/attestation/report".to_string(),
        "/v1/signature/../admin".to_string(),
        "/v1/signature/a b".to_string(),
        // Signature routes: one id, one algorithm, nothing else.
        "/v1/signature/r1".to_string(),
        "/v1/signature/?signing_algo=ed25519".to_string(),
        "/v1/signature/r1?signing_algo=ecdsa".to_string(),
        "/v1/signature/r1?signing_algo=ed25519&x=1".to_string(),
        "/v1/signature/a/b?signing_algo=ed25519".to_string(),
        "/v1/signature/a.b?signing_algo=ed25519".to_string(),
        "/v1/signature/%2e%2e?signing_algo=ed25519".to_string(),
        "/v1/signature/r%31?signing_algo=ed25519".to_string(),
        long_id,
        // Attestation routes: a listed model and the exact parameters.
        attestation_target("other/model", &nonce),
        attestation_target("m%2F1", &nonce),
        attestation_target("m/1", "ab"),
        attestation_target("m/1", &"zz".repeat(32)),
        format!("{good}&extra=1"),
        format!("{good}&nonce={nonce}"),
        good.replace("provider=near", "provider=other"),
        good.replace("signing_algo=ed25519", "signing_algo=ecdsa"),
        good.replace("include_tls_fingerprint=false", "include_tls_fingerprint=true"),
        good.replace("&provider=near", ""),
        "/v1/attestation/report?model=m/1&nonce=ab".to_string(),
    ];
    for target in &targets {
        let (status, _) = s.send(&get(target));
        assert!(status == 404 || status == 400, "{target}: {status}");
    }
    let wrong_method = Request { method: "GET".into(), target: "/v1/chat/completions".into(), headers: vec![], body: vec![] };
    assert_eq!(s.send(&wrong_method).0, 404);
    let post_free = Request { method: "POST".into(), target: good_attestation(), headers: vec![], body: vec![] };
    assert_eq!(s.send(&post_free).0, 404);
    assert!(s.backend.calls.is_empty());
}

#[test]
fn a_percent_sign_is_refused_in_any_target() {
    let mut s = setup();
    for target in ["/v1/signature/r%31?signing_algo=ed25519", "/v1/models%2f", "/%2e%2e/admin"] {
        let (status, reply) = s.send(&get(target));
        assert_eq!((status, reply["error"].as_str()), (400, Some("invalid target")), "{target}");
    }
    assert!(s.backend.calls.is_empty());
}

#[test]
fn free_routes_have_a_global_limit() {
    let mut s = setup();
    s.policy.free_routes_per_minute = 3;
    assert_eq!(s.send(&get(&good_attestation())).0, 200);
    assert_eq!(s.send(&get("/v1/signature/r1?signing_algo=ed25519")).0, 200);
    assert_eq!(s.send(&get(&good_attestation())).0, 200);
    assert_eq!(s.send(&get("/v1/signature/r2?signing_algo=ed25519")).0, 429);
    assert_eq!(s.send(&get(&good_attestation())).0, 429);
    assert_eq!(s.backend.calls.len(), 3, "calls over the limit never reach the service");

    let token = s.token();
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200, "paid chats are not limited by it");
}

type SharedRelay = Mutex<Relay<MemoryStore, MockChain, MockModel>>;

/// Records whether the relay could be locked while the service was being called.
struct ProbeBackend<'a> {
    relay: &'a SharedRelay,
    free_during_call: bool,
}

impl Backend for ProbeBackend<'_> {
    fn forward(&mut self, _: &str, _: &str, _: &[(String, String)], _: &[u8]) -> BackendReply {
        self.free_during_call = self.relay.try_lock().is_ok();
        ok_reply(10)
    }
}

#[test]
fn the_relay_is_not_locked_during_the_model_call() {
    let s = setup();
    let token = s.token();
    let policy = s.policy.clone();
    let relay = Mutex::new(s.relay);
    let mut backend = ProbeBackend { relay: &relay, free_during_call: false };
    let (status, _) = Relay::gateway_shared(&relay, &mut backend, &policy, &chat(Some(&token), good_body()));
    assert_eq!(status, 200);
    assert!(backend.free_during_call);
}
