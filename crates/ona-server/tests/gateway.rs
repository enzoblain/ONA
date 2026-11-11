use std::net::TcpListener;
use std::sync::mpsc::channel;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ona_server::gateway::{
    Backend, BackendFailure, GatewayPolicy, NearAiBackend, ATTESTATIONS_PER_TOKEN, ENCRYPTION_OVERHEAD, MAX_CHAT_BODY,
    SIGNATURES_PER_CHAT, TEMPLATE_TOKENS,
};
use ona_server::http::Request;
use ona_server::mock::{MockChain, MockModel};
use ona_server::{Config, FileStore, MemoryStore, Relay, SharedRelay, Store};
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

const PROMPT: usize = 120;
/// One token over what a chat may consume: reply, largest prompt and chat template.
const OVER: u64 = LIMIT as u64 + PROMPT as u64 + TEMPLATE_TOKENS + 1;

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
        max_prompt_bytes: PROMPT,
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

/// A free route call showing a request token.
fn get_with(target: &str, token: &str) -> Request {
    let mut request = get(target);
    request.headers.push(("X-Ona-Token".to_string(), token.to_string()));
    request
}

fn signature_target(id: &str) -> String {
    format!("/v1/signature/{id}?signing_algo=ed25519")
}

fn store_at(path: &std::path::Path) -> FileStore {
    if path.exists() {
        FileStore::open(path, "test").unwrap()
    } else {
        FileStore::create(path, "test").unwrap()
    }
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
    assert_eq!(
        names,
        vec![
            "Content-Type",
            "X-Signing-Algo",
            "X-Client-Pub-Key",
            "X-Model-Pub-Key",
            "X-Encryption-Version",
            "Accept-Encoding"
        ]
    );
}

#[test]
fn the_relay_sets_the_content_type_and_free_routes_pass_no_client_header() {
    let mut s = setup();
    let token = s.token();
    let mut request = chat(Some(&token), good_body());
    request.headers.push(("Content-Type".to_string(), "text/plain".to_string()));
    assert_eq!(s.send(&request).0, 200);
    let content_types: Vec<&str> =
        s.backend.calls[0].2.iter().filter(|(k, _)| k == "Content-Type").map(|(_, v)| v.as_str()).collect();
    assert_eq!(content_types, vec!["application/json"]);

    let unused = s.token();
    let mut attestation = get_with(&good_attestation(), &unused);
    attestation.headers.extend(encryption_headers());
    assert_eq!(s.send(&attestation).0, 200);
    let names: Vec<&str> = s.backend.calls[1].2.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, vec!["Accept-Encoding"]);
}

#[test]
fn x_no_aliasing_must_be_a_plain_word() {
    let mut s = setup();
    let token = s.token();
    for value in ["", "a b", "x".repeat(17).as_str(), "1;drop"] {
        let mut headers = encryption_headers();
        headers.push(("x-no-aliasing".to_string(), value.to_string()));
        assert_eq!(s.send(&chat_with_headers(Some(&token), good_body(), headers)).0, 400, "{value:?}");
    }
    let mut headers = encryption_headers();
    headers.push(("x-no-aliasing".to_string(), "true".to_string()));
    assert_eq!(s.send(&chat_with_headers(Some(&token), good_body(), headers)).0, 200);
}

#[test]
fn the_service_is_always_asked_for_an_uncompressed_reply() {
    let mut s = setup();
    let token = s.token();
    let mut request = chat(Some(&token), good_body());
    request.headers.push(("Accept-Encoding".to_string(), "gzip, br".to_string()));
    assert_eq!(s.send(&request).0, 200);
    let mut attestation = get_with(&good_attestation(), &s.token());
    attestation.headers.push(("Accept-Encoding".to_string(), "gzip".to_string()));
    assert_eq!(s.send(&attestation).0, 200);
    assert_eq!(s.backend.calls.len(), 2);
    for (_, _, headers, _) in &s.backend.calls {
        let asked: Vec<&str> =
            headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("accept-encoding")).map(|(_, v)| v.as_str()).collect();
        assert_eq!(asked, vec!["identity"], "a compressed reply could not be read and would be withheld after billing");
    }
}

#[test]
fn encryption_versions_2_and_3_are_the_only_ones_passed_on() {
    let mut s = setup();
    for (version, expected) in [("2", 200), ("3", 200), ("1", 400), ("4", 400), ("", 400), ("03", 400), ("3 2", 400)] {
        let token = s.token();
        let headers = encryption_headers()
            .into_iter()
            .map(|(k, v)| if k == "X-Encryption-Version" { (k, version.to_string()) } else { (k, v) })
            .collect();
        assert_eq!(s.send(&chat_with_headers(Some(&token), good_body(), headers)).0, expected, "version {version:?}");
    }
    assert_eq!(s.backend.calls.len(), 2);
}

#[test]
fn the_content_must_be_lowercase_hexadecimal() {
    let mut s = setup();
    let token = s.token();
    for content in ["ABCD", "aBcd", "0x00"] {
        let payload =
            json!({"model":"m/1","messages":[{"role":"user","content":content}],"stream":false,"max_tokens":LIMIT});
        assert_eq!(s.send(&chat(Some(&token), payload.to_string().into_bytes())).0, 400, "{content}");
    }
    assert!(s.backend.calls.is_empty());
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200, "lowercase, as the clients write it");
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
    s.backend.reply = ok_reply(OVER - 1);
    assert_eq!(s.send(&chat(Some(&s.token()), good_body())).0, 200, "the largest prompt and the template fit");
    s.backend.reply = ok_reply(OVER);
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
    let (status, reply) = s.send(&get_with(&good_attestation(), &s.token()));
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
            let mut s = setup_with(store_at(&path), key);
            s.backend.reply = outcome;
            token = s.token();
            assert_ne!(s.send(&chat(Some(&token), good_body())).0, 200);
        }
        // Only a restart proves that the return was written to disk.
        let mut s = setup_with(store_at(&path), key);
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
            let mut s = setup_with(store_at(&path), key);
            s.backend.reply = outcome;
            token = s.token();
            s.send(&chat(Some(&token), good_body()));
        }
        let mut s = setup_with(store_at(&path), key);
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
fn attestations_and_signatures_cost_no_token() {
    let mut s = setup();
    let token = s.token();
    assert_eq!(s.send(&get_with(&good_attestation(), &token)).0, 200);
    s.backend.reply = Ok((200, json!({"id":"chatcmpl-a_1B","usage":{"total_tokens":10}}).to_string().into_bytes()));
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200, "the token shown for the attestation is still unused");
    assert_eq!(s.send(&get_with(&signature_target("chatcmpl-a_1B"), &token)).0, 200);
    assert_eq!(s.backend.calls.len(), 3);
}

#[test]
fn an_attestation_needs_an_unused_request_token_and_each_gives_a_few() {
    let mut s = setup();
    assert_eq!(s.send(&get(&good_attestation())).0, 401, "anonymous calls are refused");
    assert_eq!(s.send(&get_with(&good_attestation(), &setup().token())).0, 401, "a forged token too");

    let token = s.token();
    for _ in 0..ATTESTATIONS_PER_TOKEN {
        assert_eq!(s.send(&get_with(&good_attestation(), &token)).0, 200);
    }
    assert_eq!(s.send(&get_with(&good_attestation(), &token)).0, 429);

    let spent = s.token();
    assert_eq!(s.send(&chat(Some(&spent), good_body())).0, 200);
    assert_eq!(s.send(&get_with(&good_attestation(), &spent)).0, 409, "a spent token gives no attestation");
    assert_eq!(s.backend.calls.len(), usize::from(ATTESTATIONS_PER_TOKEN) + 1);
}

#[test]
fn a_signature_needs_the_token_of_the_chat_it_signs() {
    let mut s = setup();
    let other = s.token();
    assert_eq!(s.send(&get(&signature_target("r1"))).0, 401);
    assert_eq!(s.send(&get_with(&signature_target("r1"), &other)).0, 401, "an unused token is no ticket");

    let paid = s.token();
    assert_eq!(s.send(&chat(Some(&paid), good_body())).0, 200);
    assert_eq!(s.send(&get_with(&signature_target("r2"), &paid)).0, 401, "only for its own reply");
    for _ in 0..SIGNATURES_PER_CHAT {
        assert_eq!(s.send(&get_with(&signature_target("r1"), &paid)).0, 200);
    }
    assert_eq!(s.send(&get_with(&signature_target("r1"), &paid)).0, 429);
    assert_eq!(s.backend.calls.len(), 1 + usize::from(SIGNATURES_PER_CHAT));
}

#[test]
fn a_withheld_reply_gives_no_signature_ticket() {
    let mut s = setup();
    s.backend.reply = ok_reply(OVER);
    let token = s.token();
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 402);
    assert_eq!(s.send(&get_with(&signature_target("r1"), &token)).0, 401);
}

#[test]
fn a_reply_without_an_id_gives_no_signature_ticket() {
    let mut s = setup();
    s.backend.reply = Ok((200, json!({"usage":{"total_tokens":10}}).to_string().into_bytes()));
    let token = s.token();
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200);
    assert_eq!(s.send(&get_with(&signature_target("anything"), &token)).0, 401, "no reply id, so nothing to sign");
}

#[test]
fn a_signature_the_service_did_not_answer_is_not_counted() {
    let mut s = setup();
    let paid = s.token();
    assert_eq!(s.send(&chat(Some(&paid), good_body())).0, 200);
    s.backend.reply = Ok((503, vec![]));
    for _ in 0..10 {
        assert_eq!(s.send(&get_with(&signature_target("r1"), &paid)).0, 503);
    }
    s.backend.reply = ok_reply(10);
    for _ in 0..SIGNATURES_PER_CHAT {
        assert_eq!(s.send(&get_with(&signature_target("r1"), &paid)).0, 200, "failed fetches used none of the four");
    }
}

#[test]
fn a_token_returned_after_an_unbilled_chat_keeps_its_attestation_count() {
    let mut s = setup();
    let token = s.token();
    for _ in 0..ATTESTATIONS_PER_TOKEN {
        assert_eq!(s.send(&get_with(&good_attestation(), &token)).0, 200);
    }
    s.backend.reply = Ok((429, vec![]));
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 429, "not billed, so the token comes back");
    s.backend.reply = ok_reply(10);
    assert_eq!(
        s.send(&get_with(&good_attestation(), &token)).0,
        429,
        "returning the token does not give it fresh attestations"
    );
}

#[test]
fn a_spent_token_loses_its_attestation_count_and_its_attestations() {
    let mut s = setup();
    let token = s.token();
    for _ in 0..ATTESTATIONS_PER_TOKEN {
        assert_eq!(s.send(&get_with(&good_attestation(), &token)).0, 200);
    }
    assert_eq!(s.send(&get_with(&good_attestation(), &token)).0, 429, "the count does not reset by itself");
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200, "attestations do not spend the token");
    assert_eq!(s.send(&get_with(&good_attestation(), &token)).0, 409, "once spent, none at all");
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
fn attestations_have_a_global_limit_that_never_stops_a_paid_signature() {
    let mut s = setup();
    s.policy.free_routes_per_minute = 3;
    for _ in 0..3 {
        assert_eq!(s.send(&get_with(&good_attestation(), &s.token())).0, 200);
    }
    assert_eq!(s.send(&get_with(&good_attestation(), &s.token())).0, 429, "one client cannot take more");
    assert_eq!(s.backend.calls.len(), 3, "calls over the limit never reach the service");

    let token = s.token();
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 200, "paid chats are not limited by it");
    assert_eq!(s.send(&get_with(&signature_target("r1"), &token)).0, 200, "nor the signature a chat paid for");
}

#[test]
fn a_message_longer_than_the_budget_is_refused_before_the_token_is_spent() {
    let mut s = setup();
    let token = s.token();
    let fits = "ab".repeat(PROMPT + ENCRYPTION_OVERHEAD);
    let over = "ab".repeat(PROMPT + ENCRYPTION_OVERHEAD + 1);
    let payload = |content: &str| {
        json!({"model":"m/1","messages":[{"role":"user","content":content}],"stream":false,"max_tokens":LIMIT})
            .to_string()
            .into_bytes()
    };
    let (status, reply) = s.send(&chat(Some(&token), payload(&over)));
    assert_eq!((status, reply["error"].as_str()), (413, Some("message too long for the request budget")));
    assert!(s.backend.calls.is_empty(), "the service is never paid for it");
    assert_eq!(s.send(&chat(Some(&token), payload(&fits))).0, 200, "the token is still good");
}

#[test]
fn a_redirect_from_the_service_is_not_followed() {
    let elsewhere = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let elsewhere_port = elsewhere.local_addr().unwrap().port();
    elsewhere.set_nonblocking(true).unwrap();
    let service = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = service.local_addr().unwrap().port();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        if let Ok((mut stream, _)) = service.accept() {
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let reply = format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:{elsewhere_port}/steal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    let mut backend = NearAiBackend::with_timeout(&format!("http://127.0.0.1:{port}"), "test".into(), Duration::from_secs(2));
    let _ = backend.forward("POST", "/v1/chat/completions", &[], b"ciphertext");
    std::thread::sleep(Duration::from_millis(100));
    assert!(elsewhere.accept().is_err(), "the encrypted body must not be sent to another host");
}

type Locked = Mutex<Relay<MemoryStore, MockChain, MockModel>>;

/// Records whether the relay could be locked while the service was being called.
struct ProbeBackend<'a> {
    relay: &'a Locked,
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
    let shared = SharedRelay::new(s.relay);
    let mut backend = ProbeBackend { relay: shared.state(), free_during_call: false };
    let (status, _) = shared.gateway(&mut backend, &policy, &chat(Some(&token), good_body()));
    assert_eq!(status, 200);
    assert!(backend.free_during_call);
}

#[test]
fn a_request_token_is_checked_without_locking_the_relay() {
    let s = setup();
    let forged = setup().token();
    let policy = s.policy.clone();
    let shared = SharedRelay::new(s.relay);

    let held = shared.state().lock().unwrap();
    let (done, finished) = channel();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut backend = FakeBackend { calls: vec![], reply: ok_reply(10) };
            done.send(shared.gateway(&mut backend, &policy, &chat(Some(&forged), good_body())).0).unwrap();
            done.send(shared.gateway(&mut backend, &policy, &chat(Some(&forged), b"[]".to_vec())).0).unwrap();
        });
        let first = finished.recv_timeout(Duration::from_secs(10));
        let second = finished.recv_timeout(Duration::from_secs(10));
        drop(held);
        assert_eq!(first, Ok(401), "the token signature must be checked while the relay is locked elsewhere");
        assert_eq!(second, Ok(400), "and the chat policy too");
    });
}

#[test]
fn a_poisoned_relay_answers_503() {
    let s = setup();
    let token = s.token();
    let policy = s.policy.clone();
    let shared = SharedRelay::new(s.relay);
    let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = shared.state().lock().unwrap();
        panic!("simulated panic while the relay is locked");
    }));
    assert!(poisoned.is_err());

    let mut backend = FakeBackend { calls: vec![], reply: ok_reply(10) };
    let (status, body) = shared.gateway(&mut backend, &policy, &chat(Some(&token), good_body()));
    assert_eq!(status, 503);
    assert_eq!(serde_json::from_slice::<Value>(&body).unwrap()["error"], "relay unavailable");
    assert!(backend.calls.is_empty(), "nothing is sent for a relay whose state is unknown");
}
