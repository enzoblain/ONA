use ona_server::gateway::{Backend, GatewayPolicy};
use ona_server::http::Request;
use ona_server::mock::{MockChain, MockModel};
use ona_server::{Config, MemoryStore, Relay};
use ona_token::{hash_to_g1, keygen, sign_blinded, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};

const LIMIT: u32 = 100;

struct FakeBackend {
    calls: Vec<(String, String, Vec<(String, String)>, Vec<u8>)>,
    reply: Result<(u16, Vec<u8>), String>,
}

fn ok_reply(tokens: u64) -> Result<(u16, Vec<u8>), String> {
    Ok((200, json!({"id":"r1","usage":{"total_tokens":tokens}}).to_string().into_bytes()))
}

impl Backend for FakeBackend {
    fn forward(
        &mut self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), String> {
        self.calls.push((method.into(), target.into(), headers.to_vec(), body.to_vec()));
        self.reply.clone()
    }
}

struct Setup {
    relay: Relay<MemoryStore, MockChain, MockModel>,
    backend: FakeBackend,
    policy: GatewayPolicy,
    key: SecretKey,
}

fn setup() -> Setup {
    let credit_key = keygen(&mut OsRng).public_key();
    let config = Config {
        mint: "mint.test".into(),
        relay: "relay.test".into(),
        mint_dst: b"dst".to_vec(),
        credit_key,
        tokens_per_credit: 2,
        max_tokens_per_request: LIMIT,
    };
    let bytes = keygen(&mut OsRng).to_bytes();
    let relay = Relay::new(
        MemoryStore::default(),
        MockChain::default(),
        MockModel,
        config,
        SecretKey::from_bytes(&bytes).unwrap(),
    );
    let policy = GatewayPolicy { models: ["m/1".to_string()].into_iter().collect() };
    Setup {
        relay,
        backend: FakeBackend { calls: vec![], reply: ok_reply(50) },
        policy,
        key: SecretKey::from_bytes(&bytes).unwrap(),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Setup {
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

fn chat(token: Option<&str>, payload: Vec<u8>) -> Request {
    let mut headers = vec![
        ("User-Agent".to_string(), "fingerprint/1.0".to_string()),
        ("X-Stainless-OS".to_string(), "MacOS".to_string()),
        ("X-Client-Pub-Key".to_string(), "aa".to_string()),
        ("Authorization".to_string(), "Bearer from-client".to_string()),
    ];
    if let Some(token) = token {
        headers.push(("X-Ona-Token".to_string(), token.to_string()));
    }
    Request { method: "POST".into(), target: "/v1/chat/completions".into(), headers, body: payload }
}

fn get(target: &str) -> Request {
    Request { method: "GET".into(), target: target.into(), headers: vec![], body: vec![] }
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
    assert_eq!(names, vec!["X-Client-Pub-Key"]);
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
    let bad = [
        body(json!(LIMIT + 1), json!(false), "m/1"),
        body(json!(0), json!(false), "m/1"),
        body(Value::Null, json!(false), "m/1"),
        body(json!(LIMIT), json!(true), "m/1"),
        body(json!(LIMIT), json!(false), "other/model"),
        b"not json".to_vec(),
    ];
    for payload in bad {
        assert_eq!(s.send(&chat(Some(&token), payload)).0, 400);
    }
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
fn service_errors_are_passed_on_and_failures_reported() {
    let mut s = setup();
    s.backend.reply = Ok((402, br#"{"error":"no credits"}"#.to_vec()));
    let token = s.token();
    assert_eq!(s.send(&chat(Some(&token), good_body())).0, 402);

    s.backend.reply = Err("connection reset, key=secret".into());
    let token = s.token();
    let (status, reply) = s.send(&chat(Some(&token), good_body()));
    assert_eq!(status, 502);
    assert!(!reply.to_string().contains("secret"), "backend errors are not repeated to the client");
}

#[test]
fn attestations_and_signatures_are_free() {
    let mut s = setup();
    assert_eq!(s.send(&get("/v1/attestation/report?model=m&nonce=ab")).0, 200);
    assert_eq!(s.send(&get("/v1/signature/r1?signing_algo=ed25519")).0, 200);
    assert_eq!(s.backend.calls.len(), 2);
}

#[test]
fn other_routes_are_refused() {
    let mut s = setup();
    for target in ["/v1/models", "/admin", "/v1/attestation/report", "/v1/signature/../admin", "/v1/signature/a b"] {
        let (status, _) = s.send(&get(target));
        assert!(status == 404 || status == 400, "{target}: {status}");
    }
    let wrong_method = Request { method: "GET".into(), target: "/v1/chat/completions".into(), headers: vec![], body: vec![] };
    assert_eq!(s.send(&wrong_method).0, 404);
    assert!(s.backend.calls.is_empty());
}
