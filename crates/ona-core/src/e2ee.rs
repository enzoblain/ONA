//! End-to-end encrypted chat with NEAR AI Cloud, through a relay that holds the API key.
//!
//! Uses encryption version 3 by default, written from the public `nearai/inference-proxy` sources
//! as read on 2026-11-10 and tested only against a simulated enclave. Whether the NEAR AI gateway
//! accepts version 3 is not verified. Version 2, checked with a real model call on 2026-11-10, is
//! used only when asked for with `with_encryption_version`. A failed call never falls back to it.
//! The relay sees ciphertext, the model name, the token limit and the usage counters.
//!
//! Version 3 binds each encrypted request field to the reply key, so a relay replacing
//! `X-Client-Pub-Key` makes the decryption of the request fail inside the enclave. It does not:
//! - bind a reply to one precise request, and a replay carrying the original reply key is still
//!   processed;
//! - hide sizes and counters from the relay.
//!
//! In version 2 a dishonest relay can replace `X-Client-Pub-Key` and read the reply: the signed
//! text covers the request and response bytes, not that header. The prompt stays confidential. The
//! swap can show up afterwards, as a validly signed reply this client cannot decrypt, reported with
//! `DISHONEST_RELAY_ALERT`. By then the relay has already read that reply, and a relay that returns
//! an error instead is not detected at all.
//!
//! In both versions the relay sees the length of each prompt and reply. Nothing is padded here:
//! nothing verified shows that the enclave removes padding, so it would reach the model as part of
//! the prompt.
//!
//! Not done here: verifying the Intel TDX and NVIDIA quotes. Until that check is added, the key
//! returned by `attested_model_key` is only as trustworthy as the party that returned the report:
//! a relay that answers with its own key reads every prompt and can write every reply, signed
//! "validly" with that key. Nothing here can detect it.

use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroizing;

const INFO: &[u8] = b"ed25519_encryption";
const HEADER_LEN: usize = 32 + 24;
const REQUEST_AAD_PREFIX_V3: &[u8] = b"nearai-e2ee-request-v3";
const ED25519_SUITE_V3: u8 = 0x02;
/// Label of a message's content in the version 3 associated data.
pub const MESSAGE_CONTENT_FIELD: &str = "messages[].content";
/// Most tokens one reply may use, thinking included. Every real call costs credits.
pub const DEFAULT_MAX_TOKENS: u32 = 512;
/// Starts the error returned when the model signed a reply that this client cannot decrypt.
pub const DISHONEST_RELAY_ALERT: &str = "ALERT: dishonest relay suspected";
/// Limit on one whole HTTP exchange, so a silent relay cannot hang the client.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// A paid reply is lost without its signature, so a failed fetch is worth repeating.
const SIGNATURE_ATTEMPTS: u32 = 8;
/// First wait between attempts. It doubles up to `MAX_SIGNATURE_RETRY_DELAY`: about 30 s in all.
const SIGNATURE_RETRY_DELAY: Duration = Duration::from_millis(500);
const MAX_SIGNATURE_RETRY_DELAY: Duration = Duration::from_secs(8);
/// Smallest ciphertext this protocol can produce: peer key, nonce, tag and at least one byte.
const MIN_CIPHERTEXT_LEN: usize = HEADER_LEN + 16 + 1;
/// Added to the prompt estimate for the role markers the model's template wraps around it.
const PROMPT_OVERHEAD_TOKENS: u64 = 16;
/// Longest reply id accepted before it goes into a request path and the journal.
const MAX_REPLY_ID_LEN: usize = 128;

/// A reply id goes into `/v1/signature/{id}` and the journal: letters, digits, `-`, `_`, `.` only.
fn reply_id_is_acceptable(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_REPLY_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && id != "."
        && id != ".."
}

/// Deliberately high estimate of the tokens in a prompt: one per byte.
fn estimate_prompt_tokens(prompt: &str) -> u64 {
    (prompt.len() as u64).saturating_add(PROMPT_OVERHEAD_TOKENS)
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    to_hex(&Sha256::digest(data))
}

/// The key is wiped from memory when it goes out of scope.
fn derive_key(shared: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(INFO, key.as_mut())
        .expect("32 bytes is a valid HKDF output length");
    key
}

fn ed_public_to_x25519(ed_public: &[u8; 32]) -> Result<[u8; 32], String> {
    let key = VerifyingKey::from_bytes(ed_public).map_err(|_| "invalid ed25519 key".to_string())?;
    if key.is_weak() {
        return Err("weak ed25519 key".into());
    }
    Ok(key.to_montgomery().to_bytes())
}

/// Which NEAR AI encryption protocol a client speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionVersion {
    V2,
    V3,
}

impl EncryptionVersion {
    fn header(self) -> &'static str {
        match self {
            Self::V2 => "2",
            Self::V3 => "3",
        }
    }
}

/// Associated data of one version 3 request field, which binds it to the ed25519 reply key.
pub fn request_aad_v3(reply_key_ed: &[u8; 32], field: &str) -> Vec<u8> {
    let mut aad = REQUEST_AAD_PREFIX_V3.to_vec();
    aad.push(ED25519_SUITE_V3);
    aad.extend_from_slice(reply_key_ed);
    aad.push(0x00);
    aad.extend_from_slice(field.as_bytes());
    aad
}

/// Encrypts to an ed25519 public key. Output: ephemeral public key, nonce, ciphertext.
pub fn encrypt_to(recipient_ed: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    encrypt_with_aad(recipient_ed, plaintext, &[])
}

/// As `encrypt_to`, with a new ephemeral key and nonce and the given associated data.
pub fn encrypt_with_aad(recipient_ed: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let recipient = XPublic::from(ed_public_to_x25519(recipient_ed)?);
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err("key exchange produced a low-order result".into());
    }
    let key = derive_key(shared.as_bytes());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = XPublic::from(&ephemeral).as_bytes().to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// One key pair per request, so two requests cannot be linked through a client key.
pub struct ClientKey(SigningKey);

impl ClientKey {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() <= HEADER_LEN {
            return Err("ciphertext too short".into());
        }
        let peer: [u8; 32] = blob[..32].try_into().map_err(|_| "bad peer key".to_string())?;
        let secret = StaticSecret::from(*Zeroizing::new(self.0.to_scalar_bytes()));
        let shared = secret.diffie_hellman(&XPublic::from(peer));
        if !shared.was_contributory() {
            return Err("key exchange produced a low-order result".into());
        }
        let key = derive_key(shared.as_bytes());
        XChaCha20Poly1305::new(key.as_ref().into())
            .decrypt(XNonce::from_slice(&blob[32..56]), &blob[56..])
            .map_err(|_| "reply cannot be decrypted".to_string())
    }
}

/// Picks the model key from an attestation report, for the attestation answering our nonce.
pub fn attested_model_key(report: &Value, nonce: &str) -> Result<[u8; 32], String> {
    let attestations = report["model_attestations"].as_array().ok_or("report has no model attestation")?;
    let matching = attestations
        .iter()
        .find(|a| a["request_nonce"].as_str() == Some(nonce))
        .ok_or("no attestation answers our nonce: the report may be replayed")?;
    let key: [u8; 32] = matching["signing_public_key"]
        .as_str()
        .and_then(from_hex)
        .and_then(|k| k.try_into().ok())
        .ok_or("attested model key is not 32 bytes")?;
    ed_public_to_x25519(&key)?;
    Ok(key)
}

/// Checks that the attested model signed exactly the bytes sent and received. Only a signature
/// from the model's own enclave key counts: a signature by the gateway proves nothing about it.
pub fn verify_reply_signature(
    signature: &Value,
    model: &str,
    request_body: &[u8],
    response_body: &[u8],
    model_key: &[u8; 32],
) -> Result<(), String> {
    if signature["signature_kind"].as_str() != Some("provider_tee") {
        return Err("reply is not signed by the model's enclave".into());
    }
    let signer: [u8; 32] = signature["signing_address"]
        .as_str()
        .and_then(from_hex)
        .and_then(|k| k.try_into().ok())
        .ok_or("bad signer key")?;
    if &signer != model_key {
        return Err("signer is not the attested model key".into());
    }
    let text = signature["text"].as_str().ok_or("signature has no text")?;
    let expected = format!("{model}:{}:{}", sha256_hex(request_body), sha256_hex(response_body));
    if text != expected {
        return Err("signed text does not match the bytes sent and received".into());
    }
    let bytes: [u8; 64] = signature["signature"]
        .as_str()
        .and_then(from_hex)
        .and_then(|s| s.try_into().ok())
        .ok_or("bad signature encoding")?;
    VerifyingKey::from_bytes(&signer)
        .map_err(|_| "invalid signer key".to_string())?
        .verify_strict(text.as_bytes(), &Signature::from_bytes(&bytes))
        .map_err(|_| "signature is invalid".to_string())
}

pub trait Transport {
    /// Returns the status and the exact bytes of the body.
    fn get(&mut self, path: &str, headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String>;
    fn post(&mut self, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String>;
    /// Called before the requests of one model call (attestation, completion, signature). Through Tor, they then share
    /// one circuit, and the next call gets a new one. Nothing to do elsewhere.
    fn new_call(&mut self) -> Result<(), String> {
        Ok(())
    }
}

impl<T: Transport> Transport for &mut T {
    fn get(&mut self, path: &str, headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        (**self).get(path, headers)
    }
    fn post(&mut self, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        (**self).post(path, headers, body)
    }
    fn new_call(&mut self) -> Result<(), String> {
        (**self).new_call()
    }
}

/// HTTP to a relay. Compression is off because the signature covers the exact bytes. Proxies from
/// the environment (`HTTP_PROXY`, `ALL_PROXY`...) are ignored and redirects are not followed, so the
/// request token goes only to the configured relay. No `User-Agent` header is sent.
pub struct HttpTransport {
    base: String,
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new(base: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .user_agent(ureq::config::AutoHeaderValue::None)
            .http_status_as_error(false)
            .timeout_global(Some(REQUEST_TIMEOUT))
            .build()
            .into();
        Self { base: base.trim_end_matches('/').to_string(), agent }
    }
}

impl Transport for HttpTransport {
    fn get(&mut self, path: &str, headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        let mut request = self.agent.get(format!("{}{path}", self.base));
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let mut response = request.call().map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let body = response.body_mut().read_to_vec().map_err(|e| e.to_string())?;
        Ok((status, body))
    }

    fn post(&mut self, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        let mut request = self.agent.post(format!("{}{path}", self.base));
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let mut response = request.send(body).map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let reply = response.body_mut().read_to_vec().map_err(|e| e.to_string())?;
        Ok((status, reply))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatReply {
    pub content: String,
    pub tokens_used: u32,
}

pub struct E2eeClient<T> {
    transport: T,
    model: String,
    max_tokens: u32,
    token_budget: u64,
    spent: u64,
    signature_retry_delay: Duration,
    version: EncryptionVersion,
}

fn base_headers() -> Vec<(String, String)> {
    vec![
        ("x-no-aliasing".to_string(), "true".to_string()),
        ("Accept-Encoding".to_string(), "identity".to_string()),
    ]
}

/// The base headers, plus the request token when the call goes through the relay.
fn token_headers(token: Option<&str>) -> Vec<(String, String)> {
    let mut headers = base_headers();
    if let Some(token) = token {
        headers.push(("X-Ona-Token".to_string(), token.to_string()));
    }
    headers
}

impl<T: Transport> E2eeClient<T> {
    /// `token_budget` is a hard stop on the tokens this client may spend, across all its calls.
    pub fn new(transport: T, model: &str, max_tokens: u32, token_budget: u64) -> Self {
        Self {
            transport,
            model: model.to_string(),
            max_tokens,
            token_budget,
            spent: 0,
            signature_retry_delay: SIGNATURE_RETRY_DELAY,
            version: EncryptionVersion::V3,
        }
    }

    /// Explicit configuration only: the client never changes version by itself after a failure.
    pub fn with_encryption_version(mut self, version: EncryptionVersion) -> Self {
        self.version = version;
        self
    }

    pub fn tokens_spent(&self) -> u64 {
        self.spent
    }

    /// Through the relay, an attestation needs the request token about to be spent: the relay checks
    /// it is unused, without spending it.
    fn fetch_model_key(&mut self, token: Option<&str>) -> Result<[u8; 32], String> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let nonce = to_hex(&bytes);
        let path = format!(
            "/v1/attestation/report?model={}&provider=near&signing_algo=ed25519&include_tls_fingerprint=false&nonce={nonce}",
            self.model
        );
        let (status, body) = self.transport.get(&path, &token_headers(token))?;
        if status != 200 {
            return Err(format!("attestation request failed with status {status}"));
        }
        let report: Value = serde_json::from_slice(&body).map_err(|_| "attestation is not JSON".to_string())?;
        attested_model_key(&report, &nonce)
    }

    /// Sends one prompt, paid with a request token bought from the relay.
    pub fn chat_with_token(&mut self, prompt: &str, token: &str) -> Result<ChatReply, String> {
        self.send_chat(prompt, Some(token))
    }

    pub fn chat(&mut self, prompt: &str) -> Result<ChatReply, String> {
        self.send_chat(prompt, None)
    }

    /// Retries anything but a usable signature. It may not be ready at once, and a paid reply is
    /// lost without it. Through the relay, it needs the request token spent on the chat.
    fn fetch_signature(&mut self, id: &str, token: Option<&str>) -> Result<Value, String> {
        let path = format!("/v1/signature/{id}?signing_algo=ed25519");
        let mut last_error = String::new();
        let mut delay = self.signature_retry_delay;
        for attempt in 0..SIGNATURE_ATTEMPTS {
            if attempt > 0 {
                std::thread::sleep(delay);
                delay = (delay * 2).min(MAX_SIGNATURE_RETRY_DELAY);
            }
            match self.transport.get(&path, &token_headers(token)) {
                Ok((200, body)) => match serde_json::from_slice::<Value>(&body) {
                    Ok(value) if value["signature"].is_string() => return Ok(value),
                    Ok(_) => last_error = "signature is not ready".to_string(),
                    Err(_) => last_error = "signature is not JSON".to_string(),
                },
                Ok((status, _)) => last_error = format!("signature request failed with status {status}"),
                Err(e) => last_error = format!("signature request failed: {e}"),
            }
        }
        Err(format!("{last_error}, after {SIGNATURE_ATTEMPTS} attempts"))
    }

    /// A deliberately high estimate of the cost is reserved before the request leaves and stays
    /// reserved if anything fails afterwards, since the call may have been paid. Only the usage in
    /// a validly signed reply replaces it. Until enclave quotes are verified, that signature only
    /// proves as much as the key the relay reported.
    fn send_chat(&mut self, prompt: &str, token: Option<&str>) -> Result<ChatReply, String> {
        let reserved = u64::from(self.max_tokens).saturating_add(estimate_prompt_tokens(prompt));
        if self.spent.saturating_add(reserved) > self.token_budget {
            return Err("token budget exhausted".into());
        }
        self.transport.new_call()?;
        let model_key = self.fetch_model_key(token)?;
        let client = ClientKey::generate();
        let aad = match self.version {
            EncryptionVersion::V2 => Vec::new(),
            EncryptionVersion::V3 => request_aad_v3(&client.public_bytes(), MESSAGE_CONTENT_FIELD),
        };
        let ciphertext = encrypt_with_aad(&model_key, prompt.as_bytes(), &aad)?;
        let body = json!({
            "model": self.model,
            "messages": [{"role": "user", "content": to_hex(&ciphertext)}],
            "stream": false,
            "max_tokens": self.max_tokens,
        })
        .to_string()
        .into_bytes();

        let mut headers = base_headers();
        headers.extend([
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Signing-Algo".to_string(), "ed25519".to_string()),
            ("X-Client-Pub-Key".to_string(), to_hex(&client.public_bytes())),
            ("X-Model-Pub-Key".to_string(), to_hex(&model_key)),
            ("X-Encryption-Version".to_string(), self.version.header().to_string()),
        ]);
        if let Some(token) = token {
            headers.push(("X-Ona-Token".to_string(), token.to_string()));
        }
        self.spent = self.spent.saturating_add(reserved);
        let (status, raw) = self.transport.post("/v1/chat/completions", &headers, &body)?;
        if status != 200 {
            return Err(format!("chat failed with status {status}"));
        }
        let response: Value = serde_json::from_slice(&raw).map_err(|_| "reply is not JSON".to_string())?;
        let id = response["id"].as_str().ok_or("reply has no id")?;
        if !reply_id_is_acceptable(id) {
            return Err("reply id is malformed".into());
        }
        let signature = self.fetch_signature(id, token)?;
        verify_reply_signature(&signature, &self.model, &body, &raw, &model_key)?;

        // A missing or zero count says nothing about the cost, so the reservation stands.
        let tokens_used = match response["usage"]["total_tokens"].as_u64() {
            Some(used) if used > 0 => {
                self.spent = self.spent.saturating_sub(reserved).saturating_add(used);
                used
            }
            _ => reserved,
        };

        // No content at all (null, as NEAR AI sends when thinking used up every token, or missing) is the same case as an
        // empty one below.
        let content = &response["choices"][0]["message"]["content"];
        let encrypted = if content.is_null() {
            Vec::new()
        } else {
            content.as_str().and_then(from_hex).ok_or("reply has no encrypted content")?
        };
        // Too short to be ciphertext, for example when thinking used up every token. Not an attack.
        if encrypted.len() < MIN_CIPHERTEXT_LEN {
            return Err("reply has no content; the token limit may be too low".into());
        }
        let plaintext = client.decrypt(&encrypted).map_err(|e| {
            format!("{DISHONEST_RELAY_ALERT}: the model signed this reply but it cannot be decrypted ({e}); the relay may have tampered with the exchange, and with encryption version 2 it may have replaced the client key and read the reply")
        })?;
        let content = String::from_utf8(plaintext).map_err(|_| "reply is not text".to_string())?;
        Ok(ChatReply { content, tokens_used: u32::try_from(tokens_used).unwrap_or(u32::MAX) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    const MODEL: &str = "test/model";

    /// Replies with whatever `usage` is configured. No test here touches the network.
    struct Fake {
        model_key: SigningKey,
        usage: Value,
        post_status: u16,
        post_fails: bool,
        attestation_fails: bool,
        signature_failures: u32,
        signature_calls: u32,
        encrypt_to_other_key: bool,
        empty_content: bool,
        null_content: bool,
        signature_not_ready: u32,
        chats: u32,
        request: Vec<u8>,
        raw: Vec<u8>,
        reply_id: &'static str,
    }

    fn fake(usage: Value) -> Fake {
        Fake {
            model_key: SigningKey::generate(&mut OsRng),
            usage,
            post_status: 200,
            post_fails: false,
            attestation_fails: false,
            signature_failures: 0,
            signature_calls: 0,
            encrypt_to_other_key: false,
            empty_content: false,
            null_content: false,
            signature_not_ready: 0,
            chats: 0,
            request: vec![],
            raw: vec![],
            reply_id: "reply-1",
        }
    }

    impl Transport for Fake {
        fn get(&mut self, path: &str, _headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
            if path.starts_with("/v1/attestation/report") {
                if self.attestation_fails {
                    return Ok((500, vec![]));
                }
                let nonce = path.rsplit("nonce=").next().unwrap_or_default();
                let report = json!({"model_attestations": [{
                    "signing_public_key": to_hex(self.model_key.verifying_key().as_bytes()),
                    "request_nonce": nonce,
                }]});
                return Ok((200, report.to_string().into_bytes()));
            }
            self.signature_calls += 1;
            if self.signature_calls <= self.signature_failures {
                return if self.signature_calls % 2 == 0 { Err("connection reset".into()) } else { Ok((404, vec![])) };
            }
            if self.signature_calls <= self.signature_failures + self.signature_not_ready {
                return Ok((200, b"{}".to_vec()));
            }
            let text = format!("{MODEL}:{}:{}", sha256_hex(&self.request), sha256_hex(&self.raw));
            let signature = json!({
                "text": text,
                "signature": to_hex(&self.model_key.sign(text.as_bytes()).to_bytes()),
                "signing_address": to_hex(self.model_key.verifying_key().as_bytes()),
                "signature_kind": "provider_tee",
            });
            Ok((200, signature.to_string().into_bytes()))
        }

        fn post(&mut self, _path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
            self.chats += 1;
            if self.post_fails {
                return Err("connection lost".into());
            }
            self.request = body.to_vec();
            let named = headers.iter().find(|(k, _)| k == "X-Client-Pub-Key").map(|(_, v)| v.as_str()).unwrap_or("");
            let client_key: [u8; 32] = from_hex(named).unwrap().try_into().unwrap();
            let recipient = if self.encrypt_to_other_key { ClientKey::generate().public_bytes() } else { client_key };
            let reply = encrypt_to(&recipient, b"secret reply").unwrap();
            let content = if self.null_content {
                Value::Null
            } else if self.empty_content {
                json!("")
            } else {
                json!(to_hex(&reply))
            };
            let mut response = json!({"id": self.reply_id, "choices": [{"message": {"content": content}}]});
            if !self.usage.is_null() {
                response["usage"] = self.usage.clone();
            }
            self.raw = response.to_string().into_bytes();
            Ok((self.post_status, self.raw.clone()))
        }
    }

    fn client(transport: &mut Fake, max_tokens: u32, budget: u64) -> E2eeClient<&mut Fake> {
        let mut c = E2eeClient::new(transport, MODEL, max_tokens, budget);
        c.signature_retry_delay = Duration::ZERO;
        c
    }

    /// What one call with prompt "x" and `max_tokens` 100 reserves.
    const RESERVED: u64 = 100 + 1 + PROMPT_OVERHEAD_TOKENS;

    #[test]
    fn the_prompt_counts_against_the_budget_before_anything_is_sent() {
        let mut t = fake(json!({"total_tokens": 1}));
        let mut c = client(&mut t, 100, 150);
        assert_eq!(c.chat(&"a".repeat(200)).unwrap_err(), "token budget exhausted");
        assert_eq!(c.tokens_spent(), 0);
        assert_eq!(t.chats, 0);
    }

    #[test]
    fn the_reservation_is_kept_when_the_request_fails() {
        let mut t = fake(json!({"total_tokens": 1}));
        t.post_fails = true;
        let mut c = client(&mut t, 100, 1000);
        assert!(c.chat("x").is_err());
        assert_eq!(c.tokens_spent(), RESERVED, "it may have reached the model and been paid");
    }

    #[test]
    fn the_reservation_is_kept_on_an_error_status() {
        let mut t = fake(json!({"total_tokens": 1}));
        t.post_status = 500;
        let mut c = client(&mut t, 100, 1000);
        assert!(c.chat("x").is_err());
        assert_eq!(c.tokens_spent(), RESERVED);
    }

    #[test]
    fn nothing_is_charged_when_no_request_left() {
        let mut t = fake(json!({"total_tokens": 1}));
        t.attestation_fails = true;
        let mut c = client(&mut t, 100, 1000);
        assert!(c.chat("x").unwrap_err().contains("attestation"));
        assert_eq!(c.tokens_spent(), 0);
        assert_eq!(t.chats, 0);
    }

    #[test]
    fn usage_only_counts_once_the_signature_is_valid() {
        let mut t = fake(json!({"total_tokens": 1}));
        t.signature_failures = u32::MAX;
        let mut c = client(&mut t, 100, 1000);
        assert!(c.chat("x").is_err());
        assert_eq!(c.tokens_spent(), RESERVED, "unsigned usage must not free the budget");
    }

    #[test]
    fn signed_usage_replaces_the_reservation() {
        let mut t = fake(json!({"total_tokens": 40}));
        let mut c = client(&mut t, 100, 1000);
        assert_eq!(c.chat("x").unwrap().tokens_used, 40);
        assert_eq!(c.tokens_spent(), 40);
    }

    #[test]
    fn missing_or_zero_usage_does_not_free_the_budget() {
        for usage in [Value::Null, json!({}), json!({"total_tokens": 0}), json!({"total_tokens": "12"})] {
            let mut t = fake(usage.clone());
            let mut c = client(&mut t, 100, 1000);
            assert_eq!(c.chat("x").unwrap().tokens_used as u64, RESERVED, "{usage}");
            assert_eq!(c.tokens_spent(), RESERVED, "{usage}");
        }
    }

    #[test]
    fn huge_usage_saturates_instead_of_overflowing() {
        let mut t = fake(json!({"total_tokens": u64::MAX}));
        let mut c = client(&mut t, 100, u64::MAX - 1);
        c.chat("x").unwrap();
        assert_eq!(c.tokens_spent(), u64::MAX);
        assert_eq!(c.chat("y").unwrap_err(), "token budget exhausted");
    }

    #[test]
    fn a_signature_that_arrives_late_still_saves_the_reply() {
        let mut t = fake(json!({"total_tokens": 40}));
        t.signature_failures = SIGNATURE_ATTEMPTS - 1;
        let mut c = client(&mut t, 100, 1000);
        assert_eq!(c.chat("x").unwrap().content, "secret reply");
        assert_eq!(t.signature_calls, SIGNATURE_ATTEMPTS);
        assert_eq!(t.chats, 1, "the paid chat is not sent again");
    }

    #[test]
    fn signature_retries_are_bounded() {
        let mut t = fake(json!({"total_tokens": 40}));
        t.signature_failures = u32::MAX;
        let mut c = client(&mut t, 100, 1000);
        assert!(c.chat("x").unwrap_err().contains(&format!("after {SIGNATURE_ATTEMPTS} attempts")));
        assert_eq!(t.signature_calls, SIGNATURE_ATTEMPTS);
    }

    #[test]
    fn a_signed_reply_that_cannot_be_decrypted_raises_the_relay_alert() {
        let mut t = fake(json!({"total_tokens": 40}));
        t.encrypt_to_other_key = true;
        let mut c = client(&mut t, 100, 1000);
        assert!(c.chat("x").unwrap_err().starts_with(DISHONEST_RELAY_ALERT));
    }

    #[test]
    fn an_unsigned_undecryptable_reply_is_not_called_a_relay_alert() {
        let mut t = fake(json!({"total_tokens": 40}));
        t.encrypt_to_other_key = true;
        t.signature_failures = u32::MAX;
        let mut c = client(&mut t, 100, 1000);
        assert!(!c.chat("x").unwrap_err().starts_with(DISHONEST_RELAY_ALERT));
    }

    #[test]
    fn an_empty_signed_reply_is_not_called_a_relay_alert() {
        let mut t = fake(json!({"total_tokens": 40}));
        t.empty_content = true;
        let mut c = client(&mut t, 100, 1000);
        let error = c.chat("x").unwrap_err();
        assert!(!error.starts_with(DISHONEST_RELAY_ALERT), "{error}");
        assert!(error.contains("token limit"), "{error}");
    }

    /// What NEAR AI sent on 13/11/2026 when a reasoning model spent its 512 tokens thinking: `"content": null`.
    #[test]
    fn a_signed_reply_with_null_content_points_at_the_token_limit() {
        let mut t = fake(json!({"total_tokens": 40}));
        t.null_content = true;
        let mut c = client(&mut t, 100, 1000);
        let error = c.chat("x").unwrap_err();
        assert!(!error.starts_with(DISHONEST_RELAY_ALERT), "{error}");
        assert!(error.contains("token limit"), "{error}");
    }

    #[test]
    fn a_signature_answer_that_is_not_ready_is_retried() {
        let mut t = fake(json!({"total_tokens": 40}));
        t.signature_not_ready = SIGNATURE_ATTEMPTS - 1;
        let mut c = client(&mut t, 100, 1000);
        assert_eq!(c.chat("x").unwrap().content, "secret reply");
        assert_eq!(t.signature_calls, SIGNATURE_ATTEMPTS);
        assert_eq!(t.chats, 1);
    }

    #[test]
    fn a_malformed_reply_id_never_reaches_a_request_path() {
        for id in ["../../v1/chat", "reply?x=1", "reply#1", "a/b", "..", &"x".repeat(MAX_REPLY_ID_LEN + 1)] {
            let mut t = fake(json!({"total_tokens": 40}));
            t.reply_id = Box::leak(id.to_string().into_boxed_str());
            let mut c = client(&mut t, 100, 1000);
            assert_eq!(c.chat("x").unwrap_err(), "reply id is malformed", "{id}");
            assert_eq!(t.signature_calls, 0, "{id}");
        }
        let mut t = fake(json!({"total_tokens": 40}));
        t.reply_id = "chatcmpl-AbC_1.2";
        assert!(client(&mut t, 100, 1000).chat("x").is_ok());
    }

    #[test]
    fn the_http_transport_has_a_global_timeout() {
        let transport = HttpTransport::new("http://127.0.0.1:1");
        assert_eq!(transport.agent.config().timeouts().global, Some(REQUEST_TIMEOUT));
    }
}
