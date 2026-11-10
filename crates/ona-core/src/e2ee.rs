//! End-to-end encrypted chat with NEAR AI Cloud, through a relay that holds the API key.
//!
//! Follows encryption version 2, as checked with a real model call on 2026-11-10. The relay sees
//! ciphertext, the model name, the token limit and the usage counters.
//!
//! Not done here: verifying the Intel TDX and NVIDIA quotes. Until that check is added, the key
//! returned by `attested_model_key` is only as trustworthy as the party that returned the report.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

const INFO: &[u8] = b"ed25519_encryption";
const HEADER_LEN: usize = 32 + 24;
/// Most tokens one reply may use, thinking included. Every real call costs credits.
pub const DEFAULT_MAX_TOKENS: u32 = 512;

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

fn derive_key(shared: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared)
        .expand(INFO, &mut key)
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

/// Encrypts to an ed25519 public key. Output: ephemeral public key, nonce, ciphertext.
pub fn encrypt_to(recipient_ed: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let recipient = XPublic::from(ed_public_to_x25519(recipient_ed)?);
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err("key exchange produced a low-order result".into());
    }
    let key = derive_key(shared.as_bytes());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new((&key).into())
        .encrypt(XNonce::from_slice(&nonce), plaintext)
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
        let secret = StaticSecret::from(self.0.to_scalar_bytes());
        let shared = secret.diffie_hellman(&XPublic::from(peer));
        if !shared.was_contributory() {
            return Err("key exchange produced a low-order result".into());
        }
        let key = derive_key(shared.as_bytes());
        XChaCha20Poly1305::new((&key).into())
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
        .verify(text.as_bytes(), &Signature::from_bytes(&bytes))
        .map_err(|_| "signature is invalid".to_string())
}

pub trait Transport {
    /// Returns the status and the exact bytes of the body.
    fn get(&mut self, path: &str, headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String>;
    fn post(&mut self, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String>;
}

impl<T: Transport> Transport for &mut T {
    fn get(&mut self, path: &str, headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        (**self).get(path, headers)
    }
    fn post(&mut self, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        (**self).post(path, headers, body)
    }
}

/// HTTP to a relay. Compression is off because the signature covers the exact bytes.
pub struct HttpTransport {
    base: String,
    agent: ureq::Agent,
}

impl HttpTransport {
    pub fn new(base: &str) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
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
}

fn base_headers() -> Vec<(String, String)> {
    vec![
        ("x-no-aliasing".to_string(), "true".to_string()),
        ("Accept-Encoding".to_string(), "identity".to_string()),
    ]
}

impl<T: Transport> E2eeClient<T> {
    /// `token_budget` is a hard stop on the tokens this client may spend, across all its calls.
    pub fn new(transport: T, model: &str, max_tokens: u32, token_budget: u64) -> Self {
        Self { transport, model: model.to_string(), max_tokens, token_budget, spent: 0 }
    }

    pub fn tokens_spent(&self) -> u64 {
        self.spent
    }

    fn fetch_model_key(&mut self) -> Result<[u8; 32], String> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let nonce = to_hex(&bytes);
        let path = format!(
            "/v1/attestation/report?model={}&provider=near&signing_algo=ed25519&include_tls_fingerprint=false&nonce={nonce}",
            self.model
        );
        let (status, body) = self.transport.get(&path, &base_headers())?;
        if status != 200 {
            return Err(format!("attestation request failed with status {status}"));
        }
        let report: Value = serde_json::from_slice(&body).map_err(|_| "attestation is not JSON".to_string())?;
        attested_model_key(&report, &nonce)
    }

    /// Sends one prompt. The budget is checked first, so an exhausted client spends nothing.
    pub fn chat(&mut self, prompt: &str) -> Result<ChatReply, String> {
        if self.spent + u64::from(self.max_tokens) > self.token_budget {
            return Err("token budget exhausted".into());
        }
        let model_key = self.fetch_model_key()?;
        let client = ClientKey::generate();
        let ciphertext = encrypt_to(&model_key, prompt.as_bytes())?;
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
            ("X-Encryption-Version".to_string(), "2".to_string()),
        ]);
        let (status, raw) = self.transport.post("/v1/chat/completions", &headers, &body)?;
        if status != 200 {
            return Err(format!("chat failed with status {status}"));
        }
        let response: Value = serde_json::from_slice(&raw).map_err(|_| "reply is not JSON".to_string())?;
        let tokens_used = response["usage"]["total_tokens"].as_u64().unwrap_or(u64::from(self.max_tokens));
        self.spent += tokens_used;

        let id = response["id"].as_str().ok_or("reply has no id")?;
        let path = format!("/v1/signature/{id}?signing_algo=ed25519");
        let (status, signature) = self.transport.get(&path, &base_headers())?;
        if status != 200 {
            return Err(format!("signature request failed with status {status}"));
        }
        let signature: Value = serde_json::from_slice(&signature).map_err(|_| "signature is not JSON".to_string())?;
        verify_reply_signature(&signature, &self.model, &body, &raw, &model_key)?;

        let encrypted = response["choices"][0]["message"]["content"]
            .as_str()
            .and_then(from_hex)
            .ok_or("reply has no encrypted content")?;
        let content = String::from_utf8(client.decrypt(&encrypted)?).map_err(|_| "reply is not text".to_string())?;
        Ok(ChatReply { content, tokens_used: u32::try_from(tokens_used).unwrap_or(u32::MAX) })
    }
}
