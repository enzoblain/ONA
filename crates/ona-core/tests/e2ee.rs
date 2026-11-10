//! The E2EE client against a simulated enclave. No test here calls NEAR AI or spends credits.

use ed25519_dalek::{Signer, SigningKey};
use ona_core::e2ee::*;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MODEL: &str = "test/model";

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> &'a str {
    headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or("")
}

#[derive(Clone, Copy, PartialEq)]
enum Attack {
    None,
    ReplayNonce,
    TamperReply,
    GatewaySignature,
    OtherSigner,
    SwapModelKey,
}

/// Plays the relay and the enclave, and can misbehave in the ways a malicious relay could.
struct FakeEnclave {
    model_key: SigningKey,
    attack: Attack,
    tokens_per_reply: u64,
    received_prompts: Vec<String>,
    last_body: Vec<u8>,
    last_request: Vec<u8>,
    last_raw: Vec<u8>,
    chats: usize,
}

impl FakeEnclave {
    fn new(attack: Attack) -> Self {
        Self {
            model_key: SigningKey::generate(&mut OsRng),
            attack,
            tokens_per_reply: 50,
            received_prompts: vec![],
            last_body: vec![],
            last_request: vec![],
            last_raw: vec![],
            chats: 0,
        }
    }

    fn reports_key(&self) -> [u8; 32] {
        if self.attack == Attack::SwapModelKey {
            [9u8; 32]
        } else {
            self.model_key.verifying_key().to_bytes()
        }
    }
}

impl Transport for FakeEnclave {
    fn get(&mut self, path: &str, _headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        if path.starts_with("/v1/attestation/report") {
            let nonce = path.rsplit("nonce=").next().unwrap_or_default();
            let answered = if self.attack == Attack::ReplayNonce { "old-nonce" } else { nonce };
            let report = json!({"model_attestations": [
                {"signing_public_key": hex(&self.reports_key()), "request_nonce": answered},
            ]});
            return Ok((200, report.to_string().into_bytes()));
        }
        assert!(path.starts_with("/v1/signature/reply-1"));
        let text = format!("{MODEL}:{}:{}", sha(&self.last_request), sha(&self.last_raw));
        let signer = if self.attack == Attack::OtherSigner { SigningKey::generate(&mut OsRng) } else { self.model_key.clone() };
        let kind = if self.attack == Attack::GatewaySignature { "gateway" } else { "provider_tee" };
        let signature = json!({
            "text": text,
            "signature": format!("0x{}", hex(&signer.sign(text.as_bytes()).to_bytes())),
            "signing_address": format!("0x{}", hex(signer.verifying_key().as_bytes())),
            "signature_kind": kind,
        });
        Ok((200, signature.to_string().into_bytes()))
    }

    fn post(&mut self, _path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        self.chats += 1;
        self.last_request = body.to_vec();
        let request: Value = serde_json::from_slice(body).unwrap();
        let encrypted = unhex(request["messages"][0]["content"].as_str().unwrap());
        let enclave = ClientKeyFor(&self.model_key);
        let prompt = String::from_utf8(enclave.decrypt(&encrypted)).unwrap();
        self.received_prompts.push(prompt);

        let client_key: [u8; 32] = unhex(header(headers, "X-Client-Pub-Key")).try_into().unwrap();
        let reply = encrypt_to(&client_key, b"secret reply").unwrap();
        let raw = json!({
            "id": "reply-1",
            "choices": [{"message": {"content": hex(&reply)}}],
            "usage": {"total_tokens": self.tokens_per_reply},
        })
        .to_string()
        .into_bytes();
        self.last_raw = raw.clone();
        self.last_body = body.to_vec();
        if self.attack == Attack::TamperReply {
            let mut altered = raw;
            let position = altered.len() - 3;
            altered[position] = b'9';
            return Ok((200, altered));
        }
        Ok((200, raw))
    }
}

/// Decrypts as the enclave does, with the X25519 secret derived from its signing key.
struct ClientKeyFor<'a>(&'a SigningKey);

impl ClientKeyFor<'_> {
    fn decrypt(&self, blob: &[u8]) -> Vec<u8> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use x25519_dalek::{PublicKey, StaticSecret};
        let peer: [u8; 32] = blob[..32].try_into().unwrap();
        let shared = StaticSecret::from(self.0.to_scalar_bytes()).diffie_hellman(&PublicKey::from(peer));
        let mut key = [0u8; 32];
        hkdf::Hkdf::<Sha256>::new(None, shared.as_bytes()).expand(b"ed25519_encryption", &mut key).unwrap();
        chacha20poly1305::XChaCha20Poly1305::new((&key).into())
            .decrypt(chacha20poly1305::XNonce::from_slice(&blob[32..56]), &blob[56..])
            .unwrap()
    }
}

fn client(attack: Attack) -> E2eeClient<FakeEnclave> {
    E2eeClient::new(FakeEnclave::new(attack), MODEL, 100, 1000)
}

#[test]
fn a_chat_round_trips_through_the_enclave() {
    let mut c = client(Attack::None);
    let reply = c.chat("mon dossier confidentiel").unwrap();
    assert_eq!(reply, ChatReply { content: "secret reply".into(), tokens_used: 50 });
    assert_eq!(c.tokens_spent(), 50);
}

#[test]
fn encryption_interoperates_with_a_client_key() {
    let key = ClientKey::generate();
    let blob = encrypt_to(&key.public_bytes(), b"bonjour").unwrap();
    assert_eq!(key.decrypt(&blob).unwrap(), b"bonjour");
    assert!(ClientKey::generate().decrypt(&blob).is_err(), "another key cannot read it");
    let mut tampered = blob;
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(key.decrypt(&tampered).is_err());
    assert!(key.decrypt(&[0u8; 20]).is_err());
}

#[test]
fn a_token_limit_is_always_sent() {
    let mut enclave = FakeEnclave::new(Attack::None);
    let mut c = E2eeClient::new(&mut enclave, MODEL, 77, 1000);
    c.chat("x").unwrap();
    let body: Value = serde_json::from_slice(&enclave.last_body).unwrap();
    assert_eq!(body["max_tokens"], 77);
    assert_eq!(body["stream"], false);
    assert!(!String::from_utf8_lossy(&enclave.last_body).contains("Bonjour"));
}

#[test]
fn the_prompt_reaches_the_model_only_as_ciphertext() {
    let mut enclave = FakeEnclave::new(Attack::None);
    let mut c = E2eeClient::new(&mut enclave, MODEL, 100, 1000);
    c.chat("dossier Dupont").unwrap();
    assert_eq!(enclave.received_prompts, vec!["dossier Dupont"]);
    assert!(!String::from_utf8_lossy(&enclave.last_body).contains("Dupont"));
}

#[test]
fn the_budget_stops_calls_before_they_spend() {
    let mut enclave = FakeEnclave::new(Attack::None);
    let mut c = E2eeClient::new(&mut enclave, MODEL, 100, 120);
    c.chat("x").unwrap();
    assert_eq!(c.chat("y").unwrap_err(), "token budget exhausted");
    assert_eq!(enclave.chats, 1, "the second call never left");
}

#[test]
fn a_replayed_attestation_is_refused_before_any_chat() {
    let mut enclave = FakeEnclave::new(Attack::ReplayNonce);
    let mut c = E2eeClient::new(&mut enclave, MODEL, 100, 1000);
    assert!(c.chat("x").unwrap_err().contains("nonce"));
    assert_eq!(enclave.chats, 0, "nothing is sent to an unproven key");
}

#[test]
fn an_altered_reply_is_refused() {
    assert!(client(Attack::TamperReply).chat("x").unwrap_err().contains("signed text"));
}

#[test]
fn a_gateway_signature_is_not_enough() {
    assert!(client(Attack::GatewaySignature).chat("x").unwrap_err().contains("enclave"));
}

#[test]
fn a_signature_from_another_key_is_refused() {
    assert!(client(Attack::OtherSigner).chat("x").unwrap_err().contains("attested"));
}

#[test]
fn an_invalid_model_key_is_refused() {
    let report = json!({"model_attestations": [{"signing_public_key": "abcd", "request_nonce": "n"}]});
    assert!(attested_model_key(&report, "n").unwrap_err().contains("32 bytes"));
    assert!(attested_model_key(&json!({}), "n").is_err());
    let low_order = json!({"model_attestations": [{"signing_public_key": hex(&[0u8; 32]), "request_nonce": "n"}]});
    assert!(attested_model_key(&low_order, "n").is_err(), "a weak key would make the encryption worthless");
}

#[test]
fn the_right_attestation_is_chosen_among_several() {
    let wanted = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let other = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let report = json!({"model_attestations": [
        {"signing_public_key": hex(&other), "request_nonce": "old"},
        {"signing_public_key": hex(&wanted), "request_nonce": "mine"},
    ]});
    assert_eq!(attested_model_key(&report, "mine").unwrap(), wanted);
}

#[test]
fn a_forged_signature_value_is_refused() {
    let key = SigningKey::generate(&mut OsRng);
    let (body, raw) = (b"req".to_vec(), b"resp".to_vec());
    let text = format!("{MODEL}:{}:{}", sha(&body), sha(&raw));
    let good = key.sign(text.as_bytes()).to_bytes();
    let pk = key.verifying_key().to_bytes();
    let make = |sig: &[u8]| json!({"text": text, "signature": hex(sig), "signing_address": hex(&pk), "signature_kind": "provider_tee"});
    assert!(verify_reply_signature(&make(&good), MODEL, &body, &raw, &pk).is_ok());
    let mut bad = good;
    bad[10] ^= 1;
    assert!(verify_reply_signature(&make(&bad), MODEL, &body, &raw, &pk).unwrap_err().contains("invalid"));
    assert!(verify_reply_signature(&make(&good), "other/model", &body, &raw, &pk).is_err(), "another model name");
}
