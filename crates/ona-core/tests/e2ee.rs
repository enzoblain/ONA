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
    SwapReplyKey,
    DowngradeHeader,
    WrongLabel,
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
    last_token: String,
    last_version: String,
    chats: usize,
    /// In order: `call` for each `new_call`, then each request's path, up to its `?`.
    sequence: Vec<String>,
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
            last_token: String::new(),
            last_version: String::new(),
            chats: 0,
            sequence: vec![],
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
    fn new_call(&mut self) -> Result<(), String> {
        self.sequence.push("call".into());
        Ok(())
    }

    fn get(&mut self, path: &str, _headers: &[(String, String)]) -> Result<(u16, Vec<u8>), String> {
        self.sequence.push(path.split('?').next().unwrap_or_default().into());
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

    fn post(&mut self, path: &str, headers: &[(String, String)], body: &[u8]) -> Result<(u16, Vec<u8>), String> {
        self.sequence.push(path.into());
        self.chats += 1;
        self.last_token = header(headers, "X-Ona-Token").to_string();
        self.last_request = body.to_vec();
        let request: Value = serde_json::from_slice(body).unwrap();
        let encrypted = unhex(request["messages"][0]["content"].as_str().unwrap());

        // What the enclave receives, after anything a dishonest relay changed on the way.
        self.last_version = header(headers, "X-Encryption-Version").to_string();
        let version = if self.attack == Attack::DowngradeHeader { "2" } else { self.last_version.as_str() };
        let client_key: [u8; 32] = if self.attack == Attack::SwapReplyKey {
            SigningKey::generate(&mut OsRng).verifying_key().to_bytes()
        } else {
            unhex(header(headers, "X-Client-Pub-Key")).try_into().unwrap()
        };
        let label = if self.attack == Attack::WrongLabel { "messages[].name" } else { MESSAGE_CONTENT_FIELD };
        let aad = if version == "3" { request_aad_v3(&client_key, label) } else { vec![] };

        let Some(prompt) = ClientKeyFor(&self.model_key).decrypt(&encrypted, &aad) else {
            return Ok((400, b"request cannot be decrypted".to_vec()));
        };
        self.received_prompts.push(String::from_utf8(prompt).unwrap());

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
    fn decrypt(&self, blob: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use x25519_dalek::{PublicKey, StaticSecret};
        let peer: [u8; 32] = blob[..32].try_into().unwrap();
        let shared = StaticSecret::from(self.0.to_scalar_bytes()).diffie_hellman(&PublicKey::from(peer));
        let mut key = [0u8; 32];
        hkdf::Hkdf::<Sha256>::new(None, shared.as_bytes()).expand(b"ed25519_encryption", &mut key).unwrap();
        chacha20poly1305::XChaCha20Poly1305::new((&key).into())
            .decrypt(chacha20poly1305::XNonce::from_slice(&blob[32..56]), Payload { msg: &blob[56..], aad })
            .ok()
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
fn version_3_is_the_default() {
    let mut enclave = FakeEnclave::new(Attack::None);
    let mut c = E2eeClient::new(&mut enclave, MODEL, 100, 1000);
    assert_eq!(c.chat("bonjour").unwrap().content, "secret reply");
    assert_eq!(enclave.last_version, "3");
    assert_eq!(enclave.received_prompts, vec!["bonjour"]);
}

// Through Tor, `new_call` gives the three requests of one model call a circuit of their own: it comes before them, once.
#[test]
fn each_model_call_starts_with_new_call() {
    let mut enclave = FakeEnclave::new(Attack::None);
    let mut c = E2eeClient::new(&mut enclave, MODEL, 100, 1000);
    c.chat("un").unwrap();
    c.chat("deux").unwrap();
    let one = ["call", "/v1/attestation/report", "/v1/chat/completions", "/v1/signature/reply-1"];
    assert_eq!(enclave.sequence, [one, one].concat());
}

#[test]
fn version_2_needs_an_explicit_setting() {
    let mut enclave = FakeEnclave::new(Attack::None);
    let mut c = E2eeClient::new(&mut enclave, MODEL, 100, 1000).with_encryption_version(EncryptionVersion::V2);
    assert_eq!(c.chat("bonjour").unwrap().content, "secret reply");
    assert_eq!(enclave.last_version, "2");
}

/// The request never opens, nothing reaches the model, and the client does not try another version.
fn assert_refused_without_downgrade(attack: Attack) {
    let mut enclave = FakeEnclave::new(attack);
    let mut c = E2eeClient::new(&mut enclave, MODEL, 100, 1000);
    assert!(c.chat("dossier Dupont").unwrap_err().contains("chat failed"));
    assert!(enclave.received_prompts.is_empty(), "the model must not see the prompt");
    assert_eq!(enclave.chats, 1, "a failure is not retried");
    assert_eq!(enclave.last_version, "3", "and never with a lower version");
}

#[test]
fn a_replaced_reply_key_makes_the_request_undecryptable() {
    assert_refused_without_downgrade(Attack::SwapReplyKey);
}

#[test]
fn a_version_changed_on_the_way_is_refused() {
    assert_refused_without_downgrade(Attack::DowngradeHeader);
}

#[test]
fn a_changed_field_label_is_refused() {
    assert_refused_without_downgrade(Attack::WrongLabel);
}

#[test]
fn the_v3_associated_data_has_the_documented_layout() {
    let key = [7u8; 32];
    let mut expected = b"nearai-e2ee-request-v3".to_vec();
    expected.push(0x02);
    expected.extend_from_slice(&key);
    expected.push(0x00);
    expected.extend_from_slice(b"messages[].content");
    assert_eq!(request_aad_v3(&key, "messages[].content"), expected);
}

#[test]
fn every_part_of_the_v3_associated_data_is_enforced() {
    let model = SigningKey::generate(&mut OsRng);
    let reply_key = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let other_key = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let good = request_aad_v3(&reply_key, MESSAGE_CONTENT_FIELD);
    let blob = encrypt_with_aad(&model.verifying_key().to_bytes(), b"secret", &good).unwrap();
    let enclave = ClientKeyFor(&model);
    assert_eq!(enclave.decrypt(&blob, &good).unwrap(), b"secret");

    let mut other_version = good.clone();
    other_version[21] = b'2';
    let mut other_suite = good.clone();
    other_suite[22] = 0x01;
    for wrong in [
        vec![],
        other_version,
        other_suite,
        request_aad_v3(&other_key, MESSAGE_CONTENT_FIELD),
        request_aad_v3(&reply_key, "messages[].name"),
    ] {
        assert!(enclave.decrypt(&blob, &wrong).is_none());
    }
}

#[test]
fn each_v3_field_gets_its_own_ephemeral_key_and_nonce() {
    let model = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let aad = request_aad_v3(&[7u8; 32], MESSAGE_CONTENT_FIELD);
    let first = encrypt_with_aad(&model, b"same", &aad).unwrap();
    let second = encrypt_with_aad(&model, b"same", &aad).unwrap();
    assert_ne!(first[..32], second[..32]);
    assert_ne!(first[32..56], second[32..56]);
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
fn a_request_token_travels_in_its_header() {
    let mut enclave = FakeEnclave::new(Attack::None);
    let mut c = E2eeClient::new(&mut enclave, MODEL, 100, 1000);
    c.chat_with_token("x", "abc123").unwrap();
    assert_eq!(enclave.last_token, "abc123");
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
