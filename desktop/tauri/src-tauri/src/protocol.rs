//! Bytes of the phone ↔ computer protocol, version 1 (docs/ios/protocol-draft.md). Identical to the macOS app
//! (desktop/ONADesktop/Core/Protocol/ProtocolBytes.swift): both test suites check the same vectors.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const VERSION: u64 = 1;
pub const COMMIT_DOMAIN: &str = "ona/pair-commit/v1";
pub const PAIR_DOMAIN: &str = "ona/pair/v1";
pub const SAS_DOMAIN: &str = "ona/sas/v1";
pub const REPLY_DOMAIN: &str = "ona/reply/v1";
pub const CONFIRM_DOMAIN: &str = "ona/confirm/v1";
pub const MESSAGE_DOMAIN: &str = "ona/message/v1";
pub const DELETE_DOMAIN: &str = "ona/delete/v1";
pub const PLAN_DOMAIN: &str = "ona/plan/v1";
pub const OFFERS_DOMAIN: &str = "ona/offers/v1";
pub const QUERIES_DOMAIN: &str = "ona/queries/v1";
pub const PAY_DOMAIN: &str = "ona/pay/v2";
pub const PAYLOAD_PREFIX: &str = "ona-pair:";

pub enum Field<'a> {
    Text(Option<&'a str>),
    Bytes(&'a [u8]),
}

/// Each field: u32 little-endian length, then its bytes (text as UTF-8, None as empty).
pub fn encode(fields: &[Field]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        let raw: &[u8] = match field {
            Field::Text(text) => text.unwrap_or("").as_bytes(),
            Field::Bytes(bytes) => bytes,
        };
        out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        out.extend_from_slice(raw);
    }
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// 16 random bytes as 32 lowercase hex characters (nonces, identifiers).
pub fn random_hex16() -> String {
    use rand::RngCore;
    let mut random = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    hex(&random)
}

pub fn is_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// Pairing (commit, then reveal)

/// What the phone sends first: SHA-256 of its key and its nonce, before it learns the computer's nonce.
pub fn commitment(phone_key: &[u8], phone_nonce: &str) -> String {
    sha256_hex(&encode(&[Field::Text(Some(COMMIT_DOMAIN)), Field::Bytes(phone_key), Field::Text(Some(phone_nonce))]))
}

/// Signed by the phone's key when it reveals it: proves possession and binds the whole exchange.
pub fn pair_message(pairing_id: &str, code: &str, phone_key: &[u8], computer_key: &[u8], phone_nonce: &str,
                    computer_nonce: &str) -> Vec<u8> {
    encode(&[
        Field::Text(Some(PAIR_DOMAIN)), Field::Text(Some(pairing_id)), Field::Text(Some(code)), Field::Bytes(phone_key),
        Field::Bytes(computer_key), Field::Text(Some(phone_nonce)), Field::Text(Some(computer_nonce)),
    ])
}

/// 6-digit code shown on both screens. Covers both nonces: the phone's key was fixed (committed) before the computer's
/// nonce was known, so a key cannot be searched to match a given code.
pub fn verification_code(computer_key: &[u8], phone_key: &[u8], code: &str, phone_nonce: &str, computer_nonce: &str)
                         -> String {
    let digest = Sha256::digest(encode(&[
        Field::Text(Some(SAS_DOMAIN)), Field::Bytes(computer_key), Field::Bytes(phone_key), Field::Text(Some(code)),
        Field::Text(Some(phone_nonce)), Field::Text(Some(computer_nonce)),
    ]));
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:06}", value % 1_000_000)
}

// Requests signed by the phone's key

pub fn confirm_message(pairing_id: &str, counter: u64, id: Option<&str>, decision: Option<&str>, firm: Option<&str>,
                       digest: Option<&str>, content: &str) -> Vec<u8> {
    let counter = counter.to_string();
    encode(&[
        Field::Text(Some(CONFIRM_DOMAIN)), Field::Text(Some(pairing_id)), Field::Text(Some(&counter)), Field::Text(id),
        Field::Text(decision), Field::Text(firm), Field::Text(digest), Field::Text(Some(content)),
    ])
}

pub fn chat_message(pairing_id: &str, counter: u64, chat_id: Option<&str>, text: Option<&str>) -> Vec<u8> {
    let counter = counter.to_string();
    encode(&[
        Field::Text(Some(MESSAGE_DOMAIN)), Field::Text(Some(pairing_id)), Field::Text(Some(&counter)),
        Field::Text(chat_id), Field::Text(text),
    ])
}

pub fn delete_message(pairing_id: &str, counter: u64, chat_id: &str) -> Vec<u8> {
    let counter = counter.to_string();
    encode(&[
        Field::Text(Some(DELETE_DOMAIN)), Field::Text(Some(pairing_id)), Field::Text(Some(&counter)),
        Field::Text(Some(chat_id)),
    ])
}

// Replies signed by the computer's key

/// What the computer signs for each reply: the phone's request nonce, the request's method and path, the HTTP status
/// and the exact reply text. A reply cannot be passed off as the answer to another request.
pub fn reply_message(request_nonce: &str, method: &str, path: &str, status: u16, reply: &str) -> Vec<u8> {
    let status = status.to_string();
    encode(&[Field::Text(Some(REPLY_DOMAIN)), Field::Text(Some(request_nonce)), Field::Text(Some(method)),
             Field::Text(Some(path)), Field::Text(Some(&status)), Field::Text(Some(reply))])
}

/// ECDSA P-256 / SHA-256 signature, DER, base64 (low-s, as produced by RFC 6979 signing in `p256`).
pub fn sign(key: &SigningKey, message: &[u8]) -> String {
    let signature: Signature = key.sign(message);
    let signature = signature.normalize_s().unwrap_or(signature);
    STANDARD.encode(signature.to_der().as_bytes())
}

// Digests of what the phone shows (the phone recomputes them from what it displays and signs them)

pub fn plan_digest(id: &str, steps: &[String]) -> String {
    let count = steps.len().to_string();
    let mut fields = vec![Field::Text(Some(PLAN_DOMAIN)), Field::Text(Some(id)), Field::Text(Some(&count))];
    fields.extend(steps.iter().map(|s| Field::Text(Some(s))));
    sha256_hex(&encode(&fields))
}

/// The search queries of a free research (docs/research.md): `fields("ona/queries/v1", id, query_1, query_2, …)`,
/// without a count (each field carries its length).
pub fn queries_digest(id: &str, queries: &[String]) -> String {
    let mut fields = vec![Field::Text(Some(QUERIES_DOMAIN)), Field::Text(Some(id))];
    fields.extend(queries.iter().map(|q| Field::Text(Some(q))));
    sha256_hex(&encode(&fields))
}

/// Offers as JSON (`firm_id`, `price_cents`, `delay_days`, `source_spans`): numbers as decimal text.
pub fn offers_digest(id: &str, offers: &[Value]) -> String {
    let mut texts: Vec<String> = vec![OFFERS_DOMAIN.to_owned(), id.to_owned(), offers.len().to_string()];
    for offer in offers {
        texts.push(offer["firm_id"].as_str().unwrap_or("").to_owned());
        texts.push(offer["price_cents"].as_i64().map(|n| n.to_string()).unwrap_or_default());
        texts.push(offer["delay_days"].as_i64().map(|n| n.to_string()).unwrap_or_default());
        let spans: Vec<&str> = offer["source_spans"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        texts.push(spans.len().to_string());
        texts.extend(spans.iter().map(|s| (*s).to_owned()));
    }
    let fields: Vec<Field> = texts.iter().map(|t| Field::Text(Some(t))).collect();
    sha256_hex(&encode(&fields))
}

/// Payment confirmation v2 (shared with ona-core):
/// `SHA-256(fields("ona/pay/v2", network, contract, mission_id, nonce_hex, to, amount_decimal))`.
pub fn payment_digest_v2(network: &str, contract: &str, mission_id: &str, nonce_hex: &str, to: &str, amount: &str)
                         -> String {
    sha256_hex(&encode(&[
        Field::Text(Some(PAY_DOMAIN)), Field::Text(Some(network)), Field::Text(Some(contract)),
        Field::Text(Some(mission_id)), Field::Text(Some(nonce_hex)), Field::Text(Some(to)), Field::Text(Some(amount)),
    ]))
}

/// Text of the pairing QR code: `ona-pair:` + base64url(JSON).
/// `onion_auth`: with an onion address, the phone's key for this computer's restricted onion service (Tor client
/// authorization), base32 of the 32-byte x25519 secret. Absent without an onion address.
pub fn pairing_payload(name: &str, address: Option<&str>, onion: Option<&str>, onion_auth: Option<&str>,
                       computer_key: &[u8], code: &str, expires_at: u64) -> String {
    let mut object = json!({
        "v": VERSION, "name": name, "address": address, "onion": onion,
        "computer_key": STANDARD.encode(computer_key), "code": code, "expires_at": expires_at,
    });
    if let (Some(auth), Some(_)) = (onion_auth, onion) {
        object["onion_auth"] = json!(auth);
    }
    format!("{PAYLOAD_PREFIX}{}", URL_SAFE_NO_PAD.encode(object.to_string()))
}

/// RFC 4648 base32, upper case, without padding: the form Tor uses for client authorization keys.
pub fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

/// A P-256 public key as the phone sends it: X9.63 uncompressed, 65 bytes starting with 0x04 (as CryptoKit).
pub fn public_key(bytes: &[u8]) -> Option<VerifyingKey> {
    if bytes.len() != 65 || bytes[0] != 4 {
        return None;
    }
    VerifyingKey::from_sec1_bytes(bytes).ok()
}

/// Verifies an ECDSA P-256 / SHA-256 signature (DER, base64) with an uncompressed public key. High-s signatures are
/// refused, so a signature has a single valid encoding.
pub fn verify(signature: Option<&str>, message: &[u8], public_key_bytes: &[u8]) -> bool {
    let Some(der) = signature.and_then(b64_decode) else { return false };
    let Some(key) = public_key(public_key_bytes) else { return false };
    let Ok(signature) = Signature::from_der(&der) else { return false };
    if signature.normalize_s().is_some() {
        return false; // high s
    }
    key.verify(message, &signature).is_ok()
}

/// Constant-time comparison of two byte strings (secrets: pairing code, read token).
pub fn same_secret(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A NEAR account id as the phone may show it: 2 to 64 characters among `a-z 0-9 . _ -`.
pub fn is_near_account(account: &str) -> bool {
    (2..=64).contains(&account.len())
        && account.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-')
}

/// ona-core's payment screen: "Pay {amount} yoctoNEAR to {account}".
pub fn parse_payment_screen(screen: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = screen.split(' ').collect();
    match parts.as_slice() {
        ["Pay", amount, "yoctoNEAR", "to", to]
            if !amount.is_empty() && amount.len() <= 39 && amount.bytes().all(|b| b.is_ascii_digit())
                && is_near_account(to) => Some((amount.to_string(), to.to_string())),
        _ => None,
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Fixed inputs shared with the macOS tests (desktop/ONADesktop/Tests) and the iPhone note.
    pub fn vector_computer_key() -> Vec<u8> {
        std::iter::once(4).chain(1..=64).collect()
    }
    pub fn vector_phone_key() -> Vec<u8> {
        std::iter::once(4).chain(65..=128).collect()
    }
    pub const PHONE_NONCE: &str = "00112233445566778899aabbccddeeff";
    pub const COMPUTER_NONCE: &str = "ffeeddccbbaa99887766554433221100";
    pub const CODE: &str = "c29tZS1jb2Rl";
    pub const PAIRING_ID: &str = "p-0123456789abcdef0123456789abcdef";

    #[test]
    fn fields_layout() {
        let encoded = encode(&[Field::Text(Some("ab")), Field::Bytes(&[1]), Field::Text(None)]);
        assert_eq!(encoded, [2, 0, 0, 0, 0x61, 0x62, 1, 0, 0, 0, 1, 0, 0, 0, 0]);
    }

    /// Vectors shared with the macOS tests and given to the iPhone app (SHA-256 of the signed bytes).
    #[test]
    fn protocol_v1_vectors() {
        let (computer, phone) = (vector_computer_key(), vector_phone_key());
        let digest = |bytes: Vec<u8>| hex(&Sha256::digest(bytes));
        assert_eq!(commitment(&phone, PHONE_NONCE), "6c2ee677c6aa3c2c1721f781e55f7e223caf87d729cc5e68bd6414de0a17bb7b");
        assert_eq!(verification_code(&computer, &phone, CODE, PHONE_NONCE, COMPUTER_NONCE), "587047");
        assert_eq!(digest(pair_message(PAIRING_ID, CODE, &phone, &computer, PHONE_NONCE, COMPUTER_NONCE)),
                   "3332d89e36dd9adeb88e8f5f18861d92fdcc048357c78bc7c7ed6284c1a069cd");
        let confirm = confirm_message(PAIRING_ID, 7, Some("c-1"), Some("accept"), None, Some("ab"), "cd");
        assert_eq!(digest(confirm.clone()), "1c61312dbd420b5f78b85dc82cf6f3c505386043f9704f4cd087f882a9389139");
        assert_eq!(digest(chat_message(PAIRING_ID, 8, None, Some("bonjour"))),
                   "7f4041bdaaef1fae3f26bd2abf1ad93d65e5f0b086c585ac5cb2e5979e5da082");
        assert_eq!(digest(delete_message(PAIRING_ID, 9, "chat-1")),
                   "ee3c7db20a817bb5c643f005a052fbf5af413ce9780a6fa31f3acc0e91ed959c");
        assert_eq!(digest(reply_message(PHONE_NONCE, "POST", "/v1/chats/list", 200, r#"{"ok":true}"#)),
                   "c9e6dc8eb32a3f5a97b226281a3151a023754cf518c0828468f3b25dd4e855b0");
        assert_eq!(plan_digest("c-1", &["search".into(), "read".into()]),
                   "10b2ecd6ff60485e505b911709ed14b162137f0237abaa8aed21eee7c26edb84");
        let offers = vec![json!({"firm_id": "cabinet-b", "price_cents": 60000, "delay_days": 10,
                                 "source_spans": ["Forfait 600 euros, sous 10 jours"]})];
        assert_eq!(queries_digest("c-0123456789abcdef0123456789abcdef",
                                  &["plombier Lyon".into(), "tarif déplacement plombier".into()]),
                   "8174711c622fea16bd82439613d544f31d2c2d8c3fb4bc1e22414a092a7cb01c");
        assert_eq!(offers_digest("c-2", &offers), "5127c86b14fc1406536bc274ea9c5b9e85e4a9b7e2adaf0c7b156ccf2dfb97b6");
        assert_eq!(payment_digest_v2("testnet", "pay.ona.testnet", "m-1", PHONE_NONCE, "cabinet-b.testnet",
                                     "1000000000000000000000000"),
                   "ee00b991ccc819a4b64630c245ae7e281ef98d74f0eb971b1ff4dd9290957950");
        // Deterministic signature (RFC 6979) by the private key 0x07…07: verifiable by CryptoKit.
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let public = key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        assert_eq!(b64(&public), "BB4YUy/UdUwC8wQdnHXOszuD/9gax85P6ILMscmLxYlupGwxHE4v9A3ZajZT5uRURdMt/khuztdcepDGoYiBwKM=");
        let signature = "MEUCIQCKpmfTBH6QHkQjK+2OSErWZ8NWVddjujyvnAIvA9OSSAIgPYwZ31pcNKYUz59ysuap+EQESYYeUfOI8n8sUxE/SHU=";
        assert_eq!(sign(&key, &confirm), signature);
        assert!(verify(Some(signature), &confirm, &public));
    }

    #[test]
    fn the_code_depends_on_both_nonces() {
        let (computer, phone) = (vector_computer_key(), vector_phone_key());
        let code = verification_code(&computer, &phone, CODE, PHONE_NONCE, COMPUTER_NONCE);
        assert_ne!(code, verification_code(&computer, &phone, CODE, COMPUTER_NONCE, COMPUTER_NONCE));
        assert_ne!(code, verification_code(&computer, &phone, CODE, PHONE_NONCE, PHONE_NONCE));
    }

    #[test]
    fn content_digests_change_with_what_is_shown() {
        let offer = |price: i64| vec![json!({"firm_id": "cabinet-b", "price_cents": price, "delay_days": 10,
                                             "source_spans": ["x"]})];
        assert_ne!(offers_digest("c-2", &offer(60000)), offers_digest("c-2", &offer(6000)));
        assert_ne!(plan_digest("c-1", &["search".into()]), plan_digest("c-1", &["pay".into()]));
        assert_ne!(plan_digest("c-1", &["search".into()]), plan_digest("c-9", &["search".into()]));
        assert_ne!(queries_digest("c-1", &["a b".into()]), queries_digest("c-1", &["a".into(), "b".into()]));
        assert_ne!(queries_digest("c-1", &["a".into()]), queries_digest("c-9", &["a".into()]));
        assert_ne!(payment_digest_v2("testnet", "c", "m-1", PHONE_NONCE, "a.testnet", "1"),
                   payment_digest_v2("testnet", "c", "m-2", PHONE_NONCE, "a.testnet", "1"));
    }

    #[test]
    fn verifies_low_s_signatures_only_and_uncompressed_keys_only() {
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let public = key.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let message = b"ona";
        let signature = sign(&key, message);
        assert!(verify(Some(&signature), message, &public));
        assert!(!verify(Some(&signature), b"onb", &public));
        assert!(!verify(None, message, &public));

        // (r, n - s) is the same signature mathematically: refused.
        let low = Signature::from_der(&b64_decode(&signature).unwrap()).unwrap();
        let (r, s) = low.split_scalars();
        let high = Signature::from_scalars(r, -*s).unwrap();
        assert!(VerifyingKey::from_sec1_bytes(&public).unwrap().verify(message, &high).is_ok());
        assert!(!verify(Some(&b64(high.to_der().as_bytes())), message, &public));

        let compressed = key.verifying_key().to_encoded_point(true).as_bytes().to_vec();
        assert!(!verify(Some(&signature), message, &compressed));
    }

    #[test]
    fn checks_the_payment_screen_and_the_account_shape() {
        assert_eq!(
            parse_payment_screen("Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet"),
            Some(("1000000000000000000000000".into(), "cabinet-b.testnet".into()))
        );
        assert_eq!(parse_payment_screen("Pay me to x"), None);
        assert_eq!(parse_payment_screen("Pay 1 yoctoNEAR to Cabinet-B.testnet"), None);
        assert_eq!(parse_payment_screen("Pay 1 yoctoNEAR to cabinet\u{202e}b.testnet"), None);
        assert!(!is_near_account("a"));
        assert!(!is_near_account(&"a".repeat(65)));
    }

    #[test]
    fn compares_secrets() {
        assert!(same_secret(b"abc", b"abc"));
        assert!(!same_secret(b"abc", b"abd"));
        assert!(!same_secret(b"abc", b"ab"));
    }

    /// RFC 4648 test vectors (without padding).
    #[test]
    fn base32_matches_rfc4648() {
        for (input, expected) in [("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"),
                                  ("fooba", "MZXW6YTB"), ("foobar", "MZXW6YTBOI")] {
            assert_eq!(base32(input.as_bytes()), expected);
        }
        assert_eq!(base32(&[0u8; 32]).len(), 52);
    }
}
