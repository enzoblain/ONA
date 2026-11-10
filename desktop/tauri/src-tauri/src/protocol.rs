//! Bytes of the phone ↔ computer protocol (docs/ios/protocol-draft.md). Identical to the iPhone app, the macOS app
//! and the Python mock: the tests share vectors.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256};

pub const PAIR_DOMAIN: &str = "ona/pair/v0";
pub const CONFIRM_DOMAIN: &str = "ona/confirm/v0";
pub const SAS_DOMAIN: &str = "ona/sas/v0";
pub const MESSAGE_DOMAIN: &str = "ona/message/v0";
pub const DELETE_DOMAIN: &str = "ona/delete/v0";
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

pub fn pair_message(code: &str, phone_key: &[u8], computer_key: &[u8]) -> Vec<u8> {
    encode(&[Field::Text(Some(PAIR_DOMAIN)), Field::Text(Some(code)), Field::Bytes(phone_key), Field::Bytes(computer_key)])
}

pub fn confirm_message(pairing_id: &str, id: Option<&str>, decision: Option<&str>, firm: Option<&str>,
                       digest: Option<&str>) -> Vec<u8> {
    encode(&[
        Field::Text(Some(CONFIRM_DOMAIN)), Field::Text(Some(pairing_id)), Field::Text(id), Field::Text(decision),
        Field::Text(firm), Field::Text(digest),
    ])
}

pub fn chat_message(pairing_id: &str, chat_id: Option<&str>, text: Option<&str>) -> Vec<u8> {
    encode(&[Field::Text(Some(MESSAGE_DOMAIN)), Field::Text(Some(pairing_id)), Field::Text(chat_id), Field::Text(text)])
}

pub fn delete_message(pairing_id: &str, chat_id: &str) -> Vec<u8> {
    encode(&[Field::Text(Some(DELETE_DOMAIN)), Field::Text(Some(pairing_id)), Field::Text(Some(chat_id))])
}

/// 6-digit code shown on both screens after pairing.
pub fn verification_code(computer_key: &[u8], phone_key: &[u8], code: &str) -> String {
    let digest = Sha256::digest(encode(&[
        Field::Text(Some(SAS_DOMAIN)), Field::Bytes(computer_key), Field::Bytes(phone_key), Field::Text(Some(code)),
    ]));
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:06}", value % 1_000_000)
}

/// Text of the pairing QR code: `ona-pair:` + base64url(JSON).
pub fn pairing_payload(name: &str, address: Option<&str>, onion: Option<&str>, computer_key: &[u8], code: &str) -> String {
    let object = json!({
        "v": 0, "name": name, "address": address, "onion": onion,
        "computer_key": STANDARD.encode(computer_key), "code": code,
    });
    format!("{PAYLOAD_PREFIX}{}", URL_SAFE_NO_PAD.encode(object.to_string()))
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text).ok()
}

/// Verifies an ECDSA P-256 / SHA-256 signature (DER, base64) with a public key in X9.63 / SEC1 form.
pub fn verify(signature: Option<&str>, message: &[u8], public_key: &[u8]) -> bool {
    let Some(der) = signature.and_then(b64_decode) else { return false };
    let Ok(key) = VerifyingKey::from_sec1_bytes(public_key) else { return false };
    let Ok(signature) = Signature::from_der(&der) else { return false };
    key.verify(message, &signature).is_ok()
}

/// ona-core's payment screen: "Pay {amount} yoctoNEAR to {account}".
pub fn parse_payment_screen(screen: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = screen.split(' ').collect();
    match parts.as_slice() {
        ["Pay", amount, "yoctoNEAR", "to", to] if !amount.is_empty() && amount.bytes().all(|b| b.is_ascii_digit()) => {
            Some((amount.to_string(), to.to_string()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_layout() {
        let encoded = encode(&[Field::Text(Some("ab")), Field::Bytes(&[1]), Field::Text(None)]);
        assert_eq!(encoded, [2, 0, 0, 0, 0x61, 0x62, 1, 0, 0, 0, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn verification_code_vector() {
        let computer: Vec<u8> = std::iter::once(4).chain(1..=64).collect();
        let phone: Vec<u8> = std::iter::once(4).chain(65..=128).collect();
        assert_eq!(verification_code(&computer, &phone, "c29tZS1jb2Rl"), "093832");
    }

    #[test]
    fn verifies_the_cryptokit_vector_from_the_iphone_app() {
        let key = b64_decode("BAyQHUI8gxyoXifHPCY7oTJyG7nXqExPA4CypnVv1gEzHIhwI03sh4UEwXQUT6SxS2amUWkWBtgXPlW9N+OBVp4=").unwrap();
        let message = confirm_message("p-1", Some("c-3"), Some("accept"), None, Some("ab"));
        let signature = "MEYCIQD0k1mmYvXAC4IWy6hNET+ZmTBAdqnrm+5gdIb1rIs7QgIhALKtYM/kYDAzqHau+ifTx8uJI9AdlkYaUn5w9w8M3AdK";
        assert!(verify(Some(signature), &message, &key));
        assert!(!verify(Some(signature), &[message.as_slice(), &[0]].concat(), &key));
        assert!(!verify(None, &message, &key));
    }

    #[test]
    fn parses_the_ona_core_payment_screen() {
        assert_eq!(
            parse_payment_screen("Pay 1000000000000000000000000 yoctoNEAR to cabinet-b.testnet"),
            Some(("1000000000000000000000000".into(), "cabinet-b.testnet".into()))
        );
        assert_eq!(parse_payment_screen("Pay me to x"), None);
    }
}
