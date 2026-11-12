//! Proof that a cash issue is asked for by the account that deposited: a message signed by one of the account's
//! full-access keys, in the NEP-413 form NEAR wallets use to sign off-chain messages (`signMessage`).
//!
//! The format is written from the NEP-413 standard as recalled here, **not verified** against a wallet: the
//! signed bytes are `SHA-256(borsh(2^31 + 413 as u32) || borsh(payload))`, the payload being `message` (string),
//! `nonce` (32 bytes), `recipient` (string) and `callback_url` (an absent option). The message names the pool,
//! the account and a hash of every blinded point with its tier, so a proof cannot serve other points.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// `2^31 + 413`, the NEP-413 tag that keeps a signed message from ever being a valid transaction.
pub const TAG: u32 = 2_147_484_061;

fn borsh_string(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// The 32 bytes a wallet signs for `message`, `nonce` and `recipient`, with no callback URL.
pub fn payload_hash(message: &str, nonce: &[u8; 32], recipient: &str) -> [u8; 32] {
    let mut bytes = TAG.to_le_bytes().to_vec();
    borsh_string(&mut bytes, message);
    bytes.extend_from_slice(nonce);
    borsh_string(&mut bytes, recipient);
    bytes.push(0);
    Sha256::digest(&bytes).into()
}

/// `hex(SHA-256((tier || blinded point)*))` over the notes in request order.
pub fn notes_hash(notes: &[(u8, [u8; 48])]) -> String {
    let mut h = Sha256::new();
    for (tier, blinded) in notes {
        h.update([*tier]);
        h.update(blinded);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The exact text the depositor's wallet signs to have these cash notes issued.
pub fn issue_message(pool: &str, account: &str, notes: &[(u8, [u8; 48])]) -> String {
    format!("ONA pool cash issue v1\npool: {pool}\naccount: {account}\nnotes: {}", notes_hash(notes))
}

/// Reads `ed25519:<base58>`, the form NEAR writes public keys in.
pub fn parse_public_key(text: &str) -> Result<[u8; 32], String> {
    let encoded = text.strip_prefix("ed25519:").ok_or("public key must start with ed25519:")?;
    bs58::decode(encoded)
        .into_vec()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| "public key is not 32 bytes of base58".to_string())
}

pub fn write_public_key(pk: &[u8; 32]) -> String {
    format!("ed25519:{}", bs58::encode(pk).into_string())
}

/// Strict ed25519 check of a wallet's signature over the payload hash.
pub fn verify(pk: &[u8; 32], hash: &[u8; 32], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(pk).is_ok_and(|key| key.verify_strict(hash, &Signature::from_bytes(signature)).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn the_payload_layout_follows_borsh() {
        let nonce = [7u8; 32];
        let mut expected = vec![0x9d, 0x01, 0x00, 0x80];
        expected.extend_from_slice(&[2, 0, 0, 0, b'h', b'i']);
        expected.extend_from_slice(&nonce);
        expected.extend_from_slice(&[1, 0, 0, 0, b'p']);
        expected.push(0);
        assert_eq!(payload_hash("hi", &nonce, "p"), <[u8; 32]>::from(Sha256::digest(&expected)));
    }

    #[test]
    fn a_signature_covers_the_message_nonce_and_recipient() {
        let key = SigningKey::from_bytes(&[4u8; 32]);
        let pk = key.verifying_key().to_bytes();
        let notes = [(1u8, [9u8; 48])];
        let message = issue_message("pool.test", "alice.test", &notes);
        let hash = payload_hash(&message, &[1u8; 32], "pool.test");
        let sig = key.sign(&hash).to_bytes();
        assert!(verify(&pk, &hash, &sig));
        assert!(!verify(&pk, &payload_hash(&message, &[2u8; 32], "pool.test"), &sig));
        assert!(!verify(&pk, &payload_hash(&message, &[1u8; 32], "other.test"), &sig));
        let other = issue_message("pool.test", "alice.test", &[(1u8, [8u8; 48])]);
        assert!(!verify(&pk, &payload_hash(&other, &[1u8; 32], "pool.test"), &sig), "other points");
        assert_eq!(parse_public_key(&write_public_key(&pk)).unwrap(), pk);
        assert!(parse_public_key("secp256k1:abc").is_err());
    }
}
