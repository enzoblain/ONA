//! Hands the journal's master key to an auditor, then forgets it.
//!
//! Sealed form: version (1 byte), ephemeral X25519 public key (32), nonce (24), ciphertext of the
//! 32-byte key with its tag (48). The AEAD key comes from HKDF-SHA256 over the X25519 secret, bound
//! to both public keys and to the journal (its chain start), so a sealed key cannot be passed off as the
//! key of another journal.
//!
//! The auditor's public key is checked against a fingerprint the caller already holds from a source other
//! than the one that delivered the key (pinned in the application, or published in the registry): a key
//! swapped in transit would otherwise receive the journal while the real auditor loses it for good. Nothing
//! here checks that the auditor received the sealed key; keep it until they confirm.
//!
//! Wiping covers the caller's buffer; copies the compiler or the OS made elsewhere are out of reach of
//! this code.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const VERSION: u8 = 2;
const INFO: &[u8] = b"ona/auditor-key/v2";
pub const SEALED_LEN: usize = 1 + 32 + 24 + 32 + 16;

/// `SHA-256("ona/auditor-fp/v1" || public key)`: what is pinned or published to identify an auditor.
pub fn auditor_fingerprint(public: &[u8; 32]) -> [u8; 32] {
    Sha256::new().chain_update(b"ona/auditor-fp/v1").chain_update(public).finalize().into()
}

fn context(ephemeral: &[u8; 32], auditor: &[u8; 32], journal_start: &[u8; 32]) -> Vec<u8> {
    let mut out = INFO.to_vec();
    out.push(VERSION);
    out.extend_from_slice(ephemeral);
    out.extend_from_slice(auditor);
    out.extend_from_slice(journal_start);
    out
}

fn derive(shared: &[u8; 32], context: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(context, key.as_mut())
        .expect("32 bytes is a valid HKDF output length");
    key
}

/// A new auditor key pair: the secret, to keep offline, and the public key to give the agent.
pub fn auditor_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret).to_bytes();
    (Zeroizing::new(secret.to_bytes()), public)
}

/// Seals `master` for the auditor, then wipes it. Refused, with the key left as it was, if the auditor key
/// does not match `expected_fingerprint` or the seal fails: a refusal never loses the journal.
pub fn seal_master_key(
    master: &mut [u8; 32],
    auditor_public: &[u8; 32],
    expected_fingerprint: &[u8; 32],
    journal_start: &[u8; 32],
) -> Result<Vec<u8>, String> {
    if &auditor_fingerprint(auditor_public) != expected_fingerprint {
        return Err("this is not the expected auditor key".into());
    }
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let shared = ephemeral.diffie_hellman(&PublicKey::from(*auditor_public));
    if !shared.was_contributory() {
        return Err("auditor key is invalid".into());
    }
    let info = context(&ephemeral_public, auditor_public, journal_start);
    let key = derive(shared.as_bytes(), &info);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: master.as_slice(), aad: &info })
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = vec![VERSION];
    out.extend_from_slice(&ephemeral_public);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    master.zeroize();
    Ok(out)
}

/// The auditor's side, for the journal whose chain start is `journal_start`.
pub fn open_master_key(
    auditor_secret: &[u8; 32],
    sealed: &[u8],
    journal_start: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, String> {
    if sealed.len() != SEALED_LEN || sealed[0] != VERSION {
        return Err("not a sealed master key".into());
    }
    let ephemeral_public: [u8; 32] = sealed[1..33].try_into().map_err(|_| "bad key".to_string())?;
    let secret = StaticSecret::from(*auditor_secret);
    let auditor_public = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral_public));
    if !shared.was_contributory() {
        return Err("sealed key is invalid".into());
    }
    let info = context(&ephemeral_public, &auditor_public, journal_start);
    let key = derive(shared.as_bytes(), &info);
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(key.as_ref().into())
            .decrypt(XNonce::from_slice(&sealed[33..57]), Payload { msg: &sealed[57..], aad: &info })
            .map_err(|_| "wrong auditor key, wrong journal or altered sealed key".to_string())?,
    );
    let mut master = Zeroizing::new([0u8; 32]);
    master.copy_from_slice(&plain);
    Ok(master)
}
