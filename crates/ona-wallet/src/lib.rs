//! Encrypted wallet file. Each change is one appended line, synced to disk before the action it
//! protects: a token's secrets are saved before its deposit, so a crash cannot lose it.
//!
//! Each line is `hex(nonce24 || XChaCha20-Poly1305(key, record, aad = line index))`, so lines cannot
//! be altered or reordered. Removing lines from the end is not detected. Getting the key from
//! the operating system's secure storage is not implemented.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use ona_token::{PendingToken, Token, G1_LEN, G2_LEN, TOKEN_LEN};
use rand::rngs::OsRng;
use rand::RngCore;

const PENDING: u8 = 0;
const MINTED: u8 = 1;
const SPENDING: u8 = 2;
const RELEASED: u8 = 3;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub struct Wallet {
    file: File,
    cipher: XChaCha20Poly1305,
    lines: u64,
    pending: Vec<Vec<u8>>,
    tokens: Vec<(Token, [u8; 32])>,
    spending: BTreeSet<[u8; 32]>,
}

impl Wallet {
    /// Opens or creates the wallet. A wrong key or any altered line is an error.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self, String> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let text = if path.exists() {
            fs::read_to_string(path).map_err(|e| e.to_string())?
        } else {
            String::new()
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        let mut wallet = Self {
            file,
            cipher,
            lines: 0,
            pending: Vec::new(),
            tokens: Vec::new(),
            spending: BTreeSet::new(),
        };
        for line in text.lines() {
            let record = wallet.decrypt(line)?;
            wallet.apply(&record)?;
            wallet.lines += 1;
        }
        Ok(wallet)
    }

    fn decrypt(&self, line: &str) -> Result<Vec<u8>, String> {
        let bytes = from_hex(line).filter(|b| b.len() > 24).ok_or("corrupt wallet line")?;
        let (nonce, ciphertext) = bytes.split_at(24);
        let aad = self.lines.to_le_bytes();
        self.cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| "wrong key or altered wallet".to_string())
    }

    fn apply(&mut self, record: &[u8]) -> Result<(), String> {
        let (kind, data) = record.split_first().ok_or("empty wallet record")?;
        match *kind {
            PENDING => self.pending.push(data.to_vec()),
            MINTED => {
                if data.len() != G1_LEN + TOKEN_LEN + 32 {
                    return Err("bad minted record".into());
                }
                let (blinded, rest) = data.split_at(G1_LEN);
                let (token, seed) = rest.split_at(TOKEN_LEN);
                let token = Token::from_bytes(token).map_err(|e| e.to_string())?;
                let seed: [u8; 32] = seed.try_into().map_err(|_| "bad minted record")?;
                self.pending.retain(|p| {
                    PendingToken::from_secret_bytes(p).map(|t| t.blinded[..] != *blinded).unwrap_or(true)
                });
                self.tokens.push((token, seed));
            }
            SPENDING | RELEASED => {
                let nf: [u8; 32] = data.try_into().map_err(|_| "bad spend record")?;
                if *kind == SPENDING {
                    self.spending.insert(nf);
                } else {
                    self.spending.remove(&nf);
                }
            }
            _ => return Err("unknown wallet record".into()),
        }
        Ok(())
    }

    fn append(&mut self, record: Vec<u8>) -> Result<(), String> {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = self.lines.to_le_bytes();
        let ciphertext = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &record, aad: &aad })
            .map_err(|_| "encryption failed".to_string())?;
        let mut line = nonce.to_vec();
        line.extend_from_slice(&ciphertext);
        writeln!(self.file, "{}", to_hex(&line)).map_err(|e| e.to_string())?;
        self.file.sync_all().map_err(|e| e.to_string())?;
        self.lines += 1;
        self.apply(&record)
    }

    /// Call this before sending the deposit.
    pub fn save_pending(&mut self, token: &PendingToken) -> Result<(), String> {
        let mut record = vec![PENDING];
        record.extend_from_slice(&token.to_secret_bytes());
        self.append(record)
    }

    /// Tokens waiting for a signature, including those from before a restart.
    pub fn pending(&self) -> Result<Vec<PendingToken>, String> {
        self.pending
            .iter()
            .map(|p| PendingToken::from_secret_bytes(p).map_err(|e| e.to_string()))
            .collect()
    }

    /// Completes a token from the signer's answer, verified under the key read from the contract.
    pub fn finish(
        &mut self,
        blinded: &[u8; G1_LEN],
        blind_sig: &[u8; G1_LEN],
        denom_pk: &[u8; G2_LEN],
    ) -> Result<Token, String> {
        let pending = self
            .pending()?
            .into_iter()
            .find(|p| &p.blinded == blinded)
            .ok_or("no pending token with this blinded point")?;
        let (token, owner) = pending.finish(blind_sig, denom_pk).map_err(|e| e.to_string())?;
        let mut record = vec![MINTED];
        record.extend_from_slice(blinded);
        record.extend_from_slice(&token.to_bytes());
        record.extend_from_slice(&owner.to_bytes());
        self.append(record)?;
        Ok(token)
    }

    /// Tokens that can be spent now.
    pub fn available(&self) -> Vec<(Token, SigningKey)> {
        self.tokens
            .iter()
            .filter(|(t, _)| !self.spending.contains(&t.nullifier()))
            .map(|(t, seed)| (t.clone(), SigningKey::from_bytes(seed)))
            .collect()
    }

    /// Call this before sending a spend, so a restart cannot use the same token twice.
    pub fn mark_spending(&mut self, nf: &[u8; 32]) -> Result<(), String> {
        let mut record = vec![SPENDING];
        record.extend_from_slice(nf);
        self.append(record)
    }

    /// Makes a token available again, only after the chain shows the spend did not happen.
    pub fn release(&mut self, nf: &[u8; 32]) -> Result<(), String> {
        let mut record = vec![RELEASED];
        record.extend_from_slice(nf);
        self.append(record)
    }
}
