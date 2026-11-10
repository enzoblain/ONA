//! Hash-chained mission journal. The exact bytes of each line are hashed, so integrity can be
//! checked without any key and without JSON canonicalization.
//!
//! Lines are plaintext during a mission. `seal` turns them into the encrypted form for an auditor.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"ona/j/v1";
/// Plaintext is padded to a multiple of this, so an entry's length does not reveal its kind.
pub const PADDING_BLOCK: usize = 512;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn genesis(salt: &[u8; 32]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(salt).finalize().into()
}

/// Key for one entry. Giving it to someone discloses that entry and no other.
pub fn entry_key(master: &[u8; 32], index: u64) -> [u8; 32] {
    let mut info = b"ona/j/e".to_vec();
    info.extend_from_slice(&index.to_le_bytes());
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, master)
        .expand(&info, &mut key)
        .expect("32 bytes is a valid HKDF output length");
    key
}

fn entry_aad(index: u64, prev: &[u8]) -> Vec<u8> {
    let mut aad = index.to_le_bytes().to_vec();
    aad.extend_from_slice(prev);
    aad
}

fn pad(text: &str) -> Vec<u8> {
    let mut out = (text.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(text.as_bytes());
    let target = out.len().div_ceil(PADDING_BLOCK) * PADDING_BLOCK;
    out.resize(target, 0);
    out
}

fn unpad(bytes: &[u8]) -> Option<String> {
    let len = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    String::from_utf8(bytes.get(4..4 + len)?.to_vec()).ok()
}

/// Encrypted journal. Its chain is checked by `verify`, with no key at all.
pub struct Sealed {
    pub bytes: Vec<u8>,
    pub head: [u8; 32],
}

/// Decrypts one line of a sealed journal with that entry's key.
pub fn open_entry(key: &[u8; 32], line: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(line).map_err(|_| "not valid JSON".to_string())?;
    let index = value["i"].as_u64().ok_or("missing index")?;
    let prev = value["prev"].as_str().and_then(from_hex).ok_or("missing chain link")?;
    let bytes = value["ct"].as_str().and_then(from_hex).filter(|b| b.len() > 24).ok_or("missing ciphertext")?;
    let (nonce, ciphertext) = bytes.split_at(24);
    let aad = entry_aad(index, &prev);
    let plain = XChaCha20Poly1305::new(key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
        .map_err(|_| "wrong key or altered entry".to_string())?;
    unpad(&plain).ok_or_else(|| "bad padding".to_string())
}

/// Decrypts a whole sealed journal with the master key.
pub fn open_all(master: &[u8; 32], bytes: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "not text".to_string())?;
    text.lines()
        .enumerate()
        .map(|(i, line)| open_entry(&entry_key(master, i as u64), line))
        .collect()
}

fn link(prev: &[u8; 32], line: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(prev).chain_update(line).finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    MissionOpen,
    PlanAccepted,
    GateDecision,
    ToolCommit,
    LlmCommit,
    HumanConfirm,
    TxSubmitted,
    MissionClose,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::MissionOpen => "mission_open",
            Kind::PlanAccepted => "plan_accepted",
            Kind::GateDecision => "gate_decision",
            Kind::ToolCommit => "tool_commit",
            Kind::LlmCommit => "llm_commit",
            Kind::HumanConfirm => "human_confirm",
            Kind::TxSubmitted => "tx_submitted",
            Kind::MissionClose => "mission_close",
        }
    }
}

pub struct Journal {
    salt: [u8; 32],
    lines: Vec<String>,
    head: [u8; 32],
}

impl Journal {
    pub fn new(salt: [u8; 32]) -> Self {
        Self { salt, lines: Vec::new(), head: genesis(&salt) }
    }

    /// Salted fingerprint of a value, so the journal proves content without holding it.
    pub fn fingerprint(&self, value: &[u8]) -> String {
        let digest: [u8; 32] = Sha256::new()
            .chain_update(b"ona/j/fp")
            .chain_update(self.salt)
            .chain_update(value)
            .finalize()
            .into();
        to_hex(&digest)
    }

    pub fn append(&mut self, kind: Kind, data: Value) {
        let line = format!(
            "{{\"i\":{},\"prev\":\"{}\",\"kind\":\"{}\",\"data\":{}}}",
            self.lines.len(),
            to_hex(&self.head),
            kind.as_str(),
            data
        );
        self.head = link(&self.head, line.as_bytes());
        self.lines.push(line);
    }

    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for line in &self.lines {
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        out
    }

    /// Produces the encrypted journal. The caller wipes `master` once it is sealed for the
    /// auditor, after which the agent can no longer read its own journal.
    pub fn seal(&self, master: &[u8; 32]) -> Result<Sealed, String> {
        let mut head = genesis(&self.salt);
        let mut bytes = Vec::new();
        for (i, line) in self.lines.iter().enumerate() {
            let index = i as u64;
            let aad = entry_aad(index, &head);
            let mut nonce = [0u8; 24];
            OsRng.fill_bytes(&mut nonce);
            let key = entry_key(master, index);
            let plain = pad(line);
            let ciphertext = XChaCha20Poly1305::new((&key).into())
                .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad })
                .map_err(|_| "encryption failed".to_string())?;
            let mut ct = nonce.to_vec();
            ct.extend_from_slice(&ciphertext);
            let sealed = format!(
                "{{\"v\":1,\"i\":{index},\"prev\":\"{}\",\"ct\":\"{}\"}}",
                to_hex(&head),
                to_hex(&ct)
            );
            head = link(&head, sealed.as_bytes());
            bytes.extend_from_slice(sealed.as_bytes());
            bytes.push(b'\n');
        }
        Ok(Sealed { bytes, head })
    }

    pub fn entries(&self) -> Vec<Value> {
        self.lines.iter().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }
}

/// `entry` is the first line that disagrees with the chain. The altered line is that one or the
/// one before it, because a line's content is only committed to by its successor.
#[derive(Debug, PartialEq, Eq)]
pub struct JournalError {
    pub entry: usize,
    pub reason: &'static str,
}

/// Checks the whole chain against the expected final head.
pub fn verify(salt: &[u8; 32], bytes: &[u8], expected_head: &[u8; 32]) -> Result<usize, JournalError> {
    let mut current = genesis(salt);
    let body = if bytes.is_empty() {
        bytes
    } else {
        let last = bytes.iter().filter(|b| **b == b'\n').count();
        bytes.strip_suffix(b"\n").ok_or(JournalError { entry: last, reason: "missing final newline" })?
    };
    let mut count = 0usize;
    if !body.is_empty() {
        for (index, line) in body.split(|b| *b == b'\n').enumerate() {
            let fail = |reason| JournalError { entry: index, reason };
            let value: Value = serde_json::from_slice(line).map_err(|_| fail("not valid JSON"))?;
            if value["i"].as_u64() != Some(index as u64) {
                return Err(fail("wrong index"));
            }
            if value["prev"].as_str() != Some(to_hex(&current).as_str()) {
                return Err(fail("broken chain"));
            }
            current = link(&current, line);
            count += 1;
        }
    }
    if &current != expected_head {
        return Err(JournalError { entry: count.saturating_sub(1), reason: "final head differs" });
    }
    Ok(count)
}
