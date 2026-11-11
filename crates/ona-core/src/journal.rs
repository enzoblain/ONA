//! Hash-chained mission journal. The exact bytes of each line are hashed, so integrity can be
//! checked without any key and without JSON canonicalization.
//!
//! Three values come from the mission's secret salt, which only the agent holds:
//! - the **chain start** `SHA-256("ona/j/v1" || salt)`: enough to check the chain (`verify_from`), and it
//!   does not give the salt back;
//! - the **fingerprint key**: fingerprints are HMACs under it, so whoever checks the chain cannot test
//!   guessed contents against them. Two equal contents in one mission still give the same fingerprint;
//! - the **checkpoint key** (`checkpoint` module), for the auditor who checks the anchors.
//!
//! Lines are plaintext during a mission. `seal` consumes the journal, wipes its plaintext and returns the
//! encrypted form for an auditor. Copies the caller made before (`to_bytes`, `entries`) are its own.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::checkpoint::prf;

const DOMAIN: &[u8] = b"ona/j/v1";
const SEALED_VERSION: u64 = 2;
/// Plaintext is padded to a multiple of this, so an entry's length does not reveal its kind.
pub const PADDING_BLOCK: usize = 512;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// The value the chain starts from. Give this, not the salt, to whoever checks the chain.
pub fn chain_start(salt: &[u8; 32]) -> [u8; 32] {
    Sha256::new().chain_update(DOMAIN).chain_update(salt).finalize().into()
}

/// Key for one entry of one journal. Giving it to someone discloses that entry and no other, in this
/// journal only: the chain start is the HKDF salt.
pub fn entry_key(master: &[u8; 32], start: &[u8; 32], index: u64) -> Zeroizing<[u8; 32]> {
    let mut info = b"ona/j/e".to_vec();
    info.extend_from_slice(&index.to_le_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(start), master)
        .expand(&info, key.as_mut())
        .expect("32 bytes is a valid HKDF output length");
    key
}

/// Written in each sealed line, so whoever receives an entry key can check it is the one the line was
/// sealed with.
fn key_commitment(key: &[u8; 32]) -> [u8; 32] {
    Sha256::new().chain_update(b"ona/j/kc").chain_update(key).finalize().into()
}

fn entry_aad(index: u64, prev: &[u8]) -> Vec<u8> {
    let mut aad = index.to_le_bytes().to_vec();
    aad.extend_from_slice(prev);
    aad
}

fn pad(text: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new((text.len() as u32).to_le_bytes().to_vec());
    out.extend_from_slice(text.as_bytes());
    let target = out.len().div_ceil(PADDING_BLOCK) * PADDING_BLOCK;
    out.resize(target, 0);
    out
}

fn unpad(bytes: &[u8]) -> Option<String> {
    let len = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    String::from_utf8(bytes.get(4..4 + len)?.to_vec()).ok()
}

/// A plain line starts with `{"i":<n>,"prev":"<64 hex>"`. The sealed entry holds the line without the
/// 64 hex digits of `prev`: one disclosed entry does not hand out the chain head before it.
fn prev_range(line: &str) -> Option<std::ops::Range<usize>> {
    let marker = ",\"prev\":\"";
    let start = line.find(marker)? + marker.len();
    let end = start + 64;
    (line.get(start..end)?.bytes().all(|b| b.is_ascii_hexdigit()) && line.get(end..end + 1) == Some("\""))
        .then_some(start..end)
}

fn without_prev(line: &str) -> Option<String> {
    let range = prev_range(line)?;
    Some(format!("{}{}", &line[..range.start], &line[range.end..]))
}

fn with_prev(inner: &str, prev: &[u8; 32]) -> Option<String> {
    let marker = ",\"prev\":\"\"";
    let at = inner.find(marker)? + marker.len() - 1;
    Some(format!("{}{}{}", &inner[..at], to_hex(prev), &inner[at..]))
}

/// Encrypted journal. Its chain is checked by `verify_from` with the chain start and no key.
///
/// `head` changes at every seal (fresh nonces). Whoever closes the mission must anchor it, or nothing ties
/// this sealed form to a date.
pub struct Sealed {
    pub bytes: Vec<u8>,
    pub head: [u8; 32],
}

/// Decrypts one sealed line with that entry's key. Returns the entry without its `prev` field.
pub fn open_entry(key: &[u8; 32], line: &str) -> Result<String, String> {
    let value: Value = serde_json::from_str(line).map_err(|_| "not valid JSON".to_string())?;
    if value["v"].as_u64() != Some(SEALED_VERSION) {
        return Err("unknown sealed format".into());
    }
    let index = value["i"].as_u64().ok_or("missing index")?;
    let prev = value["prev"].as_str().and_then(from_hex).ok_or("missing chain link")?;
    let commitment = value["kc"].as_str().and_then(from_hex).ok_or("missing key commitment")?;
    if commitment != key_commitment(key) {
        return Err("this key is not the one the entry was sealed with".into());
    }
    let bytes = value["ct"].as_str().and_then(from_hex).filter(|b| b.len() > 24).ok_or("missing ciphertext")?;
    let (nonce, ciphertext) = bytes.split_at(24);
    let aad = entry_aad(index, &prev);
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| "wrong key or altered entry".to_string())?,
    );
    unpad(&plain).ok_or_else(|| "bad padding".to_string())
}

/// Checks the sealed chain against `sealed_head`, then decrypts every entry and rebuilds the plaintext
/// lines, whose own chain the caller can then check with `verify_from`. Nothing is decrypted if the sealed
/// chain does not hold.
pub fn open_all(master: &[u8; 32], start: &[u8; 32], bytes: &[u8], sealed_head: &[u8; 32]) -> Result<Vec<String>, String> {
    verify_from(start, bytes, sealed_head).map_err(|e| format!("sealed journal, entry {}: {}", e.entry, e.reason))?;
    let text = std::str::from_utf8(bytes).map_err(|_| "not text".to_string())?;
    let mut plain_head = *start;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let inner = open_entry(&entry_key(master, start, i as u64), line)?;
        let full = with_prev(&inner, &plain_head).ok_or("entry without a chain link")?;
        plain_head = link(&plain_head, full.as_bytes());
        out.push(full);
    }
    Ok(out)
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

/// A failed seal: the reason, and the journal itself, untouched.
pub struct SealError {
    pub journal: Journal,
    pub reason: String,
}

impl std::fmt::Debug for SealError {
    /// The reason only: never the journal's content.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealError").field("reason", &self.reason).finish_non_exhaustive()
    }
}

pub struct Journal {
    salt: [u8; 32],
    lines: Vec<String>,
    head: [u8; 32],
}

impl Drop for Journal {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.lines.zeroize();
    }
}

impl Journal {
    /// `salt` must be secret and new for each mission.
    pub fn new(salt: [u8; 32]) -> Self {
        Self { salt, lines: Vec::new(), head: chain_start(&salt) }
    }

    pub fn start(&self) -> [u8; 32] {
        chain_start(&self.salt)
    }

    /// For the auditor who checks the anchored checkpoints of this journal.
    pub fn checkpoint_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(prf(&self.salt, b"ona/cp/key", &[]))
    }

    /// Keyed fingerprint of a value, so the journal proves content without holding it. Only the agent can
    /// compute it; checking the chain gives no way to test a guess.
    pub fn fingerprint(&self, value: &[u8]) -> String {
        let key = Zeroizing::new(prf(&self.salt, b"ona/j/fp-key", &[]));
        to_hex(&prf(key.as_ref(), b"ona/j/fp", value))
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

    /// Produces the encrypted journal and wipes the plaintext: the journal is consumed. The caller then
    /// seals `master` for the auditor (`auditor::seal_master_key`), which wipes it too.
    ///
    /// Reading the plaintext after sealing does not compile:
    ///
    /// ```compile_fail
    /// use ona_core::journal::{Journal, Kind};
    /// let mut j = Journal::new([7; 32]);
    /// j.append(Kind::TxSubmitted, serde_json::json!({"to": "eve.near"}));
    /// let _sealed = j.seal(&[9; 32]).unwrap();
    /// let _still_readable = j.to_bytes();
    /// ```
    /// If sealing fails, nothing is wiped: the journal comes back in the error.
    pub fn seal(mut self, master: &[u8; 32]) -> Result<Sealed, SealError> {
        match self.sealed_form(master) {
            Ok(sealed) => {
                self.lines.zeroize();
                Ok(sealed)
            }
            Err(reason) => Err(SealError { journal: self, reason }),
        }
    }

    fn sealed_form(&self, master: &[u8; 32]) -> Result<Sealed, String> {
        let start = self.start();
        let mut head = start;
        let mut bytes = Vec::new();
        for (i, line) in self.lines.iter().enumerate() {
            let index = i as u64;
            let aad = entry_aad(index, &head);
            let mut nonce = [0u8; 24];
            OsRng.fill_bytes(&mut nonce);
            let key = entry_key(master, &start, index);
            let inner = Zeroizing::new(without_prev(line).ok_or("journal line without a chain link")?);
            let plain = pad(&inner);
            let ciphertext = XChaCha20Poly1305::new(key.as_ref().into())
                .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: &aad })
                .map_err(|_| "encryption failed".to_string())?;
            let mut ct = nonce.to_vec();
            ct.extend_from_slice(&ciphertext);
            let sealed = format!(
                "{{\"v\":{SEALED_VERSION},\"i\":{index},\"prev\":\"{}\",\"kc\":\"{}\",\"ct\":\"{}\"}}",
                to_hex(&head),
                to_hex(&key_commitment(&key)),
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

/// The chain start, then the head after each line. Checks indexes and links, not a final head.
pub fn heads_from(start: &[u8; 32], bytes: &[u8]) -> Result<Vec<[u8; 32]>, JournalError> {
    let mut heads = vec![*start];
    if bytes.is_empty() {
        return Ok(heads);
    }
    let last = bytes.iter().filter(|b| **b == b'\n').count();
    let body = bytes.strip_suffix(b"\n").ok_or(JournalError { entry: last, reason: "missing final newline" })?;
    for (index, line) in body.split(|b| *b == b'\n').enumerate() {
        let fail = |reason| JournalError { entry: index, reason };
        let value: Value = serde_json::from_slice(line).map_err(|_| fail("not valid JSON"))?;
        if value["i"].as_u64() != Some(index as u64) {
            return Err(fail("wrong index"));
        }
        let current = *heads.last().expect("never empty");
        if value["prev"].as_str() != Some(to_hex(&current).as_str()) {
            return Err(fail("broken chain"));
        }
        heads.push(link(&current, line));
    }
    Ok(heads)
}

/// Checks the whole chain from `start` against the expected final head.
pub fn verify_from(start: &[u8; 32], bytes: &[u8], expected_head: &[u8; 32]) -> Result<usize, JournalError> {
    let heads = heads_from(start, bytes)?;
    let count = heads.len() - 1;
    if heads.last() != Some(expected_head) {
        return Err(JournalError { entry: count.saturating_sub(1), reason: "final head differs" });
    }
    Ok(count)
}

/// The agent's own check, from the salt.
pub fn verify(salt: &[u8; 32], bytes: &[u8], expected_head: &[u8; 32]) -> Result<usize, JournalError> {
    verify_from(&chain_start(salt), bytes, expected_head)
}

/// What an auditor runs on a plaintext journal (from `open_all`) and its anchored checkpoints: the chain,
/// the checkpoints (`checkpoint::verify_checkpoints`), and a last entry that closes the mission.
pub fn audit<R: crate::checkpoint::AnchorReader>(
    start: &[u8; 32],
    checkpoint_key: &[u8; 32],
    trust: &crate::checkpoint::AuditTrust,
    lines: &[String],
    presented: &[crate::checkpoint::PresentedCheckpoint],
    reader: &R,
) -> Result<crate::checkpoint::CheckpointAudit, String> {
    let mut bytes = Vec::new();
    for line in lines {
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }
    let heads = heads_from(start, &bytes).map_err(|e| format!("journal, entry {}: {}", e.entry, e.reason))?;
    let closes = lines
        .last()
        .and_then(|l| serde_json::from_str::<Value>(l).ok())
        .is_some_and(|v| v["kind"] == Kind::MissionClose.as_str());
    if !closes {
        return Err("the journal does not end with mission_close".into());
    }
    crate::checkpoint::verify_checkpoints(checkpoint_key, trust, &heads, presented, reader)
}
