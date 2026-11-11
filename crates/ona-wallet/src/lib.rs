//! Encrypted wallet file. Each change is one appended line, synced to disk before the action it
//! protects: a token's secrets are saved before its deposit, so a crash cannot lose it.
//!
//! Each line is `hex(nonce24 || XChaCha20-Poly1305(key, record, aad = line index))`, so lines cannot
//! be altered or reordered. A seal file next to the wallet (`<wallet>.seal`, encrypted with the same
//! key) holds the number of lines and a hash chain over them, updated after each line:
//! - a last line cut by a crash (no final newline, does not decrypt) is dropped and reported by
//!   `dropped_torn_line`;
//! - an older copy of the wallet, or a wallet with lines removed from its end, is refused;
//! - a missing wallet whose seal says lines existed is refused instead of being recreated empty;
//! - a wallet with lines and no seal is refused by design; `open_adopting_unsealed` adopts one.
//!
//! Nothing is written to the file before these checks pass, and a torn line is cut only once the
//! key is shown to be right (by a complete line or by the seal).
//!
//! Restoring both the wallet and its seal from the same older backup is not detected: for that the
//! caller must keep `state()` somewhere the backup does not reach (the system keychain), and check it
//! with `open_expecting`. Getting the key from the operating system's secure storage is not
//! implemented. The file is locked while open: a second `open` of the same file is refused.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use ona_token::{PendingToken, Token, G1_LEN, G2_LEN, TOKEN_LEN};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

const PENDING: u8 = 0;
const MINTED: u8 = 1;
const SPENDING: u8 = 2;
const RELEASED: u8 = 3;
const SEAL_AAD: &[u8] = b"ona/wallet/seal/v1";
const CHAIN_TAG: &[u8] = b"ona/wallet/line/v1";

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn chain(head: &[u8; 32], line: &str) -> [u8; 32] {
    Sha256::new().chain_update(CHAIN_TAG).chain_update(head).chain_update(line.as_bytes()).finalize().into()
}

/// How many lines the wallet holds and the hash chain over them. Keep it outside the wallet's
/// folder (keychain) to detect a restore of both the wallet and its seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletState {
    pub lines: u64,
    pub head: [u8; 32],
}

pub struct Wallet {
    file: File,
    seal_path: PathBuf,
    cipher: XChaCha20Poly1305,
    lines: u64,
    head: [u8; 32],
    pending: Vec<Vec<u8>>,
    tokens: Vec<(Token, [u8; 32])>,
    spending: BTreeSet<[u8; 32]>,
    /// A write failed: nothing more is written until the wallet is opened again.
    broken: bool,
    dropped_torn_line: bool,
}

fn seal_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".seal");
    path.with_file_name(name)
}

fn sync_folder(path: &Path) -> Result<(), String> {
    let folder = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(folder).and_then(|d| d.sync_all()).map_err(|e| e.to_string())
}

impl Wallet {
    /// Opens or creates the wallet. A wrong key, any altered line, a rollback or a missing file
    /// that existed is an error; so is a wallet already open elsewhere.
    pub fn open(path: &Path, key: &[u8; 32]) -> Result<Self, String> {
        Self::open_inner(path, key, None, false)
    }

    /// As `open`, and also refuses a wallet older than `expected`, a state kept by the caller.
    pub fn open_expecting(path: &Path, key: &[u8; 32], expected: WalletState) -> Result<Self, String> {
        Self::open_inner(path, key, Some(expected), false)
    }

    /// Opens a wallet written before seals existed, and seals it. `open` refuses a wallet without
    /// a seal by design: a deleted seal could hide a rollback. Use this only for a wallet known to
    /// be the latest copy; every line must still decrypt with `key`.
    pub fn open_adopting_unsealed(path: &Path, key: &[u8; 32]) -> Result<Self, String> {
        if seal_path(path).exists() {
            return Err("this wallet already has a seal: use open".into());
        }
        Self::open_inner(path, key, None, true)
    }

    fn open_inner(path: &Path, key: &[u8; 32], expected: Option<WalletState>, adopt_unsealed: bool) -> Result<Self, String> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let seal_path = seal_path(path);
        let existed = path.exists();
        let seal = read_seal(&seal_path, &cipher)?;
        if !existed && seal.is_some_and(|s| s.lines > 0) {
            return Err("the wallet file is missing, but a wallet existed here (its seal remains)".into());
        }
        // Checked before the file is created: a refusal leaves nothing behind.
        if let Some(expected) = expected.filter(|e| e.lines > 0) {
            if !existed {
                return Err(format!("the wallet was rolled back or deleted: it is missing, {} records were written", expected.lines));
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        file.try_lock().map_err(|_| "the wallet is already open in another process".to_string())?;
        let mode = file.metadata().map_err(|e| e.to_string())?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err("the wallet file must be readable by its owner only (chmod 600)".into());
        }
        let mut bytes = Vec::new();
        (&file).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        let text = String::from_utf8(bytes).map_err(|_| "corrupt wallet line".to_string())?;

        let mut wallet = Self {
            file,
            seal_path,
            cipher,
            lines: 0,
            head: [0u8; 32],
            pending: Vec::new(),
            tokens: Vec::new(),
            spending: BTreeSet::new(),
            broken: false,
            dropped_torn_line: false,
        };
        // Nothing is written to the file until every check below has passed.
        let mut heads = vec![wallet.head];
        let mut complete_len = 0usize;
        let mut torn: Option<&str> = None;
        for piece in text.split_inclusive('\n') {
            match piece.strip_suffix('\n') {
                Some(line) => {
                    let record = wallet.decrypt(line)?;
                    wallet.apply(&record)?;
                    wallet.advance(line);
                    heads.push(wallet.head);
                    complete_len += piece.len();
                }
                None => torn = Some(piece),
            }
        }
        enum Repair {
            None,
            AddNewline,
            Cut,
        }
        let mut repair = Repair::None;
        if let Some(line) = torn {
            match wallet.decrypt(line) {
                // Written in full, only the newline is missing: keep it.
                Ok(record) => {
                    wallet.apply(&record)?;
                    wallet.advance(line);
                    heads.push(wallet.head);
                    repair = Repair::AddNewline;
                }
                // A crash during an append, but only if the key is shown to be right: by a complete
                // line or by the seal. Otherwise it may be a wrong key, and nothing is touched.
                Err(e) => {
                    if wallet.lines == 0 && seal.is_none() {
                        return Err(e);
                    }
                    repair = Repair::Cut;
                }
            }
        }

        for state in [seal, expected].into_iter().flatten() {
            if state.lines > wallet.lines {
                return Err(format!(
                    "the wallet was rolled back or cut: it holds {} records, {} were written",
                    wallet.lines, state.lines
                ));
            }
            if heads[state.lines as usize] != state.head {
                return Err("the wallet does not match its recorded state".into());
            }
        }
        let reseal = match seal {
            None if wallet.lines > 0 && !adopt_unsealed => {
                return Err("the wallet seal is missing: refused by design (see open_adopting_unsealed)".into())
            }
            // One line may have been written just before a crash, before its seal.
            Some(s) if wallet.lines > s.lines + 1 => return Err("the wallet seal is older than the wallet".into()),
            Some(s) => s.lines != wallet.lines,
            None => true,
        };
        match repair {
            Repair::None => {}
            Repair::AddNewline => {
                wallet.file.write_all(b"\n").and_then(|_| wallet.file.sync_all()).map_err(|e| e.to_string())?;
            }
            Repair::Cut => {
                wallet.file.set_len(complete_len as u64).and_then(|_| wallet.file.sync_all()).map_err(|e| e.to_string())?;
                wallet.dropped_torn_line = true;
            }
        }
        if reseal {
            wallet.write_seal()?;
        }
        Ok(wallet)
    }

    /// True if `open` found and removed a last line cut by a crash.
    pub fn dropped_torn_line(&self) -> bool {
        self.dropped_torn_line
    }

    /// The current line count and hash chain, to keep outside the wallet's folder.
    pub fn state(&self) -> WalletState {
        WalletState { lines: self.lines, head: self.head }
    }

    fn advance(&mut self, line: &str) {
        self.head = chain(&self.head, line);
        self.lines += 1;
    }

    fn decrypt(&self, line: &str) -> Result<Vec<u8>, String> {
        let bytes = from_hex(line).filter(|b| b.len() > 24).ok_or("corrupt wallet line")?;
        let (nonce, ciphertext) = bytes.split_at(24);
        let aad = self.lines.to_le_bytes();
        self.cipher
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| "wrong key or altered wallet".to_string())
    }

    fn write_seal(&mut self) -> Result<(), String> {
        let mut plain = self.lines.to_le_bytes().to_vec();
        plain.extend_from_slice(&self.head);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let sealed = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: SEAL_AAD })
            .map_err(|_| "encryption failed".to_string())?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&sealed);
        let mut temporary = self.seal_path.clone().into_os_string();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        // The wallet lock is held, so no other writer uses this name; a leftover is removed.
        let _ = fs::remove_file(&temporary);
        let result = (|| -> std::io::Result<()> {
            let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)?;
            f.write_all(format!("{}\n", to_hex(&blob)).as_bytes())?;
            f.sync_all()?;
            fs::rename(&temporary, &self.seal_path)
        })();
        result.map_err(|e| format!("cannot update the wallet seal: {e}"))?;
        sync_folder(&self.seal_path)
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
        if self.broken {
            return Err("an earlier write to the wallet failed; open it again".into());
        }
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = self.lines.to_le_bytes();
        let ciphertext = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &record, aad: &aad })
            .map_err(|_| "encryption failed".to_string())?;
        let mut line = nonce.to_vec();
        line.extend_from_slice(&ciphertext);
        let line = to_hex(&line);
        // One write for the line and its newline, so a crash leaves at most one torn line.
        if let Err(e) = self.file.write_all(format!("{line}\n").as_bytes()).and_then(|_| self.file.sync_all()) {
            self.broken = true;
            return Err(e.to_string());
        }
        self.apply(&record)?;
        self.advance(&line);
        if let Err(e) = self.write_seal() {
            self.broken = true;
            return Err(e);
        }
        Ok(())
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

    /// Call this before sending a spend, so a restart cannot use the same token twice. Only a
    /// token of this wallet that is not already being spent can be marked.
    pub fn mark_spending(&mut self, nf: &[u8; 32]) -> Result<(), String> {
        if !self.tokens.iter().any(|(t, _)| &t.nullifier() == nf) {
            return Err("no token with this nullifier in the wallet".into());
        }
        if self.spending.contains(nf) {
            return Err("this token is already being spent".into());
        }
        let mut record = vec![SPENDING];
        record.extend_from_slice(nf);
        self.append(record)
    }

    /// Makes a token available again, only after the chain shows the spend did not happen.
    pub fn release(&mut self, nf: &[u8; 32]) -> Result<(), String> {
        if !self.spending.contains(nf) {
            return Err("this token is not being spent".into());
        }
        let mut record = vec![RELEASED];
        record.extend_from_slice(nf);
        self.append(record)
    }
}

/// Reads the seal, if any. A seal that does not decrypt is an error (wrong key or altered).
fn read_seal(path: &Path, cipher: &XChaCha20Poly1305) -> Result<Option<WalletState>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let bytes = from_hex(text.trim()).filter(|b| b.len() > 24).ok_or("corrupt wallet seal")?;
    let (nonce, ciphertext) = bytes.split_at(24);
    let plain = cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: SEAL_AAD })
        .map_err(|_| "wrong key or altered wallet seal".to_string())?;
    if plain.len() != 40 {
        return Err("corrupt wallet seal".into());
    }
    let lines = u64::from_le_bytes(plain[..8].try_into().expect("8 bytes"));
    let head: [u8; 32] = plain[8..].try_into().expect("32 bytes");
    Ok(Some(WalletState { lines, head }))
}
