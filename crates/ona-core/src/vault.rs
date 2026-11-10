//! Chat results kept on the device. By default they last at most 24 hours. A longer life exists
//! only as an explicit choice by the user for one chat (`keep`), which `forget` can undo.
//!
//! Each chat has its own key, stored apart from its encrypted file. Expiry destroys the key first,
//! then the file, so a chat is unreadable as soon as its key is gone. A read after the expiry
//! time is refused even if the purge has not run yet.
//!
//! Limits: keys are in a local file until the operating system's keychain is wired in, and a
//! deleted file can linger on a disk at the hardware level. Copies the user makes are theirs.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

pub const MAX_TTL_SECS: u64 = 24 * 3600;
const KEPT: u64 = u64::MAX;
const MAX_ID_LEN: usize = 64;
const KEYS_FILE: &str = "keys";

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

struct Entry {
    key: [u8; 32],
    expires_at: u64,
}

pub struct Vault {
    dir: PathBuf,
    ttl: u64,
    entries: BTreeMap<String, Entry>,
}

/// An id becomes a file name, so it must not be able to leave the vault directory.
fn check_id(id: &str) -> Result<(), String> {
    let valid = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if valid {
        Ok(())
    } else {
        Err("invalid chat id".into())
    }
}

/// Ties the ciphertext to its id and expiry, so editing the key file cannot extend a chat's life.
fn aad(id: &str, expires_at: u64) -> Vec<u8> {
    let mut out = id.as_bytes().to_vec();
    out.push(0);
    out.extend_from_slice(&expires_at.to_le_bytes());
    out
}

fn write_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    file.write_all(contents).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn sync_dir(dir: &Path) -> Result<(), String> {
    File::open(dir).and_then(|d| d.sync_all()).map_err(|e| e.to_string())
}

impl Vault {
    /// Opens the vault and destroys everything already expired.
    pub fn open(dir: &Path, now: u64) -> Result<Self, String> {
        Self::with_ttl(dir, now, MAX_TTL_SECS)
    }

    /// A shorter default is allowed. A longer one is not: keeping a chat is a choice made per chat.
    pub fn with_ttl(dir: &Path, now: u64, ttl: u64) -> Result<Self, String> {
        if ttl == 0 || ttl > MAX_TTL_SECS {
            return Err("lifetime must be between 1 second and 24 hours".into());
        }
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        let mut vault = Self { dir: dir.to_path_buf(), ttl, entries: BTreeMap::new() };
        vault.load_keys()?;
        vault.purge(now)?;
        vault.remove_orphans()?;
        Ok(vault)
    }

    fn keys_path(&self) -> PathBuf {
        self.dir.join(KEYS_FILE)
    }

    fn chat_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.chat"))
    }

    fn kept_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.kept"))
    }

    fn path_for(&self, id: &str, expires_at: u64) -> PathBuf {
        if expires_at == KEPT {
            self.kept_path(id)
        } else {
            self.chat_path(id)
        }
    }

    fn encrypt_to(&self, path: &Path, id: &str, key: &[u8; 32], expires_at: u64, text: &str) -> Result<(), String> {
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let associated = aad(id, expires_at);
        let ciphertext = XChaCha20Poly1305::new(key.into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: text.as_bytes(), aad: &associated })
            .map_err(|_| "encryption failed".to_string())?;
        let mut contents = nonce.to_vec();
        contents.extend_from_slice(&ciphertext);
        write_private(path, &contents)?;
        sync_dir(&self.dir)
    }

    fn load_keys(&mut self) -> Result<(), String> {
        let path = self.keys_path();
        if !path.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        for line in text.lines() {
            let mut parts = line.split(' ');
            let (Some(id), Some(key), Some(expires), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err("corrupt key file".into());
            };
            check_id(id)?;
            let key: [u8; 32] = from_hex(key)
                .and_then(|k| k.try_into().ok())
                .ok_or("corrupt key file")?;
            let expires_at = expires.parse().map_err(|_| "corrupt key file")?;
            self.entries.insert(id.to_string(), Entry { key, expires_at });
        }
        Ok(())
    }

    fn save_keys(&self) -> Result<(), String> {
        let mut text = String::new();
        for (id, entry) in &self.entries {
            text.push_str(&format!("{id} {} {}\n", to_hex(&entry.key), entry.expires_at));
        }
        write_private(&self.keys_path(), text.as_bytes())?;
        sync_dir(&self.dir)
    }

    /// A chat file with no key can never be read again, for instance after a crash mid-purge.
    fn remove_orphans(&self) -> Result<(), String> {
        for item in fs::read_dir(&self.dir).map_err(|e| e.to_string())? {
            let path = item.map_err(|e| e.to_string())?.path();
            let is_kept_file = path.extension().is_some_and(|e| e == "kept");
            if is_kept_file || path.extension().is_some_and(|e| e == "chat") {
                let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
                // Also clears the leftover of a `keep` interrupted before or after its key update.
                let current = self.entries.get(id).is_some_and(|e| (e.expires_at == KEPT) == is_kept_file);
                if !current {
                    fs::remove_file(&path).map_err(|e| e.to_string())?;
                }
            }
        }
        sync_dir(&self.dir)
    }

    /// The user chooses to keep this chat: it no longer expires. The new file is written before
    /// the key entry changes, so a crash at any point leaves the chat readable in one form.
    pub fn keep(&mut self, id: &str, now: u64) -> Result<(), String> {
        let text = self.get(id, now)?.ok_or("no such chat")?;
        let key = self.entries[id].key;
        if self.entries[id].expires_at == KEPT {
            return Ok(());
        }
        self.encrypt_to(&self.kept_path(id), id, &key, KEPT, &text)?;
        if let Some(entry) = self.entries.get_mut(id) {
            entry.expires_at = KEPT;
        }
        self.save_keys()?;
        fs::remove_file(self.chat_path(id)).map_err(|e| e.to_string())?;
        sync_dir(&self.dir)
    }

    /// The user deletes a chat now, kept or not. Returns false if there was nothing to delete.
    pub fn forget(&mut self, id: &str) -> Result<bool, String> {
        check_id(id)?;
        let Some(mut entry) = self.entries.remove(id) else {
            return Ok(false);
        };
        let path = self.path_for(id, entry.expires_at);
        entry.key.fill(0);
        self.save_keys()?;
        fs::remove_file(path).map_err(|e| e.to_string())?;
        sync_dir(&self.dir)?;
        Ok(true)
    }

    /// Saves a chat result. Saving again keeps the original expiry: activity never extends it.
    pub fn put(&mut self, id: &str, text: &str, now: u64) -> Result<(), String> {
        check_id(id)?;
        self.purge(now)?;
        if !self.entries.contains_key(id) {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            self.entries.insert(id.to_string(), Entry { key, expires_at: now + self.ttl });
            self.save_keys()?;
        }
        let (key, expires_at) = (self.entries[id].key, self.entries[id].expires_at);
        self.encrypt_to(&self.path_for(id, expires_at), id, &key, expires_at, text)
    }

    /// Returns the chat, or `None` if it does not exist or has expired.
    pub fn get(&mut self, id: &str, now: u64) -> Result<Option<String>, String> {
        check_id(id)?;
        self.purge(now)?;
        let Some(entry) = self.entries.get(id) else {
            return Ok(None);
        };
        let bytes = fs::read(self.path_for(id, entry.expires_at)).map_err(|e| e.to_string())?;
        if bytes.len() <= 24 {
            return Err("corrupt chat file".into());
        }
        let (nonce, ciphertext) = bytes.split_at(24);
        let associated = aad(id, entry.expires_at);
        let plain = XChaCha20Poly1305::new((&entry.key).into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &associated })
            .map_err(|_| "chat file altered, or its expiry was changed".to_string())?;
        String::from_utf8(plain).map(Some).map_err(|_| "corrupt chat".to_string())
    }

    /// Destroys expired chats: keys first, so nothing is readable if this stops halfway.
    pub fn purge(&mut self, now: u64) -> Result<usize, String> {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, e)| now >= e.expires_at)
            .map(|(id, _)| id.clone())
            .collect();
        if expired.is_empty() {
            return Ok(0);
        }
        for id in &expired {
            if let Some(mut entry) = self.entries.remove(id) {
                entry.key.fill(0);
            }
        }
        self.save_keys()?;
        for id in &expired {
            match fs::remove_file(self.chat_path(id)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        sync_dir(&self.dir)?;
        Ok(expired.len())
    }
}
