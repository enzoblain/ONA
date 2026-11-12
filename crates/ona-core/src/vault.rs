//! Chat results kept on the device. By default they last at most 24 hours. A longer life exists
//! only as an explicit choice by the user for one chat (`keep`), which `forget` can undo.
//!
//! Each chat has its own key, held by a `KeyStore` apart from the vault directory, never next to the
//! encrypted file. Expiry destroys the key first, then the file, so a chat is unreadable as soon as its key is
//! gone. A read after the expiry time is refused even if the purge has not run yet.
//!
//! Clock: the vault records the latest time it has seen, in the key store with the keys, and never goes back.
//! Removing that record removes the keys too. If the clock is set back by more than `CLOCK_TOLERANCE_SECS`,
//! every chat that was going to expire is destroyed at once (kept chats stay).
//!
//! An earlier version kept a `keys` file and a `clock` file in the vault directory; both are overwritten and
//! removed when the vault opens.
//!
//! What stays true, and is not solved here:
//! - **Expiry runs only when the vault is used.** Nothing purges while the application is closed; a system
//!   task that opens the vault on a schedule is needed for that. Someone who sets the clock back before the
//!   application ever saw a later time reads a chat that should have expired.
//! - **Keys in a file.** `FileKeyStore` is a stand-in until the operating system's keychain is wired in.
//!   Someone who can read both the key file and the vault directory can decrypt what has not expired yet.
//! - **Erasure.** Deleted files and replaced key files are overwritten with zeros before they are released.
//!   On an SSD, and on copy-on-write file systems such as APFS, that does not reach the old blocks; snapshots
//!   and backups the system made are out of reach too. The vault directory should be excluded from backups by
//!   the application. Copies the user makes are theirs.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::private_fs::{self, OwnerOnly};

pub const MAX_TTL_SECS: u64 = 24 * 3600;
/// Small corrections of the clock are absorbed; a larger step back destroys every expiring chat.
pub const CLOCK_TOLERANCE_SECS: u64 = 300;
const KEPT: u64 = u64::MAX;
const MAX_ID_LEN: usize = 64;
const LEGACY_FILES: [&str; 2] = ["clock", "keys"];
const LOCK_FILE: &str = "lock";
/// The recorded time is written again once it has advanced this much.
const CLOCK_STEP_SECS: u64 = 60;

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Where the chat keys live. The keychain of the operating system belongs here; `FileKeyStore` is the
/// stand-in.
pub trait KeyStore: Send {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String>;
    fn store(&self, contents: &[u8]) -> Result<(), String>;
    /// The file it writes, if any, so the vault can refuse a key file inside its own directory.
    fn file(&self) -> Option<&Path> {
        None
    }
}

/// Keys in one file, readable by its owner only, outside the vault directory.
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_path_buf() }
    }
}

impl KeyStore for FileKeyStore {
    fn load(&self) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        match fs::read(&self.path) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn store(&self, contents: &[u8]) -> Result<(), String> {
        replace_private(&self.path, contents)?;
        if let Some(parent) = self.path.parent() {
            sync_dir(parent)?;
        }
        Ok(())
    }

    fn file(&self) -> Option<&Path> {
        Some(&self.path)
    }
}

/// When a chat ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    At(u64),
    Kept,
}

struct Entry {
    key: Zeroizing<[u8; 32]>,
    expires_at: u64,
}

pub struct Vault {
    dir: PathBuf,
    ttl: u64,
    entries: BTreeMap<String, Entry>,
    keys: Box<dyn KeyStore>,
    /// The latest time seen; the vault's notion of now never goes below it.
    floor: u64,
    written_floor: u64,
    /// Held for the vault's lifetime: a second process cannot open the same vault.
    _lock: File,
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

/// Writes zeros over the whole file and flushes them.
fn overwrite(file: &mut File) -> Result<(), String> {
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let zeros = [0u8; 4096];
    let mut left = len;
    while left > 0 {
        let n = left.min(zeros.len() as u64) as usize;
        file.write_all(&zeros[..n]).map_err(|e| e.to_string())?;
        left -= n as u64;
    }
    file.sync_all().map_err(|e| e.to_string())
}

/// Overwrites a file, then removes it. A missing file is not an error.
fn shred(path: &Path) -> Result<(), String> {
    match OpenOptions::new().write(true).open(path) {
        Ok(mut file) => {
            overwrite(&mut file)?;
            drop(file);
            fs::remove_file(path).map_err(|e| e.to_string())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Atomic replacement: the new contents go to a temporary file renamed over the old one. The old file stays
/// open across the rename and is overwritten afterwards, so its former contents are not simply released.
fn replace_private(path: &Path, contents: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    shred(&tmp)?;
    let old = OpenOptions::new().write(true).open(path).ok();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .owner_only()
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    file.write_all(contents).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())?;
    if let Some(mut old) = old {
        overwrite(&mut old)?;
    }
    Ok(())
}

fn sync_dir(dir: &Path) -> Result<(), String> {
    private_fs::sync_dir(dir).map_err(|e| e.to_string())
}

impl Vault {
    /// Opens the vault and destroys everything already expired.
    pub fn open(dir: &Path, keys: Box<dyn KeyStore>, now: u64) -> Result<Self, String> {
        Self::with_ttl(dir, keys, now, MAX_TTL_SECS)
    }

    /// A shorter default is allowed. A longer one is not: keeping a chat is a choice made per chat.
    pub fn with_ttl(dir: &Path, keys: Box<dyn KeyStore>, now: u64, ttl: u64) -> Result<Self, String> {
        if ttl == 0 || ttl > MAX_TTL_SECS {
            return Err("lifetime must be between 1 second and 24 hours".into());
        }
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        private_fs::private_dir(dir).map_err(|e| e.to_string())?;
        if let Some(file) = keys.file() {
            let inside = match (file.parent().map(fs::canonicalize), fs::canonicalize(dir)) {
                (Some(Ok(parent)), Ok(dir)) => parent.starts_with(&dir),
                _ => return Err("the key file's folder must exist".into()),
            };
            if inside {
                return Err("the key file must not be inside the vault directory".into());
            }
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .owner_only()
            .open(dir.join(LOCK_FILE))
            .map_err(|e| e.to_string())?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err("the vault is already open in another process".into()),
            Err(TryLockError::Error(e)) => return Err(e.to_string()),
        }
        // Files an earlier version kept in the vault directory: the clock, and the keys next to the chats.
        for legacy in LEGACY_FILES {
            shred(&dir.join(legacy))?;
        }
        let mut vault =
            Self { dir: dir.to_path_buf(), ttl, entries: BTreeMap::new(), keys, floor: 0, written_floor: 0, _lock: lock };
        vault.load_keys()?;
        let now = vault.observe(now)?;
        vault.purge(now)?;
        vault.remove_orphans()?;
        Ok(vault)
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

    /// The vault's time: never below the latest time seen. A step back beyond the tolerance destroys every
    /// expiring chat and starts again from the new time.
    fn observe(&mut self, now: u64) -> Result<u64, String> {
        if now.saturating_add(CLOCK_TOLERANCE_SECS) < self.floor {
            let expiring: Vec<String> =
                self.entries.iter().filter(|(_, e)| e.expires_at != KEPT).map(|(id, _)| id.clone()).collect();
            self.destroy(&expiring)?;
            self.floor = now;
            self.write_floor()?;
            return Ok(now);
        }
        self.floor = self.floor.max(now);
        if self.floor >= self.written_floor.saturating_add(CLOCK_STEP_SECS) || self.written_floor > self.floor {
            self.write_floor()?;
        }
        Ok(self.floor)
    }

    /// The recorded time is stored with the keys: removing it removes the keys, so every chat goes with it.
    fn write_floor(&mut self) -> Result<(), String> {
        self.save_keys()
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
        replace_private(path, &contents)?;
        sync_dir(&self.dir)
    }

    fn load_keys(&mut self) -> Result<(), String> {
        let Some(bytes) = self.keys.load()? else {
            return Ok(());
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| "corrupt key file")?;
        let mut lines = text.lines();
        // An empty store holds no key: nothing it lost can be read anyway.
        let Some(first) = lines.next() else {
            return Ok(());
        };
        let floor = first.strip_prefix("floor ").ok_or("corrupt key file")?;
        self.floor = floor.parse().map_err(|_| "corrupt key file")?;
        self.written_floor = self.floor;
        for line in lines {
            let mut parts = line.split(' ');
            let (Some(id), Some(key), Some(expires), None) = (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err("corrupt key file".into());
            };
            check_id(id)?;
            let mut raw = Zeroizing::new(from_hex(key).ok_or("corrupt key file")?);
            if raw.len() != 32 {
                return Err("corrupt key file".into());
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&raw);
            raw.zeroize();
            let expires_at = expires.parse().map_err(|_| "corrupt key file")?;
            self.entries.insert(id.to_string(), Entry { key, expires_at });
        }
        Ok(())
    }

    fn save_keys(&mut self) -> Result<(), String> {
        let mut text = Zeroizing::new(format!("floor {}\n", self.floor));
        for (id, entry) in &self.entries {
            let hex = Zeroizing::new(to_hex(entry.key.as_ref()));
            text.push_str(&format!("{id} {} {}\n", hex.as_str(), entry.expires_at));
        }
        self.keys.store(text.as_bytes())?;
        self.written_floor = self.floor;
        Ok(())
    }

    /// Clears what a crash can leave: a chat file with no key, a key with no file, a temporary file.
    fn remove_orphans(&mut self) -> Result<(), String> {
        let mut seen = std::collections::BTreeSet::new();
        for item in fs::read_dir(&self.dir).map_err(|e| e.to_string())? {
            let path = item.map_err(|e| e.to_string())?.path();
            let extension = path.extension().and_then(|e| e.to_str()).unwrap_or_default().to_string();
            let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_string();
            match extension.as_str() {
                "tmp" => shred(&path)?,
                "chat" | "kept" => {
                    let is_kept_file = extension == "kept";
                    // Also clears the leftover of a `keep` interrupted before or after its key update.
                    let current = self.entries.get(&id).is_some_and(|e| (e.expires_at == KEPT) == is_kept_file);
                    if current {
                        seen.insert(id);
                    } else {
                        shred(&path)?;
                    }
                }
                _ => {}
            }
        }
        let keyless: Vec<String> = self.entries.keys().filter(|id| !seen.contains(*id)).cloned().collect();
        if !keyless.is_empty() {
            for id in &keyless {
                self.entries.remove(id);
            }
            self.save_keys()?;
        }
        sync_dir(&self.dir)
    }

    /// Keys first, then files: nothing is readable if this stops halfway.
    fn destroy(&mut self, ids: &[String]) -> Result<(), String> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut paths = Vec::new();
        for id in ids {
            if let Some(entry) = self.entries.remove(id) {
                paths.push(self.path_for(id, entry.expires_at));
            }
        }
        self.save_keys()?;
        for path in paths {
            shred(&path)?;
        }
        sync_dir(&self.dir)
    }

    /// When this chat ends, if it exists.
    pub fn expiry(&self, id: &str) -> Option<Expiry> {
        self.entries.get(id).map(|e| if e.expires_at == KEPT { Expiry::Kept } else { Expiry::At(e.expires_at) })
    }

    /// The user chooses to keep this chat: it no longer expires. The new file is written before
    /// the key entry changes, so a crash at any point leaves the chat readable in one form.
    pub fn keep(&mut self, id: &str, now: u64) -> Result<(), String> {
        let text = Zeroizing::new(self.get(id, now)?.ok_or("no such chat")?);
        if self.entries[id].expires_at == KEPT {
            return Ok(());
        }
        let key = self.entries[id].key.clone();
        self.encrypt_to(&self.kept_path(id), id, &key, KEPT, &text)?;
        if let Some(entry) = self.entries.get_mut(id) {
            entry.expires_at = KEPT;
        }
        self.save_keys()?;
        shred(&self.chat_path(id))?;
        sync_dir(&self.dir)
    }

    /// The user deletes a chat now, kept or not. Returns false if there was nothing to delete.
    pub fn forget(&mut self, id: &str) -> Result<bool, String> {
        check_id(id)?;
        if !self.entries.contains_key(id) {
            return Ok(false);
        }
        self.destroy(&[id.to_string()])?;
        Ok(true)
    }

    /// Saves a chat result. Saving again keeps the original expiry: activity never extends it.
    pub fn put(&mut self, id: &str, text: &str, now: u64) -> Result<(), String> {
        check_id(id)?;
        let now = self.observe(now)?;
        self.purge(now)?;
        if !self.entries.contains_key(id) {
            let mut key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(key.as_mut());
            self.entries.insert(id.to_string(), Entry { key, expires_at: now.saturating_add(self.ttl) });
            self.save_keys()?;
        }
        let (key, expires_at) = (self.entries[id].key.clone(), self.entries[id].expires_at);
        self.encrypt_to(&self.path_for(id, expires_at), id, &key, expires_at, text)
    }

    /// Returns the chat, or `None` if it does not exist or has expired.
    pub fn get(&mut self, id: &str, now: u64) -> Result<Option<String>, String> {
        check_id(id)?;
        let now = self.observe(now)?;
        self.purge(now)?;
        let Some(entry) = self.entries.get(id) else {
            return Ok(None);
        };
        let bytes = match fs::read(self.path_for(id, entry.expires_at)) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        if bytes.len() <= 24 {
            return Err("corrupt chat file".into());
        }
        let (nonce, ciphertext) = bytes.split_at(24);
        let associated = aad(id, entry.expires_at);
        let plain = XChaCha20Poly1305::new(entry.key.as_ref().into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &associated })
            .map_err(|_| "chat file altered, or its expiry was changed".to_string())?;
        String::from_utf8(plain).map(Some).map_err(|_| "corrupt chat".to_string())
    }

    /// Destroys expired chats: keys first, so nothing is readable if this stops halfway.
    pub fn purge(&mut self, now: u64) -> Result<usize, String> {
        let now = self.observe(now)?;
        let expired: Vec<String> =
            self.entries.iter().filter(|(_, e)| now >= e.expires_at).map(|(id, _)| id.clone()).collect();
        self.destroy(&expired)?;
        Ok(expired.len())
    }
}
