//! Pairing on the computer side: the QR code, the phone's commitment then reveal, the 6-digit code confirmed on the
//! computer, the read token, and the checks on every request from the phone (signature, counter, used ids).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use p256::ecdsa::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::protocol::{self, b64url};

/// A pairing code (in the QR) is valid this long, in seconds.
pub const CODE_TTL: u64 = 600;
/// Time between the phone's commitment and its reveal, in seconds.
pub const COMMIT_TTL: u64 = 120;
/// Time the person has to compare the codes once the phone revealed its key, in seconds.
pub const AWAIT_TTL: u64 = 300;
/// Wrong codes accepted before the code is replaced by a new one (a new QR).
pub const MAX_FAILED_CODES: u32 = 5;
/// Confirmation ids remembered per pairing (the ids are random and never reissued; this is a second barrier).
pub const MAX_USED_IDS: usize = 256;

/// Error codes sent back to the phone (the iPhone app translates them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    UsedCode,
    ExpiredCode,
    CommitmentMismatch,
    PairingSignature,
    NotPaired,
    UnknownPairing,
    MissingSignature,
    BadSignature,
    BadToken,
    Replayed,
    Storage,
    Stale,
    UnknownChat,
    BadText,
    BadRequest,
    BadHost,
    Browser,
}

impl ProtocolError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UsedCode => "unknown or used pairing code",
            Self::ExpiredCode => "expired pairing code",
            Self::CommitmentMismatch => "pairing commitment does not match",
            Self::PairingSignature => "pairing signature does not verify",
            Self::NotPaired => "not paired",
            Self::UnknownPairing => "unknown pairing",
            Self::MissingSignature => "missing or malformed signature",
            Self::BadSignature => "signature does not verify",
            Self::BadToken => "missing or wrong token",
            Self::Replayed => "replayed request",
            Self::Storage => "could not save on the computer",
            Self::Stale => "stale confirmation",
            Self::UnknownChat => "unknown chat",
            Self::BadText => "empty or too long message",
            Self::BadRequest => "bad request",
            Self::BadHost => "unexpected host",
            Self::Browser => "browser requests are refused",
        }
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PairedPhone {
    pub pairing_id: String,
    /// The phone's P-256 public key (SEC1, uncompressed): every signed request must verify with it.
    pub phone_key: Vec<u8>,
    pub paired_at: u64,
    /// Always true for a phone written by this version (a phone is saved only after the codes were compared).
    /// Files from earlier versions may hold an unverified phone: it is dropped when loading.
    #[serde(default)]
    pub verified: bool,
    /// Secret given to the phone at pairing (base64url, 32 bytes): every request carries it (reads included).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// Highest request counter accepted from this phone. Saved before the request is carried out.
    #[serde(default)]
    pub last_counter: u64,
    /// Confirmation ids already answered by this phone, most recent last.
    #[serde(default)]
    pub used_confirmations: Vec<String>,
}

/// What the computer keeps: its own P-256 key, and the phone it trusts. Saved as a file readable by the user only;
/// with a secret store (`with_secret_store`), the computer's key and the phone's token are kept there instead and
/// are left out of the file.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Record {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub computer_key: Vec<u8>,
    pub phone: Option<PairedPhone>,
    /// The x25519 secret of the phone's Tor client authorization (32 bytes): the onion service is published for this
    /// key only, and the QR code gives it to the phone. A new one with every new pairing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub onion_auth: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Code {
    pub value: String,
    pub issued_at: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Commit {
    pub(crate) pairing_id: String,
    commitment: String,
    pub(crate) computer_nonce: String,
    code: String,
    pub(crate) at: u64,
}

/// A phone that revealed its key, waiting for the person to compare the codes. Kept in memory only.
#[derive(Clone, Debug, PartialEq)]
pub struct Awaiting {
    pub code: String,
    pub pairing_id: String,
    phone: PairedPhone,
    /// When the phone revealed its key: the comparison must be done within `AWAIT_TTL`.
    pub(crate) at: u64,
}

/// The system's credential store for the pairing secrets.
pub trait SecretStore {
    /// None when nothing was stored yet.
    fn get(&self) -> Result<Option<Vec<u8>>, String>;
    fn set(&self, secret: &[u8]) -> Result<(), String>;
}

/// The secret store and what it held, or why it could not be read.
pub type LoadedSecrets = Result<(Box<dyn SecretStore>, Option<Vec<u8>>), String>;

/// macOS Keychain, Windows Credential Manager, or the Secret Service on Linux (keyring crate).
pub struct SystemStore(keyring::Entry);

impl SystemStore {
    pub fn new() -> Result<Self, String> {
        keyring::Entry::new("org.ona.desktop", "pairing").map(Self).map_err(|e| e.to_string())
    }
}

impl SecretStore for SystemStore {
    fn get(&self) -> Result<Option<Vec<u8>>, String> {
        match self.0.get_secret() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn set(&self, secret: &[u8]) -> Result<(), String> {
        self.0.set_secret(secret).map_err(|e| e.to_string())
    }
}

/// What the secret store holds: the computer's key and the paired phone's token.
#[derive(Serialize, Deserialize, PartialEq)]
struct Secrets {
    computer_key: Vec<u8>,
    #[serde(default)]
    token: String,
    #[serde(default)]
    onion_auth: Vec<u8>,
}

pub struct PairingAuthority {
    pub name: String,
    pub record: Record,
    /// Single-use code currently in the QR; None once used or while a phone is paired.
    pub pairing_code: Option<Code>,
    pub awaiting: Option<Awaiting>,
    pub(crate) commit: Option<Commit>,
    failed_codes: u32,
    path: Option<PathBuf>,
    /// Last failure to read or write the record, shown in the window.
    pub storage_error: Option<String>,
    /// Set when the record exists but cannot be read: pairing is disabled and nothing is written.
    unreadable: Option<String>,
    /// Where the computer's key and the phone's token go; None keeps them in the file.
    secrets: Option<Box<dyn SecretStore>>,
    /// What the secret store holds now, so that it is written only when it changes (not at every request).
    stored: Option<Vec<u8>>,
    /// Shown in the window when the secret store could not be used and the secrets stay in the file.
    fallback: Option<String>,
}

impl PairingAuthority {
    /// Loads the record from `path` (or creates one). `None` keeps everything in memory (tests).
    /// A record that exists but cannot be read is left untouched: the error is shown, nothing is written and no QR
    /// code is offered (a new key would silently replace the computer's identity and forget the phone).
    #[cfg(test)]
    pub fn new(name: &str, path: Option<PathBuf>) -> Self {
        Self::load(name, path, None)
    }

    /// Like `new`, with the computer's key and the phone's token in `store` rather than in the file. A file written
    /// before keeps its secrets until they are moved to the store, then they leave the file. If the store cannot be
    /// read (no Secret Service running on Linux, for instance), the secrets stay in the file, readable by this user
    /// only, and the window says so.
    pub fn with_secret_store(name: &str, path: PathBuf, store: Result<Box<dyn SecretStore>, String>) -> Self {
        let loaded = store.and_then(|store| store.get().map(|got| (store, got)));
        Self::load(name, Some(path), Some(loaded))
    }

    /// Like `with_secret_store`, with the store already read (`SecretStore::get`), on another thread: reading the
    /// Keychain can wait for the person to answer a macOS dialog, and the worker thread must keep serving meanwhile.
    pub fn with_loaded_secrets(name: &str, path: PathBuf, loaded: LoadedSecrets) -> Self {
        Self::load(name, Some(path), Some(loaded))
    }

    /// While the secret store is being read: no pairing, no QR code, nothing written; the window says why.
    pub fn waiting(name: &str) -> Self {
        let reason = "Reading the system credential store… If a window asks, allow ONA.".to_owned();
        Self {
            name: name.to_owned(),
            record: Record { computer_key: SigningKey::random(&mut OsRng).to_bytes().to_vec(), phone: None, onion_auth: Vec::new() },
            pairing_code: None, awaiting: None, commit: None, failed_codes: 0, path: None,
            storage_error: Some(reason.clone()), unreadable: Some(reason), secrets: None, stored: None, fallback: None,
        }
    }

    fn load(name: &str, path: Option<PathBuf>, store: Option<LoadedSecrets>) -> Self {
        let mut unreadable = None;
        let saved = match path.as_ref().map(std::fs::read) {
            None => None,
            Some(Ok(bytes)) => match serde_json::from_slice::<Record>(&bytes) {
                Ok(record) => Some(record),
                Err(e) => {
                    unreadable = Some(format!("Unreadable pairing file ({e}): nothing was changed."));
                    None
                }
            },
            Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
            Some(Err(e)) => {
                unreadable = Some(format!("Unreadable pairing file ({e}): nothing was changed."));
                None
            }
        };
        if unreadable.is_some() {
            return Self {
                name: name.to_owned(),
                record: Record { computer_key: SigningKey::random(&mut OsRng).to_bytes().to_vec(), phone: None, onion_auth: Vec::new() },
                pairing_code: None, awaiting: None, commit: None, failed_codes: 0, path: None,
                storage_error: unreadable.clone(), unreadable, secrets: None, stored: None, fallback: None,
            };
        }
        let mut created = saved.is_none();
        let mut record = saved.unwrap_or(Record { computer_key: Vec::new(), phone: None, onion_auth: Vec::new() });
        let (mut secrets, mut stored, mut fallback) = (None, None, None);
        match store {
            None => {}
            Some(Ok((store, got))) => {
                match got.as_deref().map(serde_json::from_slice::<Secrets>) {
                    Some(Ok(found)) => {
                        record.computer_key = found.computer_key;
                        record.onion_auth = found.onion_auth;
                        if let Some(phone) = record.phone.as_mut() {
                            phone.token = found.token;
                        }
                        stored = got;
                    }
                    // Unreadable: like an unreadable file, nothing is replaced and no pairing is offered.
                    Some(Err(e)) => unreadable = Some(format!("Unreadable pairing secret in the credential store ({e}): nothing was changed.")),
                    // Nothing stored yet: the secrets still in the file (an earlier version) move to the store below.
                    None => created = true,
                }
                secrets = Some(store);
            }
            Some(Err(e)) => {
                fallback = Some(format!("System credential store unavailable ({e}): the pairing key stays in a file only you can read."));
            }
        }
        if let Some(error) = unreadable {
            return Self {
                name: name.to_owned(),
                record: Record { computer_key: SigningKey::random(&mut OsRng).to_bytes().to_vec(), phone: None, onion_auth: Vec::new() },
                pairing_code: None, awaiting: None, commit: None, failed_codes: 0, path: None,
                storage_error: Some(error.clone()), unreadable: Some(error), secrets: None, stored: None, fallback: None,
            };
        }
        if SigningKey::from_slice(&record.computer_key).is_err() {
            // No key anywhere: a new identity, and a phone paired with the old one must pair again.
            record.computer_key = SigningKey::random(&mut OsRng).to_bytes().to_vec();
            record.phone = None;
            created = true;
        }
        if record.onion_auth.len() != 32 {
            // No client key yet (or from an earlier version): a new one. A phone paired without one pairs again, since
            // the onion service is now published for this key only.
            record.onion_auth = new_onion_auth();
            record.phone = None;
            created = true;
        }
        // A phone from an earlier version (not verified, or without token) must pair again.
        let legacy = record.phone.as_ref()
            .is_some_and(|p| !p.verified || p.token.is_empty() || protocol::public_key(&p.phone_key).is_none());
        if legacy {
            record.phone = None;
        }
        let mut authority = Self {
            name: name.to_owned(), record, pairing_code: None, awaiting: None, commit: None, failed_codes: 0, path,
            storage_error: fallback.clone(), unreadable: None, secrets, stored, fallback,
        };
        if created || legacy {
            let _ = authority.save();
        }
        if authority.record.phone.is_none() {
            authority.new_code();
        }
        authority
    }

    fn signing_key(&self) -> Option<SigningKey> {
        SigningKey::from_slice(&self.record.computer_key).ok()
    }

    pub fn computer_public_key(&self) -> Vec<u8> {
        self.signing_key().map(|k| k.verifying_key().to_encoded_point(false).as_bytes().to_vec()).unwrap_or_default()
    }

    /// Signs a reply to the phone with the computer's key (the phone knows the public key from the QR).
    pub fn sign_reply(&self, request_nonce: &str, method: &str, path: &str, status: u16, reply: &str) -> Option<String> {
        Some(protocol::sign(&self.signing_key()?, &protocol::reply_message(request_nonce, method, path, status, reply)))
    }

    #[cfg(test)]
    pub fn is_paired(&self) -> bool {
        self.record.phone.is_some()
    }

    pub fn payload(&self, address: Option<&str>, onion: Option<&str>) -> Option<String> {
        let code = self.pairing_code.as_ref().filter(|c| now() < c.issued_at + CODE_TTL)?;
        let auth = protocol::base32(&self.record.onion_auth);
        Some(protocol::pairing_payload(&self.name, address, onion, Some(&auth), &self.computer_public_key(), &code.value,
                                       code.issued_at + CODE_TTL))
    }

    /// The line tor reads in `authorized_clients/` for the phone's key: `descriptor:x25519:<base32 public key>`.
    pub fn onion_client_auth(&self) -> Option<String> {
        let secret: [u8; 32] = self.record.onion_auth.as_slice().try_into().ok()?;
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        Some(format!("descriptor:x25519:{}", protocol::base32(public.as_bytes())))
    }

    /// Replaces an expired code, and drops a commitment never revealed. Called on the worker's timer.
    pub fn tick(&mut self) {
        let now = now();
        if self.pairing_code.as_ref().is_some_and(|c| now >= c.issued_at + CODE_TTL) {
            self.new_code();
        }
        if self.commit.as_ref().is_some_and(|c| now >= c.at + COMMIT_TTL) {
            self.commit = None;
            self.new_code();
        }
        if self.awaiting.as_ref().is_some_and(|a| now >= a.at + AWAIT_TTL) {
            self.awaiting = None;
            self.new_code();
        }
    }

    /// `POST /v1/pair`: the phone sends the QR code and `commitment(phone_key, phone_nonce)`. The code is used up.
    /// Returns the pairing id and the computer's nonce.
    pub fn commit(&mut self, code: Option<&str>, commitment: Option<&str>) -> Result<(String, String), ProtocolError> {
        let current = self.pairing_code.clone().ok_or(ProtocolError::UsedCode)?;
        if now() >= current.issued_at + CODE_TTL {
            self.new_code();
            return Err(ProtocolError::ExpiredCode);
        }
        if !protocol::same_secret(code.unwrap_or("").as_bytes(), current.value.as_bytes()) {
            self.failed_codes += 1;
            if self.failed_codes >= MAX_FAILED_CODES {
                self.new_code();
            }
            return Err(ProtocolError::UsedCode);
        }
        let commitment = commitment.filter(|c| protocol::is_hex(c, 64)).ok_or(ProtocolError::BadRequest)?;
        self.pairing_code = None; // single use, whatever happens next
        let commit = Commit {
            pairing_id: format!("p-{}", protocol::random_hex16()),
            commitment: commitment.to_owned(),
            computer_nonce: protocol::random_hex16(),
            code: current.value,
            at: now(),
        };
        let answer = (commit.pairing_id.clone(), commit.computer_nonce.clone());
        self.commit = Some(commit);
        Ok(answer)
    }

    /// `POST /v1/pair/reveal`: the phone reveals its key and nonce, signed. One attempt per commitment: on failure, a
    /// new code is issued. Returns the pairing id and the token. The phone is kept in memory until the codes match.
    pub fn reveal(&mut self, pairing_id: Option<&str>, phone_key: Option<&str>, phone_nonce: Option<&str>,
                  signature: Option<&str>) -> Result<(String, String), ProtocolError> {
        let commit = self.commit.clone()
            .filter(|c| Some(c.pairing_id.as_str()) == pairing_id && now() < c.at + COMMIT_TTL)
            .ok_or(ProtocolError::UnknownPairing)?;
        self.commit = None;
        let result = self.check_reveal(&commit, phone_key, phone_nonce, signature);
        if result.is_err() {
            self.new_code();
        }
        result
    }

    fn check_reveal(&mut self, commit: &Commit, phone_key: Option<&str>, phone_nonce: Option<&str>,
                    signature: Option<&str>) -> Result<(String, String), ProtocolError> {
        let phone_nonce = phone_nonce.filter(|n| protocol::is_hex(n, 32)).ok_or(ProtocolError::BadRequest)?;
        let phone_key = phone_key.and_then(protocol::b64_decode).filter(|k| protocol::public_key(k).is_some())
            .ok_or(ProtocolError::BadRequest)?;
        if protocol::commitment(&phone_key, phone_nonce) != commit.commitment {
            return Err(ProtocolError::CommitmentMismatch);
        }
        let computer_key = self.computer_public_key();
        let message = protocol::pair_message(&commit.pairing_id, &commit.code, &phone_key, &computer_key, phone_nonce,
                                             &commit.computer_nonce);
        if !protocol::verify(signature, &message, &phone_key) {
            return Err(ProtocolError::PairingSignature);
        }
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let token = b64url(&secret);
        let code = protocol::verification_code(&computer_key, &phone_key, &commit.code, phone_nonce, &commit.computer_nonce);
        let phone = PairedPhone {
            pairing_id: commit.pairing_id.clone(), phone_key, paired_at: now(), verified: true, token: token.clone(),
            last_counter: 0, used_confirmations: Vec::new(),
        };
        self.awaiting = Some(Awaiting { code, pairing_id: commit.pairing_id.clone(), phone, at: now() });
        Ok((commit.pairing_id.clone(), token))
    }

    /// The person saw the same code on both screens: the phone is trusted and saved.
    pub fn confirm_code(&mut self) -> Result<(), String> {
        let Some(awaiting) = self.awaiting.take() else { return Ok(()) };
        if now() >= awaiting.at + AWAIT_TTL {
            self.new_code();
            return Err("Time is up: pair again with the new code.".into());
        }
        self.record.phone = Some(awaiting.phone);
        self.save()
    }

    /// The codes differ, or the person forgets the phone: a new QR code is issued.
    pub fn forget_phone(&mut self) -> Result<(), String> {
        self.record.phone = None;
        // The forgotten phone keeps its copy of the client key: a new one, and the onion service is published again.
        self.record.onion_auth = new_onion_auth();
        self.awaiting = None;
        self.commit = None;
        self.new_code();
        self.save()
    }

    /// Every request after pairing carries the token. Reads need nothing else.
    pub fn authorize(&self, token: Option<&str>) -> Result<&PairedPhone, ProtocolError> {
        let phone = self.record.phone.as_ref().ok_or(ProtocolError::NotPaired)?;
        if !protocol::same_secret(token.unwrap_or("").as_bytes(), phone.token.as_bytes()) {
            return Err(ProtocolError::BadToken);
        }
        Ok(phone)
    }

    /// Checks a request that changes something: token, pairing id, signature by the phone's key over bytes that include
    /// `counter`, a counter higher than any accepted before and, for a confirmation, an id never answered before.
    /// The new counter (and id) is saved before the caller carries out the request.
    pub fn check(&mut self, token: Option<&str>, pairing_id: Option<&str>, counter: Option<u64>, signature: Option<&str>,
                 confirmation: Option<&str>, signed: impl Fn(&str, u64) -> Vec<u8>) -> Result<(), ProtocolError> {
        let phone = self.authorize(token)?;
        if pairing_id != Some(phone.pairing_id.as_str()) {
            return Err(ProtocolError::UnknownPairing);
        }
        let (Some(counter), Some(_)) = (counter, signature) else { return Err(ProtocolError::MissingSignature) };
        if !protocol::verify(signature, &signed(&phone.pairing_id, counter), &phone.phone_key) {
            return Err(ProtocolError::BadSignature);
        }
        if counter <= phone.last_counter {
            return Err(ProtocolError::Replayed);
        }
        if confirmation.is_some_and(|id| phone.used_confirmations.iter().any(|u| u == id)) {
            return Err(ProtocolError::Replayed);
        }
        let phone = self.record.phone.as_mut().ok_or(ProtocolError::NotPaired)?;
        phone.last_counter = counter;
        // The counter is raised in memory even if the file cannot be written; the request is then refused.
        self.save().map_err(|_| ProtocolError::Storage)
    }

    /// A confirmation the computer carried out: its id is never accepted again. Called only after success, so a
    /// refused answer (the counter already stops its replay) does not block the next one. A failed write is shown in
    /// the window (`storage_error`).
    pub fn record_confirmation(&mut self, id: &str) {
        let Some(phone) = self.record.phone.as_mut() else { return };
        phone.used_confirmations.push(id.to_owned());
        let excess = phone.used_confirmations.len().saturating_sub(MAX_USED_IDS);
        phone.used_confirmations.drain(..excess);
        let _ = self.save();
    }

    fn new_code(&mut self) {
        if self.unreadable.is_some() {
            self.pairing_code = None; // no pairing until the record can be read
            return;
        }
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        self.pairing_code = Some(Code { value: b64url(&random), issued_at: now() });
        self.failed_codes = 0;
    }

    fn save(&mut self) -> Result<(), String> {
        if let Some(error) = &self.unreadable {
            self.storage_error = Some(error.clone());
            return Err(error.clone());
        }
        let Some(path) = self.path.clone() else { return Ok(()) };
        let result = self.save_secrets().and_then(|file| {
            let bytes = serde_json::to_vec(&file).map_err(|e| e.to_string())?;
            write_private(&path, &bytes).map_err(|e| e.to_string())
        });
        self.storage_error = match &result {
            Err(e) => Some(format!("Could not save the pairing: {e}")),
            Ok(()) => self.fallback.clone(),
        };
        result
    }

    /// Writes the secrets to the store when they changed, and returns the record to write in the file: without them
    /// when they are in the store.
    fn save_secrets(&mut self) -> Result<Record, String> {
        let Some(store) = &self.secrets else { return Ok(self.record.clone()) };
        let secrets = Secrets {
            computer_key: self.record.computer_key.clone(),
            token: self.record.phone.as_ref().map(|p| p.token.clone()).unwrap_or_default(),
            onion_auth: self.record.onion_auth.clone(),
        };
        let bytes = serde_json::to_vec(&secrets).map_err(|e| e.to_string())?;
        if self.stored.as_ref() != Some(&bytes) {
            store.set(&bytes).map_err(|e| format!("trousseau : {e}"))?;
            self.stored = Some(bytes);
        }
        let mut file = self.record.clone();
        file.computer_key.clear();
        file.onion_auth.clear();
        if let Some(phone) = file.phone.as_mut() {
            phone.token.clear();
        }
        Ok(file)
    }
}

fn new_onion_auth() -> Vec<u8> {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    secret.to_vec()
}

/// Writes a file readable by the current user only (0600 on Unix; per-user AppData on Windows), atomically: a
/// temporary file is written, flushed, renamed over the old one, and the folder is flushed.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let _ = std::fs::remove_file(&temporary);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path)?;
    // The rename itself reaches the disk only when the folder is flushed (Unix).
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::protocol::random_hex16;

    pub struct Phone {
        pub key: SigningKey,
        pub counter: std::cell::Cell<u64>,
    }

    pub struct Paired {
        pub id: String,
        pub token: String,
    }

    impl Phone {
        pub fn new() -> Self {
            Self { key: SigningKey::random(&mut OsRng), counter: std::cell::Cell::new(0) }
        }

        pub fn public_key(&self) -> Vec<u8> {
            self.key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
        }

        pub fn sign(&self, message: &[u8]) -> String {
            protocol::sign(&self.key, message)
        }

        pub fn next(&self) -> u64 {
            self.counter.set(self.counter.get() + 1);
            self.counter.get()
        }

        /// Commit, reveal; returns the pairing and the code the phone shows.
        pub fn pair_showing(&self, authority: &mut PairingAuthority) -> (Paired, String) {
            let code = authority.pairing_code.clone().unwrap().value;
            let nonce = random_hex16();
            let (id, computer_nonce) = authority.commit(Some(&code), Some(&protocol::commitment(&self.public_key(), &nonce))).unwrap();
            let proof = self.sign(&protocol::pair_message(&id, &code, &self.public_key(), &authority.computer_public_key(),
                                                          &nonce, &computer_nonce));
            let (id, token) = authority.reveal(Some(&id), Some(&protocol::b64(&self.public_key())), Some(&nonce), Some(&proof)).unwrap();
            let shown = protocol::verification_code(&authority.computer_public_key(), &self.public_key(), &code, &nonce, &computer_nonce);
            (Paired { id, token }, shown)
        }

        pub fn pair(&self, authority: &mut PairingAuthority) -> Paired {
            self.pair_showing(authority).0
        }
    }

    fn temp_path(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("ona-pairing-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (dir.clone(), dir.join("pairing.json"))
    }

    #[test]
    fn pairs_by_commit_and_reveal_then_waits_for_the_code_comparison() {
        let mut authority = PairingAuthority::new("PC", None);
        let phone = Phone::new();
        let (paired, shown) = phone.pair_showing(&mut authority);
        assert_eq!(authority.awaiting.as_ref().unwrap().code, shown);
        assert!(authority.pairing_code.is_none());
        let message = |p: &str, c: u64| protocol::chat_message(p, c, None, Some("bonjour"));
        let counter = phone.next();
        let signature = phone.sign(&message(&paired.id, counter));
        assert_eq!(authority.check(Some(&paired.token), Some(&paired.id), Some(counter), Some(&signature), None, message),
                   Err(ProtocolError::NotPaired));
        authority.confirm_code().unwrap();
        assert!(authority.is_paired());
        assert_eq!(authority.check(Some(&paired.token), Some(&paired.id), Some(counter), Some(&signature), None, message), Ok(()));
        let counter = phone.next();
        let other = Phone::new().sign(&message(&paired.id, counter));
        assert_eq!(authority.check(Some(&paired.token), Some(&paired.id), Some(counter), Some(&other), None, message),
                   Err(ProtocolError::BadSignature));
        assert_eq!(authority.check(Some(&paired.token), Some("p-x"), Some(counter), Some(&other), None, message),
                   Err(ProtocolError::UnknownPairing));
        assert_eq!(authority.check(Some("wrong"), Some(&paired.id), Some(counter), Some(&other), None, message),
                   Err(ProtocolError::BadToken));
    }

    /// A key chosen after seeing the exchange cannot be swapped in. The attacker would have to commit to it
    /// before the computer's nonce exists, and the code covers both nonces.
    #[test]
    fn refuses_a_key_that_does_not_match_the_commitment() {
        let mut authority = PairingAuthority::new("PC", None);
        let code = authority.pairing_code.clone().unwrap().value;
        let (phone, attacker) = (Phone::new(), Phone::new());
        let nonce = random_hex16();
        let (id, computer_nonce) = authority.commit(Some(&code), Some(&protocol::commitment(&phone.public_key(), &nonce))).unwrap();
        // The code is used up: no second commitment with it.
        assert_eq!(authority.commit(Some(&code), Some(&protocol::commitment(&attacker.public_key(), &nonce))),
                   Err(ProtocolError::UsedCode));
        let proof = attacker.sign(&protocol::pair_message(&id, &code, &attacker.public_key(), &authority.computer_public_key(),
                                                          &nonce, &computer_nonce));
        let swapped = authority.reveal(Some(&id), Some(&protocol::b64(&attacker.public_key())), Some(&nonce), Some(&proof));
        assert_eq!(swapped, Err(ProtocolError::CommitmentMismatch));
        assert!(authority.awaiting.is_none());
        // One attempt per commitment: the real phone must scan the new QR code.
        let proof = phone.sign(&protocol::pair_message(&id, &code, &phone.public_key(), &authority.computer_public_key(),
                                                       &nonce, &computer_nonce));
        assert_eq!(authority.reveal(Some(&id), Some(&protocol::b64(&phone.public_key())), Some(&nonce), Some(&proof)),
                   Err(ProtocolError::UnknownPairing));
        assert_ne!(authority.pairing_code.clone().unwrap().value, code);
    }

    #[test]
    fn refuses_a_proof_from_another_key() {
        let mut authority = PairingAuthority::new("PC", None);
        let code = authority.pairing_code.clone().unwrap().value;
        let (phone, other) = (Phone::new(), Phone::new());
        let nonce = random_hex16();
        let (id, computer_nonce) = authority.commit(Some(&code), Some(&protocol::commitment(&phone.public_key(), &nonce))).unwrap();
        let proof = other.sign(&protocol::pair_message(&id, &code, &phone.public_key(), &authority.computer_public_key(),
                                                       &nonce, &computer_nonce));
        assert_eq!(authority.reveal(Some(&id), Some(&protocol::b64(&phone.public_key())), Some(&nonce), Some(&proof)),
                   Err(ProtocolError::PairingSignature));
    }

    /// Limited attempts, single use, expiry.
    #[test]
    fn the_code_expires_and_wrong_codes_are_limited() {
        let mut authority = PairingAuthority::new("PC", None);
        let commitment = protocol::commitment(&Phone::new().public_key(), &random_hex16());
        let code = authority.pairing_code.clone().unwrap().value;
        for _ in 0..MAX_FAILED_CODES {
            assert_eq!(authority.commit(Some("guess"), Some(&commitment)), Err(ProtocolError::UsedCode));
        }
        assert_eq!(authority.commit(Some(&code), Some(&commitment)), Err(ProtocolError::UsedCode));

        let code = authority.pairing_code.clone().unwrap().value;
        authority.pairing_code.as_mut().unwrap().issued_at -= CODE_TTL;
        assert!(authority.payload(None, Some("x.onion")).is_none());
        assert_eq!(authority.commit(Some(&code), Some(&commitment)), Err(ProtocolError::ExpiredCode));
        assert_ne!(authority.pairing_code.clone().unwrap().value, code);

        let code = authority.pairing_code.clone().unwrap().value;
        authority.pairing_code.as_mut().unwrap().issued_at -= CODE_TTL;
        authority.tick();
        assert_ne!(authority.pairing_code.clone().unwrap().value, code);

        // A commitment never revealed expires too, and gives a new code.
        let code = authority.pairing_code.clone().unwrap().value;
        let (id, _) = authority.commit(Some(&code), Some(&commitment)).unwrap();
        authority.commit.as_mut().unwrap().at -= COMMIT_TTL;
        authority.tick();
        assert!(authority.commit.is_none() && authority.pairing_code.is_some());
        assert_eq!(authority.reveal(Some(&id), None, None, None), Err(ProtocolError::UnknownPairing));
    }

    /// A request (or a confirmation id) accepted once is refused afterwards, also after a restart.
    #[test]
    fn refuses_replays_even_after_a_restart() {
        let (dir, path) = temp_path("replay");
        let mut authority = PairingAuthority::new("PC", Some(path.clone()));
        let phone = Phone::new();
        let paired = phone.pair(&mut authority);
        authority.confirm_code().unwrap();
        let message = |p: &str, c: u64| protocol::confirm_message(p, c, Some("c-1"), Some("accept"), None, None, "x");
        let signature = phone.sign(&message(&paired.id, 5));
        let check = |a: &mut PairingAuthority, counter: u64, signature: &str, id: &str| {
            a.check(Some(&paired.token), Some(&paired.id), Some(counter), Some(signature), Some(id), message)
        };
        assert_eq!(check(&mut authority, 5, &signature, "c-1"), Ok(()));
        authority.record_confirmation("c-1"); // carried out
        assert_eq!(check(&mut authority, 5, &signature, "c-1"), Err(ProtocolError::Replayed));

        let mut restarted = PairingAuthority::new("PC", Some(path));
        assert_eq!(check(&mut restarted, 5, &signature, "c-1"), Err(ProtocolError::Replayed));
        let lower = phone.sign(&message(&paired.id, 4));
        assert_eq!(check(&mut restarted, 4, &lower, "c-1"), Err(ProtocolError::Replayed));
        // A higher counter, but a confirmation id already answered.
        let higher = phone.sign(&message(&paired.id, 6));
        assert_eq!(check(&mut restarted, 6, &higher, "c-1"), Err(ProtocolError::Replayed));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Nothing is written before the codes are compared.
    #[test]
    fn an_unverified_phone_is_not_saved() {
        let (dir, path) = temp_path("unverified");
        let mut authority = PairingAuthority::new("PC", Some(path.clone()));
        Phone::new().pair(&mut authority);
        let restarted = PairingAuthority::new("PC", Some(path.clone()));
        assert!(restarted.record.phone.is_none());
        assert!(restarted.pairing_code.is_some());
        authority.confirm_code().unwrap();
        assert!(PairingAuthority::new("PC", Some(path)).is_paired());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A record from the earlier protocol (unverified phone, no token) is dropped: the phone pairs again.
    #[test]
    fn drops_a_phone_saved_by_an_earlier_version() {
        let (dir, path) = temp_path("legacy");
        let key = SigningKey::random(&mut OsRng).to_bytes().to_vec();
        let old = serde_json::json!({"computer_key": key, "phone": {"pairing_id": "p-1-x", "phone_key": Phone::new().public_key(),
                                     "paired_at": 1, "verified": true}});
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, old.to_string()).unwrap();
        let authority = PairingAuthority::new("PC", Some(path));
        assert!(authority.record.phone.is_none());
        assert_eq!(authority.record.computer_key, key);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A code comparison left pending expires: neither a late click nor the timer trusts the phone.
    #[test]
    fn a_pending_code_comparison_expires() {
        let mut authority = PairingAuthority::new("PC", None);
        Phone::new().pair(&mut authority);
        authority.awaiting.as_mut().unwrap().at -= AWAIT_TTL;
        assert!(authority.confirm_code().is_err());
        assert!(!authority.is_paired() && authority.pairing_code.is_some());

        Phone::new().pair(&mut authority);
        authority.awaiting.as_mut().unwrap().at -= AWAIT_TTL;
        authority.tick();
        assert!(authority.awaiting.is_none() && authority.pairing_code.is_some());
        assert_eq!(authority.confirm_code(), Ok(()));
        assert!(!authority.is_paired());
    }

    /// A record that exists but cannot be read is shown as an error and never overwritten.
    #[test]
    fn leaves_an_unreadable_record_untouched() {
        let (dir, path) = temp_path("unreadable");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, b"{\"computer_key\": [1, 2").unwrap();
        let mut authority = PairingAuthority::new("PC", Some(path.clone()));
        assert!(authority.storage_error.is_some());
        assert!(authority.pairing_code.is_none());
        assert!(authority.payload(None, Some("x.onion")).is_none());
        assert!(authority.forget_phone().is_err());
        assert!(authority.pairing_code.is_none());
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"computer_key\": [1, 2");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A failed write is reported, not ignored.
    #[test]
    fn reports_a_record_that_cannot_be_written() {
        let (dir, path) = temp_path("unwritable");
        let mut authority = PairingAuthority::new("PC", Some(path));
        assert!(authority.storage_error.is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
            let result = authority.forget_phone();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(result.is_err());
            assert!(authority.storage_error.is_some());
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The QR gives the phone the client key of the restricted onion service; tor is given its public half. A forgotten
    /// phone's key stops working.
    #[test]
    fn gives_the_phone_a_tor_client_key() {
        let mut authority = PairingAuthority::new("PC", None);
        let decode = |payload: String| -> serde_json::Value {
            let text = payload.strip_prefix(protocol::PAYLOAD_PREFIX).unwrap();
            serde_json::from_slice(&base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, text).unwrap()).unwrap()
        };
        let onion = decode(authority.payload(None, Some("x.onion")).unwrap());
        let secret = authority.record.onion_auth.clone();
        assert_eq!(onion["onion_auth"], protocol::base32(&secret));
        assert!(decode(authority.payload(Some("http://192.168.1.2:8790"), None).unwrap()).get("onion_auth").is_none());
        let line = authority.onion_client_auth().unwrap();
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(secret.as_slice()).unwrap()));
        assert_eq!(line, format!("descriptor:x25519:{}", protocol::base32(public.as_bytes())));
        authority.forget_phone().unwrap();
        assert_ne!(authority.onion_client_auth().unwrap(), line);
    }

    /// Keeps what it is given, and can be made to fail.
    #[derive(Clone, Default)]
    struct MemoryStore(std::rc::Rc<std::cell::RefCell<(Option<Vec<u8>>, bool, u32)>>);

    impl SecretStore for MemoryStore {
        fn get(&self) -> Result<Option<Vec<u8>>, String> {
            let state = self.0.borrow();
            if state.1 { Err("no secret service".into()) } else { Ok(state.0.clone()) }
        }
        fn set(&self, secret: &[u8]) -> Result<(), String> {
            let mut state = self.0.borrow_mut();
            state.0 = Some(secret.to_vec());
            state.2 += 1;
            Ok(())
        }
    }

    fn with_store(path: &Path, store: &MemoryStore) -> PairingAuthority {
        PairingAuthority::with_secret_store("PC", path.to_path_buf(), Ok(Box::new(store.clone())))
    }

    /// The computer's key and the phone's token are in the store, not in the file, and survive a restart.
    #[test]
    fn keeps_the_secrets_in_the_secret_store() {
        let (dir, path) = temp_path("store");
        let store = MemoryStore::default();
        let mut first = with_store(&path, &store);
        let key = first.computer_public_key();
        Phone::new().pair(&mut first);
        first.confirm_code().unwrap();
        let token = first.record.phone.as_ref().unwrap().token.clone();
        let file = std::fs::read_to_string(&path).unwrap();
        assert!(!file.contains("computer_key") && !file.contains(&token), "{file}");
        let stored = String::from_utf8(store.0.borrow().0.clone().unwrap()).unwrap();
        assert!(stored.contains(&token));

        let writes = store.0.borrow().2;
        first.record_confirmation("c-1");
        assert_eq!(store.0.borrow().2, writes, "the store is written only when the secrets change");

        let again = with_store(&path, &store);
        assert_eq!(again.computer_public_key(), key);
        assert!(again.is_paired());
        assert_eq!(again.record.phone.as_ref().unwrap().token, token);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A file from an earlier version: its secrets move to the store and leave the file, the pairing stays.
    #[test]
    fn moves_the_secrets_of_an_earlier_file_to_the_store() {
        let (dir, path) = temp_path("migrate");
        let mut old = PairingAuthority::new("PC", Some(path.clone()));
        Phone::new().pair(&mut old);
        old.confirm_code().unwrap();
        let key = old.computer_public_key();
        assert!(std::fs::read_to_string(&path).unwrap().contains("computer_key"));

        let store = MemoryStore::default();
        let moved = with_store(&path, &store);
        assert_eq!(moved.computer_public_key(), key);
        assert!(moved.is_paired());
        assert!(!std::fs::read_to_string(&path).unwrap().contains("computer_key"));
        assert!(store.0.borrow().0.is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// No store available: the secrets stay in the file and the window says so.
    #[test]
    fn without_a_secret_store_the_file_keeps_the_secrets_and_says_so() {
        let (dir, path) = temp_path("fallback");
        let store = MemoryStore::default();
        store.0.borrow_mut().1 = true;
        let authority = with_store(&path, &store);
        assert!(authority.storage_error.as_deref().is_some_and(|e| e.starts_with("System credential store unavailable")));
        assert!(std::fs::read_to_string(&path).unwrap().contains("computer_key"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The file says a phone is paired but the store lost the secrets: a new identity, and the phone pairs again.
    #[test]
    fn a_lost_secret_means_a_new_pairing() {
        let (dir, path) = temp_path("lost");
        let store = MemoryStore::default();
        let mut first = with_store(&path, &store);
        let key = first.computer_public_key();
        Phone::new().pair(&mut first);
        first.confirm_code().unwrap();
        store.0.borrow_mut().0 = None;
        let again = with_store(&path, &store);
        assert_ne!(again.computer_public_key(), key);
        assert!(!again.is_paired());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The file is private on every write, not only when created.
    #[test]
    fn keeps_the_record_in_a_private_file() {
        let (dir, path) = temp_path("private");
        let mut first = PairingAuthority::new("PC", Some(path.clone()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let key = first.computer_public_key();
        Phone::new().pair(&mut first);
        first.confirm_code().unwrap();
        let again = PairingAuthority::new("PC", Some(path.clone()));
        assert_eq!(again.computer_public_key(), key);
        assert!(again.is_paired());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
