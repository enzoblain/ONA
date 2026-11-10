//! Pairing on the computer side: the QR code, the phone's proof of key, the 6-digit code confirmed on the computer,
//! and the signature check on every request from the phone.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use p256::ecdsa::SigningKey;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::protocol::{self, b64url};

/// Error codes sent back to the phone (the iPhone app translates them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    UsedCode,
    PairingSignature,
    NotPaired,
    UnknownPairing,
    NotVerified,
    MissingSignature,
    BadSignature,
    Stale,
    UnknownChat,
    BadText,
    BadRequest,
}

impl ProtocolError {
    pub fn code(self) -> &'static str {
        match self {
            Self::UsedCode => "unknown or used pairing code",
            Self::PairingSignature => "pairing signature does not verify",
            Self::NotPaired => "not paired",
            Self::UnknownPairing => "unknown pairing",
            Self::NotVerified => "pairing not verified",
            Self::MissingSignature => "missing or malformed signature",
            Self::BadSignature => "signature does not verify",
            Self::Stale => "stale confirmation",
            Self::UnknownChat => "unknown chat",
            Self::BadText => "empty or too long message",
            Self::BadRequest => "bad request",
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct PairedPhone {
    pub pairing_id: String,
    /// The phone's P-256 public key (SEC1, uncompressed): every signed request must verify with it.
    pub phone_key: Vec<u8>,
    pub paired_at: u64,
    /// False until the person confirms on the computer that both screens show the same code.
    pub verified: bool,
}

/// What the computer keeps: its own P-256 key, and the phone it trusts. Saved as a file readable by the user only.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Record {
    pub computer_key: Vec<u8>,
    pub phone: Option<PairedPhone>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Awaiting {
    pub code: String,
    pub pairing_id: String,
}

pub struct PairingAuthority {
    pub name: String,
    pub record: Record,
    /// Single-use code currently in the QR; None once used.
    pub pairing_code: Option<String>,
    pub awaiting: Option<Awaiting>,
    path: Option<PathBuf>,
    count: u32,
}

impl PairingAuthority {
    /// Loads the record from `path` (or creates one). `None` keeps everything in memory (tests).
    pub fn new(name: &str, path: Option<PathBuf>) -> Self {
        let saved = path.as_ref().and_then(|p| std::fs::read(p).ok()).and_then(|b| serde_json::from_slice::<Record>(&b).ok());
        let record = saved.unwrap_or_else(|| Record { computer_key: SigningKey::random(&mut OsRng).to_bytes().to_vec(), phone: None });
        let mut authority = Self { name: name.to_owned(), record, pairing_code: None, awaiting: None, path, count: 0 };
        authority.save();
        if authority.record.phone.is_none() {
            authority.new_code();
        }
        authority
    }

    pub fn computer_public_key(&self) -> Vec<u8> {
        SigningKey::from_slice(&self.record.computer_key)
            .map(|k| k.verifying_key().to_encoded_point(false).as_bytes().to_vec())
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub fn is_paired(&self) -> bool {
        self.record.phone.as_ref().is_some_and(|p| p.verified)
    }

    pub fn payload(&self, address: Option<&str>, onion: Option<&str>) -> Option<String> {
        let code = self.pairing_code.as_deref()?;
        Some(protocol::pairing_payload(&self.name, address, onion, &self.computer_public_key(), code))
    }

    /// `POST /v0/pair`: returns the pairing id.
    pub fn pair(&mut self, code: Option<&str>, phone_key: Option<&str>, signature: Option<&str>) -> Result<String, ProtocolError> {
        let pairing_code = self.pairing_code.clone().ok_or(ProtocolError::UsedCode)?;
        if code != Some(pairing_code.as_str()) {
            return Err(ProtocolError::UsedCode);
        }
        let phone_key = phone_key.and_then(protocol::b64_decode).ok_or(ProtocolError::BadSignature)?;
        if p256::ecdsa::VerifyingKey::from_sec1_bytes(&phone_key).is_err() {
            return Err(ProtocolError::BadSignature);
        }
        let computer_key = self.computer_public_key();
        let message = protocol::pair_message(&pairing_code, &phone_key, &computer_key);
        if !protocol::verify(signature, &message, &phone_key) {
            return Err(ProtocolError::PairingSignature);
        }
        self.pairing_code = None; // single use
        self.count += 1;
        let mut random = [0u8; 6];
        OsRng.fill_bytes(&mut random);
        let id = format!("p-{}-{}", self.count, b64url(&random));
        let paired_at = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        self.awaiting = Some(Awaiting {
            code: protocol::verification_code(&computer_key, &phone_key, &pairing_code),
            pairing_id: id.clone(),
        });
        self.record.phone = Some(PairedPhone { pairing_id: id.clone(), phone_key, paired_at, verified: false });
        self.save();
        Ok(id)
    }

    /// The person saw the same code on both screens.
    pub fn confirm_code(&mut self) {
        let Some(awaiting) = self.awaiting.take() else { return };
        if let Some(phone) = self.record.phone.as_mut().filter(|p| p.pairing_id == awaiting.pairing_id) {
            phone.verified = true;
        }
        self.save();
    }

    /// The codes differ, or the person forgets the phone: a new QR code is issued.
    pub fn forget_phone(&mut self) {
        self.record.phone = None;
        self.awaiting = None;
        self.save();
        self.new_code();
    }

    /// Checks that a request was signed by the paired, verified phone. `signed` builds the bytes from the pairing id.
    pub fn check(&self, pairing_id: Option<&str>, signature: Option<&str>, signed: impl Fn(&str) -> Vec<u8>) -> Result<(), ProtocolError> {
        let phone = self.record.phone.as_ref().ok_or(ProtocolError::NotPaired)?;
        if pairing_id != Some(phone.pairing_id.as_str()) {
            return Err(ProtocolError::UnknownPairing);
        }
        if !phone.verified {
            return Err(ProtocolError::NotVerified);
        }
        if signature.is_none() {
            return Err(ProtocolError::MissingSignature);
        }
        if !protocol::verify(signature, &signed(&phone.pairing_id), &phone.phone_key) {
            return Err(ProtocolError::BadSignature);
        }
        Ok(())
    }

    /// Reading needs a phone paired and verified.
    pub fn read_refusal(&self) -> Option<ProtocolError> {
        match &self.record.phone {
            None => Some(ProtocolError::NotPaired),
            Some(p) if !p.verified => Some(ProtocolError::NotVerified),
            Some(_) => None,
        }
    }

    fn new_code(&mut self) {
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        self.pairing_code = Some(b64url(&random));
    }

    fn save(&self) {
        let Some(path) = &self.path else { return };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let Ok(bytes) = serde_json::to_vec(&self.record) else { return };
        let _ = write_private(path, &bytes);
    }
}

/// Writes a file readable by the current user only (0600 on Unix; per-user AppData on Windows).
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::Signature;

    pub struct Phone {
        pub key: SigningKey,
    }

    impl Phone {
        pub fn new() -> Self {
            Self { key: SigningKey::random(&mut OsRng) }
        }

        pub fn public_key(&self) -> Vec<u8> {
            self.key.verifying_key().to_encoded_point(false).as_bytes().to_vec()
        }

        pub fn sign(&self, message: &[u8]) -> String {
            let signature: Signature = self.key.sign(message);
            protocol::b64(signature.to_der().as_bytes())
        }

        pub fn pair(&self, authority: &mut PairingAuthority) -> String {
            let code = authority.pairing_code.clone().unwrap();
            let proof = self.sign(&protocol::pair_message(&code, &self.public_key(), &authority.computer_public_key()));
            authority.pair(Some(&code), Some(&protocol::b64(&self.public_key())), Some(&proof)).unwrap()
        }
    }

    #[test]
    fn pairs_then_waits_for_the_code_comparison() {
        let mut authority = PairingAuthority::new("PC", None);
        let phone = Phone::new();
        let code = authority.pairing_code.clone().unwrap();
        let id = phone.pair(&mut authority);
        assert_eq!(
            authority.awaiting.as_ref().unwrap().code,
            protocol::verification_code(&authority.computer_public_key(), &phone.public_key(), &code)
        );
        assert!(authority.pairing_code.is_none());

        let message = protocol::chat_message(&id, None, Some("bonjour"));
        let signature = phone.sign(&message);
        assert_eq!(authority.check(Some(&id), Some(&signature), |_| message.clone()), Err(ProtocolError::NotVerified));
        authority.confirm_code();
        assert!(authority.is_paired());
        assert_eq!(authority.check(Some(&id), Some(&signature), |_| message.clone()), Ok(()));
        let other = Phone::new().sign(&message);
        assert_eq!(authority.check(Some(&id), Some(&other), |_| message.clone()), Err(ProtocolError::BadSignature));
        assert_eq!(authority.check(Some("p-x"), Some(&signature), |_| message.clone()), Err(ProtocolError::UnknownPairing));
    }

    #[test]
    fn refuses_a_proof_from_another_key_and_a_reused_code() {
        let mut authority = PairingAuthority::new("PC", None);
        let code = authority.pairing_code.clone().unwrap();
        let (phone, other) = (Phone::new(), Phone::new());
        let proof = other.sign(&protocol::pair_message(&code, &phone.public_key(), &authority.computer_public_key()));
        let result = authority.pair(Some(&code), Some(&protocol::b64(&phone.public_key())), Some(&proof));
        assert_eq!(result, Err(ProtocolError::PairingSignature));
        phone.pair(&mut authority);
        let again = authority.pair(Some(&code), Some(&protocol::b64(&phone.public_key())), Some(&proof));
        assert_eq!(again, Err(ProtocolError::UsedCode));
    }

    #[test]
    fn keeps_the_record_in_a_private_file() {
        let dir = std::env::temp_dir().join(format!("ona-pairing-test-{}", std::process::id()));
        let path = dir.join("pairing.json");
        let first = PairingAuthority::new("PC", Some(path.clone()));
        let key = first.computer_public_key();
        let mut first = first;
        Phone::new().pair(&mut first);
        first.confirm_code();
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
