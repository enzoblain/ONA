//! The relay's request-signing key, in a file only its owner can read. The file starts with a type
//! line, so that a key file made for another use (such as the signer's mint keys) is refused: a mint
//! key used as a request key would let one credit buy blind signatures under the mint's key.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ona_token::{keygen, SecretKey};
use rand::rngs::OsRng;
use zeroize::Zeroize;

const HEADER: &[u8] = b"ONA-RELAY-REQUEST-KEY-V1\n";

/// Overwrites a buffer that held key bytes, in a way the compiler keeps.
pub fn wipe(bytes: &mut [u8]) {
    bytes.zeroize();
}

/// Creates a new key file. Never overwrites one: request tokens already sold depend on it.
pub fn create(path: &Path) -> Result<SecretKey, String> {
    let key = keygen(&mut OsRng);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create key file: {e}"))?;
    let mut bytes = HEADER.to_vec();
    bytes.extend_from_slice(&key.to_bytes());
    let written = file.write_all(&bytes).and_then(|()| file.sync_all());
    wipe(&mut bytes);
    written.map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn load(path: &Path) -> Result<SecretKey, String> {
    let meta = fs::metadata(path).map_err(|e| format!("cannot read key file: {e}"))?;
    if !meta.is_file() {
        return Err("key file is not a regular file".into());
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err("key file is accessible to other users".into());
    }
    let mut bytes = fs::read(path).map_err(|e| e.to_string())?;
    let result = match bytes.strip_prefix(HEADER) {
        None => Err("not a relay request key file".to_string()),
        Some(rest) => <&[u8; 32]>::try_from(rest)
            .map_err(|_| "key file has the wrong size".to_string())
            .and_then(|key| SecretKey::from_bytes(key).map_err(|e| e.to_string())),
    };
    wipe(&mut bytes);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_rules() {
        let path = std::env::temp_dir().join(format!("ona-relay-key-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        let key = create(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load(&path).unwrap().public_key(), key.public_key());
        assert!(create(&path).is_err(), "an existing key is never overwritten");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&path).err().unwrap().contains("other users"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut short = HEADER.to_vec();
        short.extend_from_slice(&[1u8; 31]);
        fs::write(&path, short).unwrap();
        assert!(load(&path).err().unwrap().contains("wrong size"));
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_key_file_of_another_kind_is_refused() {
        let path = std::env::temp_dir().join(format!("ona-relay-key-kind-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        // A bare 32-byte key, as a signer key file holding one mint key used to look.
        fs::write(&path, keygen(&mut OsRng).to_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&path).err().unwrap().contains("not a relay request key file"));
        fs::remove_file(&path).unwrap();
    }
}
