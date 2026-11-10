//! The relay's request-signing key, in a file only its owner can read.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ona_token::{keygen, SecretKey};
use rand::rngs::OsRng;

/// Creates a new key file. Never overwrites one: request tokens already sold depend on it.
pub fn create(path: &Path) -> Result<SecretKey, String> {
    let key = keygen(&mut OsRng);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create key file: {e}"))?;
    file.write_all(&key.to_bytes()).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn load(path: &Path) -> Result<SecretKey, String> {
    let meta = fs::metadata(path).map_err(|e| format!("cannot read key file: {e}"))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err("key file is accessible to other users".into());
    }
    let bytes: [u8; 32] = fs::read(path)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "key file has the wrong size".to_string())?;
    SecretKey::from_bytes(&bytes).map_err(|e| e.to_string())
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
        fs::write(&path, [1u8; 31]).unwrap();
        assert!(load(&path).err().unwrap().contains("wrong size"));
        fs::remove_file(&path).unwrap();
    }
}
