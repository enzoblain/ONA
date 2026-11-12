//! What both local-node programs need before they start the node.

use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Result};

/// The local node binary to run. Refuses to go on without one, so the library never downloads and runs an
/// unchecked binary.
pub fn sandbox_binary(value: Option<OsString>) -> Result<PathBuf> {
    let path = PathBuf::from(value.filter(|v| !v.is_empty()).ok_or_else(|| {
        anyhow!("set NEAR_SANDBOX_BIN_PATH to a near-sandbox binary you have checked (docs/INSTALL.md)")
    })?);
    if !path.is_file() {
        bail!("NEAR_SANDBOX_BIN_PATH does not name a file: {}", path.display());
    }
    Ok(path)
}

/// The 32-byte seed of an `ed25519:<base58>` key in the 64-byte form.
pub fn key_seed(secret: &str) -> Result<[u8; 32]> {
    let raw = bs58::decode(secret.trim_start_matches("ed25519:")).into_vec()?;
    if raw.len() != 64 {
        bail!("the genesis key is not a 64-byte ed25519 key");
    }
    Ok(raw[..32].try_into()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Without a binary of its own, the program stops before the library can download one.
    #[test]
    fn a_local_binary_is_required() {
        assert!(sandbox_binary(None).is_err());
        assert!(sandbox_binary(Some(OsString::new())).is_err());
        assert!(sandbox_binary(Some(OsString::from("/nonexistent/near-sandbox"))).is_err());
        let file = std::env::temp_dir().join(format!("ona-sandbox-bin-{}", std::process::id()));
        std::fs::write(&file, b"").unwrap();
        assert_eq!(sandbox_binary(Some(file.clone().into_os_string())).unwrap(), file);
        std::fs::remove_file(&file).unwrap();
    }

    #[test]
    fn a_malformed_genesis_key_is_an_error() {
        assert!(key_seed("ed25519:abc").is_err());
        let key = bs58::encode([7u8; 64]).into_string();
        assert_eq!(key_seed(&format!("ed25519:{key}")).unwrap(), [7u8; 32]);
    }
}
