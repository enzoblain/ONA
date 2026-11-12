//! The agent's blind-signing keys: one per cash tier, and one per tier of each vault. They live in one file that
//! only its owner can read, after a type line, so that a key file made for another use (the mint signer, the relay)
//! is refused.
//!
//! Layout after the type line: the number of cash tiers (one byte) and their 32-byte keys, the number of vaults
//! (one byte), then for each vault the number of its tiers (one byte) and their keys.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ona_token::{keygen, SecretKey, G2_LEN};
use rand::rngs::OsRng;
use zeroize::Zeroize;

const HEADER: &[u8] = b"ONA-POOL-AGENT-KEYS-V1\n";
/// As the contract: at most 8 tiers per vault or for the cash, at most 32 vaults.
pub const MAX_TIERS: usize = 8;
pub const MAX_VAULTS: usize = 32;

pub struct AgentKeys {
    pub cash: Vec<SecretKey>,
    pub vaults: Vec<Vec<SecretKey>>,
}

fn check_layout(cash: usize, vaults: &[usize]) -> Result<(), String> {
    if cash == 0 || cash > MAX_TIERS {
        return Err(format!("the cash needs 1 to {MAX_TIERS} tiers"));
    }
    if vaults.len() > MAX_VAULTS {
        return Err(format!("at most {MAX_VAULTS} vaults"));
    }
    if vaults.iter().any(|t| *t == 0 || *t > MAX_TIERS) {
        return Err(format!("each vault needs 1 to {MAX_TIERS} tiers"));
    }
    Ok(())
}

impl AgentKeys {
    /// New keys: `cash` cash tiers, and one entry of `vaults` per vault with its number of tiers.
    pub fn generate(cash: usize, vaults: &[usize]) -> Result<Self, String> {
        check_layout(cash, vaults)?;
        Ok(Self {
            cash: (0..cash).map(|_| keygen(&mut OsRng)).collect(),
            vaults: vaults.iter().map(|n| (0..*n).map(|_| keygen(&mut OsRng)).collect()).collect(),
        })
    }

    pub fn cash_public(&self) -> Vec<[u8; G2_LEN]> {
        self.cash.iter().map(SecretKey::public_key).collect()
    }

    pub fn vault_public(&self, vault: usize) -> Option<Vec<[u8; G2_LEN]>> {
        self.vaults.get(vault).map(|tiers| tiers.iter().map(SecretKey::public_key).collect())
    }

    /// Writes a new file readable by this user only. Never overwrites one.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("cannot create key file: {e}"))?;
        let mut bytes = HEADER.to_vec();
        bytes.push(self.cash.len() as u8);
        for key in &self.cash {
            bytes.extend_from_slice(&key.to_bytes());
        }
        bytes.push(self.vaults.len() as u8);
        for tiers in &self.vaults {
            bytes.push(tiers.len() as u8);
            for key in tiers {
                bytes.extend_from_slice(&key.to_bytes());
            }
        }
        let written = file.write_all(&bytes).and_then(|()| file.sync_all());
        bytes.zeroize();
        written.map_err(|e| e.to_string())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let meta = fs::metadata(path).map_err(|e| format!("cannot read key file: {e}"))?;
        if !meta.is_file() {
            return Err("key file is not a regular file".into());
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err("key file is accessible to other users".into());
        }
        let mut bytes = fs::read(path).map_err(|e| e.to_string())?;
        let parsed = match bytes.strip_prefix(HEADER) {
            None => Err("not a pool agent key file".to_string()),
            Some(rest) => parse(rest),
        };
        bytes.zeroize();
        parsed
    }
}

fn parse(mut rest: &[u8]) -> Result<AgentKeys, String> {
    let wrong = || "key file has the wrong size".to_string();
    let take_keys = |rest: &mut &[u8]| -> Result<Vec<SecretKey>, String> {
        let (&count, tail) = rest.split_first().ok_or_else(wrong)?;
        let count = usize::from(count);
        if tail.len() < count * 32 {
            return Err(wrong());
        }
        let (keys, tail) = tail.split_at(count * 32);
        *rest = tail;
        keys.chunks_exact(32)
            .map(|chunk| {
                let chunk: &[u8; 32] = chunk.try_into().map_err(|_| wrong())?;
                SecretKey::from_bytes(chunk).map_err(|e| e.to_string())
            })
            .collect()
    };
    let cash = take_keys(&mut rest)?;
    let (&vault_count, tail) = rest.split_first().ok_or_else(wrong)?;
    rest = tail;
    let mut vaults = Vec::new();
    for _ in 0..vault_count {
        vaults.push(take_keys(&mut rest)?);
    }
    if !rest.is_empty() {
        return Err(wrong());
    }
    check_layout(cash.len(), &vaults.iter().map(Vec::len).collect::<Vec<_>>())?;
    Ok(AgentKeys { cash, vaults })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("ona-agent-keys-{name}-{}", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    #[test]
    fn keys_round_trip_and_are_private() {
        let path = temp("round");
        let keys = AgentKeys::generate(3, &[3, 2]).unwrap();
        keys.save(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let loaded = AgentKeys::load(&path).unwrap();
        assert_eq!(loaded.cash_public(), keys.cash_public());
        assert_eq!(loaded.vault_public(1), keys.vault_public(1));
        assert!(keys.save(&path).is_err(), "never overwritten");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(AgentKeys::load(&path).err().unwrap().contains("other users"));
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_key_file_of_another_kind_or_size_is_refused() {
        let path = temp("kind");
        fs::write(&path, keygen(&mut OsRng).to_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AgentKeys::load(&path).err().unwrap().contains("not a pool agent key file"));
        let mut short = HEADER.to_vec();
        short.extend_from_slice(&[2, 1, 2, 3]);
        fs::write(&path, short).unwrap();
        assert!(AgentKeys::load(&path).err().unwrap().contains("wrong size"));
        fs::remove_file(&path).unwrap();
        assert!(AgentKeys::generate(0, &[]).is_err());
        assert!(AgentKeys::generate(1, &[9]).is_err());
    }
}
