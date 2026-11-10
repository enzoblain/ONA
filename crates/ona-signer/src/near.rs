//! The `Chain` used in production: reads and writes `ona-mint` over NEAR RPC.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use ona_near::Client;
use ona_token::{g2_from_raw, G1_LEN, G2_LEN, G2_RAW_LEN};
use serde_json::{json, Value};

use crate::{Chain, PendingRecord};

// Measured on near-sandbox 2.13.4: about 2 Tgas for lock, and 6.9 Tgas per token for issue.
const LOCK_TGAS: u64 = 10;
const ISSUE_BASE_TGAS: u64 = 10;
const ISSUE_TGAS_PER_TOKEN: u64 = 8;

pub struct NearChain {
    client: Client,
    account: String,
    mint: String,
}

impl NearChain {
    pub fn new(client: Client, account: String, mint: String) -> Self {
        Self { client, account, mint }
    }

    fn write(&self, method: &str, args: Value, gas_tgas: u64) -> Result<(), String> {
        let outcome = self
            .client
            .call_with_gas(&self.account, &self.mint, method, args, gas_tgas, 0)
            .map_err(|e| e.to_string())?;
        match outcome.failure {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

/// Reads a NEAR account key (`ed25519:<base58>`) from a file only its owner can read.
pub fn load_account_key(path: &Path) -> Result<SigningKey, String> {
    let meta = fs::metadata(path).map_err(|e| format!("cannot read account key: {e}"))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err("account key file is accessible to other users".into());
    }
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_account_key(text.trim())
}

/// Accepts the 64-byte form NEAR tools write, and refuses one whose public half does not match.
pub fn parse_account_key(text: &str) -> Result<SigningKey, String> {
    let encoded = text.strip_prefix("ed25519:").ok_or("account key must start with ed25519:")?;
    let bytes = bs58::decode(encoded).into_vec().map_err(|_| "account key is not base58".to_string())?;
    if bytes.len() != 64 {
        return Err("account key must be 64 bytes".into());
    }
    let seed: [u8; 32] = bytes[..32].try_into().map_err(|_| "account key length".to_string())?;
    let key = SigningKey::from_bytes(&seed);
    if key.verifying_key().as_bytes()[..] != bytes[32..] {
        return Err("account key is inconsistent".into());
    }
    Ok(key)
}

fn parse_u64(value: &Value) -> Option<u64> {
    value.as_str()?.parse().ok()
}

/// Parses `pending_deposits`. A malformed record fails the whole read rather than being skipped.
pub fn parse_pending(value: &Value) -> Result<Vec<PendingRecord>, String> {
    let bad = || format!("unexpected pending_deposits reply: {value}");
    value
        .as_array()
        .ok_or_else(bad)?
        .iter()
        .map(|record| {
            let items = record["items"]
                .as_array()
                .ok_or_else(bad)?
                .iter()
                .map(|item| {
                    let denom = item["denom_id"].as_u64().and_then(|d| u8::try_from(d).ok()).ok_or_else(bad)?;
                    let blinded: [u8; G1_LEN] = item["blinded"]
                        .as_str()
                        .and_then(|b| B64.decode(b).ok())
                        .and_then(|b| b.try_into().ok())
                        .ok_or_else(bad)?;
                    Ok((denom, blinded))
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(PendingRecord {
                id: parse_u64(&record["id"]).ok_or_else(bad)?,
                items,
                deadline: parse_u64(&record["deadline"]).ok_or_else(bad)?,
                locked_until: parse_u64(&record["locked_until"]).ok_or_else(bad)?,
            })
        })
        .collect()
}

impl Chain for NearChain {
    fn pending(&mut self, from: u64, limit: u16) -> Result<Vec<PendingRecord>, String> {
        let args = json!({"from": from.to_string(), "limit": limit});
        let value = self
            .client
            .view_final(&self.mint, "pending_deposits", args)
            .map_err(|e| e.to_string())?;
        parse_pending(&value)
    }

    fn lock(&mut self, id: u64) -> Result<(), String> {
        self.write("lock", json!({"deposit_id": id.to_string()}), LOCK_TGAS)
    }

    fn denom_key(&mut self, denom_id: u8) -> Result<[u8; G2_LEN], String> {
        let value = self
            .client
            .view_final(&self.mint, "get_denom", json!({"denom_id": denom_id}))
            .map_err(|e| e.to_string())?;
        let raw: [u8; G2_RAW_LEN] = value["pk_raw"]
            .as_str()
            .and_then(|k| B64.decode(k).ok())
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| format!("unexpected get_denom reply: {value}"))?;
        g2_from_raw(&raw).map_err(|e| e.to_string())
    }

    fn now(&mut self) -> Result<u64, String> {
        self.client.final_timestamp().map_err(|e| e.to_string())
    }

    fn issue(&mut self, id: u64, sigs: Vec<[u8; G1_LEN]>) -> Result<(), String> {
        let gas = ISSUE_BASE_TGAS + ISSUE_TGAS_PER_TOKEN * sigs.len() as u64;
        let encoded: Vec<String> = sigs.iter().map(|s| B64.encode(s)).collect();
        self.write("issue", json!({"deposit_id": id.to_string(), "sigs": encoded}), gas)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_records_are_parsed() {
        let value = json!([{
            "id": "4", "depositor": "a.test", "deadline": "100", "locked_until": "0", "total": "1", "is_change": false,
            "items": [{"denom_id": 2, "blinded": B64.encode([7u8; G1_LEN])}],
        }]);
        let records = parse_pending(&value).unwrap();
        assert_eq!(records[0].id, 4);
        assert_eq!(records[0].deadline, 100);
        assert_eq!(records[0].locked_until, 0);
        assert_eq!(records[0].items, vec![(2, [7u8; G1_LEN])]);
    }

    #[test]
    fn malformed_records_fail_the_read() {
        let short = json!([{"id":"1","deadline":"1","locked_until":"0","items":[{"denom_id":0,"blinded":B64.encode([1u8; 3])}]}]);
        assert!(parse_pending(&short).is_err());
        assert!(parse_pending(&json!({"not": "a list"})).is_err());
        assert!(parse_pending(&json!([{"id":"x","deadline":"1","locked_until":"0","items":[]}])).is_err());
        assert!(parse_pending(&json!([{"id":"1","deadline":"1","items":[]}])).is_err(), "a missing lock field must not read as unlocked");
    }

    fn encoded_key(key: &SigningKey) -> Vec<u8> {
        let mut bytes = key.to_bytes().to_vec();
        bytes.extend_from_slice(key.verifying_key().as_bytes());
        bytes
    }

    #[test]
    fn account_keys_are_validated() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let text = format!("ed25519:{}", bs58::encode(encoded_key(&key)).into_string());
        assert_eq!(parse_account_key(&text).unwrap().to_bytes(), key.to_bytes());

        assert!(parse_account_key("secp256k1:abc").is_err());
        assert!(parse_account_key("ed25519:not-base-58!").is_err());
        assert!(parse_account_key(&format!("ed25519:{}", bs58::encode([1u8; 32]).into_string())).is_err());

        let mut wrong = encoded_key(&key);
        wrong[40] ^= 1;
        assert!(parse_account_key(&format!("ed25519:{}", bs58::encode(wrong).into_string())).is_err());
    }

    #[test]
    fn an_account_key_readable_by_others_is_refused() {
        let path = std::env::temp_dir().join(format!("ona-account-key-{}", std::process::id()));
        let key = SigningKey::from_bytes(&[6u8; 32]);
        fs::write(&path, format!("ed25519:{}\n", bs58::encode(encoded_key(&key)).into_string())).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_account_key(&path).err().unwrap().contains("other users"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_account_key(&path).is_ok());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn gas_covers_the_largest_batch_as_measured() {
        let measured_tgas_for_64 = 442.452;
        assert!((ISSUE_BASE_TGAS + ISSUE_TGAS_PER_TOKEN * 64) as f64 > measured_tgas_for_64 * 1.1);
    }
}
