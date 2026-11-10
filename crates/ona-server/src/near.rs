//! The `Chain` used in production: reads and writes `ona-mint` over NEAR RPC.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_near::Client;
use serde_json::{json, Value};

use crate::{Chain, Claim};

// Measured on near-sandbox 2.13.4: 264.635 Tgas for 32 claims, about 8.3 per claim.
const CLAIM_BASE_TGAS: u64 = 10;
const CLAIM_TGAS_PER_ITEM: u64 = 10;

pub struct NearRelayChain {
    client: Client,
    account: String,
    mint: String,
}

impl NearRelayChain {
    pub fn new(client: Client, account: String, mint: String) -> Self {
        Self { client, account, mint }
    }

    fn view_bool(&self, method: &str, nf: &[u8; 32]) -> Result<bool, String> {
        let value = self
            .client
            .view_final(&self.mint, method, json!({"nf": B64.encode(nf)}))
            .map_err(|e| e.to_string())?;
        value.as_bool().ok_or_else(|| format!("unexpected {method} reply: {value}"))
    }
}

pub fn claim_json(claim: &Claim) -> Value {
    json!({
        "token": {
            "denom_id": claim.token.denom_id,
            "pk": B64.encode(claim.token.pk),
            "nonce": B64.encode(claim.token.nonce),
            "sig": B64.encode(claim.token.sig),
        },
        "owner_sig": B64.encode(claim.owner_sig),
    })
}

/// One boolean per claim, or an error: a partial answer must never be read as refusals.
pub fn parse_claim_results(value: &Value, expected: usize) -> Result<Vec<bool>, String> {
    let results: Option<Vec<bool>> = value.as_array().map(|a| a.iter().filter_map(Value::as_bool).collect());
    match results {
        Some(results) if results.len() == expected && value.as_array().is_some_and(|a| a.len() == expected) => Ok(results),
        _ => Err(format!("unexpected relay_claim reply: {value}")),
    }
}

impl Chain for NearRelayChain {
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.view_bool("is_spent", nf)
    }

    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
        let items: Vec<Value> = claims.iter().map(claim_json).collect();
        let gas = CLAIM_BASE_TGAS + CLAIM_TGAS_PER_ITEM * claims.len() as u64;
        let outcome = self
            .client
            .call_with_gas(&self.account, &self.mint, "relay_claim", json!({"items": items}), gas, 0)
            .map_err(|e| e.to_string())?;
        if let Some(failure) = outcome.failure {
            return Err(failure);
        }
        parse_claim_results(&outcome.value, claims.len())
    }

    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.view_bool("spent_by_relay", nf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_results_must_match_the_batch() {
        assert_eq!(parse_claim_results(&json!([true, false]), 2).unwrap(), vec![true, false]);
        assert!(parse_claim_results(&json!([true]), 2).is_err());
        assert!(parse_claim_results(&json!(null), 1).is_err());
        assert!(parse_claim_results(&json!([true, "no"]), 2).is_err());
    }
}
