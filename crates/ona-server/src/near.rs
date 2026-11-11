//! The `Chain` used in production: reads `ona-mint` through two RPC endpoints that must agree, and
//! sends transactions through the first one.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_near::{Client, TxUnknown};
use ona_token::{g2_from_raw, G2_LEN, G2_RAW_LEN};
use serde_json::{json, Value};

use crate::crossrpc::{CrossRpc, HttpRpc, Rpc};
use crate::{Chain, Claim};

// 264.635 Tgas were measured for 32 claims on near-sandbox 2.13.4 with the earlier contract, about 8.3 per
// claim; the contract now takes at most 28 (10 + 10 x 28 = 290 Tgas). 28 claims are not measured yet.
const CLAIM_BASE_TGAS: u64 = 10;
const CLAIM_TGAS_PER_ITEM: u64 = 10;

/// `client` sends transactions only. Every read that a signature depends on goes through `reads`.
pub struct NearRelayChain<A = HttpRpc, B = HttpRpc> {
    client: Client,
    reads: CrossRpc<A, B>,
    account: String,
    mint: String,
    /// A `relay_claim` whose outcome the node could not give. Its status is asked for before the next
    /// claim is sent.
    unknown_claim: Option<[u8; 32]>,
}

impl<A: Rpc, B: Rpc> NearRelayChain<A, B> {
    pub fn new(client: Client, reads: CrossRpc<A, B>, account: String, mint: String) -> Self {
        Self { client, reads, account, mint, unknown_claim: None }
    }

    /// Before a new claim, the fate of an unknown earlier one is asked for. If it landed, this batch is
    /// not sent: the relay reads the chain at its next flush and signs what that claim collected. If the
    /// node still does not know it, the new claim goes out: a credit claimed twice is refused the second
    /// time by its nullifier, so nothing is paid twice.
    fn settle_unknown_claim(&mut self) -> Result<(), String> {
        let Some(hash) = self.unknown_claim else {
            return Ok(());
        };
        match self.client.tx_status(&hash, &self.account) {
            Ok(Some(_)) => {
                self.unknown_claim = None;
                Err("an earlier claim landed after all: reading the chain before claiming again".into())
            }
            Ok(None) => {
                self.unknown_claim = None;
                Ok(())
            }
            Err(e) => Err(format!("cannot learn the fate of an earlier claim: {e}")),
        }
    }

    /// The key that verifies credits, read from the contract so it cannot drift from it.
    pub fn credit_key(&self) -> Result<[u8; G2_LEN], String> {
        let value = self.reads.view(&self.mint, "get_denom", json!({"denom_id": 0}))?;
        let raw: [u8; G2_RAW_LEN] = value["pk_raw"]
            .as_str()
            .and_then(|k| B64.decode(k).ok())
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| format!("unexpected get_denom reply: {value}"))?;
        g2_from_raw(&raw).map_err(|e| e.to_string())
    }

    fn view_bool(&self, method: &str, nf: &[u8; 32]) -> Result<bool, String> {
        let value = self.reads.view(&self.mint, method, json!({"nf": B64.encode(nf)}))?;
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
        "expires_at": claim.expires_at.to_string(),
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

/// `relay_claim` results come from the first endpoint alone, so the relay signs only after a
/// cross-checked read says the claim landed (`claimed_by_relay`).
impl<A: Rpc, B: Rpc> Chain for NearRelayChain<A, B> {
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.view_bool("is_spent", nf)
    }

    fn relay_claim(&mut self, claims: &[Claim]) -> Result<Vec<bool>, String> {
        self.settle_unknown_claim()?;
        let items: Vec<Value> = claims.iter().map(claim_json).collect();
        let gas = CLAIM_BASE_TGAS + CLAIM_TGAS_PER_ITEM * claims.len() as u64;
        let outcome = match self.client.call_with_gas(&self.account, &self.mint, "relay_claim", json!({"items": items}), gas, 0)
        {
            Ok(outcome) => outcome,
            Err(e) => {
                if let Some(unknown) = e.downcast_ref::<TxUnknown>() {
                    self.unknown_claim = Some(unknown.hash);
                }
                return Err(e.to_string());
            }
        };
        if let Some(failure) = outcome.failure {
            return Err(failure);
        }
        parse_claim_results(&outcome.value, claims.len())
    }

    fn claimed_by_relay(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.view_bool("spent_by_relay", nf)
    }

    fn final_timestamp(&mut self) -> Result<u64, String> {
        self.reads.final_timestamp()
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
