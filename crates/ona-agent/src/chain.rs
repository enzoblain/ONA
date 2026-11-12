//! What the agent reads from and sends to `ona-pool`. `NearPoolChain` reads through two RPC endpoints that must
//! agree on one final block, pinned by `begin`, and sends transactions with the agent's key through the first.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_near::{Client, TxUnknown};
use ona_server::crossrpc::{Block, CrossRpc, HttpRpc, Rpc};
use ona_token::{g2_from_raw, G1_LEN, G2_LEN, G2_RAW_LEN};
use serde_json::{json, Value};

/// A note as the contract takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    pub tier: u8,
    pub pk: [u8; 32],
    pub nonce: [u8; 32],
    pub sig: [u8; G1_LEN],
}

impl Note {
    pub fn to_json(&self) -> Value {
        json!({"tier": self.tier, "pk": B64.encode(self.pk), "nonce": B64.encode(self.nonce), "sig": B64.encode(self.sig)})
    }
}

#[derive(Clone, Debug)]
pub struct ConfigInfo {
    pub agent: String,
    pub network: String,
    pub vault_count: u32,
    pub escape_open: bool,
    pub last_agent_call: u64,
    pub admin_pending_until: u64,
}

#[derive(Clone, Debug)]
pub struct CashInfo {
    /// Value of one note and the tier's key, per tier.
    pub tiers: Vec<(u128, [u8; G2_LEN])>,
    pub liquid: u128,
    pub outstanding: u128,
    /// Most cash paid out per calendar hour, exits of every kind together.
    pub hourly_cap: u128,
    /// Exit requests listed on the cash.
    pub requests: u32,
    /// Anyone may pay listed cash notes (`escape_exit`).
    pub open: bool,
}

#[derive(Clone, Debug)]
pub struct VaultInfo {
    /// Shares of one note and the tier's key, per tier.
    pub tiers: Vec<(u128, [u8; G2_LEN])>,
    pub liquid: u128,
    pub placed: u128,
    pub withdrawing: u128,
    pub total_shares: u128,
    pub share_price: u128,
    pub synced_at: u64,
    pub max_assets: u128,
    pub hourly_cap: u128,
    pub frozen: bool,
    pub busy: bool,
    /// Exit requests listed on this vault: their value must stay liquid.
    pub requests: u32,
    pub open: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderInfo {
    pub issued: u128,
    pub refundable: u128,
}

/// Why a transaction gave no result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError {
    /// Certainly not done: not sent, refused by the node, or failed on chain.
    Refused(String),
    /// Sent, outcome unknown: it may still land.
    Unknown(String),
}

impl CallError {
    pub fn message(&self) -> &str {
        match self {
            Self::Refused(m) | Self::Unknown(m) => m,
        }
    }
}

pub trait PoolChain {
    /// Pins the final block every read until the next `begin` is made at. Returns its time, in nanoseconds.
    fn begin(&mut self) -> Result<u64, String>;
    fn config(&mut self) -> Result<ConfigInfo, String>;
    fn cash(&mut self) -> Result<CashInfo, String>;
    fn vault(&mut self, id: u32) -> Result<VaultInfo, String>;
    fn holder(&mut self, account: &str) -> Result<HolderInfo, String>;
    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String>;
    /// Whether `pk` is a full-access key of `account`.
    fn full_access_key(&mut self, account: &str, pk: &[u8; 32]) -> Result<bool, String>;

    fn issue_cash(&mut self, account: &str, tier: u8, count: u64) -> Result<(), CallError>;
    fn enter(&mut self, vault: u32, note: &Note, owner_sig: &[u8; 64], outputs: &[(u8, u64)], expires_at: u64) -> Result<(), CallError>;
    fn leave(&mut self, vault: u32, note: &Note, owner_sig: &[u8; 64], outputs: &[(u8, u64)], expires_at: u64) -> Result<(), CallError>;
    fn pay_exit(&mut self, note: &Note, owner_sig: &[u8; 64], to: &str, expires_at: u64) -> Result<(), CallError>;
    fn place(&mut self, vault: u32, amount: u128) -> Result<(), CallError>;
    fn sync(&mut self, vault: u32) -> Result<(), CallError>;
    fn unstake(&mut self, vault: u32, amount: u128) -> Result<(), CallError>;
    fn withdraw(&mut self, vault: u32, amount: u128) -> Result<(), CallError>;

    /// The hash of the last transaction sent (succeeded, failed or with an unknown outcome), taken once.
    fn take_last_tx(&mut self) -> Option<[u8; 32]> {
        None
    }
    /// A transaction's final outcome as both read endpoints report it: `Some(true)` it succeeded, `Some(false)` it
    /// failed, `None` when either does not know, is not final, or they disagree.
    fn tx_outcome(&mut self, _hash: &[u8; 32]) -> Result<Option<bool>, String> {
        Ok(None)
    }
}

/// One endpoint's answer to `tx`: the final outcome of the transaction named `hash`, or `None`.
fn outcome_of(answer: Result<Value, String>, hash: &[u8; 32]) -> Option<bool> {
    let result = answer.ok()?;
    if result["transaction"]["hash"].as_str() != Some(bs58::encode(hash).into_string().as_str()) {
        return None;
    }
    ona_near::parse_outcome(&result).ok().map(|o| o.failure.is_none())
}

/// The outcome both endpoints agree on, if any.
pub fn agreed_outcome(first: Result<Value, String>, second: Result<Value, String>, hash: &[u8; 32]) -> Option<bool> {
    match (outcome_of(first, hash), outcome_of(second, hash)) {
        (Some(a), Some(b)) if a == b => Some(a),
        _ => None,
    }
}

fn u128_of(v: &Value, key: &str) -> Result<u128, String> {
    v[key].as_str().and_then(|s| s.parse().ok()).ok_or_else(|| format!("pool view without {key}"))
}

fn u64_of(v: &Value, key: &str) -> Result<u64, String> {
    v[key].as_u64().ok_or_else(|| format!("pool view without {key}"))
}

fn bool_of(v: &Value, key: &str) -> Result<bool, String> {
    v[key].as_bool().ok_or_else(|| format!("pool view without {key}"))
}

fn tier_key(v: &Value) -> Result<[u8; G2_LEN], String> {
    let raw: [u8; G2_RAW_LEN] = v["pk_raw"]
        .as_str()
        .and_then(|s| B64.decode(s).ok())
        .and_then(|b| b.try_into().ok())
        .ok_or("pool view without a valid pk_raw")?;
    g2_from_raw(&raw).map_err(|e| format!("bad tier key: {e}"))
}

pub fn parse_config(v: &Value) -> Result<ConfigInfo, String> {
    Ok(ConfigInfo {
        agent: v["agent"].as_str().ok_or("pool config without agent")?.to_string(),
        network: v["network"].as_str().ok_or("pool config without network")?.to_string(),
        vault_count: u32::try_from(u64_of(v, "vault_count")?).map_err(|_| "too many vaults")?,
        escape_open: bool_of(v, "escape_open")?,
        last_agent_call: u64_of(v, "last_agent_call")?,
        admin_pending_until: u64_of(v, "admin_pending_until")?,
    })
}

pub fn parse_cash(v: &Value) -> Result<CashInfo, String> {
    let tiers = v["tiers"]
        .as_array()
        .ok_or("cash view without tiers")?
        .iter()
        .map(|t| Ok((u128_of(t, "value")?, tier_key(t)?)))
        .collect::<Result<_, String>>()?;
    Ok(CashInfo {
        tiers,
        liquid: u128_of(v, "liquid")?,
        outstanding: u128_of(v, "outstanding")?,
        hourly_cap: u128_of(v, "hourly_cap")?,
        requests: u32::try_from(u64_of(v, "requests")?).map_err(|_| "too many requests")?,
        open: bool_of(v, "open")?,
    })
}

pub fn parse_vault(v: &Value) -> Result<VaultInfo, String> {
    let tiers = v["tiers"]
        .as_array()
        .ok_or("vault view without tiers")?
        .iter()
        .map(|t| Ok((u128_of(t, "shares")?, tier_key(t)?)))
        .collect::<Result<_, String>>()?;
    Ok(VaultInfo {
        tiers,
        liquid: u128_of(v, "liquid")?,
        placed: u128_of(v, "placed")?,
        withdrawing: u128_of(v, "withdrawing")?,
        total_shares: u128_of(v, "total_shares")?,
        share_price: u128_of(v, "share_price")?,
        synced_at: u64_of(v, "synced_at")?,
        max_assets: u128_of(v, "max_assets")?,
        hourly_cap: u128_of(v, "hourly_cap")?,
        frozen: bool_of(v, "frozen")?,
        busy: bool_of(v, "busy")?,
        requests: u32::try_from(u64_of(v, "requests")?).map_err(|_| "too many requests")?,
        open: bool_of(v, "open")?,
    })
}

pub fn parse_holder(v: &Value) -> Result<HolderInfo, String> {
    Ok(HolderInfo { issued: u128_of(v, "issued")?, refundable: u128_of(v, "refundable")? })
}

fn outputs_json(outputs: &[(u8, u64)]) -> Value {
    json!(outputs.iter().map(|(tier, count)| json!({"tier": tier, "count": count})).collect::<Vec<_>>())
}

// Gas per call. None of these is measured on a real chain; the vault calls carry the contract's own budgets for the
// staking pool call and its callback (50 + 20, or 80 for a read callback).
const NOTE_TGAS: u64 = 100;
const VAULT_TGAS: u64 = 200;

/// `client` sends transactions only; every read goes through `reads` at the block pinned by `begin`.
pub struct NearPoolChain<A = HttpRpc, B = HttpRpc> {
    client: Client,
    reads: CrossRpc<A, B>,
    account: String,
    pool: String,
    pinned: Option<Block>,
    last: Option<[u8; 32]>,
}

impl<A: Rpc, B: Rpc> NearPoolChain<A, B> {
    pub fn new(client: Client, reads: CrossRpc<A, B>, account: String, pool: String) -> Self {
        Self { client, reads, account, pool, pinned: None, last: None }
    }

    fn block(&mut self) -> Result<Block, String> {
        match &self.pinned {
            Some(block) => Ok(block.clone()),
            None => {
                let block = self.reads.agreed_final_block()?;
                self.pinned = Some(block.clone());
                Ok(block)
            }
        }
    }

    fn view(&mut self, method: &str, args: Value) -> Result<Value, String> {
        let block = self.block()?;
        self.reads.view_at(&block, &self.pool, method, args)
    }

    fn call(&mut self, method: &str, args: Value, tgas: u64) -> Result<(), CallError> {
        match self.client.call_with_gas(&self.account, &self.pool, method, args, tgas, 0) {
            Ok(outcome) => {
                self.last = outcome.tx_hash;
                match outcome.failure {
                    Some(failure) => Err(CallError::Refused(failure)),
                    None => Ok(()),
                }
            }
            Err(e) if e.downcast_ref::<TxUnknown>().is_some() => {
                self.last = e.downcast_ref::<TxUnknown>().map(|u| u.hash);
                Err(CallError::Unknown(e.to_string()))
            }
            Err(e) => Err(CallError::Refused(e.to_string())),
        }
    }
}

impl<A: Rpc, B: Rpc> PoolChain for NearPoolChain<A, B> {
    fn begin(&mut self) -> Result<u64, String> {
        self.pinned = None;
        Ok(self.block()?.timestamp)
    }

    fn config(&mut self) -> Result<ConfigInfo, String> {
        parse_config(&self.view("get_config", json!({}))?)
    }

    fn cash(&mut self) -> Result<CashInfo, String> {
        parse_cash(&self.view("get_cash", json!({}))?)
    }

    fn vault(&mut self, id: u32) -> Result<VaultInfo, String> {
        parse_vault(&self.view("get_vault", json!({"vault_id": id}))?)
    }

    fn holder(&mut self, account: &str) -> Result<HolderInfo, String> {
        parse_holder(&self.view("get_holder", json!({"account": account}))?)
    }

    fn is_spent(&mut self, nf: &[u8; 32]) -> Result<bool, String> {
        self.view("is_spent", json!({"nf": B64.encode(nf)}))?.as_bool().ok_or_else(|| "is_spent did not answer a boolean".into())
    }

    /// `view_access_key`, from the NEAR RPC documentation (not verified against a node here). An unknown key is an
    /// RPC error, read as "not a full-access key".
    fn full_access_key(&mut self, account: &str, pk: &[u8; 32]) -> Result<bool, String> {
        let block = self.block()?;
        let params = json!({
            "request_type": "view_access_key", "account_id": account,
            "public_key": crate::nep413::write_public_key(pk),
        });
        match self.reads.query_at(&block, params) {
            Ok(result) => Ok(result["permission"] == json!("FullAccess")),
            Err(e) if e.contains("rpc error") => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn issue_cash(&mut self, account: &str, tier: u8, count: u64) -> Result<(), CallError> {
        self.call("issue_cash", json!({"account": account, "tier": tier, "count": count}), NOTE_TGAS)
    }

    fn enter(&mut self, vault: u32, note: &Note, owner_sig: &[u8; 64], outputs: &[(u8, u64)], expires_at: u64) -> Result<(), CallError> {
        let args = json!({
            "vault_id": vault, "note": note.to_json(), "owner_sig": B64.encode(owner_sig),
            "outputs": outputs_json(outputs), "expires_at": expires_at,
        });
        self.call("enter", args, NOTE_TGAS)
    }

    fn leave(&mut self, vault: u32, note: &Note, owner_sig: &[u8; 64], outputs: &[(u8, u64)], expires_at: u64) -> Result<(), CallError> {
        let args = json!({
            "vault_id": vault, "note": note.to_json(), "owner_sig": B64.encode(owner_sig),
            "outputs": outputs_json(outputs), "expires_at": expires_at,
        });
        self.call("leave", args, NOTE_TGAS)
    }

    fn pay_exit(&mut self, note: &Note, owner_sig: &[u8; 64], to: &str, expires_at: u64) -> Result<(), CallError> {
        let args = json!({"note": note.to_json(), "owner_sig": B64.encode(owner_sig), "to": to, "expires_at": expires_at});
        self.call("pay_exit", args, NOTE_TGAS)
    }

    fn place(&mut self, vault: u32, amount: u128) -> Result<(), CallError> {
        self.call("place", json!({"vault_id": vault, "amount": amount.to_string()}), VAULT_TGAS)
    }

    fn sync(&mut self, vault: u32) -> Result<(), CallError> {
        self.call("sync", json!({"vault_id": vault}), VAULT_TGAS)
    }

    fn unstake(&mut self, vault: u32, amount: u128) -> Result<(), CallError> {
        self.call("unstake", json!({"vault_id": vault, "amount": amount.to_string()}), VAULT_TGAS)
    }

    fn withdraw(&mut self, vault: u32, amount: u128) -> Result<(), CallError> {
        self.call("withdraw", json!({"vault_id": vault, "amount": amount.to_string()}), VAULT_TGAS)
    }

    fn take_last_tx(&mut self) -> Option<[u8; 32]> {
        self.last.take()
    }

    /// `tx` with `wait_until: FINAL` on both read endpoints (method and fields from the NEAR RPC documentation, not
    /// verified against a node). The sending node is not asked: its word alone decides nothing.
    fn tx_outcome(&mut self, hash: &[u8; 32]) -> Result<Option<bool>, String> {
        let params = json!({"tx_hash": bs58::encode(hash).into_string(), "sender_account_id": self.account, "wait_until": "FINAL"});
        Ok(agreed_outcome(self.reads.first.post("tx", params.clone()), self.reads.second.post("tx", params), hash))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ona_token::{g2_to_raw, keygen};
    use rand::rngs::OsRng;

    fn raw_key() -> String {
        B64.encode(g2_to_raw(&keygen(&mut OsRng).public_key()).unwrap())
    }

    #[test]
    fn views_are_parsed_and_malformed_ones_refused() {
        let vault = json!({
            "tiers": [{"shares": "10000", "pk_raw": raw_key(), "issued": 0, "paid": 0}],
            "liquid": "5", "placed": "6", "withdrawing": "0", "fee_owed": "0", "total_shares": "7", "orphan": "0",
            "share_price": "8", "synced_at": 9, "max_assets": "10", "hourly_cap": "11", "frozen": false, "busy": false,
            "busy_op": 0, "requests": 0, "open": false,
        });
        let v = parse_vault(&vault).unwrap();
        assert_eq!((v.liquid, v.placed, v.synced_at, v.tiers[0].0), (5, 6, 9, 10_000));
        let mut bad = vault.clone();
        bad["liquid"] = json!(5);
        assert!(parse_vault(&bad).is_err(), "amounts are strings in NEAR JSON");
        let mut bad_key = vault;
        bad_key["tiers"][0]["pk_raw"] = json!("AAAA");
        assert!(parse_vault(&bad_key).is_err());

        let cash = json!({"tiers": [{"value": "100", "pk_raw": raw_key(), "issued": 1, "paid": 0}], "liquid": "3", "outstanding": "2", "hourly_cap": "1", "requests": 0, "open": false});
        assert_eq!(parse_cash(&cash).unwrap().tiers[0].0, 100);
        assert_eq!(parse_holder(&json!({"issued": "4", "refundable": "5"})).unwrap(), HolderInfo { issued: 4, refundable: 5 });
        assert!(parse_config(&json!({"agent": "a"})).is_err());
    }

    fn final_tx(hash: &[u8; 32], status: Value) -> Result<Value, String> {
        Ok(json!({
            "final_execution_status": "FINAL", "status": status, "receipts_outcome": [],
            "transaction": {"hash": bs58::encode(hash).into_string()}, "transaction_outcome": {"outcome": {"status": {}}},
        }))
    }

    #[test]
    fn a_transaction_outcome_counts_only_when_both_endpoints_agree() {
        let h = [7u8; 32];
        let ok = || final_tx(&h, json!({"SuccessValue": ""}));
        let failed = || final_tx(&h, json!({"Failure": {"x": 1}}));
        assert_eq!(agreed_outcome(ok(), ok(), &h), Some(true));
        assert_eq!(agreed_outcome(failed(), failed(), &h), Some(false));
        assert_eq!(agreed_outcome(failed(), Err("timeout".into()), &h), None, "one node saying failed is not enough");
        assert_eq!(agreed_outcome(ok(), failed(), &h), None, "a disagreement decides nothing");
        assert_eq!(agreed_outcome(ok(), final_tx(&[8u8; 32], json!({"SuccessValue": ""})), &h), None, "another transaction");
        let mut pending = ok().unwrap();
        pending["final_execution_status"] = json!("EXECUTED_OPTIMISTIC");
        assert_eq!(agreed_outcome(ok(), Ok(pending), &h), None, "not final");
    }

    #[test]
    fn outputs_are_written_as_the_contract_reads_them() {
        assert_eq!(outputs_json(&[(1, 2)]), json!([{"tier": 1, "count": 2}]));
    }
}
