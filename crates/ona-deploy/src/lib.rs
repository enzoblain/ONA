//! Builds the transactions that deploy the ONA contracts.
//!
//! Each contract is created, funded, deployed and initialized in one transaction, with no access
//! key. Nobody can initialize it first, and nobody holds a key to it afterwards, so a mistake in the
//! plan cannot be corrected: every role is checked before anything is sent.
//!
//! Mainnet is refused twice: from the configured names here, and from the chain id the node reports
//! (`ona_near::check_network`), which the binary asks before sending anything.
#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_near::{check_account_id, check_chain_id, check_rpc_url, Action, TGAS};
use ona_token::G2_LEN;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const INIT_TGAS: u64 = 300;
pub const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MAX_TIERS: usize = 8;
/// `REDEEM_FEE + MIN_PAYOUT` in the contract: a smaller tier could never be redeemed.
const MIN_TIER_VALUE: u128 = 20_000_000_000_000_000_000_000;

pub struct MintPlan {
    pub network: String,
    pub signer: String,
    pub relay: String,
    pub guardian: String,
    pub denom_keys: Vec<[u8; G2_LEN]>,
    /// Value of tier 0. Each following tier doubles.
    pub base_value: u128,
    pub circulation_cap: u64,
    pub hourly_redeem_cap: u64,
    pub funding: u128,
}

/// Checks the configuration before any request: names, chain id and RPC address. `network` is the name
/// written into the contracts, `chain_id` the one the node must report.
pub fn check_names(network: &str, chain_id: &str, rpc_url: &str) -> Result<()> {
    if network.is_empty() || network.to_ascii_lowercase().contains("mainnet") {
        bail!("only testnet and local networks are allowed (network {network:?})");
    }
    check_chain_id(chain_id, chain_id)?;
    check_rpc_url(rpc_url)?;
    if rpc_url.to_ascii_lowercase().contains("mainnet") {
        bail!("only testnet and local networks are allowed (RPC {rpc_url})");
    }
    Ok(())
}

/// The account that creates the contracts. On testnet it must be a `.testnet` account, and a `.near`
/// account (a mainnet name) is always refused.
pub fn check_parent(chain_id: &str, parent: &str) -> Result<()> {
    check_account_id(parent)?;
    if parent.ends_with(".near") || parent == "near" {
        bail!("{parent} is a mainnet account");
    }
    if chain_id == "testnet" && !parent.ends_with(".testnet") {
        bail!("on testnet the parent account must end with .testnet, not {parent}");
    }
    Ok(())
}

/// Every role must be a well-formed account, and no account may hold two roles.
pub fn check_roles(roles: &[(&str, &str)]) -> Result<()> {
    for (i, (role, account)) in roles.iter().enumerate() {
        check_account_id(account).map_err(|e| anyhow!("{role}: {e}"))?;
        if let Some((other, _)) = roles[..i].iter().find(|(_, a)| a == account) {
            bail!("{account} cannot be both {other} and {role}");
        }
    }
    Ok(())
}

/// `value * unit`, refused instead of wrapping.
pub fn amount(value: u128, unit: u128) -> Result<u128> {
    value.checked_mul(unit).ok_or_else(|| anyhow!("amount too large"))
}

/// The NEAR sent to a new contract account, in yoctoNEAR. Every contract needs some, so zero is refused.
pub fn funding(near: u128) -> Result<u128> {
    if near == 0 {
        bail!("the contract account needs funding");
    }
    amount(near, NEAR)
}

/// SHA-256 of a contract. NEAR records this as the account's `code_hash`, in base58 (not checked against
/// a node).
pub fn code_hash(code: &[u8]) -> [u8; 32] {
    Sha256::digest(code).into()
}

/// Compares the `code_hash` of a deployed account (`view_account`) with the contract that was sent.
pub fn check_deployed_code(account_view: &Value, code: &[u8]) -> Result<()> {
    let expected = bs58::encode(code_hash(code)).into_string();
    match account_view["code_hash"].as_str() {
        Some(found) if found == expected => Ok(()),
        found => bail!("the account runs code {found:?}, not the contract sent ({expected})"),
    }
}

impl MintPlan {
    fn tier_value(&self, tier: usize) -> Result<u128> {
        let factor = 1u128.checked_shl(tier as u32).ok_or_else(|| anyhow!("too many tiers"))?;
        amount(self.base_value, factor).map_err(|_| anyhow!("tier {tier} is worth more than a u128 holds"))
    }

    pub fn check(&self) -> Result<()> {
        if self.denom_keys.is_empty() || self.denom_keys.len() > MAX_TIERS {
            bail!("between 1 and {MAX_TIERS} keys are required");
        }
        for (i, key) in self.denom_keys.iter().enumerate() {
            if self.denom_keys[..i].contains(key) {
                bail!("each tier needs its own key");
            }
            self.tier_value(i)?;
        }
        if self.base_value < MIN_TIER_VALUE {
            bail!("the lowest tier is too small to be redeemed");
        }
        if self.circulation_cap == 0 || self.hourly_redeem_cap == 0 {
            bail!("caps must be positive");
        }
        if self.funding == 0 {
            bail!("the contract account needs funding");
        }
        check_roles(&[("signer", &self.signer), ("relay", &self.relay), ("guardian", &self.guardian)])
    }

    pub fn init_args(&self) -> Result<Value> {
        self.check()?;
        let denoms = self
            .denom_keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                Ok(json!({
                    "value": self.tier_value(i)?.to_string(),
                    "pk_g2": B64.encode(key),
                    "circulation_cap": self.circulation_cap,
                    "hourly_redeem_cap": self.hourly_redeem_cap,
                }))
            })
            .collect::<Result<Vec<Value>>>()?;
        Ok(json!({
            "denoms": denoms,
            "signer": self.signer,
            "relay": self.relay,
            "guardian": self.guardian,
            "network": self.network,
        }))
    }

    pub fn actions(&self, code: Vec<u8>) -> Result<Vec<Action>> {
        Ok(deploy_actions(self.funding, code, &self.init_args()?))
    }
}

pub fn registry_init_args(owners: [&str; 2], aggregator: &str) -> Result<Value> {
    if owners[0] == owners[1] || owners[0].is_empty() || owners[1].is_empty() {
        bail!("the registry needs two different owners");
    }
    if aggregator.is_empty() {
        bail!("the registry needs an aggregator");
    }
    check_roles(&[("first owner", owners[0]), ("second owner", owners[1]), ("aggregator", aggregator)])?;
    Ok(json!({"owners": owners, "aggregator": aggregator}))
}

/// A delay left out keeps the contract's default of 7 days.
/// The pool's cash tiers: `(value in yoctoNEAR, compressed G2 public key)`, from 1 to 8, each key used once.
pub struct PoolCash {
    pub tiers: Vec<(u128, [u8; G2_LEN])>,
    /// Most the cash exits may pay per hour, at least two of the largest notes.
    pub hourly_cap: u128,
    /// Yearly growth of exit limits in basis points; `None` keeps the contract's 20 %.
    pub max_rate_bps: Option<u16>,
    /// Live notes a tier must keep after an entry or exit, so one note never moves alone.
    pub min_live_notes: u64,
}

/// Reads the cash tiers file: a JSON list of `{"value": "<yoctoNEAR>", "pk_g2": "<base64, 96 bytes>"}`.
pub fn parse_cash_tiers(text: &str) -> Result<Vec<(u128, [u8; G2_LEN])>> {
    let list: Vec<Value> = serde_json::from_str(text).map_err(|_| anyhow!("cash tiers must be a JSON list"))?;
    list.iter()
        .map(|t| {
            let value =
                t["value"].as_str().and_then(|v| v.parse().ok()).ok_or_else(|| anyhow!("a cash tier needs a value"))?;
            let pk = t["pk_g2"]
                .as_str()
                .and_then(|k| B64.decode(k).ok())
                .and_then(|k| <[u8; G2_LEN]>::try_from(k).ok())
                .ok_or_else(|| anyhow!("a cash tier needs a 96-byte pk_g2 in base64"))?;
            Ok((value, pk))
        })
        .collect()
}

pub fn pool_init_args(
    guardian: &str,
    agent: &str,
    network: &str,
    escape_delay_secs: Option<u64>,
    admin_delay_secs: Option<u64>,
    cash: &PoolCash,
) -> Result<Value> {
    if guardian.is_empty() || agent.is_empty() || guardian == agent {
        bail!("the pool needs a guardian and a different agent");
    }
    if cash.tiers.is_empty() || cash.tiers.len() > MAX_TIERS {
        bail!("the pool needs between 1 and 8 cash tiers");
    }
    let keys: std::collections::BTreeSet<_> = cash.tiers.iter().map(|(_, k)| k.to_vec()).collect();
    if keys.len() != cash.tiers.len() {
        bail!("each cash tier needs its own key");
    }
    let largest = cash.tiers.iter().map(|(v, _)| *v).max().unwrap_or(0);
    if cash.hourly_cap < largest.saturating_mul(2) {
        bail!("the cash hourly cap must cover two of the largest notes");
    }
    if cash.max_rate_bps.is_some_and(|r| r > 10_000) {
        bail!("the exit limit rate is at most 10000 basis points");
    }
    if cash.min_live_notes == 0 {
        bail!("the minimum of live notes per tier must be at least 1");
    }
    let tiers: Vec<Value> =
        cash.tiers.iter().map(|(v, k)| json!({"value": v.to_string(), "pk_g2": B64.encode(k)})).collect();
    let mut args = json!({
        "guardian": guardian, "agent": agent, "network": network,
        "cash_tiers": tiers, "cash_hourly_cap": cash.hourly_cap.to_string(), "min_live_notes": cash.min_live_notes,
    });
    if let Some(rate) = cash.max_rate_bps {
        args["max_rate_bps"] = json!(rate);
    }
    if let Some(secs) = escape_delay_secs {
        args["escape_delay_secs"] = json!(secs);
    }
    if let Some(secs) = admin_delay_secs {
        args["admin_delay_secs"] = json!(secs);
    }
    Ok(args)
}

/// Create, fund, deploy, initialize. There is deliberately no key action.
pub fn deploy_actions(funding: u128, code: Vec<u8>, init_args: &Value) -> Vec<Action> {
    vec![
        Action::Create,
        Action::Transfer(funding),
        Action::Deploy(code),
        Action::Call {
            method: "new".into(),
            args: init_args.to_string().into_bytes(),
            gas: INIT_TGAS * TGAS,
            deposit: 0,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const UNIT: u128 = 100_000_000_000_000_000_000_000;

    fn plan() -> MintPlan {
        MintPlan {
            network: "testnet".into(),
            signer: "s.testnet".into(),
            relay: "r.testnet".into(),
            guardian: "g.testnet".into(),
            denom_keys: vec![[1u8; G2_LEN], [2u8; G2_LEN], [3u8; G2_LEN]],
            base_value: UNIT,
            circulation_cap: 100,
            hourly_redeem_cap: 10,
            funding: 5,
        }
    }

    #[test]
    fn mainnet_names_are_refused() {
        assert!(check_names("mainnet", "testnet", "https://rpc.testnet.near.org").is_err());
        assert!(check_names("Mainnet", "testnet", "https://rpc.testnet.near.org").is_err());
        assert!(check_names("testnet", "mainnet", "https://rpc.testnet.near.org").is_err());
        assert!(check_names("testnet", "testnet", "https://rpc.mainnet.near.org").is_err());
        assert!(check_names("testnet", "testnet", "https://RPC.MAINNET.example").is_err());
        assert!(check_names("", "localnet", "http://127.0.0.1:3030").is_err());
        assert!(check_names("testnet", "", "https://rpc.testnet.near.org").is_err());
        assert!(check_names("testnet", "testnet", "https://rpc.testnet.near.org").is_ok());
        assert!(check_names("sandbox", "localnet", "http://127.0.0.1:3030").is_ok());
    }

    // A plain http address outside this machine is refused.
    #[test]
    fn the_rpc_address_must_be_https() {
        assert!(check_names("testnet", "testnet", "http://rpc.testnet.near.org").is_err());
    }

    // A mainnet parent account is refused even when every name says testnet.
    #[test]
    fn the_parent_account_must_match_the_network() {
        assert!(check_parent("testnet", "ona.testnet").is_ok());
        assert!(check_parent("localnet", "test.near.sandbox").is_ok());
        assert!(check_parent("testnet", "ona.near").is_err());
        assert!(check_parent("localnet", "ona.near").is_err());
        assert!(check_parent("testnet", "ona.tesnet").is_err());
        assert!(check_parent("testnet", "Ona.testnet").is_err());
    }

    #[test]
    fn tiers_double_and_carry_their_keys() {
        let args = plan().init_args().unwrap();
        assert_eq!(args["denoms"][0]["value"], UNIT.to_string());
        assert_eq!(args["denoms"][2]["value"], (4 * UNIT).to_string());
        assert_eq!(args["denoms"][1]["pk_g2"], B64.encode([2u8; G2_LEN]));
        assert_eq!(args["network"], "testnet");
        assert_eq!(args["signer"], "s.testnet");
    }

    #[test]
    fn deployment_grants_no_key() {
        let actions = plan().actions(vec![1, 2, 3]).unwrap();
        assert_eq!(actions.len(), 4);
        assert!(!actions.iter().any(|a| matches!(a, Action::AddFullKey(_))));
        assert!(matches!(actions[0], Action::Create));
        assert!(matches!(actions[1], Action::Transfer(5)));
        assert!(matches!(actions[2], Action::Deploy(_)));
        assert!(matches!(&actions[3], Action::Call { method, .. } if method == "new"));
    }

    #[test]
    fn bad_plans_are_refused() {
        let mutations: Vec<fn(&mut MintPlan)> = vec![
            |p| p.denom_keys.clear(),
            |p| p.denom_keys = vec![[1u8; G2_LEN]; 2],
            |p| p.denom_keys = (0..9).map(|i| [i as u8; G2_LEN]).collect(),
            |p| p.base_value = MIN_TIER_VALUE - 1,
            |p| p.circulation_cap = 0,
            |p| p.hourly_redeem_cap = 0,
            |p| p.relay.clear(),
            |p| p.funding = 0,
        ];
        for mutate in mutations {
            let mut p = plan();
            mutate(&mut p);
            assert!(p.actions(vec![]).is_err());
        }
    }

    // Roles that cannot be changed later must be distinct and well formed.
    #[test]
    fn roles_must_be_distinct_and_well_formed() {
        let mutations: Vec<fn(&mut MintPlan)> = vec![
            |p| p.guardian = p.signer.clone(),
            |p| p.relay = p.guardian.clone(),
            |p| p.signer = p.relay.clone(),
            |p| p.guardian = "Guardian.testnet".into(),
            |p| p.guardian = "guardian..testnet".into(),
        ];
        for mutate in mutations {
            let mut p = plan();
            mutate(&mut p);
            assert!(p.check().is_err());
        }
        assert!(registry_init_args(["a.testnet", "b.testnet"], "a.testnet").is_err());
        assert!(registry_init_args(["a.testnet", "B.testnet"], "x.testnet").is_err());
    }

    // A tier whose value does not fit is refused instead of wrapping.
    #[test]
    fn amounts_never_wrap() {
        let mut p = plan();
        p.base_value = u128::MAX / 2;
        assert!(p.check().is_err(), "tier 2 would overflow");
        p.denom_keys.truncate(2);
        assert!(p.check().is_ok());
        assert!(amount(u128::MAX, 2).is_err());
        assert_eq!(amount(5, 3).unwrap(), 15);
    }

    #[test]
    fn every_contract_needs_funding() {
        assert!(funding(0).is_err());
        assert_eq!(funding(5).unwrap(), 5 * NEAR);
        assert!(funding(u128::MAX).is_err());
    }

    #[test]
    fn the_deployed_code_hash_is_compared() {
        let code = b"\0asm contract".to_vec();
        let view = json!({"code_hash": bs58::encode(code_hash(&code)).into_string()});
        assert!(check_deployed_code(&view, &code).is_ok());
        assert!(check_deployed_code(&view, b"other").is_err());
        assert!(check_deployed_code(&json!({}), &code).is_err());
        assert_eq!(code_hash(b"abc")[..4], [0xba, 0x78, 0x16, 0xbf]);
    }

    #[test]
    fn the_registry_needs_two_owners() {
        assert!(registry_init_args(["a1", "a1"], "x1").is_err());
        assert!(registry_init_args(["a1", ""], "x1").is_err());
        assert!(registry_init_args(["a1", "b1"], "").is_err());
        assert_eq!(registry_init_args(["a1", "b1"], "x1").unwrap()["owners"], json!(["a1", "b1"]));
    }

    fn cash() -> PoolCash {
        PoolCash { tiers: vec![(10, [1; 96]), (100, [2; 96])], hourly_cap: 200, max_rate_bps: None, min_live_notes: 5 }
    }

    #[test]
    fn the_pool_needs_a_guardian_and_a_different_agent() {
        assert!(pool_init_args("g", "g", "testnet", None, None, &cash()).is_err());
        assert!(pool_init_args("", "a", "testnet", None, None, &cash()).is_err());
        let args = pool_init_args("g", "a", "testnet", None, None, &cash()).unwrap();
        assert_eq!((args["guardian"].clone(), args["agent"].clone()), (json!("g"), json!("a")));
        assert_eq!(args["cash_hourly_cap"], json!("200"));
        assert_eq!(args["cash_tiers"][1]["value"], json!("100"));
        assert_eq!(args["min_live_notes"], json!(5));
        assert!(args.get("max_rate_bps").is_none());
        let args = pool_init_args("g", "a", "testnet", Some(600), Some(120), &cash()).unwrap();
        assert_eq!((args["escape_delay_secs"].clone(), args["admin_delay_secs"].clone()), (json!(600), json!(120)));
    }

    #[test]
    fn the_pool_cash_tiers_are_checked_before_deploying() {
        let mut c = cash();
        c.hourly_cap = 199;
        assert!(pool_init_args("g", "a", "testnet", None, None, &c).is_err(), "cap below two large notes");
        let mut c = cash();
        c.tiers[1].1 = [1; 96];
        assert!(pool_init_args("g", "a", "testnet", None, None, &c).is_err(), "a key used twice");
        let mut c = cash();
        c.max_rate_bps = Some(10_001);
        assert!(pool_init_args("g", "a", "testnet", None, None, &c).is_err());
        let mut c = cash();
        c.min_live_notes = 0;
        assert!(pool_init_args("g", "a", "testnet", None, None, &c).is_err());
        let c = PoolCash { tiers: vec![], hourly_cap: 1, max_rate_bps: None, min_live_notes: 1 };
        assert!(pool_init_args("g", "a", "testnet", None, None, &c).is_err());
        let text = format!("[{{\"value\":\"7\",\"pk_g2\":\"{}\"}}]", "AQ".repeat(64));
        assert_eq!(parse_cash_tiers(&text).unwrap()[0].0, 7);
        assert!(parse_cash_tiers("[{\"value\":\"7\",\"pk_g2\":\"AQ==\"}]").is_err());
        assert!(parse_cash_tiers("{}").is_err());
    }
}
