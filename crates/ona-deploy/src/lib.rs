//! Builds the transactions that deploy the ONA contracts.
//!
//! Each contract is created, funded, deployed and initialized in one transaction, with no access
//! key. Nobody can initialize it first, and nobody holds a key to it afterwards.
//! Mainnet is refused here on purpose.

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ona_near::{Action, TGAS};
use ona_token::G2_LEN;
use serde_json::{json, Value};

const INIT_TGAS: u64 = 300;
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

pub fn check_network(network: &str, rpc_url: &str) -> Result<()> {
    if network == "mainnet" || network.is_empty() || rpc_url.to_lowercase().contains("mainnet") {
        bail!("only testnet and local networks are allowed");
    }
    Ok(())
}

impl MintPlan {
    pub fn check(&self) -> Result<()> {
        if self.denom_keys.is_empty() || self.denom_keys.len() > MAX_TIERS {
            bail!("between 1 and {MAX_TIERS} keys are required");
        }
        for (i, key) in self.denom_keys.iter().enumerate() {
            if self.denom_keys[..i].contains(key) {
                bail!("each tier needs its own key");
            }
        }
        if self.base_value < MIN_TIER_VALUE {
            bail!("the lowest tier is too small to be redeemed");
        }
        if self.circulation_cap == 0 || self.hourly_redeem_cap == 0 {
            bail!("caps must be positive");
        }
        for account in [&self.signer, &self.relay, &self.guardian] {
            if account.is_empty() {
                bail!("signer, relay and guardian accounts are required");
            }
        }
        Ok(())
    }

    pub fn init_args(&self) -> Value {
        let denoms: Vec<Value> = self
            .denom_keys
            .iter()
            .enumerate()
            .map(|(i, key)| {
                json!({
                    "value": (self.base_value << i).to_string(),
                    "pk_g2": B64.encode(key),
                    "circulation_cap": self.circulation_cap,
                    "hourly_redeem_cap": self.hourly_redeem_cap,
                })
            })
            .collect();
        json!({
            "denoms": denoms,
            "signer": self.signer,
            "relay": self.relay,
            "guardian": self.guardian,
            "network": self.network,
        })
    }

    pub fn actions(&self, code: Vec<u8>) -> Result<Vec<Action>> {
        self.check()?;
        Ok(deploy_actions(self.funding, code, &self.init_args()))
    }
}

pub fn registry_init_args(owners: [&str; 2], aggregator: &str) -> Result<Value> {
    if owners[0] == owners[1] || owners[0].is_empty() || owners[1].is_empty() {
        bail!("the registry needs two different owners");
    }
    if aggregator.is_empty() {
        bail!("the registry needs an aggregator");
    }
    Ok(json!({"owners": owners, "aggregator": aggregator}))
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
    fn mainnet_is_refused() {
        assert!(check_network("mainnet", "https://rpc.testnet.near.org").is_err());
        assert!(check_network("testnet", "https://rpc.mainnet.near.org").is_err());
        assert!(check_network("testnet", "https://RPC.MAINNET.example").is_err());
        assert!(check_network("", "http://127.0.0.1:3030").is_err());
        assert!(check_network("testnet", "https://rpc.testnet.near.org").is_ok());
        assert!(check_network("sandbox", "http://127.0.0.1:3030").is_ok());
    }

    #[test]
    fn tiers_double_and_carry_their_keys() {
        let args = plan().init_args();
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
        ];
        for mutate in mutations {
            let mut p = plan();
            mutate(&mut p);
            assert!(p.actions(vec![]).is_err());
        }
    }

    #[test]
    fn the_registry_needs_two_owners() {
        assert!(registry_init_args(["a", "a"], "x").is_err());
        assert!(registry_init_args(["a", ""], "x").is_err());
        assert!(registry_init_args(["a", "b"], "").is_err());
        assert_eq!(registry_init_args(["a", "b"], "x").unwrap()["owners"], json!(["a", "b"]));
    }
}
