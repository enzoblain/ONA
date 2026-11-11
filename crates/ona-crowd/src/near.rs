//! Plays a timeline on a local NEAR node or on testnet. **Never run yet.** Mainnet is refused.
//!
//! - Fake users' implicit accounts are created by transfers from a funder account.
//! - A deposit is a real `deposit` on the ONA mint, with blinded tokens. Their secrets are written to
//!   a private file before the call, so the tokens can be finished or refunded later.
//! - The `ona-pool` contract does not exist yet, so the agent account stands in for it and uses its
//!   own funds: placement calls `deposit_and_stake` on a staking pool, withdrawal calls `unstake`
//!   (funds stay locked for some epochs and are not withdrawn here), and exit payments are transfers.
//! - Lending vaults are refused: no adapter is written for them.
//! - The node's chain id is read with `status` before anything is sent: mainnet is refused even
//!   behind a misleading name or address.
//!
//! **The crowd is recognizable on chain.** Every fake account is created by a transfer from the same
//! funder account, so anyone can list them and set them apart from real users. A real crowd would
//! need independent funding, which this does not attempt.
//!
//! Each denomination must match a tier of the deployed mint exactly. The mint deployed by `ona-deploy`
//! doubles its tiers, so it cannot hold 1, 10 and 100 at once: such a configuration is refused.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use ona_near::{Action, Client};
use ona_token::PendingToken;
use rand::rngs::OsRng;
use serde_json::json;

use crate::chain::Chain;
use crate::{create_private, FakeUser, Vault, VaultKind};

const MILLI_NEAR: u128 = 1_000_000_000_000_000_000_000;
/// Storage and issuing fee the mint takes per token (`ona-mint`: 1 + 2 milliNEAR), plus a margin.
/// The mint returns what is attached beyond its price.
const MINT_COST_PER_TOKEN: u128 = 10 * MILLI_NEAR;
/// Gas set aside for each transaction a funded account sends.
const GAS_PER_TRANSACTION: u128 = 50 * MILLI_NEAR;
const MAX_MINT_TIERS: u8 = 8;

pub struct NearSettings {
    pub rpc_url: String,
    pub network: String,
    pub mint: String,
    pub funder_account: String,
    pub agent_account: String,
    /// Value of one unit of the asset, in yoctoNEAR.
    pub unit_yocto: u128,
}

pub struct NearChain {
    settings: NearSettings,
    funder: Client,
    agent: Client,
    tiers: BTreeMap<u64, u8>,
    dst: Vec<u8>,
    tokens: File,
}

/// Every check that needs no network: refuses mainnet and lending vaults before anything is sent.
pub fn check_settings(settings: &NearSettings, vaults: &[Vault]) -> Result<()> {
    ona_deploy::check_network(&settings.network, &settings.rpc_url)?;
    if let Some(v) = vaults.iter().find(|v| v.kind == VaultKind::Lending) {
        bail!("lending vault {} is not supported on NEAR yet", v.contract);
    }
    if settings.unit_yocto == 0 {
        bail!("the unit value must be positive");
    }
    Ok(())
}

/// Checks the chain id the node reports with `status`. Mainnet is refused whatever the configured
/// name, and a node configured as testnet must report testnet.
pub fn check_chain_id(network: &str, chain_id: &str) -> Result<()> {
    if chain_id.is_empty() || chain_id.to_lowercase().contains("mainnet") {
        bail!("the node reports chain {chain_id:?}, refused");
    }
    if network == "testnet" && chain_id != "testnet" {
        bail!("configured for testnet but the node reports chain {chain_id:?}");
    }
    Ok(())
}

impl NearChain {
    pub fn connect(
        settings: NearSettings,
        funder_key: SigningKey,
        agent_key: SigningKey,
        denominations: &[u64],
        vaults: &[Vault],
        tokens_file: &Path,
    ) -> Result<Self> {
        check_settings(&settings, vaults)?;
        let funder = Client::new(&settings.rpc_url, funder_key);
        let agent = Client::new(&settings.rpc_url, agent_key);
        let status = funder.post("status", json!([]))?;
        check_chain_id(&settings.network, status["chain_id"].as_str().unwrap_or_default())?;

        let mut values: BTreeMap<u128, u8> = BTreeMap::new();
        for id in 0..MAX_MINT_TIERS {
            // A missing tier makes the view fail: the list of tiers ends there.
            let Ok(view) = funder.view_final(&settings.mint, "get_denom", json!({"denom_id": id})) else {
                break;
            };
            let value: u128 = view["value"].as_str().and_then(|v| v.parse().ok()).ok_or_else(|| anyhow!("tier {id} has no value"))?;
            values.insert(value, id);
        }
        let mut tiers = BTreeMap::new();
        for &d in denominations {
            let value = u128::from(d).checked_mul(settings.unit_yocto).ok_or_else(|| anyhow!("denomination too large"))?;
            let id = values.get(&value).ok_or_else(|| anyhow!("the mint has no tier worth {d} units"))?;
            tiers.insert(d, *id);
        }
        let dst = ona_token::token_dst(&settings.network, &settings.mint).map_err(|e| anyhow!("{e:?}"))?;
        let tokens = create_private(tokens_file)?;
        Ok(Self { settings, funder, agent, tiers, dst, tokens })
    }

    fn yocto(&self, units: u64) -> u128 {
        u128::from(units) * self.settings.unit_yocto
    }

    fn require(outcome: ona_near::Outcome, what: &str) -> Result<()> {
        match outcome.failure {
            Some(failure) => bail!("{what} failed: {failure}"),
            None => Ok(()),
        }
    }
}

impl Chain for NearChain {
    fn fund(&mut self, account: &str, units: u64, transactions: u64, notes: u64) -> Result<()> {
        let amount =
            self.yocto(units) + u128::from(transactions) * GAS_PER_TRANSACTION + u128::from(notes) * MINT_COST_PER_TOKEN;
        let outcome = self.funder.send(&self.settings.funder_account, account, vec![Action::Transfer(amount)])?;
        Self::require(outcome, "funding")
    }

    fn deposit(&mut self, user: &FakeUser, denomination: u64, count: u32) -> Result<()> {
        let tier = *self.tiers.get(&denomination).ok_or_else(|| anyhow!("no tier for {denomination}"))?;
        let tokens: Vec<PendingToken> = (0..count)
            .map(|_| PendingToken::new(&mut OsRng, tier, &self.dst))
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow!("{e:?}"))?;
        for t in &tokens {
            writeln!(self.tokens, "{}", B64.encode(t.to_secret_bytes())).context("cannot record token secrets")?;
        }
        self.tokens.sync_all().context("cannot record token secrets")?;
        let blinded: Vec<String> = tokens.iter().map(|t| B64.encode(t.blinded)).collect();
        let attached = u128::from(count) * (self.yocto(denomination) + MINT_COST_PER_TOKEN);
        let client = Client::new(&self.settings.rpc_url, user.key.clone());
        let args = json!({"denom_id": tier, "blinded": blinded});
        Self::require(client.call(&user.account(), &self.settings.mint, "deposit", args, attached)?, "deposit")
    }

    fn place(&mut self, vault: &Vault, denomination: u64, count: u32) -> Result<()> {
        if vault.kind != VaultKind::Staking {
            bail!("only staking vaults are supported");
        }
        let amount = self.yocto(denomination * u64::from(count));
        let outcome = self.agent.call(&self.settings.agent_account, &vault.contract, "deposit_and_stake", json!({}), amount)?;
        Self::require(outcome, "placement")
    }

    fn withdraw(&mut self, vault: &Vault, denomination: u64, count: u32) -> Result<()> {
        if vault.kind != VaultKind::Staking {
            bail!("only staking vaults are supported");
        }
        let amount = self.yocto(denomination * u64::from(count));
        let args = json!({"amount": amount.to_string()});
        let outcome = self.agent.call(&self.settings.agent_account, &vault.contract, "unstake", args, 0)?;
        Self::require(outcome, "withdrawal")
    }

    fn accrue(&mut self, vault: &Vault, _amount: u64) -> Result<()> {
        bail!("simulated yield cannot be played on a chain (vault {})", vault.contract)
    }

    fn pay(&mut self, to: &str, denomination: u64) -> Result<()> {
        let amount = self.yocto(denomination);
        let outcome = self.agent.send(&self.settings.agent_account, to, vec![Action::Transfer(amount)])?;
        Self::require(outcome, "exit payment")
    }
}
