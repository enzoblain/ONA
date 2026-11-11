//! Plays a timeline on a local NEAR node or on testnet. **Never run yet.** Mainnet is refused.
//!
//! - Fake users' implicit accounts are created by transfers from a funder account.
//! - A deposit is a real `deposit` on the ONA mint, with blinded tokens. Their secrets are written to
//!   a private file before the call, so the tokens can be finished or refunded later.
//! - The `ona-pool` contract is not used yet, so the agent account stands in for it and uses its
//!   own funds: placement calls `deposit_and_stake` on a staking pool, withdrawal calls `unstake`
//!   (funds stay locked for some epochs and are not withdrawn here), and exit payments are transfers.
//! - Lending vaults are refused: no adapter is written for them.
//! - The node's chain id is read with `status` before anything is sent (`ona_near::check_network`):
//!   mainnet is refused even behind a misleading name or address.
//! - Everything the run will spend is computed before the first transaction ([`planned_spend`]), and
//!   the run is refused above a cap the operator sets.
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
use ona_near::{check_account_id, check_network, Action, Client};
use ona_token::PendingToken;
use rand::rngs::OsRng;
use serde_json::json;

use crate::chain::{funding_plan, Chain};
use crate::{create_private, EventKind, FakeUser, Simulation, Vault, VaultKind};

const MILLI_NEAR: u128 = 1_000_000_000_000_000_000_000;
/// Storage and issuing fee the mint takes per token (`ona-mint`: 1 + 2 milliNEAR), plus a margin.
/// The mint returns what is attached beyond its price.
const MINT_COST_PER_TOKEN: u128 = 10 * MILLI_NEAR;
/// Gas set aside for each transaction a funded account sends.
const GAS_PER_TRANSACTION: u128 = 50 * MILLI_NEAR;
const MAX_MINT_TIERS: u8 = 8;

pub struct NearSettings {
    pub rpc_url: String,
    /// The network name written into the tokens (`ONA_NETWORK`).
    pub network: String,
    /// The chain id the node must report (`ONA_CHAIN_ID`).
    pub chain_id: String,
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

/// Every check that needs no network: refuses mainnet names, a plain http address, malformed accounts
/// and lending vaults before anything is sent.
pub fn check_settings(settings: &NearSettings, vaults: &[Vault]) -> Result<()> {
    ona_deploy::check_names(&settings.network, &settings.chain_id, &settings.rpc_url)?;
    for account in [&settings.mint, &settings.funder_account, &settings.agent_account] {
        check_account_id(account)?;
    }
    if let Some(v) = vaults.iter().find(|v| v.kind == VaultKind::Lending) {
        bail!("lending vault {} is not supported on NEAR yet", v.contract);
    }
    if settings.unit_yocto == 0 {
        bail!("the unit value must be positive");
    }
    Ok(())
}

/// yoctoNEAR sent to an account for `units` of the asset, its own `transactions` and the `notes` it mints.
pub fn funding_amount(unit_yocto: u128, units: u64, transactions: u64, notes: u64) -> Result<u128> {
    let too_large = || anyhow!("amount too large");
    let value = u128::from(units).checked_mul(unit_yocto).ok_or_else(too_large)?;
    let gas = u128::from(transactions).checked_mul(GAS_PER_TRANSACTION).ok_or_else(too_large)?;
    let fees = u128::from(notes).checked_mul(MINT_COST_PER_TOKEN).ok_or_else(too_large)?;
    value.checked_add(gas).and_then(|v| v.checked_add(fees)).ok_or_else(too_large)
}

/// What the agent account must hold: it stands in for the pool, so it pays every placement and every
/// exit from its own funds (`unstake` gives nothing back for several epochs), plus its gas.
pub fn agent_needs(sim: &Simulation) -> Result<(u64, u64)> {
    let mut spent: u64 = 0;
    for e in sim.timeline.iter().filter(|e| matches!(e.kind, EventKind::Placement | EventKind::ExitPayment)) {
        spent = spent.checked_add(e.amount).ok_or_else(|| anyhow!("amount too large"))?;
    }
    let transactions = sim.timeline.iter().filter(|e| e.kind != EventKind::Deposit).count() as u64;
    Ok((spent, transactions))
}

/// Everything the funder account will send during the run, in yoctoNEAR: the agent's funding and every
/// fake user's.
pub fn planned_spend(sim: &Simulation, unit_yocto: u128) -> Result<u128> {
    let (spent, transactions) = agent_needs(sim)?;
    let mut total = funding_amount(unit_yocto, spent, transactions, 0)?;
    for (_, units, transactions, notes) in funding_plan(sim) {
        total = total
            .checked_add(funding_amount(unit_yocto, units, transactions, notes)?)
            .ok_or_else(|| anyhow!("amount too large"))?;
    }
    Ok(total)
}

/// Refuses a run that would send more than `cap` yoctoNEAR.
pub fn check_spend(total: u128, cap: u128) -> Result<()> {
    if total > cap {
        bail!(
            "the run would send {} milliNEAR, above the cap of {} milliNEAR (ONA_CROWD_MAX_SPEND_NEAR)",
            total / MILLI_NEAR,
            cap / MILLI_NEAR
        );
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
        let funder = Client::connect(&settings.rpc_url, funder_key)?;
        let agent = Client::connect(&settings.rpc_url, agent_key)?;
        check_network(&funder, &settings.chain_id)?;

        let mut values: BTreeMap<u128, u8> = BTreeMap::new();
        for id in 0..MAX_MINT_TIERS {
            let view = match funder.view_final(&settings.mint, "get_denom", json!({"denom_id": id})) {
                Ok(view) => view,
                // The mint panics with this message past its last tier: the list ends there. Any other
                // error is a real failure, not the end of the list.
                Err(e) if e.to_string().contains("unknown denomination") => break,
                Err(e) => return Err(e.context(format!("cannot read tier {id} of the mint"))),
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

    fn yocto(&self, units: u64) -> Result<u128> {
        u128::from(units).checked_mul(self.settings.unit_yocto).ok_or_else(|| anyhow!("amount too large"))
    }

    /// Every operation of the run (transfers, `deposit` on the mint, `deposit_and_stake` and `unstake` on a
    /// staking pool) must have every receipt succeed: a failed one means the timeline did not happen as played.
    fn require(outcome: ona_near::Outcome, what: &str) -> Result<()> {
        outcome.require_all_receipts_ok().with_context(|| format!("{what} failed"))
    }
}

impl Chain for NearChain {
    fn fund(&mut self, account: &str, units: u64, transactions: u64, notes: u64) -> Result<()> {
        let amount = funding_amount(self.settings.unit_yocto, units, transactions, notes)?;
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
        let per_token = self.yocto(denomination)?.checked_add(MINT_COST_PER_TOKEN).ok_or_else(|| anyhow!("amount too large"))?;
        let attached = u128::from(count).checked_mul(per_token).ok_or_else(|| anyhow!("amount too large"))?;
        let client = Client::connect(&self.settings.rpc_url, user.key.clone())?;
        let args = json!({"denom_id": tier, "blinded": blinded});
        Self::require(client.call(&user.account(), &self.settings.mint, "deposit", args, attached)?, "deposit")
    }

    fn place(&mut self, vault: &Vault, denomination: u64, count: u32) -> Result<()> {
        if vault.kind != VaultKind::Staking {
            bail!("only staking vaults are supported");
        }
        let units = denomination.checked_mul(u64::from(count)).ok_or_else(|| anyhow!("amount too large"))?;
        let amount = self.yocto(units)?;
        let outcome = self.agent.call(&self.settings.agent_account, &vault.contract, "deposit_and_stake", json!({}), amount)?;
        Self::require(outcome, "placement")
    }

    fn withdraw(&mut self, vault: &Vault, denomination: u64, count: u32) -> Result<()> {
        if vault.kind != VaultKind::Staking {
            bail!("only staking vaults are supported");
        }
        let units = denomination.checked_mul(u64::from(count)).ok_or_else(|| anyhow!("amount too large"))?;
        let args = json!({"amount": self.yocto(units)?.to_string()});
        let outcome = self.agent.call(&self.settings.agent_account, &vault.contract, "unstake", args, 0)?;
        Self::require(outcome, "withdrawal")
    }

    fn accrue(&mut self, vault: &Vault, _amount: u64) -> Result<()> {
        bail!("simulated yield cannot be played on a chain (vault {})", vault.contract)
    }

    fn pay(&mut self, to: &str, denomination: u64) -> Result<()> {
        let amount = self.yocto(denomination)?;
        let outcome = self.agent.send(&self.settings.agent_account, to, vec![Action::Transfer(amount)])?;
        Self::require(outcome, "exit payment")
    }
}
