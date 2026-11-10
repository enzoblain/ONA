//! `ona-deploy mint` and `ona-deploy registry` deploy the contracts on testnet or a local node.
//! Configured by the environment variables in `docs/INSTALL.md`.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ona_deploy::{check_network, deploy_actions, registry_init_args, MintPlan};
use ona_near::{load_account_key, Action, Client};
use ona_signer::KeyStore;
use serde_json::json;

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;
const MILLI: u128 = NEAR / 1000;

fn env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| anyhow!("{name} is not set"))
}

fn env_number<T: std::str::FromStr>(name: &str, default: T) -> Result<T> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| anyhow!("{name} is not a number")),
        Err(_) => Ok(default),
    }
}

struct Deployer {
    client: Client,
    parent: String,
    network: String,
}

impl Deployer {
    fn from_env() -> Result<Self> {
        let rpc = env("ONA_RPC_URL")?;
        let network = env("ONA_NETWORK")?;
        check_network(&network, &rpc)?;
        let key = load_account_key(&PathBuf::from(env("ONA_PARENT_KEY_FILE")?))?;
        Ok(Self { client: Client::new(&rpc, key), parent: env("ONA_PARENT_ACCOUNT")?, network })
    }

    fn send(&self, account: &str, actions: Vec<Action>) -> Result<()> {
        if self.client.balance(account)?.is_some() {
            bail!("{account} already exists");
        }
        let outcome = self.client.send(&self.parent, account, actions)?;
        if let Some(failure) = outcome.failure {
            bail!("deployment failed: {failure}");
        }
        let keys = self.client.query(json!({
            "request_type":"view_access_key_list","finality":"final","account_id":account,
        }))?;
        let count = keys["keys"].as_array().map_or(usize::MAX, Vec::len);
        if count != 0 {
            bail!("{account} was deployed but holds {count} access keys");
        }
        println!("deployed {account}, no access key, {:.1} Tgas", outcome.tgas);
        Ok(())
    }
}

fn read_wasm(variable: &str, default: &str) -> Result<Vec<u8>> {
    let path = std::env::var(variable).unwrap_or_else(|_| default.to_string());
    std::fs::read(Path::new(&path)).with_context(|| format!("cannot read {path}, build the contract first"))
}

fn deploy_mint() -> Result<()> {
    let deployer = Deployer::from_env()?;
    let keys = KeyStore::load(&PathBuf::from(env("ONA_SIGNER_KEYS_FILE")?)).map_err(|e| anyhow!(e))?;
    let plan = MintPlan {
        network: deployer.network.clone(),
        signer: env("ONA_SIGNER_ACCOUNT")?,
        relay: env("ONA_RELAY_ACCOUNT")?,
        guardian: env("ONA_GUARDIAN_ACCOUNT")?,
        denom_keys: keys.public_keys(),
        base_value: env_number::<u128>("ONA_BASE_VALUE_MILLI_NEAR", 100)? * MILLI,
        circulation_cap: env_number("ONA_CIRCULATION_CAP", 1000)?,
        hourly_redeem_cap: env_number("ONA_HOURLY_REDEEM_CAP", 100)?,
        funding: env_number::<u128>("ONA_FUNDING_NEAR", 5)? * NEAR,
    };
    let code = read_wasm("ONA_MINT_WASM", "target/wasm32-unknown-unknown/contract/ona_mint.wasm")?;
    let account = format!("mint.{}", deployer.parent);
    deployer.send(&account, plan.actions(code)?)
}

fn deploy_registry() -> Result<()> {
    let deployer = Deployer::from_env()?;
    let (first, second) = (env("ONA_REGISTRY_OWNER_1")?, env("ONA_REGISTRY_OWNER_2")?);
    let args = registry_init_args([&first, &second], &env("ONA_AGGREGATOR_ACCOUNT")?)?;
    let funding = env_number::<u128>("ONA_FUNDING_NEAR", 5)? * NEAR;
    let code = read_wasm("ONA_REGISTRY_WASM", "target/wasm32-unknown-unknown/contract/ona_registry.wasm")?;
    let account = format!("registry.{}", deployer.parent);
    deployer.send(&account, deploy_actions(funding, code, &args))
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["mint"] => deploy_mint(),
        ["registry"] => deploy_registry(),
        _ => Err(anyhow!("usage: ona-deploy mint | ona-deploy registry")),
    };
    if let Err(e) = result {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
