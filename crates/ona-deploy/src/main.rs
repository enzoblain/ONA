//! `ona-deploy mint`, `ona-deploy registry` and `ona-deploy pool` deploy the contracts on testnet or a local node.
//! Configured by the environment variables in `docs/INSTALL.md`.
#![forbid(unsafe_code)]

use std::io::BufRead;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ona_deploy::{
    amount, check_deployed_code, check_names, check_parent, check_roles, code_hash, deploy_actions, pool_init_args,
    registry_init_args, MintPlan,
};
use ona_near::{check_network, load_account_key, Action, Client};
use ona_signer::KeyStore;
use serde_json::json;

const MILLI: u128 = ona_deploy::NEAR / 1000;

fn env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| anyhow!("{name} is not set"))
}

/// A variable left out takes its default. A variable that is set but unreadable is an error, never the default.
fn env_number<T: std::str::FromStr>(name: &str, default: T) -> Result<T> {
    match std::env::var(name) {
        Ok(value) => value.parse().map_err(|_| anyhow!("{name} is not a number")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow!("{name} is not valid text")),
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
        let chain_id = std::env::var("ONA_CHAIN_ID").unwrap_or_else(|_| network.clone());
        let parent = env("ONA_PARENT_ACCOUNT")?;
        check_names(&network, &chain_id, &rpc)?;
        check_parent(&chain_id, &parent)?;
        let key = load_account_key(&PathBuf::from(env("ONA_PARENT_KEY_FILE")?))?;
        let client = Client::connect(&rpc, key)?;
        let reported = check_network(&client, &chain_id)?;
        println!("node at {rpc} reports chain {reported}");
        Ok(Self { client, parent, network })
    }

    /// Every account a role is given to must already exist: a contract without a key cannot be told later.
    fn require_accounts(&self, roles: &[(&str, &str)]) -> Result<()> {
        check_roles(roles)?;
        for (role, account) in roles {
            if self.client.account(account)?.is_none() {
                bail!("{role} account {account} does not exist");
            }
        }
        Ok(())
    }

    fn send(&self, account: &str, roles: &[(&str, &str)], funding: u128, code: Vec<u8>, actions: Vec<Action>) -> Result<()> {
        self.require_accounts(roles)?;
        if self.client.account(account)?.is_some() {
            bail!("{account} already exists");
        }
        let hash = code_hash(&code);
        println!("about to create {account}, without any access key, from {}:", self.parent);
        println!("  network written into the contract: {}", self.network);
        for (role, holder) in roles {
            println!("  {role}: {holder}");
        }
        println!("  funding: {funding} yoctoNEAR");
        println!("  contract: {} bytes, sha256 {} (base58 {})", code.len(), hex(&hash), bs58::encode(hash).into_string());
        println!("Nothing can be changed afterwards. Type the account name to deploy it:");
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer).context("cannot read the confirmation")?;
        if answer.trim() != account {
            bail!("not confirmed, nothing sent");
        }

        let outcome = self.client.send(&self.parent, account, actions)?;
        let tx = outcome.tx_hash.map(|h| bs58::encode(h).into_string()).unwrap_or_default();
        // Creation, funding, code and `new` run in one receipt: any failed receipt is a failed deployment.
        outcome.require_all_receipts_ok().with_context(|| format!("deployment failed (transaction {tx})"))?;
        let keys = self.client.query(json!({
            "request_type":"view_access_key_list","finality":"final","account_id":account,
        }))?;
        let count = keys["keys"].as_array().map_or(usize::MAX, Vec::len);
        if count != 0 {
            bail!("{account} was deployed but holds {count} access keys");
        }
        let view = self.client.account(account)?.ok_or_else(|| anyhow!("{account} does not exist after deployment"))?;
        check_deployed_code(&view, &code)?;
        println!("deployed {account} in transaction {tx}: no access key, code sha256 {}, {:.1} Tgas", hex(&hash), outcome.tgas);
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_wasm(variable: &str, default: &str) -> Result<Vec<u8>> {
    let path = std::env::var(variable).unwrap_or_else(|_| default.to_string());
    std::fs::read(Path::new(&path)).with_context(|| format!("cannot read {path}, build the contract first"))
}

fn funding() -> Result<u128> {
    ona_deploy::funding(env_number::<u128>("ONA_FUNDING_NEAR", 5)?).context("ONA_FUNDING_NEAR")
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
        base_value: amount(env_number::<u128>("ONA_BASE_VALUE_MILLI_NEAR", 100)?, MILLI).context("ONA_BASE_VALUE_MILLI_NEAR")?,
        circulation_cap: env_number("ONA_CIRCULATION_CAP", 1000)?,
        hourly_redeem_cap: env_number("ONA_HOURLY_REDEEM_CAP", 100)?,
        funding: funding()?,
    };
    let code = read_wasm("ONA_MINT_WASM", "target/wasm32-unknown-unknown/contract/ona_mint.wasm")?;
    let account = format!("mint.{}", deployer.parent);
    let roles = [("signer", plan.signer.as_str()), ("relay", plan.relay.as_str()), ("guardian", plan.guardian.as_str())];
    let actions = plan.actions(code.clone())?;
    deployer.send(&account, &roles, plan.funding, code, actions)
}

fn deploy_registry() -> Result<()> {
    let deployer = Deployer::from_env()?;
    let (first, second, aggregator) =
        (env("ONA_REGISTRY_OWNER_1")?, env("ONA_REGISTRY_OWNER_2")?, env("ONA_AGGREGATOR_ACCOUNT")?);
    let args = registry_init_args([&first, &second], &aggregator)?;
    let funding = funding()?;
    let code = read_wasm("ONA_REGISTRY_WASM", "target/wasm32-unknown-unknown/contract/ona_registry.wasm")?;
    let account = format!("registry.{}", deployer.parent);
    let roles = [("first owner", first.as_str()), ("second owner", second.as_str()), ("aggregator", aggregator.as_str())];
    let actions = deploy_actions(funding, code.clone(), &args);
    deployer.send(&account, &roles, funding, code, actions)
}

fn deploy_pool() -> Result<()> {
    let deployer = Deployer::from_env()?;
    let optional = |name: &str| -> Result<Option<u64>> {
        match std::env::var(name) {
            Ok(value) => Ok(Some(value.parse().map_err(|_| anyhow!("{name} is not a number"))?)),
            Err(_) => Ok(None),
        }
    };
    let (escape, admin) = (optional("ONA_ESCAPE_DELAY_SECS")?, optional("ONA_ADMIN_DELAY_SECS")?);
    let (guardian, agent) = (env("ONA_GUARDIAN_ACCOUNT")?, env("ONA_AGENT_ACCOUNT")?);
    let args = pool_init_args(&guardian, &agent, &deployer.network, escape, admin)?;
    let funding = funding()?;
    let code = read_wasm("ONA_POOL_WASM", "target/wasm32-unknown-unknown/contract/ona_pool.wasm")?;
    let account = format!("pool.{}", deployer.parent);
    let roles = [("guardian", guardian.as_str()), ("agent", agent.as_str())];
    let actions = deploy_actions(funding, code.clone(), &args);
    deployer.send(&account, &roles, funding, code, actions)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["mint"] => deploy_mint(),
        ["registry"] => deploy_registry(),
        ["pool"] => deploy_pool(),
        _ => Err(anyhow!("usage: ona-deploy mint | ona-deploy registry | ona-deploy pool")),
    };
    if let Err(e) = result {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
